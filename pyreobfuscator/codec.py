"""Binary serializer for code objects and plain values.

No marshal, no pickle. The runtime half of this file is pasted into every
artifact, so keep it dependency-free apart from the standard library.
"""

import struct

_MAGIC = b"PB1"

_T_NONE = 0
_T_FALSE = 1
_T_TRUE = 2
_T_INT = 3
_T_NEGINT = 4
_T_FLOAT = 5
_T_COMPLEX = 6
_T_STR = 7
_T_BYTES = 8
_T_TUPLE = 9
_T_FROZENSET = 10
_T_CODE = 11
_T_LIST = 12
_T_DICT = 13
_T_ELLIPSIS = 14
_T_SLICE = 15

_FIELDS = (
    "co_argcount",
    "co_posonlyargcount",
    "co_kwonlyargcount",
    "co_nlocals",
    "co_stacksize",
    "co_flags",
    "co_code",
    "co_consts",
    "co_names",
    "co_varnames",
    "co_freevars",
    "co_cellvars",
    "co_filename",
    "co_name",
    "co_qualname",
    "co_firstlineno",
    "co_linetable",
    "co_lnotab",
    "co_exceptiontable",
)


def _fields_for(code):
    has_linetable = hasattr(code, "co_linetable")
    names = []
    for name in _FIELDS:
        if name == "co_lnotab" and has_linetable:
            continue
        if hasattr(code, name):
            names.append(name)
    return names


def _wv(out, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return


def _rv(data, pos):
    value = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _wbytes(out, raw):
    _wv(out, len(raw))
    out.extend(raw)


def _rbytes(data, pos):
    size, pos = _rv(data, pos)
    return bytes(data[pos:pos + size]), pos + size


def _wstr(out, text):
    _wbytes(out, text.encode("utf-8", "surrogatepass"))


def _rstr(data, pos):
    raw, pos = _rbytes(data, pos)
    return raw.decode("utf-8", "surrogatepass"), pos


def _wvalue(out, value):
    if value is None:
        out.append(_T_NONE)
    elif value is True:
        out.append(_T_TRUE)
    elif value is False:
        out.append(_T_FALSE)
    elif value is Ellipsis:
        out.append(_T_ELLIPSIS)
    elif isinstance(value, int):
        if value >= 0:
            out.append(_T_INT)
            _wv(out, value)
        else:
            out.append(_T_NEGINT)
            _wv(out, -value)
    elif isinstance(value, float):
        out.append(_T_FLOAT)
        out.extend(struct.pack("<d", value))
    elif isinstance(value, complex):
        out.append(_T_COMPLEX)
        out.extend(struct.pack("<dd", value.real, value.imag))
    elif isinstance(value, slice):
        out.append(_T_SLICE)
        _wvalue(out, value.start)
        _wvalue(out, value.stop)
        _wvalue(out, value.step)
    elif isinstance(value, str):
        out.append(_T_STR)
        _wstr(out, value)
    elif isinstance(value, bytes):
        out.append(_T_BYTES)
        _wbytes(out, value)
    elif isinstance(value, tuple):
        out.append(_T_TUPLE)
        _wv(out, len(value))
        for item in value:
            _wvalue(out, item)
    elif isinstance(value, frozenset):
        out.append(_T_FROZENSET)
        _wv(out, len(value))
        for item in value:
            _wvalue(out, item)
    elif isinstance(value, list):
        out.append(_T_LIST)
        _wv(out, len(value))
        for item in value:
            _wvalue(out, item)
    elif isinstance(value, dict):
        out.append(_T_DICT)
        _wv(out, len(value))
        for key, item in value.items():
            _wvalue(out, key)
            _wvalue(out, item)
    elif type(value).__name__ == "code":
        out.append(_T_CODE)
        _wcode(out, value)
    else:
        raise TypeError("cannot serialize %r" % (type(value),))


def _wcode(out, code):
    names = _fields_for(code)
    mask = 0
    for index, name in enumerate(_FIELDS):
        if name in names:
            mask |= 1 << index
    out.extend(mask.to_bytes(3, "little"))
    for name in names:
        _wvalue(out, getattr(code, name))


def _rvalue(data, pos):
    tag = data[pos]
    pos += 1
    if tag == _T_NONE:
        return None, pos
    if tag == _T_FALSE:
        return False, pos
    if tag == _T_TRUE:
        return True, pos
    if tag == _T_INT:
        value, pos = _rv(data, pos)
        return value, pos
    if tag == _T_NEGINT:
        value, pos = _rv(data, pos)
        return -value, pos
    if tag == _T_FLOAT:
        return struct.unpack("<d", data[pos:pos + 8])[0], pos + 8
    if tag == _T_COMPLEX:
        real, imag = struct.unpack("<dd", data[pos:pos + 16])
        return complex(real, imag), pos + 16
    if tag == _T_SLICE:
        start, pos = _rvalue(data, pos)
        stop, pos = _rvalue(data, pos)
        step, pos = _rvalue(data, pos)
        return slice(start, stop, step), pos
    if tag == _T_STR:
        return _rstr(data, pos)
    if tag == _T_BYTES:
        return _rbytes(data, pos)
    if tag == _T_TUPLE:
        size, pos = _rv(data, pos)
        items = []
        for _ in range(size):
            item, pos = _rvalue(data, pos)
            items.append(item)
        return tuple(items), pos
    if tag == _T_FROZENSET:
        size, pos = _rv(data, pos)
        items = []
        for _ in range(size):
            item, pos = _rvalue(data, pos)
            items.append(item)
        return frozenset(items), pos
    if tag == _T_LIST:
        size, pos = _rv(data, pos)
        items = []
        for _ in range(size):
            item, pos = _rvalue(data, pos)
            items.append(item)
        return items, pos
    if tag == _T_DICT:
        size, pos = _rv(data, pos)
        result = {}
        for _ in range(size):
            key, pos = _rvalue(data, pos)
            item, pos = _rvalue(data, pos)
            result[key] = item
        return result, pos
    if tag == _T_ELLIPSIS:
        return Ellipsis, pos
    if tag == _T_CODE:
        return _rcode(data, pos)
    raise ValueError("invalid")


def _rcode(data, pos):
    mask = int.from_bytes(data[pos:pos + 3], "little")
    pos += 3
    changes = {}
    for index, name in enumerate(_FIELDS):
        if mask & (1 << index):
            value, pos = _rvalue(data, pos)
            changes[name] = value
    base = (lambda: None).__code__
    return base.replace(**changes), pos


def dumps(value):
    out = bytearray(_MAGIC)
    _wvalue(out, value)
    return bytes(out)


def loads(data):
    if bytes(data[:len(_MAGIC)]) != _MAGIC:
        raise ValueError("invalid")
    value, pos = _rvalue(data, len(_MAGIC))
    if pos != len(data):
        raise ValueError("invalid")
    return value
