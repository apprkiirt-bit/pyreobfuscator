"""Runtime half of an artifact.

This file is never imported by pyreobfuscator. The builder pastes crypto.py, codec.py
and this file into one script, then appends the config and calls _pb_main.
"""

import sys
import builtins

_PB_META = list(sys.meta_path)
_PB_BUILTIN = type(len)
_PB_FAIL_MSG = "internal error"
_PB_FINDER = None
_PB_INSERT = len(_PB_META)


def _pb_fail():
    raise SystemError(_PB_FAIL_MSG)


def _pb_check_builtins():
    for name in ("exec", "eval", "compile", "__import__", "getattr", "setattr"):
        fn = getattr(builtins, name, None)
        if type(fn) is not _PB_BUILTIN or getattr(fn, "__self__", None) is not builtins \
                or getattr(fn, "__name__", None) != name:
            _pb_fail()
    if type(builtins.open) is not _PB_BUILTIN or getattr(builtins.open, "__name__", None) != "open":
        _pb_fail()
    for name in ("settrace", "setprofile", "gettrace", "getprofile"):
        fn = getattr(sys, name, None)
        if type(fn) is not _PB_BUILTIN or getattr(fn, "__name__", None) != name:
            _pb_fail()


def _pb_install_audit():
    def hook(event, args):
        if event in ("sys.settrace", "sys.setprofile"):
            _pb_fail()
    try:
        sys.addaudithook(hook)
    except Exception:
        _pb_fail()


def _pb_check_trace():
    if sys.gettrace() is not None or sys.getprofile() is not None:
        _pb_fail()
    monitor = getattr(sys, "monitoring", None)
    if monitor is not None:
        try:
            for tool in range(6):
                if monitor.get_tool(tool) is not None:
                    _pb_fail()
        except Exception:
            _pb_fail()


def _pb_check_meta():
    if list(sys.meta_path) != _PB_META:
        _pb_fail()


def _pb_check_modules():
    for name in ("pdb", "bdb", "trace", "coverage", "debugpy", "pydevd", "frida",
                 "ptvsd", "pyinstrument", "xdis", "uncompyle6", "decompyle3",
                 "pycdc", "pycdas"):
        if name in sys.modules:
            _pb_fail()


def _pb_check_env(strict):
    if not strict:
        return
    for name in ("PYTHONINSPECT", "PYTHONBREAKPOINT", "PYTHONSTARTUP"):
        value = os.environ.get(name)
        if value and value != "0":
            _pb_fail()


def _pb_check_antidebug():
    try:
        if sys.platform == "win32":
            import ctypes
            kernel = ctypes.windll.kernel32
            if kernel.IsDebuggerPresent():
                _pb_fail()
            present = ctypes.c_int()
            if kernel.CheckRemoteDebuggerPresent(
                    kernel.GetCurrentProcess(), ctypes.byref(present)) and present.value:
                _pb_fail()
        elif sys.platform.startswith("linux"):
            with open("/proc/self/status", "r", encoding="ascii", errors="ignore") as handle:
                for line in handle:
                    if line.startswith("TracerPid:"):
                        if line.split()[1] != "0":
                            _pb_fail()
                        break
    except SystemError:
        raise
    except Exception:
        pass


def _pb_self_hash(cfg):
    path = globals().get("__file__")
    if not path:
        return
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return
    expected = cfg.get("h")
    if not expected:
        _pb_fail()
    marker = ("'h': '" + expected + "'").encode()
    blank = data.replace(marker, b"'h': ''", 1)
    if blank == data:
        _pb_fail()
    if hashlib.sha256(blank).hexdigest() != expected:
        _pb_fail()


def _pb_master(cfg):
    seed0 = bytes.fromhex(cfg["share0"])
    seed1 = bytes.fromhex(cfg["share1"])
    tail = bytes.fromhex(cfg["share2"])
    left = kdf(seed0, "share0")
    right = kdf(seed1, "share1")
    if len(left) != 32 or len(right) != 32 or len(tail) != 32:
        _pb_fail()
    return bytes(a ^ b ^ c for a, b, c in zip(left, right, tail))


def _pb_label(name, salt, kind):
    return name + "|" + salt + "|" + kind


def _pb_code_for(record, master, name, salt):
    if sys.implementation.name != "cpython" or sys.implementation.cache_tag != record["tag"]:
        _pb_fail()
    label = _pb_label(name, salt, "code")
    return loads(open_sealed(kdf(master, label), record["code"], label.encode()))


def _pb_table_for(record, master, name, salt):
    blob = record.get("table")
    if blob is None:
        return ()
    label = _pb_label(name, salt, "table")
    return loads(open_sealed(kdf(master, label), blob, label.encode()))


def _pb_vm_make(programs, op_names):
    import operator

    binops = {
        "add": operator.add, "sub": operator.sub, "mul": operator.mul,
        "truediv": operator.truediv, "floordiv": operator.floordiv,
        "mod": operator.mod, "pow": operator.pow, "lshift": operator.lshift,
        "rshift": operator.rshift, "or_": operator.or_, "xor": operator.xor,
        "and_": operator.and_, "matmul": operator.matmul,
    }
    unary = {
        "not_": operator.not_, "neg": operator.neg, "pos": operator.pos,
        "invert": operator.invert,
    }
    compares = {
        "eq": operator.eq, "ne": operator.ne, "lt": operator.lt, "le": operator.le,
        "gt": operator.gt, "ge": operator.ge, "is_": operator.is_,
        "is_not": operator.is_not,
    }
    unset = object()

    class _ReturnSignal(Exception):
        def __init__(self, value):
            self.value = value

    class _BreakSignal(Exception):
        pass

    class _ContinueSignal(Exception):
        pass

    def execute(pid, regs, globals_, locals_):
        program = programs[pid]
        code = program["code"]
        consts = program["consts"]
        ip = 0
        while ip < len(code):
            instruction = code[ip]
            ip += 1
            name = op_names[instruction[0]]
            if name == "CONST":
                regs[instruction[1]] = consts[instruction[2]]
            elif name == "LOAD_REG":
                value = regs[instruction[2]]
                if value is unset:
                    raise UnboundLocalError("local variable referenced before assignment")
                regs[instruction[1]] = value
            elif name == "STORE_REG":
                regs[instruction[1]] = regs[instruction[2]]
            elif name == "LOAD_GLOBAL":
                key = instruction[2]
                if key in globals_:
                    regs[instruction[1]] = globals_[key]
                elif hasattr(builtins, key):
                    regs[instruction[1]] = getattr(builtins, key)
                else:
                    raise NameError("name '%s' is not defined" % key)
            elif name == "STORE_GLOBAL":
                globals_[instruction[1]] = regs[instruction[2]]
            elif name == "LOAD_ATTR":
                regs[instruction[1]] = getattr(regs[instruction[2]], instruction[3])
            elif name == "STORE_ATTR":
                setattr(regs[instruction[1]], instruction[2], regs[instruction[3]])
            elif name == "LOAD_SUBSCR":
                regs[instruction[1]] = regs[instruction[2]][regs[instruction[3]]]
            elif name == "STORE_SUBSCR":
                regs[instruction[1]][regs[instruction[2]]] = regs[instruction[3]]
            elif name == "BUILD_SLICE":
                regs[instruction[1]] = slice(regs[instruction[2]], regs[instruction[3]],
                                             regs[instruction[4]])
            elif name == "BUILD_LIST":
                regs[instruction[1]] = [regs[index] for index in instruction[2]]
            elif name == "BUILD_TUPLE":
                regs[instruction[1]] = tuple(regs[index] for index in instruction[2])
            elif name == "BUILD_SET":
                regs[instruction[1]] = {regs[index] for index in instruction[2]}
            elif name == "BUILD_MAP":
                result = {}
                for key, value in instruction[2]:
                    result[regs[key]] = regs[value]
                regs[instruction[1]] = result
            elif name == "BUILD_STRING":
                regs[instruction[1]] = "".join(
                    regs[index] if isinstance(regs[index], str) else str(regs[index])
                    for index in instruction[2])
            elif name == "FORMAT":
                value = regs[instruction[2]]
                spec = regs[instruction[3]]
                conversion = instruction[4]
                if conversion == 114:
                    value = repr(value)
                elif conversion == 115:
                    value = str(value)
                elif conversion == 97:
                    value = ascii(value)
                regs[instruction[1]] = format(value, "" if spec is None else spec)
            elif name == "BINOP":
                regs[instruction[1]] = binops[instruction[4]](
                    regs[instruction[2]], regs[instruction[3]])
            elif name == "UNARY":
                regs[instruction[1]] = unary[instruction[3]](regs[instruction[2]])
            elif name == "COMPARE":
                left = regs[instruction[2]]
                right = regs[instruction[3]]
                op = instruction[4]
                if op == "contains":
                    regs[instruction[1]] = left in right
                elif op == "not_contains":
                    regs[instruction[1]] = left not in right
                else:
                    regs[instruction[1]] = compares[op](left, right)
            elif name == "CALL":
                func = regs[instruction[2]]
                args = [regs[index] for index in instruction[3]]
                kwargs = {key: regs[index] for key, index in instruction[4]}
                regs[instruction[1]] = func(*args, **kwargs)
            elif name == "GET_ITER":
                regs[instruction[1]] = iter(regs[instruction[2]])
            elif name == "FOR_NEXT":
                try:
                    regs[instruction[1]] = next(regs[instruction[2]])
                except StopIteration:
                    ip = instruction[3]
            elif name == "JUMP":
                ip = instruction[1]
            elif name == "JUMP_IF_FALSE":
                if not regs[instruction[1]]:
                    ip = instruction[2]
            elif name == "JUMP_IF_TRUE":
                if regs[instruction[1]]:
                    ip = instruction[2]
            elif name == "IMPORT":
                module = instruction[2]
                fromlist = instruction[3]
                level = instruction[4]
                regs[instruction[1]] = __import__(
                    module, globals_, locals_, fromlist, level)
            elif name == "IMPORT_FROM":
                regs[instruction[1]] = getattr(regs[instruction[2]], instruction[3])
            elif name == "TRY":
                body, handlers, otherwise, final = instruction[1:]
                try:
                    try:
                        execute(body, regs, globals_, locals_)
                    except (_ReturnSignal, _BreakSignal, _ContinueSignal):
                        raise
                    except BaseException as error:
                        matched = False
                        for names, bind, handler in handlers:
                            if names is None:
                                caught = True
                            else:
                                types = tuple(
                                    globals_.get(item) or getattr(builtins, item)
                                    for item in names)
                                caught = isinstance(error, types)
                            if caught:
                                if bind >= 0:
                                    regs[bind] = error
                                execute(handler, regs, globals_, locals_)
                                matched = True
                                break
                        if not matched:
                            raise
                    else:
                        if otherwise >= 0:
                            execute(otherwise, regs, globals_, locals_)
                finally:
                    if final >= 0:
                        execute(final, regs, globals_, locals_)
            elif name == "RETURN":
                raise _ReturnSignal(regs[instruction[1]])
            elif name == "RAISE":
                raise regs[instruction[1]]
            else:
                raise RuntimeError("bad vm opcode")
        return None

    def run(pid, locals_, globals_):
        program = programs[pid]
        regs = [unset] * program["nregs"]
        for name, index in program["params"]:
            if name in locals_:
                regs[index] = locals_[name]
        try:
            execute(pid, regs, globals_, locals_)
        except _ReturnSignal as signal:
            return signal.value
        except (_BreakSignal, _ContinueSignal):
            return None
        return None

    return run


def _pb_vm_for(record, master, name, salt, ops):
    blob = record.get("vm")
    if blob is None:
        return None
    label = _pb_label(name, salt, "vm")
    return _pb_vm_make(loads(open_sealed(kdf(master, label), blob, label.encode())), ops)


class _PB_Loader:
    def __init__(self, manifest, master, name, record, artifact):
        self.manifest = manifest
        self.master = master
        self.name = name
        self.record = record
        self.artifact = artifact

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        record = self.record
        namespace = module.__dict__
        namespace["__builtins__"] = builtins
        namespace["__file__"] = self.artifact
        namespace["__cached__"] = None
        namespace["__loader__"] = self
        namespace[record["table_name"]] = _pb_table_for(
            record, self.master, self.name, self.manifest["salt"])
        namespace[self.manifest["iter"]] = iter
        namespace[self.manifest["next"]] = next
        namespace[self.manifest["stop"]] = StopIteration
        vm = _pb_vm_for(record, self.master, self.name, self.manifest["salt"],
                        self.manifest.get("vm_ops", {}))
        if vm is not None:
            namespace[self.manifest["vm"]] = vm
        code = _pb_code_for(record, self.master, self.name, self.manifest["salt"])
        type(lambda: None)(code, namespace)()


class _PB_Finder:
    def __init__(self, manifest, master, artifact):
        self.manifest = manifest
        self.master = master
        self.artifact = artifact

    def find_spec(self, fullname, path=None, target=None):
        record = self.manifest["modules"].get(fullname)
        if record is None:
            return None
        loader = _PB_Loader(self.manifest, self.master, fullname, record, self.artifact)
        spec = _PB_SPEC(fullname, loader, is_package=bool(record.get("pkg")))
        if record.get("pkg") and spec.submodule_search_locations is None:
            spec.submodule_search_locations = []
        return spec


def _pb_watchdog(interval, name="t", cfg=None):
    import time
    import os
    import threading

    def loop():
        while True:
            time.sleep(interval)
            try:
                _pb_check_builtins()
                _pb_check_trace()
                _pb_check_modules()
                _pb_check_antidebug()
                if cfg is not None:
                    _pb_self_hash(cfg)
                if list(sys.meta_path) != (_PB_META[:_PB_INSERT] + [_PB_FINDER] + _PB_META[_PB_INSERT:]):
                    os._exit(1)
            except BaseException:
                os._exit(1)

    thread = threading.Thread(target=loop, name=name, daemon=True)
    thread.start()


def _pb_main(cfg):
    global _PB_FAIL_MSG, _PB_FINDER, _PB_INSERT, _PB_SPEC
    _PB_FAIL_MSG = cfg.get("message", "internal error")
    artifact = globals().get("__file__") or ""
    # @@CORE_CHECKS@@
    master = _pb_master(cfg)
    salt = cfg["salt"]
    manifest = loads(open_sealed(master, bytes.fromhex(cfg["manifest"]),
                                 ("manifest|" + salt).encode()))

    import importlib.util as _importlib_util
    _PB_SPEC = _importlib_util.spec_from_loader

    finder = _PB_Finder(manifest, master, artifact)
    insert = len(sys.meta_path)
    for index, existing in enumerate(sys.meta_path):
        if getattr(existing, "__name__", "") == "PathFinder":
            insert = index
            break
    sys.meta_path.insert(insert, finder)
    _PB_INSERT = insert
    _PB_FINDER = finder

    if cfg.get("watchdog", 0):
        _pb_watchdog(float(cfg["watchdog"]), cfg.get("thread", "t"), cfg)

    entry = manifest["entry"]
    record = manifest["modules"][entry]
    namespace = {
        "__name__": "__main__",
        "__file__": artifact,
        "__package__": manifest.get("entry_pkg"),
        "__cached__": None,
        "__doc__": None,
        "__loader__": None,
        "__spec__": None,
        "__builtins__": builtins,
    }
    namespace[record["table_name"]] = _pb_table_for(record, master, entry, salt)
    namespace[manifest["iter"]] = iter
    namespace[manifest["next"]] = next
    namespace[manifest["stop"]] = StopIteration
    vm = _pb_vm_for(record, master, entry, salt, manifest.get("vm_ops", {}))
    if vm is not None:
        namespace[manifest["vm"]] = vm
    code = _pb_code_for(record, master, entry, salt)
    module = type(sys)("__main__")
    module.__dict__.update(namespace)
    sys.modules["__main__"] = module
    type(lambda: None)(code, module.__dict__)()
