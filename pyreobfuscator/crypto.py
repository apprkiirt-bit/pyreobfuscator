"""ChaCha20-Poly1305 and key derivation."""

import hashlib
import os
import struct

_MASK32 = 0xFFFFFFFF
_MASK128 = (1 << 128) - 1
_P1305 = (1 << 130) - 5




def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & _MASK32


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & _MASK32
    x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & _MASK32
    x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & _MASK32
    x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & _MASK32
    x[b] = _rotl(x[b] ^ x[c], 7)


def _chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state.append(counter & _MASK32)
    state += list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        _qr(work, 0, 4, 8, 12)
        _qr(work, 1, 5, 9, 13)
        _qr(work, 2, 6, 10, 14)
        _qr(work, 3, 7, 11, 15)
        _qr(work, 0, 5, 10, 15)
        _qr(work, 1, 6, 11, 12)
        _qr(work, 2, 7, 8, 13)
        _qr(work, 3, 4, 9, 14)
    return struct.pack("<16I", *[((work[i] + state[i]) & _MASK32) for i in range(16)])


def _chacha20(key, nonce, counter, data):
    out = bytearray()
    blocks = (len(data) + 63) // 64
    for b in range(blocks):
        stream = _chacha_block(key, counter + b, nonce)
        chunk = data[b * 64:(b + 1) * 64]
        size = len(chunk)
        value = int.from_bytes(chunk, "little") ^ int.from_bytes(stream[:size], "little")
        out.extend(value.to_bytes(size, "little"))
    return bytes(out)


def _poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for off in range(0, len(msg), 16):
        chunk = msg[off:off + 16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % _P1305
    return ((acc + s) & _MASK128).to_bytes(16, "little")


def _pad16(data):
    rem = len(data) % 16
    return b"\x00" * (16 - rem) if rem else b""


def kdf(key, label):
    """32-byte subkey from a master key and a label."""
    if isinstance(label, str):
        label = label.encode("utf-8")
    return hashlib.sha256(key + b"|" + label).digest()


def seal(key, plaintext, nonce=None, aad=b""):
    """Return nonce || ciphertext || tag."""
    nonce = nonce or os.urandom(12)
    one_time = _chacha_block(key, 0, nonce)[:32]
    ciphertext = _chacha20(key, nonce, 1, plaintext)
    mac_data = (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
                + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little"))
    return nonce + ciphertext + _poly1305(mac_data, one_time)


def open_sealed(key, blob, aad=b""):
    if len(blob) < 28:
        raise ValueError("invalid")
    nonce, ciphertext, tag = blob[:12], blob[12:-16], blob[-16:]
    one_time = _chacha_block(key, 0, nonce)[:32]
    mac_data = (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
                + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little"))
    expected = _poly1305(mac_data, one_time)
    diff = 0
    for a, b in zip(expected, tag):
        diff |= a ^ b
    if diff:
        raise ValueError("invalid")
    return _chacha20(key, nonce, 1, ciphertext)



