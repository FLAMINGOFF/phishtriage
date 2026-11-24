"""Wrap a suspicious attachment in a ZIP encrypted with the password ``infected``.

This is the industry convention for handing malware samples around: the file cannot be
opened by accident, and mail filters and anti-virus software leave it alone. It is not
meant to keep the content secret (everyone knows the password), so the traditional
PKWARE "ZipCrypto" scheme is enough, and it opens with every unzip tool, including
Python's ``zipfile`` (which can read it but not write it, hence this small writer).
"""

from __future__ import annotations

import secrets
import struct
import unicodedata
import zlib

PASSWORD = b"infected"
_DOS_DATE_1980 = (1 << 5) | 1  # 1980-01-01, the ZIP epoch: no timestamps leak
_FLAG_ENCRYPTED = 0x0001
_FLAG_UTF8 = 0x0800
_DEFLATE = 8

_CRC_TABLE = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE[_i] = _c


class _ZipCrypto:
    def __init__(self, password: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for byte in password:
            self._update(byte)

    def _update(self, byte: int) -> None:
        self.k0 = (self.k0 >> 8) ^ _CRC_TABLE[(self.k0 ^ byte) & 0xFF]
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ _CRC_TABLE[(self.k2 ^ (self.k1 >> 24)) & 0xFF]

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        k0, k1, k2, table = self.k0, self.k1, self.k2, _CRC_TABLE
        for i, plain in enumerate(data):
            temp = (k2 | 2) & 0xFFFF
            out[i] = plain ^ (((temp * (temp ^ 1)) >> 8) & 0xFF)
            k0 = (k0 >> 8) ^ table[(k0 ^ plain) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = (k2 >> 8) ^ table[(k2 ^ (k1 >> 24)) & 0xFF]
        self.k0, self.k1, self.k2 = k0, k1, k2
        return bytes(out)


def safe_filename(name: str, fallback: str = "attachment") -> str:
    """A display name made safe to write to disk: no directories, no invisible characters.

    ``../../etc/passwd`` becomes ``passwd``; a right-to-left override that disguises
    ``invoice<RLO>gpj.exe`` as a picture is dropped, so the real extension shows.
    """
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(
        "_" if ch in ':*?"<>|' else ch
        for ch in base
        if unicodedata.category(ch) not in ("Cc", "Cf", "Co", "Cs")
    )
    cleaned = cleaned.strip().lstrip(".").strip()
    return cleaned[:150] or fallback


def infected_zip(filename: str, content: bytes, password: bytes = PASSWORD) -> bytes:
    """A ZIP archive holding ``content`` as ``filename``, encrypted with ``password``."""
    name = safe_filename(filename).encode("utf-8")
    crc = zlib.crc32(content) & 0xFFFFFFFF
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    compressed = compressor.compress(content) + compressor.flush()

    crypto = _ZipCrypto(password)
    # 12-byte encryption header: random, except the last byte, which lets unzip tools
    # check the password against the CRC.
    header = secrets.token_bytes(11) + bytes([crc >> 24])
    payload = crypto.encrypt(header) + crypto.encrypt(compressed)

    flags = _FLAG_ENCRYPTED | _FLAG_UTF8
    common = struct.pack(
        "<HHHHHIII", 20, flags, _DEFLATE, 0, _DOS_DATE_1980, crc, len(payload), len(content)
    )
    local = b"PK\x03\x04" + common + struct.pack("<HH", len(name), 0) + name
    central = (
        b"PK\x01\x02"
        + struct.pack("<H", 20)
        + common
        + struct.pack("<HHHHHII", len(name), 0, 0, 0, 0, 0, 0)
        + name
    )
    offset = len(local) + len(payload)
    end = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), offset, 0)
    return local + payload + central + end
