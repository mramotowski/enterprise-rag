# Copyright (C) 2024-2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""Generate a NATS user NKey pair.

Prints two lines: the seed (an "SU..." string) and the public key (a "U..."
string), matching the encoding the nats-server and nats.go client expect. The
seed is fed to a NATS client via NkeyOptionFromSeed; the public key is listed in
the server's authorization block.
"""

import base64
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# NKey prefix bytes (see nats-io/nkeys). The values are pre-shifted.
PREFIX_SEED = 18 << 3
PREFIX_USER = 20 << 3


def _crc16(data: bytes) -> int:
    """CRC-16/XMODEM checksum (poly 0x1021, init 0), as NKeys uses."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def _b32(raw: bytes) -> str:
    """Base32 without padding, as NKeys uses."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _encode(prefix: int, payload: bytes) -> str:
    raw = bytes([prefix]) + payload
    crc = _crc16(raw)
    raw += bytes([crc & 0xFF, crc >> 8])
    return _b32(raw)


def _encode_seed(public_prefix: int, seed: bytes) -> str:
    b1 = PREFIX_SEED | (public_prefix >> 5)
    b2 = (public_prefix & 0b11111) << 3
    raw = bytes([b1, b2]) + seed
    crc = _crc16(raw)
    raw += bytes([crc & 0xFF, crc >> 8])
    return _b32(raw)


def main() -> None:
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    print(_encode_seed(PREFIX_USER, seed))
    print(_encode(PREFIX_USER, public))


if __name__ == "__main__":
    main()
    sys.exit(0)
