"""Keccak-256 (the pre-standardisation Keccak used by Ethereum).

This is *not* SHA3-256. The two differ only in the domain-separation byte of
the padding -- Keccak pads with 0x01 and SHA3 pads with 0x06 -- which is
exactly why ``hashlib.sha3_256`` cannot be used here, and why this module
exists. Everything else (the Keccak-f[1600] permutation, the sponge
construction, rate 1088 bits / 136 bytes) is shared.

Correctness is pinned by the official test vectors in tests/test_keccak.py,
including the empty-input digest:

    keccak256(b"") == c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
"""

from __future__ import annotations

__all__ = ["keccak256", "keccak256_hex", "Keccak256"]

_MASK64 = (1 << 64) - 1

# Round constants for Keccak-f[1600] (24 rounds), iota step.
_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# Rotation offsets for the rho step, indexed as _RHO[x][y].
_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_RATE_BYTES = 136  # 1088 bits, the rate for a 256-bit Keccak digest
_OUT_BYTES = 32
_PAD_BYTE = 0x01  # Keccak's pad10*1 domain byte (SHA3 would use 0x06)


def _rotl64(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(lanes: list[list[int]]) -> None:
    """Apply the 24-round Keccak-f[1600] permutation to ``lanes`` in place.

    ``lanes`` is a 5x5 grid of 64-bit integers indexed ``lanes[x][y]``.
    """
    for round_constant in _ROUND_CONSTANTS:
        # theta
        column_parity = [
            lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
            for x in range(5)
        ]
        theta = [
            column_parity[(x - 1) % 5] ^ _rotl64(column_parity[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for x in range(5):
            d = theta[x]
            column = lanes[x]
            for y in range(5):
                column[y] ^= d

        # rho and pi, combined into one scatter into a fresh grid
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(lanes[x][y], _RHO[x][y])

        # chi
        for x in range(5):
            for y in range(5):
                lanes[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & _MASK64)

        # iota
        lanes[0][0] ^= round_constant


def _absorb_block(lanes: list[list[int]], block: bytes) -> None:
    """XOR one rate-sized block into the state, then permute.

    The state is laid out little-endian, lane ``(x, y)`` occupying bytes
    ``8 * (x + 5 * y)`` of the block.
    """
    for offset in range(0, _RATE_BYTES, 8):
        lane_index = offset // 8
        x = lane_index % 5
        y = lane_index // 5
        lanes[x][y] ^= int.from_bytes(block[offset : offset + 8], "little")
    _keccak_f1600(lanes)


def _squeeze(lanes: list[list[int]]) -> bytes:
    """Read the first 32 bytes out of the state (one squeeze is enough:
    the digest is shorter than the rate)."""
    out = bytearray()
    lane_index = 0
    while len(out) < _OUT_BYTES:
        x = lane_index % 5
        y = lane_index // 5
        out += lanes[x][y].to_bytes(8, "little")
        lane_index += 1
    return bytes(out[:_OUT_BYTES])


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data``."""
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise TypeError(f"keccak256 expects bytes, got {type(data).__name__}")

    lanes = [[0] * 5 for _ in range(5)]

    full_blocks = len(data) // _RATE_BYTES
    for i in range(full_blocks):
        _absorb_block(lanes, data[i * _RATE_BYTES : (i + 1) * _RATE_BYTES])

    # pad10*1: domain byte, zeroes, and the high bit of the final byte.
    tail = bytearray(data[full_blocks * _RATE_BYTES :])
    tail.append(_PAD_BYTE)
    tail += b"\x00" * (_RATE_BYTES - len(tail))
    tail[_RATE_BYTES - 1] |= 0x80
    _absorb_block(lanes, bytes(tail))

    return _squeeze(lanes)


def keccak256_hex(data: bytes, *, prefix: bool = False) -> str:
    """Return the Keccak-256 digest of ``data`` as a hex string."""
    digest = keccak256(data).hex()
    return "0x" + digest if prefix else digest


class Keccak256:
    """Minimal hashlib-shaped wrapper. Buffers input and hashes on digest().

    Provided for convenience/readability at call sites; the one-shot
    ``keccak256`` function is the primary interface.
    """

    digest_size = _OUT_BYTES
    block_size = _RATE_BYTES
    name = "keccak256"

    def __init__(self, data: bytes = b"") -> None:
        self._buffer = bytearray(data)

    def update(self, data: bytes) -> "Keccak256":
        self._buffer += data
        return self

    def digest(self) -> bytes:
        return keccak256(bytes(self._buffer))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "Keccak256":
        return Keccak256(bytes(self._buffer))
