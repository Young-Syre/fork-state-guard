"""Address parsing, comparison and EIP-55 checksum formatting."""

from __future__ import annotations

from .keccak import keccak256_hex

__all__ = [
    "AddressError",
    "is_hex_address",
    "normalize_address",
    "to_checksum_address",
    "is_checksum_address",
    "addresses_equal",
]

_HEX_DIGITS = set("0123456789abcdefABCDEF")

ZERO_ADDRESS = "0x" + "0" * 40


class AddressError(ValueError):
    """Raised when a value cannot be read as a 20-byte hex address."""


def is_hex_address(value: object) -> bool:
    """True if ``value`` looks like a 20-byte hex address (checksum ignored)."""
    if not isinstance(value, str):
        return False
    body = value[2:] if value[:2].lower() == "0x" else value
    return len(body) == 40 and all(c in _HEX_DIGITS for c in body)


def normalize_address(value: object) -> str:
    """Return ``value`` as a lowercase ``0x``-prefixed address.

    Used for comparison: on-chain values carry no case information, so case
    is never meaningful when deciding whether two addresses match.
    """
    if not isinstance(value, str):
        raise AddressError(f"not an address: {value!r}")
    body = value[2:] if value[:2].lower() == "0x" else value
    if len(body) != 40:
        raise AddressError(
            f"address must be 20 bytes (40 hex digits), got {len(body)} digits: {value!r}"
        )
    if not all(c in _HEX_DIGITS for c in body):
        raise AddressError(f"address contains non-hex characters: {value!r}")
    return "0x" + body.lower()


def to_checksum_address(value: str) -> str:
    """Return the EIP-55 mixed-case checksum form of ``value``.

    Each hex letter is uppercased when the corresponding nibble of
    ``keccak256(lowercase_address_without_0x)`` is >= 8.
    """
    body = normalize_address(value)[2:]
    digest = keccak256_hex(body.encode("ascii"))
    out = []
    for char, nibble in zip(body, digest):
        if char in "0123456789":
            out.append(char)
        else:
            out.append(char.upper() if int(nibble, 16) >= 8 else char)
    return "0x" + "".join(out)


def is_checksum_address(value: str) -> bool:
    """True if ``value`` is a correctly EIP-55-checksummed address.

    An all-lowercase or all-uppercase address is not checksummed and so
    returns False, matching the EIP's own reference behaviour.
    """
    if not is_hex_address(value):
        return False
    body = value[2:] if value[:2].lower() == "0x" else value
    return to_checksum_address(body) == "0x" + body


def addresses_equal(left: object, right: object) -> bool:
    """Case-insensitive address comparison; False if either side is unparseable."""
    try:
        return normalize_address(left) == normalize_address(right)
    except AddressError:
        return False
