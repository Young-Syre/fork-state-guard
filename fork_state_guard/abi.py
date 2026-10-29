"""Minimal ABI codec: function selectors, encoding of static argument types,
and decoding of single return values.

Deliberately small. fork-state-guard only ever makes read-only calls with a
handful of scalar arguments, so the full ABI type system is out of scope --
see SUPPORTED_ARG_TYPES / SUPPORTED_RETURN_TYPES for exactly what is handled,
and expect a clear AbiError for anything else rather than a silent mis-encode.
"""

from __future__ import annotations

import re
from typing import Any

from .address import AddressError, normalize_address
from .keccak import keccak256

__all__ = [
    "AbiError",
    "SignatureError",
    "function_selector",
    "canonical_signature",
    "parse_signature",
    "encode_call",
    "encode_argument",
    "decode_single",
    "SUPPORTED_ARG_TYPES",
    "SUPPORTED_RETURN_TYPES",
]

WORD = 32

_SIGNATURE_RE = re.compile(r"^(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\((?P<args>.*)\)$", re.DOTALL)
_UINT_RE = re.compile(r"^uint(\d+)$")
_INT_RE = re.compile(r"^int(\d+)$")
_BYTES_N_RE = re.compile(r"^bytes(\d+)$")

SUPPORTED_ARG_TYPES = ("address", "bool", "uint<N>", "int<N>", "bytes<N>")
SUPPORTED_RETURN_TYPES = ("address", "bool", "uint<N>", "int<N>", "bytes<N>", "string", "bytes")


class AbiError(ValueError):
    """Raised when a value cannot be encoded, or return data cannot be decoded."""


class SignatureError(AbiError):
    """Raised when a function signature is malformed or uses an unsupported type."""


def _canonical_type(type_name: str) -> str:
    """Resolve ABI type aliases to their canonical spelling.

    Selectors are computed over canonical types: ``transfer(address,uint)``
    and ``transfer(address,uint256)`` are the same function, and only the
    latter spelling produces the right selector.
    """
    name = type_name.strip()
    if not name:
        raise SignatureError("empty type in signature")
    if name == "uint":
        return "uint256"
    if name == "int":
        return "int256"
    if name == "byte":
        return "bytes1"
    return name


def _validate_arg_type(type_name: str) -> str:
    """Return the canonical form of an encodable argument type."""
    name = _canonical_type(type_name)
    if name in ("address", "bool"):
        return name
    if m := _UINT_RE.match(name):
        bits = int(m.group(1))
        if bits % 8 or not 8 <= bits <= 256:
            raise SignatureError(f"invalid uint width: {name}")
        return name
    if m := _INT_RE.match(name):
        bits = int(m.group(1))
        if bits % 8 or not 8 <= bits <= 256:
            raise SignatureError(f"invalid int width: {name}")
        return name
    if m := _BYTES_N_RE.match(name):
        size = int(m.group(1))
        if not 1 <= size <= 32:
            raise SignatureError(f"invalid fixed bytes width: {name}")
        return name
    if name in ("string", "bytes") or name.endswith("]") or name.startswith("("):
        raise SignatureError(
            f"dynamic argument type {name!r} is not supported as a call argument; "
            f"supported argument types: {', '.join(SUPPORTED_ARG_TYPES)}"
        )
    raise SignatureError(
        f"unsupported argument type {name!r}; "
        f"supported argument types: {', '.join(SUPPORTED_ARG_TYPES)}"
    )


def parse_signature(signature: str) -> tuple[str, list[str]]:
    """Split ``"balanceOf(address)"`` into ``("balanceOf", ["address"])``.

    Argument types are returned in canonical form.
    """
    if not isinstance(signature, str):
        raise SignatureError(f"signature must be a string, got {type(signature).__name__}")
    text = "".join(signature.split())
    match = _SIGNATURE_RE.match(text)
    if not match:
        raise SignatureError(
            f"malformed function signature {signature!r}; expected e.g. 'owner()' "
            f"or 'balanceOf(address)'"
        )
    raw_args = match.group("args")
    if raw_args == "":
        arg_types: list[str] = []
    else:
        if "(" in raw_args or ")" in raw_args:
            raise SignatureError(f"tuple arguments are not supported: {signature!r}")
        arg_types = [_validate_arg_type(part) for part in raw_args.split(",")]
    return match.group("name"), arg_types


def canonical_signature(signature: str) -> str:
    """Return the canonical text a selector is computed over."""
    name, arg_types = parse_signature(signature)
    return f"{name}({','.join(arg_types)})"


def function_selector(signature: str) -> bytes:
    """Return the 4-byte selector for ``signature``.

    e.g. ``transfer(address,uint256)`` -> ``0xa9059cbb``.
    """
    return keccak256(canonical_signature(signature).encode("ascii"))[:4]


def _coerce_int(value: Any, type_name: str) -> int:
    """Read an integer from a TOML scalar.

    uint256 values routinely exceed what TOML can represent as an integer
    (TOML integers are 64-bit), so decimal and hex strings are accepted and
    are the documented way to write large numbers in a manifest.
    """
    if isinstance(value, bool):
        raise AbiError(f"expected {type_name}, got a boolean: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        try:
            if text[:2].lower() == "0x":
                return int(text, 16)
            return int(text, 10)
        except ValueError as exc:
            raise AbiError(f"cannot read {type_name} from {value!r}") from exc
    raise AbiError(f"cannot read {type_name} from {type(value).__name__}")


def _coerce_bytes(value: Any, type_name: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if text[:2].lower() == "0x":
            text = text[2:]
        if len(text) % 2:
            raise AbiError(f"odd-length hex for {type_name}: {value!r}")
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise AbiError(f"cannot read {type_name} from {value!r}") from exc
    raise AbiError(f"cannot read {type_name} from {type(value).__name__}")


def encode_argument(type_name: str, value: Any) -> bytes:
    """Encode a single static argument into one 32-byte word."""
    canonical = _validate_arg_type(type_name)

    if canonical == "address":
        try:
            address = normalize_address(value)
        except AddressError as exc:
            raise AbiError(str(exc)) from exc
        return bytes(12) + bytes.fromhex(address[2:])

    if canonical == "bool":
        if isinstance(value, bool):
            flag = value
        elif isinstance(value, int) and value in (0, 1):
            flag = bool(value)
        elif isinstance(value, str) and value.strip().lower() in ("true", "false"):
            flag = value.strip().lower() == "true"
        else:
            raise AbiError(f"cannot read bool from {value!r}")
        return bytes(31) + (b"\x01" if flag else b"\x00")

    if m := _UINT_RE.match(canonical):
        bits = int(m.group(1))
        number = _coerce_int(value, canonical)
        if not 0 <= number < (1 << bits):
            raise AbiError(f"{number} is out of range for {canonical}")
        return number.to_bytes(WORD, "big")

    if m := _INT_RE.match(canonical):
        bits = int(m.group(1))
        number = _coerce_int(value, canonical)
        limit = 1 << (bits - 1)
        if not -limit <= number < limit:
            raise AbiError(f"{number} is out of range for {canonical}")
        return (number & ((1 << 256) - 1)).to_bytes(WORD, "big")

    if m := _BYTES_N_RE.match(canonical):
        size = int(m.group(1))
        raw = _coerce_bytes(value, canonical)
        if len(raw) != size:
            raise AbiError(f"{canonical} needs exactly {size} bytes, got {len(raw)}")
        return raw + bytes(WORD - size)

    raise SignatureError(f"unsupported argument type {canonical!r}")


def encode_call(signature: str, args: list[Any] | tuple[Any, ...] = ()) -> bytes:
    """Build calldata: 4-byte selector followed by one word per argument."""
    name, arg_types = parse_signature(signature)
    args = list(args or [])
    if len(args) != len(arg_types):
        raise AbiError(
            f"{name}() takes {len(arg_types)} argument(s), got {len(args)}"
        )
    data = bytearray(function_selector(signature))
    for type_name, value in zip(arg_types, args):
        data += encode_argument(type_name, value)
    return bytes(data)


def decode_single(type_name: str, data: bytes) -> Any:
    """Decode return data holding exactly one value of ``type_name``.

    Returns an ``int`` for integer types, ``bool`` for bool, a checksum-less
    lowercase ``0x`` address string for address, a ``0x`` hex string for bytes
    types, and ``str`` for string.
    """
    canonical = _canonical_type(type_name)
    if not isinstance(data, (bytes, bytearray)):
        raise AbiError(f"return data must be bytes, got {type(data).__name__}")
    data = bytes(data)

    if len(data) == 0:
        raise AbiError(
            "empty return data -- the call returned nothing (wrong address, "
            "non-contract account, or a function that does not exist here)"
        )

    if canonical in ("string", "bytes"):
        return _decode_dynamic(canonical, data)

    if len(data) < WORD:
        raise AbiError(f"return data too short for {canonical}: {len(data)} bytes")
    word = data[:WORD]

    if canonical == "address":
        if any(word[:12]):
            raise AbiError(f"return data is not a clean address: 0x{word.hex()}")
        return "0x" + word[12:].hex()

    if canonical == "bool":
        number = int.from_bytes(word, "big")
        if number not in (0, 1):
            raise AbiError(f"return data is not a clean bool: 0x{word.hex()}")
        return bool(number)

    if m := _UINT_RE.match(canonical):
        bits = int(m.group(1))
        number = int.from_bytes(word, "big")
        if number >= (1 << bits):
            raise AbiError(f"return value does not fit {canonical}: 0x{word.hex()}")
        return number

    if m := _INT_RE.match(canonical):
        bits = int(m.group(1))
        number = int.from_bytes(word, "big")
        if number >= (1 << 255):
            number -= 1 << 256
        limit = 1 << (bits - 1)
        if not -limit <= number < limit:
            raise AbiError(f"return value does not fit {canonical}: 0x{word.hex()}")
        return number

    if m := _BYTES_N_RE.match(canonical):
        size = int(m.group(1))
        return "0x" + word[:size].hex()

    raise AbiError(
        f"unsupported return type {canonical!r}; "
        f"supported return types: {', '.join(SUPPORTED_RETURN_TYPES)}"
    )


def _decode_dynamic(canonical: str, data: bytes) -> Any:
    """Decode a single dynamic ``string`` or ``bytes`` return value."""
    if len(data) < WORD:
        raise AbiError(f"return data too short for {canonical}: {len(data)} bytes")
    offset = int.from_bytes(data[:WORD], "big")
    if offset + WORD > len(data):
        raise AbiError(f"{canonical} offset {offset} is outside the return data")
    length = int.from_bytes(data[offset : offset + WORD], "big")
    start = offset + WORD
    if start + length > len(data):
        raise AbiError(
            f"{canonical} claims {length} bytes but only "
            f"{len(data) - start} are present"
        )
    raw = data[start : start + length]
    if canonical == "bytes":
        return "0x" + raw.hex()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AbiError(f"string return value is not valid UTF-8: 0x{raw.hex()}") from exc
