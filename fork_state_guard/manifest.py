"""Parsing and validation of the TOML manifest.

Validation is strict and loud on purpose. A manifest is a statement about
what your PoC depends on; a typo that silently turns into "no constraint"
would quietly hand you a PASS you did not earn. Unknown keys are therefore
errors, not warnings.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .abi import SignatureError, parse_signature
from .address import AddressError, is_hex_address, normalize_address, to_checksum_address
from .proxy import PROXY_STANDARDS

__all__ = [
    "ManifestError",
    "Manifest",
    "Meta",
    "Expectation",
    "ParamCheck",
    "ProxyCheck",
    "load_manifest",
    "parse_manifest",
    "UNSET",
]


class ManifestError(ValueError):
    """Raised for any malformed or self-contradictory manifest."""


class _Unset:
    """Sentinel: 'no expected value given' (distinct from an expected None)."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNSET"

    def __bool__(self) -> bool:
        return False


UNSET = _Unset()

_META_KEYS = {"chain_id", "label", "poc", "fork_block", "notes"}
_PARAM_KEYS = {
    "name",
    "address",
    "call",
    "args",
    "returns",
    "storage",
    "balance",
    "expect",
    "expect_one_of",
    "expect_gte",
    "expect_lte",
    "allow_drift",
    "note",
}
_PROXY_KEYS = {
    "name",
    "address",
    "standard",
    "implementation",
    "implementation_one_of",
    "admin",
    "admin_one_of",
    "allow_drift",
    "note",
}
_TOP_LEVEL_KEYS = {"meta", "param", "proxy"}

VALUE_TYPES = ("address", "bool", "uint256", "bytes32", "bytes", "string")


# --------------------------------------------------------------------------
# dataclasses
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Meta:
    """The ``[meta]`` table: what this manifest is about."""

    label: str = ""
    chain_id: int | None = None
    poc: str | None = None
    fork_block: int | None = None
    notes: str | None = None


@dataclass(frozen=True)
class Expectation:
    """What a check's observed value is required to be."""

    expect: Any = UNSET
    expect_one_of: tuple[Any, ...] | None = None
    expect_gte: Any = UNSET
    expect_lte: Any = UNSET
    allow_drift: str | None = None

    @property
    def is_numeric(self) -> bool:
        return self.expect_gte is not UNSET or self.expect_lte is not UNSET

    def describe(self) -> str:
        """One-line human description of the constraint, for reports."""
        parts: list[str] = []
        if self.expect is not UNSET:
            parts.append(_fmt(self.expect))
        if self.expect_one_of is not None:
            parts.append("one of [" + ", ".join(_fmt(v) for v in self.expect_one_of) + "]")
        if self.expect_gte is not UNSET:
            parts.append(f">= {_fmt(self.expect_gte)}")
        if self.expect_lte is not UNSET:
            parts.append(f"<= {_fmt(self.expect_lte)}")
        return " and ".join(parts) if parts else "(no constraint)"


@dataclass(frozen=True)
class ParamCheck:
    """One ``[[param]]`` entry: a single on-chain value the PoC depends on."""

    name: str
    address: str
    mode: str  # "call" | "storage" | "balance"
    expectation: Expectation
    signature: str | None = None
    args: tuple[Any, ...] = ()
    returns: str | None = None  # explicit return type, if the manifest gave one
    slot: int | None = None
    note: str | None = None

    @property
    def target(self) -> str:
        """Short description of what is being read."""
        if self.mode == "call":
            rendered = ", ".join(_fmt(a) for a in self.args)
            if self.args:
                name = (self.signature or "").split("(")[0]
                return f"{name}({rendered})"
            return self.signature or ""
        if self.mode == "storage":
            return f"storage[{self.slot}]"
        return "balance"


@dataclass(frozen=True)
class ProxyCheck:
    """One ``[[proxy]]`` entry: the implementation (and optionally admin)
    behind a proxy must still be the one the PoC was written against."""

    name: str
    address: str
    standard: str = "auto"
    implementation: Any = UNSET
    implementation_one_of: tuple[str, ...] | None = None
    admin: Any = UNSET
    admin_one_of: tuple[str, ...] | None = None
    allow_drift: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class Manifest:
    """A parsed manifest: metadata plus the checks to run."""

    meta: Meta = field(default_factory=Meta)
    params: tuple[ParamCheck, ...] = ()
    proxies: tuple[ProxyCheck, ...] = ()
    path: Path | None = None

    @property
    def check_count(self) -> int:
        return len(self.params) + len(self.proxies)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def load_manifest(path: str | Path) -> Manifest:
    """Read and parse a manifest from disk."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {path}") from exc
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    return parse_manifest(raw, path=path)


def parse_manifest(data: bytes | str, *, path: str | Path | None = None) -> Manifest:
    """Parse manifest ``data`` (TOML bytes or text) into a :class:`Manifest`."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ManifestError(f"manifest is not valid UTF-8: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"invalid TOML: {exc}") from exc

    _reject_unknown(document, _TOP_LEVEL_KEYS, "manifest")

    meta = _parse_meta(document.get("meta", {}))
    params = tuple(
        _parse_param(entry, index)
        for index, entry in enumerate(_as_table_array(document.get("param", []), "param"))
    )
    proxies = tuple(
        _parse_proxy(entry, index)
        for index, entry in enumerate(_as_table_array(document.get("proxy", []), "proxy"))
    )

    if not params and not proxies:
        raise ManifestError(
            "manifest declares no checks: add at least one [[param]] or [[proxy]] entry"
        )

    _reject_duplicate_names(params, proxies)

    return Manifest(meta=meta, params=params, proxies=proxies, path=Path(path) if path else None)


def _parse_meta(table: Any) -> Meta:
    if not isinstance(table, dict):
        raise ManifestError("[meta] must be a table")
    _reject_unknown(table, _META_KEYS, "[meta]")

    chain_id = table.get("chain_id")
    if chain_id is not None:
        if isinstance(chain_id, bool) or not isinstance(chain_id, int):
            raise ManifestError("meta.chain_id must be an integer")
        if chain_id <= 0:
            raise ManifestError("meta.chain_id must be positive")

    fork_block = table.get("fork_block")
    if fork_block is not None:
        if isinstance(fork_block, bool) or not isinstance(fork_block, int):
            raise ManifestError("meta.fork_block must be an integer block number")
        if fork_block < 0:
            raise ManifestError("meta.fork_block must not be negative")

    for key in ("label", "poc", "notes"):
        if key in table and not isinstance(table[key], str):
            raise ManifestError(f"meta.{key} must be a string")

    return Meta(
        label=table.get("label", ""),
        chain_id=chain_id,
        poc=table.get("poc"),
        fork_block=fork_block,
        notes=table.get("notes"),
    )


def _parse_param(entry: Any, index: int) -> ParamCheck:
    where = f"[[param]] #{index + 1}"
    if not isinstance(entry, dict):
        raise ManifestError(f"{where} must be a table")
    _reject_unknown(entry, _PARAM_KEYS, where)

    name = _require_name(entry, where)
    where = f"param {name!r}"
    address = _require_address(entry, where)

    modes = [key for key in ("call", "storage", "balance") if key in entry]
    if not modes:
        raise ManifestError(
            f"{where} must declare exactly one of 'call', 'storage' or 'balance'"
        )
    if len(modes) > 1:
        raise ManifestError(
            f"{where} declares several read modes ({', '.join(sorted(modes))}); "
            f"use exactly one, or split it into separate [[param]] entries"
        )
    mode = modes[0]

    signature: str | None = None
    args: tuple[Any, ...] = ()
    slot: int | None = None

    if mode == "call":
        signature = entry["call"]
        if not isinstance(signature, str):
            raise ManifestError(f"{where}: 'call' must be a function signature string")
        try:
            _, arg_types = parse_signature(signature)
        except SignatureError as exc:
            raise ManifestError(f"{where}: {exc}") from exc
        raw_args = entry.get("args", [])
        if not isinstance(raw_args, list):
            raise ManifestError(f"{where}: 'args' must be an array")
        if len(raw_args) != len(arg_types):
            raise ManifestError(
                f"{where}: {signature} takes {len(arg_types)} argument(s) but "
                f"{len(raw_args)} were given in 'args'"
            )
        args = tuple(raw_args)
    elif mode == "storage":
        slot = _parse_slot(entry["storage"], where)
    else:
        if entry["balance"] is not True:
            raise ManifestError(
                f"{where}: 'balance' is a flag and must be written as 'balance = true'"
            )

    returns = entry.get("returns")
    if returns is not None:
        if not isinstance(returns, str):
            raise ManifestError(f"{where}: 'returns' must be a type name string")
        if mode == "balance":
            raise ManifestError(
                f"{where}: 'returns' does not apply to a balance check "
                f"(balances are always uint256 wei)"
            )

    expectation = _parse_expectation(entry, where)

    return ParamCheck(
        name=name,
        address=address,
        mode=mode,
        expectation=expectation,
        signature=signature,
        args=args,
        returns=returns,
        slot=slot,
        note=_optional_str(entry, "note", where),
    )


def _parse_proxy(entry: Any, index: int) -> ProxyCheck:
    where = f"[[proxy]] #{index + 1}"
    if not isinstance(entry, dict):
        raise ManifestError(f"{where} must be a table")
    _reject_unknown(entry, _PROXY_KEYS, where)

    name = _require_name(entry, where)
    where = f"proxy {name!r}"
    address = _require_address(entry, where)

    standard = entry.get("standard", "auto")
    if not isinstance(standard, str):
        raise ManifestError(f"{where}: 'standard' must be a string")
    if standard not in ("auto",) + PROXY_STANDARDS:
        raise ManifestError(
            f"{where}: unknown proxy standard {standard!r}; "
            f"choose from: auto, {', '.join(PROXY_STANDARDS)}"
        )

    implementation = entry.get("implementation", UNSET)
    admin = entry.get("admin", UNSET)
    implementation_one_of = _parse_address_list(
        entry.get("implementation_one_of"), f"{where}: implementation_one_of"
    )
    admin_one_of = _parse_address_list(entry.get("admin_one_of"), f"{where}: admin_one_of")

    if implementation is not UNSET and implementation_one_of is not None:
        raise ManifestError(
            f"{where}: give either 'implementation' or 'implementation_one_of', not both"
        )
    if admin is not UNSET and admin_one_of is not None:
        raise ManifestError(f"{where}: give either 'admin' or 'admin_one_of', not both")

    if implementation is UNSET and implementation_one_of is None and admin is UNSET and admin_one_of is None:
        raise ManifestError(
            f"{where}: declare at least an expected 'implementation' "
            f"(the address your PoC was written against)"
        )

    if implementation is not UNSET:
        implementation = _require_address_value(implementation, f"{where}: implementation")
    if admin is not UNSET:
        admin = _require_address_value(admin, f"{where}: admin")

    return ProxyCheck(
        name=name,
        address=address,
        standard=standard,
        implementation=implementation,
        implementation_one_of=implementation_one_of,
        admin=admin,
        admin_one_of=admin_one_of,
        allow_drift=_parse_allow_drift(entry, where),
        note=_optional_str(entry, "note", where),
    )


def _parse_expectation(entry: dict[str, Any], where: str) -> Expectation:
    expect = entry.get("expect", UNSET)
    expect_gte = entry.get("expect_gte", UNSET)
    expect_lte = entry.get("expect_lte", UNSET)

    raw_one_of = entry.get("expect_one_of")
    one_of: tuple[Any, ...] | None = None
    if raw_one_of is not None:
        if not isinstance(raw_one_of, list):
            raise ManifestError(f"{where}: 'expect_one_of' must be an array")
        if not raw_one_of:
            raise ManifestError(f"{where}: 'expect_one_of' must not be empty")
        one_of = tuple(raw_one_of)

    if expect is not UNSET and one_of is not None:
        raise ManifestError(
            f"{where}: give either 'expect' or 'expect_one_of', not both"
        )

    for key, value in (("expect_gte", expect_gte), ("expect_lte", expect_lte)):
        if value is UNSET:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ManifestError(
                f"{where}: '{key}' must be an integer, or a decimal/hex string for "
                f"values beyond 64 bits"
            )

    if expect is UNSET and one_of is None and expect_gte is UNSET and expect_lte is UNSET:
        raise ManifestError(
            f"{where}: declares no expectation; add 'expect', 'expect_one_of', "
            f"'expect_gte' or 'expect_lte'"
        )

    return Expectation(
        expect=expect,
        expect_one_of=one_of,
        expect_gte=expect_gte,
        expect_lte=expect_lte,
        allow_drift=_parse_allow_drift(entry, where),
    )


def _parse_allow_drift(entry: dict[str, Any], where: str) -> str | None:
    if "allow_drift" not in entry:
        return None
    value = entry["allow_drift"]
    if value is True:
        raise ManifestError(
            f"{where}: 'allow_drift' must be a justification string, not a bare true -- "
            f"a knowing exception has to say why"
        )
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(
            f"{where}: 'allow_drift' must be a non-empty justification string"
        )
    return value.strip()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _as_table_array(value: Any, key: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, dict):
        raise ManifestError(
            f"write entries as [[{key}]] (an array of tables), not [{key}]"
        )
    if not isinstance(value, list):
        raise ManifestError(f"'{key}' must be an array of tables ([[{key}]])")
    return value


def _reject_unknown(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ManifestError(
            f"{where}: unknown key(s) {', '.join(repr(k) for k in unknown)}; "
            f"allowed: {', '.join(sorted(allowed))}"
        )


def _require_name(entry: dict[str, Any], where: str) -> str:
    if "name" not in entry:
        raise ManifestError(f"{where} is missing 'name'")
    name = entry["name"]
    if not isinstance(name, str) or not name.strip():
        raise ManifestError(f"{where}: 'name' must be a non-empty string")
    return name.strip()


def _require_address(entry: dict[str, Any], where: str) -> str:
    if "address" not in entry:
        raise ManifestError(f"{where} is missing 'address'")
    return _require_address_value(entry["address"], f"{where}: address")


def _require_address_value(value: Any, where: str) -> str:
    try:
        return normalize_address(value)
    except AddressError as exc:
        raise ManifestError(f"{where}: {exc}") from exc


def _parse_address_list(value: Any, where: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ManifestError(f"{where} must be an array of addresses")
    if not value:
        raise ManifestError(f"{where} must not be empty")
    return tuple(_require_address_value(item, where) for item in value)


def _parse_slot(value: Any, where: str) -> int:
    if isinstance(value, bool):
        raise ManifestError(f"{where}: 'storage' must be a slot number or hex string")
    if isinstance(value, int):
        slot = value
    elif isinstance(value, str):
        text = value.strip().replace("_", "")
        try:
            slot = int(text, 16) if text[:2].lower() == "0x" else int(text, 10)
        except ValueError as exc:
            raise ManifestError(
                f"{where}: cannot read storage slot from {value!r}"
            ) from exc
    else:
        raise ManifestError(
            f"{where}: 'storage' must be a slot number or a hex string, "
            f"got {type(value).__name__}"
        )
    if slot < 0:
        raise ManifestError(f"{where}: storage slot must not be negative")
    if slot >= 1 << 256:
        raise ManifestError(f"{where}: storage slot does not fit in 256 bits")
    return slot


def _optional_str(entry: dict[str, Any], key: str, where: str) -> str | None:
    if key not in entry:
        return None
    value = entry[key]
    if not isinstance(value, str):
        raise ManifestError(f"{where}: '{key}' must be a string")
    return value


def _reject_duplicate_names(
    params: tuple[ParamCheck, ...], proxies: tuple[ProxyCheck, ...]
) -> None:
    seen: set[str] = set()
    for check in (*params, *proxies):
        key = check.name.lower()
        if key in seen:
            raise ManifestError(
                f"duplicate check name {check.name!r}; names identify rows in the "
                f"report and must be unique"
            )
        seen.add(key)


def _fmt(value: Any) -> str:
    """Render a manifest value for display."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and is_hex_address(value):
        return to_checksum_address(value)
    if isinstance(value, int):
        return str(value)
    return str(value)
