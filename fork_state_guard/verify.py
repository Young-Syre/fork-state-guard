"""The verification engine: read live state, compare against the manifest.

Every check produces exactly one row with one of four statuses:

* ``PASS``          -- the live value satisfies the declared expectation.
* ``DRIFT``         -- the live value does not. Your PoC's precondition is
                       gone; fix the PoC or the report before filing.
* ``DRIFT_ALLOWED`` -- it drifted, and the manifest said so in advance with a
                       written justification. Printed in full, not hidden.
* ``ERROR``          -- the value could not be read or decoded (reverting call,
                       no code at the address, undecodable return data). You
                       do not know whether the assumption holds.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from . import proxy as proxy_slots
from .abi import AbiError, decode_single, encode_call
from .address import ZERO_ADDRESS, is_hex_address, normalize_address, to_checksum_address
from .manifest import UNSET, Manifest, ParamCheck, ProxyCheck
from .rpc import RpcClient, RpcResponseError, RpcTransportError

__all__ = [
    "Status",
    "CheckResult",
    "Report",
    "ChainMismatch",
    "resolve_value_type",
    "compare",
    "verify",
]


class Status:
    """Check outcomes. Plain strings so JSON output needs no conversion."""

    PASS = "PASS"
    DRIFT = "DRIFT"
    DRIFT_ALLOWED = "DRIFT-ALLOWED"
    ERROR = "ERROR"

    ALL = (PASS, DRIFT, DRIFT_ALLOWED, ERROR)


class ChainMismatch(Exception):
    """The endpoint's chain id is not the one the manifest declares.

    Raised before any state is read: on the wrong chain every other result
    would be meaningless, and a wall of confident-looking DRIFT rows is worse
    than one clear message.
    """

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"manifest declares chain_id {expected} but the RPC endpoint reports "
            f"{actual}; you are pointed at the wrong chain "
            f"(pass --ignore-chain-id to check anyway)"
        )
        self.expected = expected
        self.actual = actual


@dataclass
class CheckResult:
    """One row of the report."""

    name: str
    kind: str  # "param" | "proxy"
    address: str
    target: str  # what was read, e.g. "owner()" or "eip1967:implementation"
    status: str
    expected: str
    actual: str
    value_type: str = ""
    detail: str = ""
    note: str | None = None
    justification: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in (Status.PASS, Status.DRIFT_ALLOWED)

    def as_dict(self) -> dict[str, Any]:
        data = {
            "name": self.name,
            "kind": self.kind,
            "address": to_checksum_address(self.address),
            "target": self.target,
            "status": self.status,
            "expected": self.expected,
            "actual": self.actual,
            "type": self.value_type,
        }
        if self.detail:
            data["detail"] = self.detail
        if self.note:
            data["note"] = self.note
        if self.justification:
            data["allow_drift"] = self.justification
        return data


@dataclass
class Report:
    """The outcome of verifying a whole manifest at one block."""

    label: str = ""
    manifest_path: str | None = None
    endpoint: str = ""
    chain_id: int | None = None
    declared_chain_id: int | None = None
    block_number: int = 0
    block_timestamp: int | None = None
    checked_at: int = field(default_factory=lambda: int(time.time()))
    fork_block: int | None = None
    poc: str | None = None
    notes: str | None = None
    results: list[CheckResult] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = {status: 0 for status in Status.ALL}
        for result in self.results:
            counts[result.status] += 1
        return counts

    @property
    def drifted(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == Status.DRIFT]

    @property
    def errored(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == Status.ERROR]

    @property
    def allowed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == Status.DRIFT_ALLOWED]

    @property
    def verified(self) -> bool:
        """True only if every declared assumption still holds (or was
        explicitly waived) and nothing failed to evaluate."""
        return not self.drifted and not self.errored

    @property
    def blocks_since_fork(self) -> int | None:
        if self.fork_block is None:
            return None
        return self.block_number - self.fork_block


# --------------------------------------------------------------------------
# type resolution
# --------------------------------------------------------------------------

_HINT_ORDER = ("expect", "expect_one_of", "expect_gte", "expect_lte")


def resolve_value_type(check: ParamCheck) -> str:
    """Decide how to decode and compare a param's value.

    An explicit ``returns`` always wins. Otherwise the type is inferred from
    the shape of the expected value, which covers the common cases without
    ceremony:

    ========================================  ==========
    expectation                               inferred
    ========================================  ==========
    ``balance = true``                        uint256
    a boolean                                 bool
    an integer, or expect_gte / expect_lte    uint256
    a 20-byte hex string                      address
    a 32-byte hex string                      bytes32
    any other 0x hex string                   bytes
    any other string                          string
    a storage read with no other hint         bytes32
    ========================================  ==========
    """
    if check.returns:
        return check.returns.strip()
    if check.mode == "balance":
        return "uint256"

    expectation = check.expectation
    if expectation.is_numeric:
        return "uint256"

    hint: Any = UNSET
    if expectation.expect is not UNSET:
        hint = expectation.expect
    elif expectation.expect_one_of:
        hint = expectation.expect_one_of[0]

    if isinstance(hint, bool):
        return "bool"
    if isinstance(hint, int):
        return "uint256"
    if isinstance(hint, str):
        if is_hex_address(hint):
            return "address"
        if hint[:2].lower() == "0x":
            body = hint[2:]
            if len(body) == 64:
                return "bytes32"
            return "bytes"
        return "string"
    if check.mode == "storage":
        return "bytes32"
    return "string"


# --------------------------------------------------------------------------
# comparison
# --------------------------------------------------------------------------


def _as_int(value: Any, what: str) -> int:
    """Read an integer from a manifest scalar (decimal or hex string, or int)."""
    if isinstance(value, bool):
        raise AbiError(f"{what}: expected a number, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        try:
            return int(text, 16) if text[:2].lower() == "0x" else int(text, 10)
        except ValueError as exc:
            raise AbiError(f"{what}: cannot read a number from {value!r}") from exc
    raise AbiError(f"{what}: cannot read a number from {type(value).__name__}")


def _normalize_hex(value: Any, width_bytes: int | None, what: str) -> str:
    """Normalize a hex expectation to lowercase 0x form.

    A ``bytes32`` expectation shorter than 32 bytes is left-padded, matching
    how the EVM right-aligns numeric values in a storage word. To compare a
    left-aligned value, write all 32 bytes out.
    """
    if isinstance(value, (bytes, bytearray)):
        body = bytes(value).hex()
    elif isinstance(value, int) and not isinstance(value, bool):
        body = format(value, "x")
    elif isinstance(value, str):
        body = value[2:] if value[:2].lower() == "0x" else value
        body = body.lower()
        try:
            bytes.fromhex(body if len(body) % 2 == 0 else "0" + body)
        except ValueError as exc:
            raise AbiError(f"{what}: {value!r} is not valid hex") from exc
    else:
        raise AbiError(f"{what}: cannot read hex from {type(value).__name__}")

    if width_bytes is not None:
        if len(body) > width_bytes * 2:
            raise AbiError(
                f"{what}: expected at most {width_bytes} bytes, got {len(body) // 2}"
            )
        body = body.rjust(width_bytes * 2, "0")
    elif len(body) % 2:
        body = "0" + body
    return "0x" + body


def compare(value_type: str, observed: Any, expectation: Any) -> tuple[bool, str]:
    """Compare an observed value against an :class:`Expectation`.

    Returns ``(satisfied, detail)``. ``detail`` explains the first failing
    constraint, or is empty on success. Raises :class:`AbiError` if an
    expectation in the manifest cannot be read as the resolved type.
    """
    canonical = value_type.strip()

    def equal(expected: Any) -> bool:
        if canonical == "address":
            return normalize_address(observed) == normalize_address(expected)
        if canonical == "bool":
            if isinstance(expected, bool):
                return bool(observed) is expected
            if isinstance(expected, str) and expected.strip().lower() in ("true", "false"):
                return bool(observed) is (expected.strip().lower() == "true")
            raise AbiError(f"cannot compare bool against {expected!r}")
        if canonical.startswith(("uint", "int")):
            return int(observed) == _as_int(expected, "expect")
        if canonical == "string":
            return str(observed) == str(expected)
        width = 32 if canonical == "bytes32" else None
        if canonical.startswith("bytes") and canonical != "bytes":
            try:
                width = int(canonical[len("bytes") :])
            except ValueError:
                width = None
        return _normalize_hex(observed, width, "observed") == _normalize_hex(
            expected, width, "expect"
        )

    if expectation.expect is not UNSET and not equal(expectation.expect):
        return False, ""

    if expectation.expect_one_of is not None:
        if not any(equal(candidate) for candidate in expectation.expect_one_of):
            return False, "value is not in the accepted set"

    if expectation.expect_gte is not UNSET:
        bound = _as_int(expectation.expect_gte, "expect_gte")
        if _numeric(observed, canonical) < bound:
            return False, f"below the declared floor ({_numeric(observed, canonical)} < {bound})"

    if expectation.expect_lte is not UNSET:
        bound = _as_int(expectation.expect_lte, "expect_lte")
        if _numeric(observed, canonical) > bound:
            return False, f"above the declared ceiling ({_numeric(observed, canonical)} > {bound})"

    return True, ""


def _numeric(observed: Any, canonical: str) -> int:
    """Coerce an observed value to an int for range comparison."""
    if isinstance(observed, bool):
        return int(observed)
    if isinstance(observed, int):
        return observed
    if isinstance(observed, str) and observed[:2].lower() == "0x":
        return int(observed, 16)
    raise AbiError(
        f"expect_gte/expect_lte need a numeric value, but the check resolved to "
        f"type {canonical!r} with value {observed!r}"
    )


def render(value: Any, value_type: str = "") -> str:
    """Render an observed value for the report."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and is_hex_address(value) and value_type == "address":
        return to_checksum_address(value)
    if isinstance(value, int):
        return str(value)
    return str(value)


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------


def verify(
    manifest: Manifest,
    client: RpcClient,
    *,
    block: str | int = "latest",
    ignore_chain_id: bool = False,
) -> Report:
    """Verify every check in ``manifest`` against live state.

    All reads are pinned to a single resolved block number so the report
    describes one consistent state, even when "latest" moves mid-run.

    Raises :class:`ChainMismatch` if the endpoint is on another chain, and
    propagates :class:`RpcTransportError` if the endpoint becomes unreachable
    (an outage is not evidence about the chain).
    """
    chain_id: int | None
    try:
        chain_id = client.chain_id()
    except RpcResponseError:
        chain_id = None  # some nodes do not expose eth_chainId; not fatal

    if (
        not ignore_chain_id
        and manifest.meta.chain_id is not None
        and chain_id is not None
        and chain_id != manifest.meta.chain_id
    ):
        raise ChainMismatch(manifest.meta.chain_id, chain_id)

    block_number = client.block_number() if block == "latest" else _block_to_int(block)
    block_tag = hex(block_number)
    block_timestamp = client.block_timestamp(block_tag)

    report = Report(
        label=manifest.meta.label,
        manifest_path=str(manifest.path) if manifest.path else None,
        endpoint=client.endpoint,
        chain_id=chain_id,
        declared_chain_id=manifest.meta.chain_id,
        block_number=block_number,
        block_timestamp=block_timestamp,
        fork_block=manifest.meta.fork_block,
        poc=manifest.meta.poc,
        notes=manifest.meta.notes,
    )

    for check in manifest.params:
        report.results.append(_verify_param(check, client, block_tag))
    for check in manifest.proxies:
        report.results.extend(_verify_proxy(check, client, block_tag))

    return report


def _block_to_int(block: str | int) -> int:
    if isinstance(block, int) and not isinstance(block, bool):
        return block
    text = str(block).strip()
    try:
        return int(text, 16) if text[:2].lower() == "0x" else int(text, 10)
    except ValueError as exc:
        raise ValueError(
            f"--block must be a block number or 'latest', got {block!r}"
        ) from exc


def _verify_param(check: ParamCheck, client: RpcClient, block_tag: str) -> CheckResult:
    value_type = resolve_value_type(check)
    result = CheckResult(
        name=check.name,
        kind="param",
        address=check.address,
        target=check.target,
        status=Status.ERROR,
        expected=check.expectation.describe(),
        actual="-",
        value_type=value_type,
        note=check.note,
    )

    try:
        observed = _read_param(check, client, block_tag, value_type)
    except RpcTransportError:
        raise  # an outage aborts the run; it is not a per-check result
    except RpcResponseError as exc:
        result.detail = _explain_rpc_error(check, exc)
        return _maybe_waive(result, check.expectation.allow_drift, keep_error=True)
    except (AbiError, ValueError) as exc:
        result.detail = str(exc)
        return _maybe_waive(result, check.expectation.allow_drift, keep_error=True)

    result.actual = render(observed, value_type)

    try:
        satisfied, detail = compare(value_type, observed, check.expectation)
    except (AbiError, ValueError) as exc:
        result.detail = str(exc)
        return result

    if satisfied:
        result.status = Status.PASS
        return result

    result.status = Status.DRIFT
    result.detail = detail
    return _maybe_waive(result, check.expectation.allow_drift)


def _read_param(
    check: ParamCheck, client: RpcClient, block_tag: str, value_type: str
) -> Any:
    if check.mode == "call":
        data = encode_call(check.signature or "", check.args)
        raw = client.eth_call(check.address, data, block_tag)
        if not raw:
            raise AbiError(
                f"{check.signature} returned no data at this address -- the "
                f"function does not exist here (wrong address, or the contract "
                f"changed shape)"
            )
        return decode_single(value_type, raw)

    if check.mode == "storage":
        word = client.get_storage_at(check.address, check.slot or 0, block_tag)
        return _decode_word(word, value_type)

    return client.get_balance(check.address, block_tag)


def _decode_word(word: bytes, value_type: str) -> Any:
    """Interpret a raw 32-byte storage word as ``value_type``."""
    canonical = value_type.strip()
    if canonical == "address":
        if any(word[:12]):
            raise AbiError(
                f"storage word 0x{word.hex()} is not a clean address "
                f"(the slot is packed; read it as bytes32 instead)"
            )
        return "0x" + word[12:].hex()
    if canonical == "bool":
        number = int.from_bytes(word, "big")
        if number not in (0, 1):
            raise AbiError(
                f"storage word 0x{word.hex()} is not a clean bool "
                f"(the slot is packed; read it as bytes32 or uint256 instead)"
            )
        return bool(number)
    if canonical.startswith(("uint", "int")):
        return decode_single(canonical, word)
    if canonical == "string":
        raise AbiError(
            "a storage slot cannot be read as 'string'; read it as bytes32 "
            "(short strings are packed into the slot) or use a view function"
        )
    return decode_single(canonical if canonical != "bytes" else "bytes32", word)


def _verify_proxy(
    check: ProxyCheck, client: RpcClient, block_tag: str
) -> list[CheckResult]:
    """Resolve a proxy's implementation (and admin) and compare them.

    The implementation slot is probed across the declared standard's slots
    and the first non-zero one wins; the standard that matched is reported,
    because "which proxy standard is this" is itself worth recording.
    """
    results: list[CheckResult] = []

    code = client.get_code(check.address, block_tag)
    if not code:
        for role in ("implementation", "admin"):
            if _expects(check, role):
                results.append(
                    CheckResult(
                        name=f"{check.name} / {role}",
                        kind="proxy",
                        address=check.address,
                        target=f"{check.standard}:{role}",
                        status=Status.ERROR,
                        expected=_describe_proxy_expectation(check, role),
                        actual="-",
                        value_type="address",
                        detail="no code at this address at this block "
                        "(not a contract here -- wrong address or wrong chain)",
                        note=check.note,
                    )
                )
        return [_maybe_waive(r, check.allow_drift, keep_error=True) for r in results]

    for role in ("implementation", "admin"):
        if not _expects(check, role):
            continue
        results.append(_verify_proxy_role(check, role, client, block_tag))
    return results


def _verify_proxy_role(
    check: ProxyCheck, role: str, client: RpcClient, block_tag: str
) -> CheckResult:
    slots = (
        proxy_slots.implementation_slots(check.standard)
        if role == "implementation"
        else proxy_slots.admin_slots(check.standard)
    )
    result = CheckResult(
        name=f"{check.name} / {role}",
        kind="proxy",
        address=check.address,
        target=f"{check.standard}:{role}",
        status=Status.ERROR,
        expected=_describe_proxy_expectation(check, role),
        actual="-",
        value_type="address",
        note=check.note,
    )

    if not slots:
        result.detail = (
            f"the {check.standard} standard defines no {role} slot; "
            f"remove the '{role}' expectation or use standard = \"auto\""
        )
        return result

    found: tuple[proxy_slots.ProxySlot, str] | None = None
    probed: list[str] = []
    for slot in slots:
        word = client.get_storage_at(check.address, slot.hex, block_tag)
        probed.append(slot.label)
        if int.from_bytes(word, "big") == 0:
            continue
        if any(word[:12]):
            result.detail = (
                f"{slot.label} slot {slot.hex} holds 0x{word.hex()}, which is not "
                f"a clean address"
            )
            return result
        found = (slot, "0x" + word[12:].hex())
        break

    if found is None:
        result.target = f"{check.standard}:{role}"
        result.actual = to_checksum_address(ZERO_ADDRESS)
        if role == "implementation":
            result.detail = (
                f"every known {role} slot is zero ({', '.join(probed)}); this is not "
                f"a proxy of a recognised standard, or it keeps the implementation "
                f"somewhere else"
            )
            return result
        # An expected admin that is simply absent is drift, not an error: a
        # UUPS or beacon proxy legitimately leaves the admin slot empty, and
        # that is exactly the kind of change that invalidates an
        # admin-dependent PoC.
        result.status = Status.DRIFT
        result.detail = (
            f"every known {role} slot is zero ({', '.join(probed)}); the proxy may "
            f"have been migrated to UUPS/beacon, where there is no admin slot"
        )
        return _maybe_waive(result, check.allow_drift)

    slot, observed = found
    result.target = f"{slot.standard}:{role}"
    result.actual = to_checksum_address(observed)
    result.detail = f"slot {slot.hex} ({slot.derivation})"

    expected_single = check.implementation if role == "implementation" else check.admin
    expected_set = (
        check.implementation_one_of if role == "implementation" else check.admin_one_of
    )

    satisfied = False
    if expected_single is not UNSET:
        satisfied = normalize_address(observed) == normalize_address(expected_single)
    elif expected_set:
        satisfied = any(
            normalize_address(observed) == normalize_address(candidate)
            for candidate in expected_set
        )

    if satisfied:
        result.status = Status.PASS
        return result

    result.status = Status.DRIFT
    if role == "implementation":
        result.detail = (
            f"the proxy has been upgraded -- slot {slot.hex} now points at a "
            f"different implementation than the PoC was written against"
        )
    else:
        result.detail = f"slot {slot.hex} ({slot.derivation})"
    return _maybe_waive(result, check.allow_drift)


def _expects(check: ProxyCheck, role: str) -> bool:
    if role == "implementation":
        return check.implementation is not UNSET or check.implementation_one_of is not None
    return check.admin is not UNSET or check.admin_one_of is not None


def _describe_proxy_expectation(check: ProxyCheck, role: str) -> str:
    single = check.implementation if role == "implementation" else check.admin
    many = check.implementation_one_of if role == "implementation" else check.admin_one_of
    if single is not UNSET:
        return to_checksum_address(single)
    if many:
        return "one of [" + ", ".join(to_checksum_address(a) for a in many) + "]"
    return "(no constraint)"


def _maybe_waive(
    result: CheckResult, justification: str | None, *, keep_error: bool = False
) -> CheckResult:
    """Downgrade a DRIFT to DRIFT-ALLOWED when the manifest waived it.

    An ERROR is never waived: ``allow_drift`` says "I know this value moved",
    not "ignore this check if it cannot be read".
    """
    if justification and not keep_error and result.status == Status.DRIFT:
        result.status = Status.DRIFT_ALLOWED
        result.justification = justification
    elif justification:
        result.justification = justification
    return result


def _explain_rpc_error(check: ParamCheck, exc: RpcResponseError) -> str:
    message = str(exc)
    if check.mode == "call":
        return (
            f"eth_call failed: {message} -- the call reverts at this block, so "
            f"the value could not be read"
        )
    return f"RPC rejected the read: {message}"
