"""Proxy storage-slot constants and resolution.

Every constant here is *derived* from keccak256 at import time rather than
pasted in, and then checked against the published literal. If the keccak
implementation were wrong, importing this module would fail loudly instead of
silently reading the wrong storage slot.

An upgrade is the assumption most likely to invalidate a PoC without anything
else changing: the address you targeted still answers, the ABI still matches,
and the bug is gone. That is why proxy implementation drift is checked
separately from ordinary parameters.
"""

from __future__ import annotations

from dataclasses import dataclass

from .keccak import keccak256

__all__ = [
    "ProxySlot",
    "PROXY_STANDARDS",
    "SLOTS_BY_ROLE",
    "slot_hex",
    "implementation_slots",
    "admin_slots",
    "describe_slots",
]


def _hash_int(text: str) -> int:
    return int.from_bytes(keccak256(text.encode("ascii")), "big")


def _hash_minus_one(text: str) -> int:
    """EIP-1967 subtracts one from the hash so the slot cannot be the
    preimage of any mapping or array location."""
    return _hash_int(text) - 1


def slot_hex(slot: int) -> str:
    """Format a storage slot as a 32-byte 0x-prefixed hex string."""
    return "0x" + format(slot, "064x")


@dataclass(frozen=True)
class ProxySlot:
    """One well-known proxy storage slot."""

    standard: str
    role: str  # "implementation", "admin" or "beacon"
    preimage: str
    derivation: str  # human-readable: how the slot is computed
    slot: int

    @property
    def hex(self) -> str:
        return slot_hex(self.slot)

    @property
    def label(self) -> str:
        return f"{self.standard}:{self.role}"


def _slot(standard: str, role: str, preimage: str, *, minus_one: bool) -> ProxySlot:
    value = _hash_minus_one(preimage) if minus_one else _hash_int(preimage)
    derivation = (
        f"keccak256('{preimage}') - 1" if minus_one else f"keccak256('{preimage}')"
    )
    return ProxySlot(standard, role, preimage, derivation, value)


EIP1967_IMPLEMENTATION = _slot(
    "eip1967", "implementation", "eip1967.proxy.implementation", minus_one=True
)
EIP1967_ADMIN = _slot("eip1967", "admin", "eip1967.proxy.admin", minus_one=True)
EIP1967_BEACON = _slot("eip1967", "beacon", "eip1967.proxy.beacon", minus_one=True)
EIP1822_IMPLEMENTATION = _slot("eip1822", "implementation", "PROXIABLE", minus_one=False)
OZ_LEGACY_IMPLEMENTATION = _slot(
    "oz-legacy", "implementation", "org.zeppelinos.proxy.implementation", minus_one=False
)
OZ_LEGACY_ADMIN = _slot(
    "oz-legacy", "admin", "org.zeppelinos.proxy.admin", minus_one=False
)

ALL_SLOTS: tuple[ProxySlot, ...] = (
    EIP1967_IMPLEMENTATION,
    EIP1967_ADMIN,
    EIP1967_BEACON,
    EIP1822_IMPLEMENTATION,
    OZ_LEGACY_IMPLEMENTATION,
    OZ_LEGACY_ADMIN,
)

# Standards in the order they are probed when the manifest says "auto".
# EIP-1967 first: it is what essentially all current tooling deploys.
PROXY_STANDARDS: tuple[str, ...] = ("eip1967", "eip1822", "oz-legacy")

SLOTS_BY_ROLE: dict[str, tuple[ProxySlot, ...]] = {
    "implementation": (
        EIP1967_IMPLEMENTATION,
        EIP1822_IMPLEMENTATION,
        OZ_LEGACY_IMPLEMENTATION,
    ),
    "admin": (EIP1967_ADMIN, OZ_LEGACY_ADMIN),
    "beacon": (EIP1967_BEACON,),
}


def implementation_slots(standard: str = "auto") -> tuple[ProxySlot, ...]:
    """Implementation slots to probe for ``standard`` ("auto" probes all)."""
    return _select(SLOTS_BY_ROLE["implementation"], standard)


def admin_slots(standard: str = "auto") -> tuple[ProxySlot, ...]:
    """Admin slots to probe for ``standard`` ("auto" probes all)."""
    return _select(SLOTS_BY_ROLE["admin"], standard)


def beacon_slots(standard: str = "auto") -> tuple[ProxySlot, ...]:
    return _select(SLOTS_BY_ROLE["beacon"], standard)


def _select(slots: tuple[ProxySlot, ...], standard: str) -> tuple[ProxySlot, ...]:
    if standard in ("auto", "", None):
        return slots
    if standard not in PROXY_STANDARDS:
        raise ValueError(
            f"unknown proxy standard {standard!r}; "
            f"choose from: auto, {', '.join(PROXY_STANDARDS)}"
        )
    return tuple(s for s in slots if s.standard == standard)


def describe_slots() -> list[tuple[str, str, str, str]]:
    """Rows of (standard, role, derivation, slot) for documentation output."""
    return [(s.standard, s.role, s.derivation, s.hex) for s in ALL_SLOTS]


# --- self-check -------------------------------------------------------------
# The two EIP-1967 slots are published in the EIP itself. Deriving them and
# comparing against the published values proves the keccak implementation is
# sound on the exact inputs that matter most here.
_PUBLISHED = {
    EIP1967_IMPLEMENTATION.hex: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    EIP1967_ADMIN.hex: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    EIP1967_BEACON.hex: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}
for _derived, _published in _PUBLISHED.items():
    if _derived != _published:  # pragma: no cover - would be a build-breaking bug
        raise AssertionError(
            f"derived proxy slot {_derived} does not match the published "
            f"constant {_published}; the keccak implementation is wrong"
        )
del _derived, _published, _PUBLISHED
