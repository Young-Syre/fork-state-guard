"""Exit codes.

Distinct codes for distinct meanings, so CI and pre-submission scripts can
react differently to "your assumption is wrong" and "the node was down".
"""

from __future__ import annotations

OK = 0
"""Every declared assumption holds (waived drift included)."""

DRIFT = 1
"""At least one assumption no longer holds. The PoC's preconditions moved."""

RPC_UNREACHABLE = 2
"""The endpoint could not be reached or did not answer usefully. Nothing was
learned about chain state -- this is NOT a verification failure."""

MANIFEST_ERROR = 3
"""The manifest is malformed, or it disagrees with the endpoint's chain id."""

CHECK_ERROR = 4
"""A check could not be evaluated (reverting call, no code at the address,
undecodable return data). The assumption is neither confirmed nor refuted."""

USAGE = 64
"""Bad command-line usage."""

DESCRIPTIONS = {
    OK: "all declared assumptions verified",
    DRIFT: "at least one assumption drifted",
    RPC_UNREACHABLE: "RPC endpoint unreachable (nothing verified)",
    MANIFEST_ERROR: "manifest invalid, or chain id mismatch",
    CHECK_ERROR: "a check could not be evaluated",
    USAGE: "bad usage",
}
