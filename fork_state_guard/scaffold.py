"""The commented example manifest written by ``fork-state-guard init``."""

from __future__ import annotations

TEMPLATE = '''# fork-state-guard manifest
#
# Declare every on-chain value your PoC depends on. Run `fork-state-guard
# check` before you file the report: anything that drifted since you wrote the
# PoC shows up as DRIFT, and the command exits nonzero.
#
# Replace the addresses below with the ones your PoC actually touches, then
# delete the entries you do not need. An honest manifest is a short one.

[meta]
chain_id = 1                      # fail fast if the RPC is on another chain
label = "Vault V2 -- fee bypass PoC"
poc = "test/VaultExploit.t.sol"   # free-text pointer, for the evidence block
fork_block = 21000000             # the block your PoC forks at
# notes = "anything a reviewer should know about these preconditions"


# --- the contract is still the contract you audited ------------------------
# The most valuable check here. An upgrade leaves the address answering and
# the ABI intact while the bug quietly disappears -- so pin the implementation
# the PoC was written against.

[[proxy]]
name = "vault proxy"
address = "0x0000000000000000000000000000000000000001"
standard = "auto"                 # auto | eip1967 | eip1822 | oz-legacy
implementation = "0x0000000000000000000000000000000000000002"
# admin = "0x0000000000000000000000000000000000000003"


# --- privileged roles ------------------------------------------------------
# "owner is an EOA" is an assumption. If it became a multisig or a timelock,
# a PoC that assumes a single signer no longer reflects production.

[[param]]
name = "vault.owner"
address = "0x0000000000000000000000000000000000000001"
call = "owner()"
expect = "0x0000000000000000000000000000000000000003"

# Several addresses are acceptable? Say so explicitly.
# [[param]]
# name = "vault.guardian"
# address = "0x0000000000000000000000000000000000000001"
# call = "guardian()"
# expect_one_of = [
#   "0x0000000000000000000000000000000000000004",
#   "0x0000000000000000000000000000000000000005",
# ]


# --- numeric parameters, with the tolerance the PoC actually needs ---------
# Do not pin a fee to an exact value if the exploit works for any fee under a
# threshold -- pin the threshold. That is the assumption; the rest is noise.

[[param]]
name = "vault.feeBps"
address = "0x0000000000000000000000000000000000000001"
call = "feeBps()"
returns = "uint256"
expect_lte = 50                   # PoC is profitable while the fee stays <= 0.5%

[[param]]
name = "vault.rateLimit"
address = "0x0000000000000000000000000000000000000001"
call = "rateLimit()"
returns = "uint256"
expect_gte = "1000000000000000000000"   # uint256 values go in quotes: TOML
                                        # integers are only 64 bits wide

# Booleans matter too: a paused contract is not an exploitable contract.
[[param]]
name = "vault.paused"
address = "0x0000000000000000000000000000000000000001"
call = "paused()"
expect = false


# --- calls with arguments --------------------------------------------------
# Argument types come from the signature; values go in `args` in order.

[[param]]
name = "vault token balance"
address = "0x0000000000000000000000000000000000000006"   # the token
call = "balanceOf(address)"
args = ["0x0000000000000000000000000000000000000001"]    # the vault
returns = "uint256"
expect_gte = "1000000000000000000"   # the PoC needs something to drain


# --- raw storage, for values with no getter --------------------------------

[[param]]
name = "vault.slot0"
address = "0x0000000000000000000000000000000000000001"
storage = 0                       # slot number, or a hex string
expect = "0x0000000000000000000000000000000000000000000000000000000000000001"


# --- native balance --------------------------------------------------------

[[param]]
name = "attacker funding"
address = "0x0000000000000000000000000000000000000007"
balance = true
expect_gte = "100000000000000000"   # 0.1 ETH, in wei


# --- a knowing exception ---------------------------------------------------
# Sometimes a value has moved and you know it does not matter. Say why, in
# writing. The report prints the justification; it is never silent.

# [[param]]
# name = "vault.totalSupply"
# address = "0x0000000000000000000000000000000000000001"
# call = "totalSupply()"
# returns = "uint256"
# expect = "4200000000000000000000"
# allow_drift = "supply drifts with every deposit; the PoC does not depend on it"
'''


def example_manifest() -> str:
    """Return the scaffolded manifest text."""
    return TEMPLATE
