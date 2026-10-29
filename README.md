# fork-state-guard

[![tests](https://github.com/Young-Syre/fork-state-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/fork-state-guard/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)
[![Read-only](https://img.shields.io/badge/chain%20access-read--only-informational.svg)](#read-only-by-construction)

**Declare the on-chain state your exploit PoC depends on. Verify every assumption against live chain state before the report ships.**

---

## The problem

A smart-contract PoC is written against a forked chain state, and then it rots.

You fork at a block, build the exploit, and it works. Days or weeks pass while you write the report. In that time the owner became a multisig, a fee moved, a parameter was retuned, a guardian was rotated — or the proxy was upgraded and the address you targeted now points at different code. The PoC still passes locally, because the fork is frozen at the old block. It no longer describes production.

The expensive outcome is not the bug being wrong. It is a reviewer closing your report as unreproducible, because one precondition quietly stopped being true — and a single stale assumption is enough to do it, because the reviewer runs your PoC against live state, not against your fork.

The fix is unglamorous. Write down every on-chain value the PoC depends on, then check each one against live state before you file. That is all this tool does — and when something has moved, you hear it from a nonzero exit code instead of from a reviewer.

See [the worked example](#worked-example) for a real run against mainnet.

## What it checks

- **Proxy implementation and admin.** The highest-value check here. An upgrade leaves the address answering and the ABI intact while the bug disappears — the single most likely way a PoC silently stops being true. EIP-1967, EIP-1822 and the OpenZeppelin pre-1967 slots are all probed.
- **View-function return values** — `owner()`, `feeBps()`, `paused()`, `balanceOf(address)` — with exact, set-membership, or bounded expectations.
- **Raw storage slots**, for state with no getter.
- **Native balances**, for "the attacker account is funded" preconditions.
- **The chain itself**: a manifest that declares `chain_id = 1` fails fast when pointed at Sepolia, instead of printing a wall of meaningless drift.

Each check produces one row, and the command exits nonzero if any assumption moved.

## Install

```bash
pip install fork-state-guard          # once published
# or, from a clone:
pip install -e .
```

Python 3.11 or newer. **No dependencies** — not a convenience, a design constraint: see [Design notes](#design-notes).

## Quickstart

```bash
fork-state-guard init vault.toml          # scaffold a commented manifest
$EDITOR vault.toml                        # declare what your PoC assumes
export ETH_RPC_URL=https://...            # or pass --rpc
fork-state-guard check vault.toml         # verify; nonzero exit on drift
fork-state-guard check vault.toml --format markdown -o evidence.md
```

Subcommands: `check`, `init`, `slots` (print the proxy slot table and how each is derived).

## Worked example

A manifest declares what the PoC assumes. The example below is real and runnable: it checks
Ethereum mainnet USDC, a contract anyone can read. Substitute your own target and the shape is
identical — this is `examples/usdc-proxy.toml`, abridged:

```toml
[meta]
chain_id = 1
label = "USDC proxy and token parameters (example)"

# The contract must still be the contract you audited.
[[proxy]]
name = "usdc proxy"
address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
standard = "auto"
implementation = "0x43506849D7C04F9138D1A2050bbF3A0c054402dd"
admin = "0x807a96288A1A408dBC13DE2b1d087d10356395d2"

# "owner is still this address" is an assumption. Say so.
[[param]]
name = "usdc.owner"
address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
call = "owner()"
expect = "0xFcb19e6a322b27c06842A71e8c725399f049AE3a"

# A paused token is not an exploitable token.
[[param]]
name = "usdc.paused"
address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
call = "paused()"
expect = false

# Pin the threshold the exploit needs, not an exact value it does not care about.
[[param]]
name = "usdc.totalSupply"
address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
call = "totalSupply()"
returns = "uint256"
expect_gte = "1000000000000000"
allow_drift = "supply moves with every mint and burn; only the floor matters here"
```

In a real PoC manifest the same entries carry the values your exploit depends on: a fee ceiling
(`expect_lte = 50`), a rate limit floor (`expect_gte = "1000000000000000000000"`), a guardian set
(`expect_one_of = [...]`), the attacker account's funding (`balance = true`), or a storage slot with
no getter (`storage = 0`). `fork-state-guard init` scaffolds one of each, commented.

Run it:

```console
$ fork-state-guard check examples/usdc-proxy.toml --rpc https://eth.drpc.org

fork-state-guard  --  USDC proxy and token parameters (example)
===============================================================

  manifest     examples/usdc-proxy.toml
  endpoint     https://eth.drpc.org
  chain id     1 (manifest declares 1)
  block        26296542  (2026-10-29T06:16:23Z)
  checked at   2026-10-29T06:16:28Z

  STATUS  CHECK                        TARGET                    OBSERVED
  ------  ---------------------------  ------------------------  ------------------------------------------
  PASS    usdc.owner                   owner()                   0xFcb19e6a322b27c06842A71e8c725399f049AE3a
  PASS    usdc.paused                  paused()                  false
  PASS    usdc.decimals                decimals()                6
  PASS    usdc.symbol                  symbol()                  USDC
  PASS    usdc.totalSupply             totalSupply()             47414031481342836
  PASS    usdc proxy / implementation  oz-legacy:implementation  0x43506849D7C04F9138D1A2050bbF3A0c054402dd
  PASS    usdc proxy / admin           oz-legacy:admin           0x807a96288A1A408dBC13DE2b1d087d10356395d2

  7 check(s) at block 26296542   PASS: 7

  VERIFIED -- every declared assumption still holds at this block.
```

Note the `oz-legacy` in the proxy rows. USDC's proxy predates EIP-1967 and keeps its implementation
in the OpenZeppelin legacy slot, so `standard = "auto"` had to probe more than one standard to find
it. A tool that only knew EIP-1967 would have reported "not a proxy" and told you nothing — which is
why the standard that matched is printed rather than assumed.

Change that expected implementation to something the proxy does not point at, and the drift is
spelled out with the slot it came from:

```console
  Details
  -------
  [DRIFT] usdc proxy / implementation  (oz-legacy:implementation)
      expected  0x1111111111111111111111111111111111111111
      observed  0x43506849D7C04F9138D1A2050bbF3A0c054402dd
      the proxy has been upgraded -- slot
      0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3 now points at a
      different implementation than the PoC was written against
      note: FiatTokenProxy; implementation lives in the pre-1967 zeppelinos slot

  7 check(s) at block 26296544   PASS: 6  DRIFT: 1

  DRIFT -- at least one declared assumption no longer holds. The PoC's preconditions have changed.
```

## Manifest reference

### `[meta]`

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chain_id` | integer | no | Expected chain id. If the endpoint reports another chain, the run aborts with exit 3 rather than producing meaningless results. Override with `--ignore-chain-id`. |
| `label` | string | no | Human label, printed as the report title. |
| `poc` | string | no | Free-text pointer to the PoC (e.g. a test path), echoed into the evidence block. |
| `fork_block` | integer | no | The block the PoC forks at. The report shows how many blocks of drift that is. |
| `notes` | string | no | Anything a reviewer should know about these preconditions. |

### `[[param]]`

Each entry reads exactly one value. Declare **exactly one** read mode (`call`, `storage` or `balance`) and **at least one** expectation.

| Key | Type | Meaning |
| --- | --- | --- |
| `name` | string | **Required.** Identifies the row in the report; must be unique. |
| `address` | string | **Required.** The contract or account to read. Any case; compared case-insensitively. |
| `call` | string | Read mode: a function signature, e.g. `"owner()"` or `"balanceOf(address)"`. |
| `args` | array | Arguments for `call`, in order. Types come from the signature. |
| `returns` | string | The return type. Recommended; inferred from the expectation when omitted (see below). |
| `storage` | integer or hex string | Read mode: a raw storage slot. |
| `balance` | `true` | Read mode: the account's native balance, in wei. |
| `expect` | any | The value must equal this. |
| `expect_one_of` | array | The value must be one of these. Mutually exclusive with `expect`. |
| `expect_gte` | integer or string | Numeric floor (inclusive). |
| `expect_lte` | integer or string | Numeric ceiling (inclusive). |
| `allow_drift` | string | A written justification. Drift on this check is reported and printed, but does not fail the run. A bare `true` is rejected — a knowing exception has to say why. |
| `note` | string | Free-text note, printed with the row. |

> **uint256 values go in quotes.** TOML integers are 64-bit, so anything larger must be written as a decimal or hex string: `expect_gte = "1000000000000000000000"`.

### `[[proxy]]`

| Key | Type | Meaning |
| --- | --- | --- |
| `name` | string | **Required.** |
| `address` | string | **Required.** The proxy address. |
| `standard` | string | `auto` (default), `eip1967`, `eip1822` or `oz-legacy`. |
| `implementation` | string | The implementation the PoC was written against. |
| `implementation_one_of` | array | Accept any of these implementations. |
| `admin` | string | Expected proxy admin. |
| `admin_one_of` | array | Accept any of these admins. |
| `allow_drift` | string | As above. |
| `note` | string | As above. |

At least one of `implementation` / `implementation_one_of` / `admin` / `admin_one_of` is required. Each role becomes its own report row (`vault proxy / implementation`).

### Type inference

An explicit `returns` always wins. Otherwise:

| Expectation shape | Inferred type |
| --- | --- |
| `balance = true` | `uint256` (wei) |
| a boolean | `bool` |
| an integer, or `expect_gte` / `expect_lte` | `uint256` |
| a 20-byte hex string | `address` |
| a 32-byte hex string | `bytes32` |
| any other `0x` hex string | `bytes` |
| any other string | `string` |
| a `storage` read with no other hint | `bytes32` |

Supported types: `address`, `bool`, `uint<N>`, `int<N>`, `bytes<N>` for arguments and returns, plus `string` and dynamic `bytes` for returns. A `bytes32` expectation shorter than 32 bytes is left-padded, matching how the EVM right-aligns numeric values in a storage word.

## Proxy slots

Every constant below is **derived from keccak256 at runtime**, then compared against the published literal; a wrong keccak implementation fails at import rather than silently reading the wrong slot. Print them yourself with `fork-state-guard slots`.

| Standard | Role | Derivation | Slot |
| --- | --- | --- | --- |
| EIP-1967 | implementation | `keccak256("eip1967.proxy.implementation") - 1` | `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` |
| EIP-1967 | admin | `keccak256("eip1967.proxy.admin") - 1` | `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103` |
| EIP-1967 | beacon | `keccak256("eip1967.proxy.beacon") - 1` | `0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50` |
| EIP-1822 | implementation | `keccak256("PROXIABLE")` | `0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7` |
| OZ legacy | implementation | `keccak256("org.zeppelinos.proxy.implementation")` | `0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3` |
| OZ legacy | admin | `keccak256("org.zeppelinos.proxy.admin")` | `0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b` |

Under `standard = "auto"` the implementation slots are probed in that order and the first non-zero one wins. The matched standard appears in the report, because "which proxy standard is this" is itself worth recording.

An expected admin that is simply absent is reported as **drift, not an error** — a migration to UUPS or a beacon proxy legitimately empties the admin slot, and that is exactly the kind of change that invalidates an admin-dependent PoC.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every declared assumption holds (explicitly waived drift included). |
| `1` | **Drift.** At least one assumption no longer holds. |
| `2` | **RPC unreachable.** The endpoint could not be reached or did not answer usefully. Nothing was verified — this is *not* a statement about chain state. |
| `3` | Manifest invalid, or the endpoint's chain id contradicts the manifest. |
| `4` | A check could not be evaluated (reverting call, no code at the address, undecodable return data). The assumption is neither confirmed nor refuted. |
| `64` | Bad command-line usage. |

The distinction between `1` and `2` is the point. "Your assumption is wrong" and "the node was down" demand different responses, and a CI job that treats an outage as a verification failure will teach you to ignore it. When several apply, `4` outranks `1`: *"I could not tell"* is a worse place to be than *"I know this moved"*, because only the first can be mistaken for a clean run.

## Markdown evidence

`--format markdown` emits a block to paste into the report, so a reviewer can see the preconditions were checked against live state, at a stated block and time:

```markdown
### Live state verification -- USDC proxy and token parameters (example)

Verified at **block 26296543** (2026-10-29T06:16:35Z) on **chain id 1**, checked 2026-10-29T06:16:43Z.

| Check | Read | Expected | Observed | Status |
| --- | --- | --- | --- | --- |
| usdc.owner | `owner()` | `0xFcb19e6a322b27c06842A71e8c725399f049AE3a` | `0xFcb19e6a322b27c06842A71e8c725399f049AE3a` | PASS |
| usdc.paused | `paused()` | `false` | `false` | PASS |
| usdc.totalSupply | `totalSupply()` | >= 1000000000000000 | `47414030244615488` | PASS |
| usdc proxy / implementation | `oz-legacy:implementation` | `0x43506849D7C04F9138D1A2050bbF3A0c054402dd` | `0x43506849D7C04F9138D1A2050bbF3A0c054402dd` | PASS |

**VERIFIED -- every declared assumption still holds at this block.**

<sub>Generated by fork-state-guard -- read-only JSON-RPC state verification. The tool holds no
keys and sends no transactions; every value above was read with `eth_call`, `eth_getStorageAt`,
`eth_getBalance` and `eth_getCode` at the stated block.</sub>
```

Every report, in every format, carries the block number it was checked at. A verification without a block height is not evidence of anything.

`--format json` gives the same data structured, with `verified`, `verdict`, `counts`, `exit_code` and one object per check — for a pre-submission gate or a CI step.

## In CI

```yaml
- name: Verify PoC preconditions still hold
  run: fork-state-guard check vault.toml --format markdown -o evidence.md
  env:
    FORK_STATE_GUARD_RPC: ${{ secrets.ETH_RPC_URL }}
```

The endpoint is read from `--rpc`, else `FORK_STATE_GUARD_RPC`, else `ETH_RPC_URL`. **No API key is ever hardcoded**, and the endpoint is redacted to scheme and host everywhere it is printed — provider URLs routinely carry a key in the path or query string, and this tool's output is designed to be pasted into a report. Requests retry with exponential backoff (`--retries`, `--backoff`, `--timeout`).

All reads are pinned to one resolved block number, so a report always describes a single consistent state even when `latest` moves mid-run.

## Read-only by construction

The tool issues exactly seven JSON-RPC methods, all of them reads:

`eth_chainId` · `eth_blockNumber` · `eth_getBlockByNumber` · `eth_call` · `eth_getStorageAt` · `eth_getBalance` · `eth_getCode`

It has **no signing capability**: no private keys, no mnemonics, no keystore, no transaction construction, no `eth_sendTransaction`, no `eth_sendRawTransaction`. There is no code path that can mutate chain state, and nothing to configure that would add one. This is enforced by a test that asserts the set of methods used stays within that list, not only by this paragraph.

## Limitations

Stated plainly, because a verification tool that oversells itself is worse than none:

- **It verifies the assumptions you declared. It cannot discover the one you forgot.** This is the real limit. An undeclared assumption is invisible, and a clean `VERIFIED` means only that everything *in the manifest* still holds. Writing an honest manifest is the work; the tool just checks it.
- **It reads values; it does not re-run your exploit.** Every precondition can hold while the PoC still fails for a reason no scalar captures — reordering, a new reentrancy guard, a changed code path behind an unchanged parameter. This is a precondition check, not a replacement for re-running the PoC against a fresh fork.
- **A `PASS` is true at one block, not forever.** State can move the minute after you check. Re-check right before you file, and keep the block number in the report.
- **Only single-value returns are decoded.** A function returning a tuple or an array is out of scope; read the components through separate getters, or via storage.
- **`eth_call` results depend on the node.** An archive node is required for historical `--block` reads; a pruned node will answer with an error, which is reported as `ERROR` (exit 4), not as drift.
- **Storage reads need the right slot.** The tool reads the slot you name; computing the slot for a mapping or a packed struct is on you. Packed slots read as `address` or `bool` are rejected with a message telling you to read them as `bytes32`.
- **Proxy detection covers the three standards listed above.** A bespoke proxy that stores its implementation elsewhere reports `ERROR`, not `PASS` — it will not quietly tell you nothing is wrong.

## Design notes

**Zero dependencies, deliberately.** A tool you run immediately before filing a report should not need a working `web3.py` install, a C toolchain for `pysha3`, or a resolvable dependency tree. `pip install` must not be the thing that fails at the moment you need an answer. Everything is implemented against the standard library: `tomllib` and `urllib` ship with Python 3.11+.

That meant implementing the primitives, so they are tested harder than the rest of the code:

- **keccak-256** — Keccak-f[1600] from scratch. This is *not* SHA3-256: the two differ in the padding domain byte (`0x01` vs `0x06`), which is why `hashlib.sha3_256` cannot be substituted. Pinned against the official vectors, including `keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, and against known function selectors (`transfer(address,uint256)` → `0xa9059cbb`, `owner()` → `0x8da5cb5b`, `balanceOf(address)` → `0x70a08231`).
- **A differential test for the permutation.** Fixed vectors alone would not prove the multi-block sponge is right. Since Keccak-256 and SHA3-256 share the permutation, lane layout, 136-byte rate and sponge, the suite runs this module's own permutation with SHA3's padding byte and requires a byte-exact match with `hashlib.sha3_256` across 17 input lengths from 0 to 4096 bytes. Any error in the rotation offsets, the lane mapping or the absorption loop breaks it — an independent reference, without an independent dependency.
- **ABI coding** — selectors, static argument encoding, and single-value decoding for static types plus `string` and dynamic `bytes`. Unsupported types raise a clear error rather than mis-encoding silently.
- **EIP-55** — checksum formatting and validation, pinned against all eight test vectors from the EIP.

**Strict manifest parsing.** Unknown keys are errors, not warnings. A typo that silently became "no constraint" would hand you a `PASS` you did not earn, which is the one failure mode a tool like this must not have.

## Tests

```bash
python -m unittest discover -s tests -t .    # 305 tests
```

No network access required, and none permitted: the RPC transport is injected, and the suite is verified to pass with an audit hook that raises on any socket connection. Coverage includes the keccak vectors and the differential permutation test, selector computation, ABI encode/decode round-trips, the EIP-55 vectors, the derived proxy slots, every manifest validation error, the full comparison matrix (`expect`, `expect_one_of`, `expect_gte`, `expect_lte`, `allow_drift`) against a mocked transport, retry and backoff behaviour, the transport-error-versus-assumption-violation distinction, and every documented exit code end to end.

## References

- [EIP-1967: Standard Proxy Storage Slots](https://eips.ethereum.org/EIPS/eip-1967)
- [EIP-1822: Universal Upgradeable Proxy Standard](https://eips.ethereum.org/EIPS/eip-1822)
- [EIP-55: Mixed-case checksum address encoding](https://eips.ethereum.org/EIPS/eip-55)
- [Ethereum JSON-RPC specification](https://ethereum.github.io/execution-apis/api-documentation/)
- [The Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf) and [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) (for the SHA-3 padding difference)

## License

MIT — see [LICENSE](LICENSE).
