"""The comparison engine, driven entirely through a fake RPC transport."""

from __future__ import annotations

import unittest

from fork_state_guard.abi import encode_call
from fork_state_guard.manifest import parse_manifest
from fork_state_guard.proxy import (
    EIP1822_IMPLEMENTATION,
    EIP1967_ADMIN,
    EIP1967_IMPLEMENTATION,
    OZ_LEGACY_IMPLEMENTATION,
)
from fork_state_guard.rpc import RpcClient, RpcTransportError
from fork_state_guard.verify import ChainMismatch, Status, verify

from .fake_rpc import FakeTransport, RpcErrorSpec, addr_word, string_word, word

VAULT = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
OWNER = "0xde709f2102306220921060314715629080e2fb77"
MULTISIG = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb"
IMPL_V1 = "0x27b1fdb04752bbc536007a920d24acb045561c26"
IMPL_V2 = "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb"


def call_key(address: str, signature: str, args=()) -> tuple[str, str]:
    return (address.lower(), "0x" + encode_call(signature, list(args)).hex())


def run(manifest_text: str, transport: FakeTransport, **kwargs):
    manifest = parse_manifest(manifest_text)
    return verify(manifest, RpcClient(transport), **kwargs)


class TestCallChecks(unittest.TestCase):
    MANIFEST = f"""
    [[param]]
    name = "vault.owner"
    address = "{VAULT}"
    call = "owner()"
    expect = "{OWNER}"
    """

    def test_matching_owner_passes(self):
        transport = FakeTransport(calls={call_key(VAULT, "owner()"): addr_word(OWNER)})
        report = run(self.MANIFEST, transport)
        self.assertEqual(report.results[0].status, Status.PASS)
        self.assertTrue(report.verified)

    def test_changed_owner_drifts(self):
        transport = FakeTransport(calls={call_key(VAULT, "owner()"): addr_word(MULTISIG)})
        report = run(self.MANIFEST, transport)
        result = report.results[0]
        self.assertEqual(result.status, Status.DRIFT)
        self.assertFalse(report.verified)
        # The observed value is reported in checksum form, so it can be
        # pasted straight into a report.
        self.assertEqual(result.actual, "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")

    def test_owner_comparison_is_case_insensitive(self):
        transport = FakeTransport(calls={call_key(VAULT, "owner()"): addr_word(OWNER.upper()[2:])})
        report = run(self.MANIFEST, transport)
        self.assertEqual(report.results[0].status, Status.PASS)

    def test_reverting_call_is_an_error_not_drift(self):
        transport = FakeTransport(
            calls={call_key(VAULT, "owner()"): RpcErrorSpec("execution reverted")}
        )
        report = run(self.MANIFEST, transport)
        result = report.results[0]
        self.assertEqual(result.status, Status.ERROR)
        self.assertIn("reverts", result.detail)
        self.assertFalse(report.verified)

    def test_missing_function_is_an_error(self):
        # The fake returns "0x" for a function it does not know about.
        report = run(self.MANIFEST, FakeTransport())
        self.assertEqual(report.results[0].status, Status.ERROR)
        self.assertIn("does not exist here", report.results[0].detail)

    def test_call_with_arguments_uses_the_right_calldata(self):
        manifest = f"""
        [[param]]
        name = "vault balance"
        address = "{OWNER}"
        call = "balanceOf(address)"
        args = ["{VAULT}"]
        returns = "uint256"
        expect_gte = "1000000000000000000"
        """
        transport = FakeTransport(
            calls={call_key(OWNER, "balanceOf(address)", [VAULT]): word(5 * 10**18)}
        )
        report = run(manifest, transport)
        self.assertEqual(report.results[0].status, Status.PASS)
        self.assertEqual(report.results[0].actual, "5000000000000000000")

    def test_string_return_value(self):
        manifest = f"""
        [[param]]
        name = "token symbol"
        address = "{VAULT}"
        call = "symbol()"
        returns = "string"
        expect = "DAI"
        """
        transport = FakeTransport(calls={call_key(VAULT, "symbol()"): string_word("DAI")})
        self.assertEqual(run(manifest, transport).results[0].status, Status.PASS)

    def test_bool_expectation(self):
        manifest = f"""
        [[param]]
        name = "vault.paused"
        address = "{VAULT}"
        call = "paused()"
        expect = false
        """
        passing = FakeTransport(calls={call_key(VAULT, "paused()"): word(0)})
        drifting = FakeTransport(calls={call_key(VAULT, "paused()"): word(1)})
        self.assertEqual(run(manifest, passing).results[0].status, Status.PASS)
        drift = run(manifest, drifting).results[0]
        self.assertEqual(drift.status, Status.DRIFT)
        self.assertEqual(drift.actual, "true")


class TestNumericTolerance(unittest.TestCase):
    def manifest(self, body: str) -> str:
        return f"""
        [[param]]
        name = "vault.feeBps"
        address = "{VAULT}"
        call = "feeBps()"
        returns = "uint256"
        {body}
        """

    def transport(self, value: int) -> FakeTransport:
        return FakeTransport(calls={call_key(VAULT, "feeBps()"): word(value)})

    def test_lte_at_the_boundary_passes(self):
        report = run(self.manifest("expect_lte = 50"), self.transport(50))
        self.assertEqual(report.results[0].status, Status.PASS)

    def test_lte_above_the_ceiling_drifts(self):
        report = run(self.manifest("expect_lte = 50"), self.transport(51))
        result = report.results[0]
        self.assertEqual(result.status, Status.DRIFT)
        self.assertIn("above the declared ceiling", result.detail)

    def test_gte_at_the_boundary_passes(self):
        report = run(self.manifest("expect_gte = 50"), self.transport(50))
        self.assertEqual(report.results[0].status, Status.PASS)

    def test_gte_below_the_floor_drifts(self):
        report = run(self.manifest("expect_gte = 50"), self.transport(49))
        self.assertIn("below the declared floor", report.results[0].detail)

    def test_both_bounds_form_a_window(self):
        manifest = self.manifest("expect_gte = 10\nexpect_lte = 50")
        self.assertEqual(run(manifest, self.transport(30)).results[0].status, Status.PASS)
        self.assertEqual(run(manifest, self.transport(9)).results[0].status, Status.DRIFT)
        self.assertEqual(run(manifest, self.transport(51)).results[0].status, Status.DRIFT)

    def test_uint256_beyond_64_bits_as_a_string(self):
        huge = 2**200
        manifest = self.manifest(f'expect_gte = "{huge}"')
        self.assertEqual(run(manifest, self.transport(huge)).results[0].status, Status.PASS)
        self.assertEqual(
            run(manifest, self.transport(huge - 1)).results[0].status, Status.DRIFT
        )

    def test_hex_bound(self):
        manifest = self.manifest('expect_lte = "0xff"')
        self.assertEqual(run(manifest, self.transport(255)).results[0].status, Status.PASS)
        self.assertEqual(run(manifest, self.transport(256)).results[0].status, Status.DRIFT)

    def test_exact_expect_on_a_number(self):
        manifest = self.manifest("expect = 42")
        self.assertEqual(run(manifest, self.transport(42)).results[0].status, Status.PASS)
        self.assertEqual(run(manifest, self.transport(43)).results[0].status, Status.DRIFT)


class TestExpectOneOf(unittest.TestCase):
    MANIFEST = f"""
    [[param]]
    name = "vault.guardian"
    address = "{VAULT}"
    call = "guardian()"
    expect_one_of = ["{OWNER}", "{MULTISIG}"]
    """

    def test_first_candidate_passes(self):
        transport = FakeTransport(calls={call_key(VAULT, "guardian()"): addr_word(OWNER)})
        self.assertEqual(run(self.MANIFEST, transport).results[0].status, Status.PASS)

    def test_second_candidate_passes(self):
        transport = FakeTransport(calls={call_key(VAULT, "guardian()"): addr_word(MULTISIG)})
        self.assertEqual(run(self.MANIFEST, transport).results[0].status, Status.PASS)

    def test_value_outside_the_set_drifts(self):
        transport = FakeTransport(calls={call_key(VAULT, "guardian()"): addr_word(IMPL_V1)})
        result = run(self.MANIFEST, transport).results[0]
        self.assertEqual(result.status, Status.DRIFT)
        self.assertIn("not in the accepted set", result.detail)

    def test_the_set_is_shown_in_the_expectation(self):
        transport = FakeTransport(calls={call_key(VAULT, "guardian()"): addr_word(IMPL_V1)})
        self.assertIn("one of", run(self.MANIFEST, transport).results[0].expected)


class TestAllowDrift(unittest.TestCase):
    MANIFEST = f"""
    [[param]]
    name = "vault.totalSupply"
    address = "{VAULT}"
    call = "totalSupply()"
    returns = "uint256"
    expect = 1000
    allow_drift = "supply moves with every deposit; the PoC does not depend on it"
    """

    def test_waived_drift_does_not_fail_the_run(self):
        transport = FakeTransport(calls={call_key(VAULT, "totalSupply()"): word(9999)})
        report = run(self.MANIFEST, transport)
        result = report.results[0]
        self.assertEqual(result.status, Status.DRIFT_ALLOWED)
        self.assertTrue(report.verified)
        self.assertEqual(report.drifted, [])

    def test_the_justification_is_printed_not_swallowed(self):
        transport = FakeTransport(calls={call_key(VAULT, "totalSupply()"): word(9999)})
        result = run(self.MANIFEST, transport).results[0]
        self.assertIn("does not depend on it", result.justification)

    def test_a_waived_check_that_still_matches_is_a_plain_pass(self):
        transport = FakeTransport(calls={call_key(VAULT, "totalSupply()"): word(1000)})
        self.assertEqual(run(self.MANIFEST, transport).results[0].status, Status.PASS)

    def test_allow_drift_never_waives_an_error(self):
        """allow_drift means "I know this value moved", not "ignore this
        check if it cannot be read"."""
        transport = FakeTransport(
            calls={call_key(VAULT, "totalSupply()"): RpcErrorSpec("execution reverted")}
        )
        report = run(self.MANIFEST, transport)
        self.assertEqual(report.results[0].status, Status.ERROR)
        self.assertFalse(report.verified)


class TestStorageChecks(unittest.TestCase):
    def test_storage_word_matches(self):
        manifest = f"""
        [[param]]
        name = "vault.slot0"
        address = "{VAULT}"
        storage = 0
        expect = "0x{'00' * 31}01"
        """
        transport = FakeTransport(storage={(VAULT, 0): word(1)})
        self.assertEqual(run(manifest, transport).results[0].status, Status.PASS)

    def test_short_bytes32_expectation_is_left_padded(self):
        manifest = f"""
        [[param]]
        name = "vault.slot0"
        address = "{VAULT}"
        storage = 0
        returns = "bytes32"
        expect = "0x01"
        """
        transport = FakeTransport(storage={(VAULT, 0): word(1)})
        self.assertEqual(run(manifest, transport).results[0].status, Status.PASS)

    def test_storage_as_uint_with_a_bound(self):
        manifest = f"""
        [[param]]
        name = "vault.cap"
        address = "{VAULT}"
        storage = "0x5"
        returns = "uint256"
        expect_gte = 100
        """
        transport = FakeTransport(storage={(VAULT, 5): word(500)})
        self.assertEqual(run(manifest, transport).results[0].status, Status.PASS)

    def test_storage_as_address(self):
        manifest = f"""
        [[param]]
        name = "vault.admin slot"
        address = "{VAULT}"
        storage = 2
        returns = "address"
        expect = "{OWNER}"
        """
        transport = FakeTransport(storage={(VAULT, 2): addr_word(OWNER)})
        self.assertEqual(run(manifest, transport).results[0].status, Status.PASS)

    def test_packed_slot_read_as_address_is_an_error_with_advice(self):
        manifest = f"""
        [[param]]
        name = "packed slot"
        address = "{VAULT}"
        storage = 3
        returns = "address"
        expect = "{OWNER}"
        """
        transport = FakeTransport(storage={(VAULT, 3): word("ff" * 32)})
        result = run(manifest, transport).results[0]
        self.assertEqual(result.status, Status.ERROR)
        self.assertIn("packed", result.detail)

    def test_unset_slot_reads_as_zero(self):
        manifest = f"""
        [[param]]
        name = "empty slot"
        address = "{VAULT}"
        storage = 99
        returns = "uint256"
        expect = 0
        """
        self.assertEqual(run(manifest, FakeTransport()).results[0].status, Status.PASS)


class TestBalanceChecks(unittest.TestCase):
    MANIFEST = f"""
    [[param]]
    name = "attacker funding"
    address = "{OWNER}"
    balance = true
    expect_gte = "100000000000000000"
    """

    def test_sufficient_balance_passes(self):
        transport = FakeTransport(balances={OWNER: 10**18})
        self.assertEqual(run(self.MANIFEST, transport).results[0].status, Status.PASS)

    def test_insufficient_balance_drifts(self):
        transport = FakeTransport(balances={OWNER: 10**15})
        self.assertEqual(run(self.MANIFEST, transport).results[0].status, Status.DRIFT)

    def test_balance_is_always_uint256(self):
        transport = FakeTransport(balances={OWNER: 10**18})
        self.assertEqual(run(self.MANIFEST, transport).results[0].value_type, "uint256")


class TestProxyChecks(unittest.TestCase):
    MANIFEST = f"""
    [[proxy]]
    name = "vault proxy"
    address = "{VAULT}"
    implementation = "{IMPL_V1}"
    """

    def eip1967(self, impl: str, admin: str | None = None) -> FakeTransport:
        storage = {(VAULT, EIP1967_IMPLEMENTATION.slot): addr_word(impl)}
        if admin:
            storage[(VAULT, EIP1967_ADMIN.slot)] = addr_word(admin)
        return FakeTransport(storage=storage)

    def test_unchanged_implementation_passes(self):
        report = run(self.MANIFEST, self.eip1967(IMPL_V1))
        result = report.results[0]
        self.assertEqual(result.status, Status.PASS)
        self.assertEqual(result.target, "eip1967:implementation")
        self.assertIn(EIP1967_IMPLEMENTATION.hex, result.detail)

    def test_upgraded_implementation_drifts_with_an_explicit_message(self):
        report = run(self.MANIFEST, self.eip1967(IMPL_V2))
        result = report.results[0]
        self.assertEqual(result.status, Status.DRIFT)
        self.assertIn("upgraded", result.detail)
        self.assertFalse(report.verified)

    def test_check_name_identifies_the_role(self):
        report = run(self.MANIFEST, self.eip1967(IMPL_V1))
        self.assertEqual(report.results[0].name, "vault proxy / implementation")

    def test_admin_is_checked_when_declared(self):
        manifest = f"""
        [[proxy]]
        name = "vault proxy"
        address = "{VAULT}"
        implementation = "{IMPL_V1}"
        admin = "{MULTISIG}"
        """
        report = run(manifest, self.eip1967(IMPL_V1, admin=MULTISIG))
        self.assertEqual(len(report.results), 2)
        self.assertTrue(all(r.status == Status.PASS for r in report.results))

    def test_admin_change_drifts(self):
        manifest = f"""
        [[proxy]]
        name = "vault proxy"
        address = "{VAULT}"
        implementation = "{IMPL_V1}"
        admin = "{MULTISIG}"
        """
        report = run(manifest, self.eip1967(IMPL_V1, admin=OWNER))
        statuses = {r.name: r.status for r in report.results}
        self.assertEqual(statuses["vault proxy / implementation"], Status.PASS)
        self.assertEqual(statuses["vault proxy / admin"], Status.DRIFT)

    def test_admin_only_manifest_produces_one_row(self):
        manifest = f"""
        [[proxy]]
        name = "vault proxy"
        address = "{VAULT}"
        admin = "{MULTISIG}"
        """
        report = run(manifest, self.eip1967(IMPL_V1, admin=MULTISIG))
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.results[0].target, "eip1967:admin")

    def test_missing_admin_slot_is_drift_with_a_uups_hint(self):
        report = run(
            f"""
            [[proxy]]
            name = "vault proxy"
            address = "{VAULT}"
            admin = "{MULTISIG}"
            """,
            self.eip1967(IMPL_V1),
        )
        result = report.results[0]
        self.assertEqual(result.status, Status.DRIFT)
        self.assertIn("UUPS", result.detail)

    def test_eip1822_proxy_is_detected_under_auto(self):
        transport = FakeTransport(
            storage={(VAULT, EIP1822_IMPLEMENTATION.slot): addr_word(IMPL_V1)}
        )
        result = run(self.MANIFEST, transport).results[0]
        self.assertEqual(result.status, Status.PASS)
        self.assertEqual(result.target, "eip1822:implementation")

    def test_oz_legacy_proxy_is_detected_under_auto(self):
        transport = FakeTransport(
            storage={(VAULT, OZ_LEGACY_IMPLEMENTATION.slot): addr_word(IMPL_V1)}
        )
        result = run(self.MANIFEST, transport).results[0]
        self.assertEqual(result.status, Status.PASS)
        self.assertEqual(result.target, "oz-legacy:implementation")

    def test_pinning_the_standard_ignores_other_slots(self):
        manifest = f"""
        [[proxy]]
        name = "vault proxy"
        address = "{VAULT}"
        standard = "eip1967"
        implementation = "{IMPL_V1}"
        """
        transport = FakeTransport(
            storage={(VAULT, OZ_LEGACY_IMPLEMENTATION.slot): addr_word(IMPL_V1)}
        )
        result = run(manifest, transport).results[0]
        self.assertEqual(result.status, Status.ERROR)
        self.assertIn("every known implementation slot is zero", result.detail)

    def test_no_proxy_slots_set_is_an_error(self):
        result = run(self.MANIFEST, FakeTransport()).results[0]
        self.assertEqual(result.status, Status.ERROR)
        self.assertIn("not a proxy of a recognised standard", result.detail)

    def test_no_code_at_the_address_is_an_error(self):
        transport = FakeTransport(code={VAULT: "0x"})
        result = run(self.MANIFEST, transport).results[0]
        self.assertEqual(result.status, Status.ERROR)
        self.assertIn("no code at this address", result.detail)

    def test_implementation_one_of_accepts_either(self):
        manifest = f"""
        [[proxy]]
        name = "vault proxy"
        address = "{VAULT}"
        implementation_one_of = ["{IMPL_V1}", "{IMPL_V2}"]
        """
        self.assertEqual(run(manifest, self.eip1967(IMPL_V2)).results[0].status, Status.PASS)

    def test_waived_proxy_drift(self):
        manifest = f"""
        [[proxy]]
        name = "vault proxy"
        address = "{VAULT}"
        implementation = "{IMPL_V1}"
        allow_drift = "the v2 upgrade only touched the fee accounting path"
        """
        report = run(manifest, self.eip1967(IMPL_V2))
        self.assertEqual(report.results[0].status, Status.DRIFT_ALLOWED)
        self.assertTrue(report.verified)

    def test_dirty_implementation_slot_is_an_error(self):
        transport = FakeTransport(
            storage={(VAULT, EIP1967_IMPLEMENTATION.slot): word("ff" * 32)}
        )
        result = run(self.MANIFEST, transport).results[0]
        self.assertEqual(result.status, Status.ERROR)
        self.assertIn("not a clean address", result.detail)


class TestBlockAndChain(unittest.TestCase):
    MANIFEST = f"""
    [meta]
    chain_id = 1
    fork_block = 20999000
    [[param]]
    name = "vault.owner"
    address = "{VAULT}"
    call = "owner()"
    expect = "{OWNER}"
    """

    def transport(self, **kwargs) -> FakeTransport:
        return FakeTransport(calls={call_key(VAULT, "owner()"): addr_word(OWNER)}, **kwargs)

    def test_latest_is_resolved_to_a_concrete_block(self):
        report = run(self.MANIFEST, self.transport(block_number=21_000_123))
        self.assertEqual(report.block_number, 21_000_123)

    def test_every_read_is_pinned_to_the_resolved_block(self):
        """Pinning matters: without it, 'latest' can move between reads and
        the report would describe two different states."""
        transport = self.transport(block_number=21_000_123)
        run(self.MANIFEST, transport)
        self.assertNotIn("latest", transport.blocks_requested)
        self.assertIn(hex(21_000_123), transport.blocks_requested)

    def test_explicit_block_is_used_verbatim(self):
        transport = self.transport()
        report = run(self.MANIFEST, transport, block=20_000_000)
        self.assertEqual(report.block_number, 20_000_000)
        self.assertNotIn("eth_blockNumber", transport.methods_used)

    def test_block_timestamp_is_recorded(self):
        report = run(self.MANIFEST, self.transport(timestamp=1_727_740_800))
        self.assertEqual(report.block_timestamp, 1_727_740_800)

    def test_blocks_since_fork(self):
        report = run(self.MANIFEST, self.transport(block_number=21_000_000))
        self.assertEqual(report.fork_block, 20_999_000)
        self.assertEqual(report.blocks_since_fork, 1000)

    def test_chain_id_mismatch_aborts_before_reading_state(self):
        transport = self.transport(chain_id=11155111)
        with self.assertRaises(ChainMismatch) as ctx:
            run(self.MANIFEST, transport)
        self.assertEqual(ctx.exception.expected, 1)
        self.assertEqual(ctx.exception.actual, 11155111)
        self.assertNotIn("eth_call", transport.methods_used)

    def test_chain_id_mismatch_can_be_overridden(self):
        report = run(self.MANIFEST, self.transport(chain_id=11155111), ignore_chain_id=True)
        self.assertEqual(report.results[0].status, Status.PASS)
        self.assertEqual(report.chain_id, 11155111)

    def test_node_without_eth_chainid_still_works(self):
        report = run(self.MANIFEST, self.transport(chain_id=None))
        self.assertIsNone(report.chain_id)
        self.assertEqual(report.results[0].status, Status.PASS)

    def test_missing_block_timestamp_is_tolerated(self):
        report = run(self.MANIFEST, self.transport(timestamp=None))
        self.assertIsNone(report.block_timestamp)
        self.assertEqual(report.results[0].status, Status.PASS)

    def test_bad_block_argument_is_rejected(self):
        with self.assertRaises(ValueError):
            run(self.MANIFEST, self.transport(), block="tomorrow")

    def test_only_read_only_methods_are_ever_called(self):
        """A hard guarantee of the tool: no signing, no sending, no state
        change. Pinned by assertion, not just by documentation."""
        transport = self.transport()
        run(self.MANIFEST, transport)
        allowed = {
            "eth_chainId",
            "eth_blockNumber",
            "eth_getBlockByNumber",
            "eth_call",
            "eth_getStorageAt",
            "eth_getBalance",
            "eth_getCode",
        }
        self.assertTrue(set(transport.methods_used) <= allowed)


class TestTransportFailure(unittest.TestCase):
    class DeadTransport:
        safe_url = "https://dead.invalid"

        def send(self, payload):
            raise RpcTransportError("cannot reach https://dead.invalid: timed out")

    def test_an_outage_propagates_rather_than_marking_everything_drifted(self):
        """An outage is not evidence about chain state, so it must not be
        reported as a verification failure."""
        manifest = parse_manifest(
            f'[[param]]\nname = "o"\naddress = "{VAULT}"\ncall = "owner()"\nexpect = "{OWNER}"\n'
        )
        with self.assertRaises(RpcTransportError):
            verify(manifest, RpcClient(self.DeadTransport()))


class TestReportAggregation(unittest.TestCase):
    MANIFEST = f"""
    [[param]]
    name = "pass"
    address = "{VAULT}"
    call = "owner()"
    expect = "{OWNER}"

    [[param]]
    name = "drift"
    address = "{VAULT}"
    call = "feeBps()"
    returns = "uint256"
    expect_lte = 10

    [[param]]
    name = "waived"
    address = "{VAULT}"
    call = "totalSupply()"
    returns = "uint256"
    expect = 1
    allow_drift = "moves constantly"

    [[param]]
    name = "error"
    address = "{VAULT}"
    call = "missing()"
    expect = 1
    """

    def setUp(self):
        transport = FakeTransport(
            calls={
                call_key(VAULT, "owner()"): addr_word(OWNER),
                call_key(VAULT, "feeBps()"): word(500),
                call_key(VAULT, "totalSupply()"): word(999),
            }
        )
        self.report = run(self.MANIFEST, transport)

    def test_one_row_per_check_in_manifest_order(self):
        self.assertEqual(
            [r.name for r in self.report.results], ["pass", "drift", "waived", "error"]
        )

    def test_counts(self):
        counts = self.report.counts
        self.assertEqual(counts[Status.PASS], 1)
        self.assertEqual(counts[Status.DRIFT], 1)
        self.assertEqual(counts[Status.DRIFT_ALLOWED], 1)
        self.assertEqual(counts[Status.ERROR], 1)

    def test_buckets(self):
        self.assertEqual([r.name for r in self.report.drifted], ["drift"])
        self.assertEqual([r.name for r in self.report.errored], ["error"])
        self.assertEqual([r.name for r in self.report.allowed], ["waived"])

    def test_not_verified_when_anything_drifted(self):
        self.assertFalse(self.report.verified)

    def test_result_dicts_are_json_ready(self):
        row = self.report.results[0].as_dict()
        self.assertEqual(row["status"], Status.PASS)
        self.assertEqual(row["kind"], "param")
        # Addresses are checksummed on the way out.
        self.assertEqual(row["address"], "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")


if __name__ == "__main__":
    unittest.main()
