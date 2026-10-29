"""Manifest parsing: the happy path, and every error case."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fork_state_guard.manifest import (
    UNSET,
    ManifestError,
    load_manifest,
    parse_manifest,
)

VAULT = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
OWNER = "0xde709f2102306220921060314715629080e2fb77"
IMPL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"

FULL = f"""
[meta]
chain_id = 1
label = "Vault V2 fee bypass"
poc = "test/VaultExploit.t.sol"
fork_block = 21000000
notes = "preconditions for the fee bypass"

[[param]]
name = "vault.owner"
address = "{VAULT}"
call = "owner()"
expect = "{OWNER}"

[[param]]
name = "vault.feeBps"
address = "{VAULT}"
call = "feeBps()"
returns = "uint256"
expect_lte = 50

[[param]]
name = "token balance"
address = "{OWNER}"
call = "balanceOf(address)"
args = ["{VAULT}"]
returns = "uint256"
expect_gte = "1000000000000000000"

[[param]]
name = "vault.slot0"
address = "{VAULT}"
storage = 0
expect = "0x0000000000000000000000000000000000000000000000000000000000000001"

[[param]]
name = "attacker funding"
address = "{OWNER}"
balance = true
expect_gte = "100000000000000000"

[[proxy]]
name = "vault proxy"
address = "{VAULT}"
implementation = "{IMPL}"
admin = "{OWNER}"
"""


def param(body: str) -> str:
    return f'[[param]]\nname = "x"\naddress = "{VAULT}"\n{body}\n'


# A minimal valid param, so [meta] error cases are isolated to [meta].
ANY_PARAM = param("balance = true\nexpect_gte = 1")


class TestHappyPath(unittest.TestCase):
    def setUp(self):
        self.manifest = parse_manifest(FULL)

    def test_meta(self):
        meta = self.manifest.meta
        self.assertEqual(meta.chain_id, 1)
        self.assertEqual(meta.label, "Vault V2 fee bypass")
        self.assertEqual(meta.poc, "test/VaultExploit.t.sol")
        self.assertEqual(meta.fork_block, 21000000)
        self.assertEqual(meta.notes, "preconditions for the fee bypass")

    def test_check_counts(self):
        self.assertEqual(len(self.manifest.params), 5)
        self.assertEqual(len(self.manifest.proxies), 1)
        self.assertEqual(self.manifest.check_count, 6)

    def test_addresses_are_normalized_for_comparison(self):
        self.assertEqual(self.manifest.params[0].address, VAULT.lower())

    def test_modes(self):
        self.assertEqual([p.mode for p in self.manifest.params],
                         ["call", "call", "call", "storage", "balance"])

    def test_call_arguments(self):
        self.assertEqual(self.manifest.params[2].args, (VAULT,))

    def test_storage_slot(self):
        self.assertEqual(self.manifest.params[3].slot, 0)

    def test_numeric_bounds_kept_as_written(self):
        self.assertEqual(self.manifest.params[1].expectation.expect_lte, 50)
        self.assertEqual(
            self.manifest.params[2].expectation.expect_gte, "1000000000000000000"
        )

    def test_proxy_entry(self):
        proxy = self.manifest.proxies[0]
        self.assertEqual(proxy.standard, "auto")
        self.assertEqual(proxy.implementation, IMPL.lower())
        self.assertEqual(proxy.admin, OWNER.lower())

    def test_target_descriptions(self):
        self.assertEqual(self.manifest.params[0].target, "owner()")
        self.assertEqual(self.manifest.params[3].target, "storage[0]")
        self.assertEqual(self.manifest.params[4].target, "balance")
        self.assertIn("balanceOf(", self.manifest.params[2].target)

    def test_expectation_descriptions(self):
        self.assertEqual(self.manifest.params[1].expectation.describe(), "<= 50")
        self.assertIn(">=", self.manifest.params[2].expectation.describe())

    def test_unset_is_falsy_and_distinct(self):
        self.assertFalse(UNSET)
        self.assertIs(self.manifest.params[1].expectation.expect, UNSET)


class TestFileLoading(unittest.TestCase):
    def test_round_trip_through_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.toml"
            path.write_text(FULL, encoding="utf-8")
            manifest = load_manifest(path)
            self.assertEqual(manifest.check_count, 6)
            self.assertEqual(manifest.path, path)

    def test_missing_file(self):
        with self.assertRaises(ManifestError) as ctx:
            load_manifest("/nonexistent/path/to/manifest.toml")
        self.assertIn("not found", str(ctx.exception))

    def test_scaffolded_manifest_parses(self):
        from fork_state_guard.scaffold import example_manifest

        manifest = parse_manifest(example_manifest())
        self.assertGreaterEqual(len(manifest.params), 5)
        self.assertEqual(len(manifest.proxies), 1)
        self.assertEqual(manifest.meta.chain_id, 1)


class TestErrorCases(unittest.TestCase):
    def assert_error(self, text: str, fragment: str):
        with self.assertRaises(ManifestError) as ctx:
            parse_manifest(text)
        self.assertIn(fragment, str(ctx.exception))

    def test_invalid_toml(self):
        self.assert_error("[meta\nchain_id = 1", "invalid TOML")

    def test_no_checks(self):
        self.assert_error("[meta]\nchain_id = 1\n", "no checks")

    def test_unknown_top_level_key(self):
        self.assert_error(f'[whatever]\nx = 1\n{param("expect = 1")}', "unknown key")

    def test_unknown_param_key(self):
        self.assert_error(param('call = "owner()"\nexpct = 1'), "unknown key")

    def test_unknown_meta_key(self):
        self.assert_error(
            f'[meta]\nchainid = 1\n{ANY_PARAM}',
            "unknown key",
        )

    def test_param_table_not_array(self):
        self.assert_error(f'[param]\nname = "x"\naddress = "{VAULT}"\n', "[[param]]")

    def test_missing_name(self):
        self.assert_error(f'[[param]]\naddress = "{VAULT}"\ncall = "owner()"\nexpect = 1',
                          "missing 'name'")

    def test_missing_address(self):
        self.assert_error('[[param]]\nname = "x"\ncall = "owner()"\nexpect = 1',
                          "missing 'address'")

    def test_bad_address(self):
        self.assert_error('[[param]]\nname = "x"\naddress = "0xdead"\ncall = "owner()"\nexpect = 1',
                          "20 bytes")

    def test_no_read_mode(self):
        self.assert_error(param("expect = 1"), "exactly one of")

    def test_several_read_modes(self):
        self.assert_error(param('call = "owner()"\nstorage = 0\nexpect = 1'),
                          "several read modes")

    def test_no_expectation(self):
        self.assert_error(param('call = "owner()"'), "declares no expectation")

    def test_expect_and_expect_one_of_together(self):
        self.assert_error(
            param(f'call = "owner()"\nexpect = "{OWNER}"\nexpect_one_of = ["{OWNER}"]'),
            "not both",
        )

    def test_empty_expect_one_of(self):
        self.assert_error(param('call = "owner()"\nexpect_one_of = []'), "must not be empty")

    def test_expect_one_of_not_an_array(self):
        self.assert_error(param('call = "owner()"\nexpect_one_of = "x"'), "must be an array")

    def test_bad_signature(self):
        self.assert_error(param('call = "owner"\nexpect = 1'), "malformed function signature")

    def test_unsupported_argument_type_in_signature(self):
        self.assert_error(param('call = "f(string)"\nargs = ["a"]\nexpect = 1'),
                          "not supported")

    def test_wrong_argument_count(self):
        self.assert_error(param('call = "balanceOf(address)"\nexpect = 1'),
                          "takes 1 argument")

    def test_args_not_an_array(self):
        self.assert_error(param('call = "balanceOf(address)"\nargs = "x"\nexpect = 1'),
                          "must be an array")

    def test_call_not_a_string(self):
        self.assert_error(param("call = 42\nexpect = 1"), "function signature string")

    def test_bad_storage_slot(self):
        self.assert_error(param('storage = "ten"\nexpect = 1'), "cannot read storage slot")

    def test_negative_storage_slot(self):
        self.assert_error(param("storage = -1\nexpect = 1"), "must not be negative")

    def test_storage_slot_as_hex_string(self):
        manifest = parse_manifest(param('storage = "0x10"\nexpect = 1'))
        self.assertEqual(manifest.params[0].slot, 16)

    def test_balance_must_be_true(self):
        self.assert_error(param("balance = false\nexpect_gte = 1"), "must be written as")

    def test_returns_on_balance_is_rejected(self):
        self.assert_error(
            param('balance = true\nreturns = "uint256"\nexpect_gte = 1'),
            "does not apply",
        )

    def test_returns_must_be_a_string(self):
        self.assert_error(param('call = "owner()"\nreturns = 1\nexpect = 1'),
                          "type name string")

    def test_allow_drift_must_be_a_justification(self):
        self.assert_error(param('call = "owner()"\nexpect = 1\nallow_drift = true'),
                          "not a bare true")

    def test_allow_drift_must_not_be_blank(self):
        self.assert_error(param('call = "owner()"\nexpect = 1\nallow_drift = "   "'),
                          "non-empty justification")

    def test_allow_drift_is_kept(self):
        manifest = parse_manifest(
            param('call = "owner()"\nexpect = 1\nallow_drift = "supply moves constantly"')
        )
        self.assertEqual(
            manifest.params[0].expectation.allow_drift, "supply moves constantly"
        )

    def test_non_numeric_bound(self):
        self.assert_error(param('call = "f()"\nexpect_gte = true'), "must be an integer")

    def test_duplicate_names(self):
        text = param('call = "owner()"\nexpect = 1') + param('call = "f()"\nexpect = 1')
        self.assert_error(text, "duplicate check name")

    def test_duplicate_names_across_param_and_proxy(self):
        text = (
            param('call = "owner()"\nexpect = 1')
            + f'[[proxy]]\nname = "X"\naddress = "{VAULT}"\nimplementation = "{IMPL}"\n'
        )
        self.assert_error(text, "duplicate check name")

    def test_bad_chain_id(self):
        self.assert_error(
            f'[meta]\nchain_id = "one"\n{ANY_PARAM}',
            "must be an integer",
        )

    def test_negative_fork_block(self):
        self.assert_error(
            f'[meta]\nfork_block = -5\n{ANY_PARAM}',
            "must not be negative",
        )

    def test_proxy_needs_an_expectation(self):
        self.assert_error(f'[[proxy]]\nname = "p"\naddress = "{VAULT}"\n',
                          "declare at least an expected 'implementation'")

    def test_proxy_unknown_standard(self):
        self.assert_error(
            f'[[proxy]]\nname = "p"\naddress = "{VAULT}"\nstandard = "eip9999"\n'
            f'implementation = "{IMPL}"\n',
            "unknown proxy standard",
        )

    def test_proxy_implementation_and_one_of_together(self):
        self.assert_error(
            f'[[proxy]]\nname = "p"\naddress = "{VAULT}"\nimplementation = "{IMPL}"\n'
            f'implementation_one_of = ["{IMPL}"]\n',
            "not both",
        )

    def test_proxy_bad_implementation_address(self):
        self.assert_error(
            f'[[proxy]]\nname = "p"\naddress = "{VAULT}"\nimplementation = "0x1"\n',
            "20 bytes",
        )

    def test_proxy_one_of_must_not_be_empty(self):
        self.assert_error(
            f'[[proxy]]\nname = "p"\naddress = "{VAULT}"\nimplementation_one_of = []\n',
            "must not be empty",
        )

    def test_proxy_one_of_parses(self):
        manifest = parse_manifest(
            f'[[proxy]]\nname = "p"\naddress = "{VAULT}"\n'
            f'implementation_one_of = ["{IMPL}", "{OWNER}"]\n'
        )
        self.assertEqual(
            manifest.proxies[0].implementation_one_of, (IMPL.lower(), OWNER.lower())
        )


if __name__ == "__main__":
    unittest.main()
