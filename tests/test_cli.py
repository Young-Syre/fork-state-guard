"""End-to-end CLI behaviour, including every documented exit code.

The HTTP transport is swapped for the fake one, so nothing here hits the
network.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fork_state_guard import cli, exitcodes
from fork_state_guard.abi import encode_call
from fork_state_guard.manifest import parse_manifest
from fork_state_guard.proxy import EIP1967_IMPLEMENTATION
from fork_state_guard.rpc import RpcTransportError, redact_url

from .fake_rpc import FakeTransport, RpcErrorSpec, addr_word, word

VAULT = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
OWNER = "0xde709f2102306220921060314715629080e2fb77"
OTHER = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb"

MANIFEST = f"""
[meta]
chain_id = 1
label = "CLI test"

[[param]]
name = "vault.owner"
address = "{VAULT}"
call = "owner()"
expect = "{OWNER}"
"""


def owner_key(value: str) -> dict:
    return {(VAULT, "0x" + encode_call("owner()").hex()): addr_word(value)}


@contextlib.contextmanager
def run_cli(argv, transport=None, env=None):
    """Run the CLI with a fake transport; yields (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.dict(
            "os.environ",
            {"FORK_STATE_GUARD_RPC": "https://rpc.test"} if env is None else env,
            clear=True,
        ),
    ]
    if transport is not None:
        patches.append(mock.patch.object(cli, "HttpTransport", lambda *a, **k: transport))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        code = cli.main(argv)
    yield code, out.getvalue(), err.getvalue()


class TestInit(unittest.TestCase):
    def test_writes_a_manifest_that_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.toml"
            with run_cli(["init", str(path)]) as (code, out, _):
                self.assertEqual(code, exitcodes.OK)
            self.assertTrue(path.exists())
            manifest = parse_manifest(path.read_bytes())
            self.assertGreater(manifest.check_count, 1)

    def test_tells_the_user_what_to_do_next(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.toml"
            with run_cli(["init", str(path)]) as (_, out, _):
                self.assertIn("check", out)
                self.assertIn(str(path), out)

    def test_refuses_to_clobber_an_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.toml"
            path.write_text("# mine\n")
            with run_cli(["init", str(path)]) as (code, _, err):
                self.assertEqual(code, exitcodes.USAGE)
                self.assertIn("already exists", err)
            self.assertEqual(path.read_text(), "# mine\n")

    def test_force_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.toml"
            path.write_text("# mine\n")
            with run_cli(["init", str(path), "--force"]) as (code, _, _):
                self.assertEqual(code, exitcodes.OK)
            self.assertIn("[meta]", path.read_text())

    def test_dash_writes_to_stdout(self):
        with run_cli(["init", "-"]) as (code, out, _):
            self.assertEqual(code, exitcodes.OK)
            self.assertIn("[[proxy]]", out)

    def test_the_scaffold_documents_every_mode(self):
        with run_cli(["init", "-"]) as (_, out, _):
            for fragment in ("call =", "storage =", "balance =", "expect_one_of",
                             "expect_gte", "expect_lte", "allow_drift", "implementation"):
                self.assertIn(fragment, out)


class TestSlots(unittest.TestCase):
    def test_prints_the_published_eip1967_slot(self):
        with run_cli(["slots"]) as (code, out, _):
            self.assertEqual(code, exitcodes.OK)
            self.assertIn(EIP1967_IMPLEMENTATION.hex, out)
            self.assertIn("keccak256('eip1967.proxy.implementation') - 1", out)


class TestCheckExitCodes(unittest.TestCase):
    def manifest_file(self, stack, text=MANIFEST) -> str:
        tmp = stack.enter_context(tempfile.TemporaryDirectory())
        path = Path(tmp) / "m.toml"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_zero_when_everything_holds(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OWNER))
            with run_cli(["check", path], transport) as (code, out, _):
                self.assertEqual(code, exitcodes.OK)
                self.assertIn("PASS", out)
                self.assertIn("VERIFIED", out)

    def test_one_on_drift(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OTHER))
            with run_cli(["check", path], transport) as (code, out, _):
                self.assertEqual(code, exitcodes.DRIFT)
                self.assertIn("DRIFT", out)

    def test_two_when_the_endpoint_is_unreachable(self):
        class Dead:
            safe_url = "https://dead.invalid"

            def send(self, payload):
                raise RpcTransportError("cannot reach https://dead.invalid: timed out")

        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            with run_cli(["check", path], Dead()) as (code, _, err):
                self.assertEqual(code, exitcodes.RPC_UNREACHABLE)
                self.assertIn("RPC unreachable", err)
                # The distinction matters: an outage is not a verdict.
                self.assertIn("nothing was verified", err)

    def test_three_on_an_invalid_manifest(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack, "[[param]]\nname = 1\n")
            with run_cli(["check", path], FakeTransport()) as (code, _, err):
                self.assertEqual(code, exitcodes.MANIFEST_ERROR)
                self.assertIn("param", err)

    def test_three_on_a_missing_manifest(self):
        with run_cli(["check", "/no/such/manifest.toml"], FakeTransport()) as (code, _, err):
            self.assertEqual(code, exitcodes.MANIFEST_ERROR)
            self.assertIn("not found", err)

    def test_three_on_a_chain_id_mismatch(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(chain_id=137, calls=owner_key(OWNER))
            with run_cli(["check", path], transport) as (code, _, err):
                self.assertEqual(code, exitcodes.MANIFEST_ERROR)
                self.assertIn("wrong chain", err)

    def test_chain_mismatch_can_be_overridden(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(chain_id=137, calls=owner_key(OWNER))
            with run_cli(["check", path, "--ignore-chain-id"], transport) as (code, _, _):
                self.assertEqual(code, exitcodes.OK)

    def test_four_when_a_check_cannot_be_evaluated(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(
                calls={(VAULT, "0x" + encode_call("owner()").hex()): RpcErrorSpec("execution reverted")}
            )
            with run_cli(["check", path], transport) as (code, out, _):
                self.assertEqual(code, exitcodes.CHECK_ERROR)
                self.assertIn("ERROR", out)

    def test_an_error_outranks_a_drift(self):
        text = MANIFEST + f"""
[[param]]
name = "fee"
address = "{VAULT}"
call = "feeBps()"
returns = "uint256"
expect_lte = 1
"""
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack, text)
            calls = owner_key(OTHER)  # drift
            calls[(VAULT, "0x" + encode_call("feeBps()").hex())] = RpcErrorSpec("reverted")
            with run_cli(["check", path], FakeTransport(calls=calls)) as (code, _, _):
                self.assertEqual(code, exitcodes.CHECK_ERROR)

    def test_sixtyfour_without_an_rpc_endpoint(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            with run_cli(["check", path], None, env={}) as (code, _, err):
                self.assertEqual(code, exitcodes.USAGE)
                self.assertIn("no RPC endpoint", err)

    def test_sixtyfour_on_bad_usage(self):
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["check"])  # missing the manifest argument
        self.assertEqual(ctx.exception.code, exitcodes.USAGE)

    def test_no_command_prints_help(self):
        with run_cli([]) as (code, out, _):
            self.assertEqual(code, exitcodes.USAGE)
            self.assertIn("usage", out)

    def test_help_documents_every_exit_code(self):
        with run_cli([]) as (_, out, _):
            for code in (0, 1, 2, 3, 4, 64):
                self.assertIn(str(code), out)


class TestEndpointResolution(unittest.TestCase):
    def manifest_file(self, stack) -> str:
        tmp = stack.enter_context(tempfile.TemporaryDirectory())
        path = Path(tmp) / "m.toml"
        path.write_text(MANIFEST, encoding="utf-8")
        return str(path)

    def test_eth_rpc_url_is_honoured(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OWNER))
            with run_cli(["check", path], transport, env={"ETH_RPC_URL": "https://rpc.test"}) as (code, _, _):
                self.assertEqual(code, exitcodes.OK)

    def test_the_flag_wins_over_the_environment(self):
        seen = {}

        def record(url, **kwargs):
            seen["url"] = url
            return FakeTransport(calls=owner_key(OWNER))

        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            stack.enter_context(mock.patch.object(cli, "HttpTransport", record))
            stack.enter_context(
                mock.patch.dict("os.environ", {"FORK_STATE_GUARD_RPC": "https://from-env"}, clear=True)
            )
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            cli.main(["check", path, "--rpc", "https://from-flag"])
        self.assertEqual(seen["url"], "https://from-flag")

    def test_the_key_is_never_echoed_into_the_report(self):
        """A provider URL usually embeds an API key, and the report is meant
        to be pasted into a vulnerability write-up. Only scheme and host may
        reach the output."""

        def redacting_transport(url, **kwargs):
            transport = FakeTransport(calls=owner_key(OWNER))
            transport.safe_url = redact_url(url)
            return transport

        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            stack.enter_context(mock.patch.object(cli, "HttpTransport", redacting_transport))
            stack.enter_context(
                mock.patch.dict("os.environ", {}, clear=True)
            )
            out = io.StringIO()
            stack.enter_context(contextlib.redirect_stdout(out))
            code = cli.main(["check", path, "--rpc", "https://rpc.example/v2/SUPERSECRET"])
        self.assertEqual(code, exitcodes.OK)
        self.assertNotIn("SUPERSECRET", out.getvalue())
        self.assertIn("https://rpc.example/...", out.getvalue())


class TestOutputFormats(unittest.TestCase):
    def manifest_file(self, stack) -> str:
        tmp = stack.enter_context(tempfile.TemporaryDirectory())
        path = Path(tmp) / "m.toml"
        path.write_text(MANIFEST, encoding="utf-8")
        return str(path)

    def test_json_output_parses_and_carries_the_exit_code(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OTHER))
            with run_cli(["check", path, "--format", "json"], transport) as (code, out, _):
                data = json.loads(out)
                self.assertEqual(code, exitcodes.DRIFT)
                self.assertEqual(data["exit_code"], exitcodes.DRIFT)
                self.assertEqual(data["verdict"], "drift")

    def test_markdown_output_is_a_paste_ready_block(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OWNER))
            with run_cli(["check", path, "--format", "markdown"], transport) as (code, out, _):
                self.assertEqual(code, exitcodes.OK)
                self.assertIn("### Live state verification", out)
                self.assertIn("| Check |", out)

    def test_output_file(self):
        with contextlib.ExitStack() as stack:
            tmp = stack.enter_context(tempfile.TemporaryDirectory())
            path = Path(tmp) / "m.toml"
            path.write_text(MANIFEST, encoding="utf-8")
            target = Path(tmp) / "evidence.md"
            transport = FakeTransport(calls=owner_key(OWNER))
            with run_cli(
                ["check", str(path), "--format", "markdown", "-o", str(target)], transport
            ) as (code, out, _):
                self.assertEqual(code, exitcodes.OK)
                self.assertIn("wrote", out)
            self.assertIn("### Live state verification", target.read_text())

    def test_colour_is_off_when_not_a_tty(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OTHER))
            with run_cli(["check", path], transport) as (_, out, _):
                self.assertNotIn("\033[", out)

    def test_explicit_block_is_reported(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OWNER))
            with run_cli(["check", path, "--block", "20000000"], transport) as (code, out, _):
                self.assertEqual(code, exitcodes.OK)
                self.assertIn("20000000", out)

    def test_unparseable_block_is_a_usage_error(self):
        with contextlib.ExitStack() as stack:
            path = self.manifest_file(stack)
            transport = FakeTransport(calls=owner_key(OWNER))
            with run_cli(["check", path, "--block", "soon"], transport) as (code, _, err):
                self.assertEqual(code, exitcodes.USAGE)
                self.assertIn("--block", err)


if __name__ == "__main__":
    unittest.main()
