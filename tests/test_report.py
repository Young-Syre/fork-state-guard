"""Report rendering in all three formats."""

from __future__ import annotations

import json
import re
import unittest

from fork_state_guard.report import format_json, format_markdown, format_text, render_report
from fork_state_guard.verify import CheckResult, Report, Status

VAULT = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
IMPL_V1 = "0x27b1fdb04752bbc536007a920d24acb045561c26"
IMPL_V2 = "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb"


def sample_report(*statuses: str) -> Report:
    report = Report(
        label="Vault V2 fee bypass",
        manifest_path="examples/vault.toml",
        endpoint="https://rpc.example/...",
        chain_id=1,
        declared_chain_id=1,
        block_number=21_000_000,
        block_timestamp=1_727_740_800,
        checked_at=1_727_827_200,
        fork_block=20_999_000,
        poc="test/VaultExploit.t.sol",
    )
    for index, status in enumerate(statuses or (Status.PASS,)):
        report.results.append(
            CheckResult(
                name=f"check{index}",
                kind="param",
                address=VAULT,
                target="owner()",
                status=status,
                expected=IMPL_V1,
                actual=IMPL_V1 if status == Status.PASS else IMPL_V2,
                value_type="address",
                detail="the proxy has been upgraded" if status == Status.DRIFT else "",
                justification="known and harmless" if status == Status.DRIFT_ALLOWED else None,
            )
        )
    return report


class TestTextReport(unittest.TestCase):
    def test_includes_the_block_number(self):
        text = format_text(sample_report())
        self.assertIn("21000000", text)

    def test_includes_the_block_time_in_utc(self):
        self.assertIn("2024-10-01T00:00:00Z", format_text(sample_report()))

    def test_includes_the_endpoint_and_chain(self):
        text = format_text(sample_report())
        self.assertIn("https://rpc.example/...", text)
        self.assertIn("chain id", text)

    def test_reports_blocks_since_fork(self):
        self.assertIn("1000 blocks before this check", format_text(sample_report()))

    def test_verified_verdict(self):
        self.assertIn("VERIFIED", format_text(sample_report(Status.PASS)))

    def test_drift_verdict(self):
        text = format_text(sample_report(Status.DRIFT))
        self.assertIn("DRIFT", text)
        self.assertNotIn("VERIFIED", text)

    def test_error_verdict_is_incomplete_not_verified(self):
        self.assertIn("INCOMPLETE", format_text(sample_report(Status.ERROR)))

    def test_waived_drift_still_verifies(self):
        self.assertIn("VERIFIED", format_text(sample_report(Status.DRIFT_ALLOWED)))

    def test_details_section_shows_expected_and_observed(self):
        text = format_text(sample_report(Status.DRIFT))
        self.assertIn("expected", text)
        self.assertIn("observed", text)
        self.assertIn("the proxy has been upgraded", text)

    def test_passing_checks_need_no_details_section(self):
        self.assertNotIn("Details", format_text(sample_report(Status.PASS)))

    def test_justification_is_printed(self):
        self.assertIn("known and harmless", format_text(sample_report(Status.DRIFT_ALLOWED)))

    def test_table_columns_are_aligned(self):
        text = format_text(sample_report(Status.PASS, Status.DRIFT))
        # Table rows only: the details section mentions the same check names.
        rows = [
            line
            for line in text.splitlines()
            if re.match(r"^  (PASS|DRIFT)\s", line) and "check" in line
        ]
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({len(row.rstrip()) for row in rows}), 1)
        # Every cell starts at the same column.
        self.assertEqual(
            len({row.index("check") for row in rows}), 1
        )

    def test_counts_line(self):
        text = format_text(sample_report(Status.PASS, Status.PASS, Status.DRIFT))
        self.assertIn("3 check(s)", text)
        self.assertIn("PASS: 2", text)
        self.assertIn("DRIFT: 1", text)

    def test_no_ansi_codes_unless_colour_requested(self):
        self.assertNotIn("\033[", format_text(sample_report(Status.DRIFT)))

    def test_colour_wraps_rows_when_requested(self):
        self.assertIn("\033[", format_text(sample_report(Status.DRIFT), color=True))


class TestJsonReport(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(format_json(sample_report(Status.PASS, Status.DRIFT), exit_code=1))

    def test_is_valid_json_with_the_expected_shape(self):
        self.assertEqual(self.data["tool"], "fork-state-guard")
        self.assertEqual(len(self.data["checks"]), 2)

    def test_block_fields(self):
        self.assertEqual(self.data["block_number"], 21_000_000)
        self.assertEqual(self.data["block_timestamp"], 1_727_740_800)
        self.assertEqual(self.data["block_time_utc"], "2024-10-01T00:00:00Z")

    def test_verdict_and_verified_flag(self):
        self.assertEqual(self.data["verdict"], "drift")
        self.assertFalse(self.data["verified"])

    def test_counts(self):
        self.assertEqual(self.data["counts"]["PASS"], 1)
        self.assertEqual(self.data["counts"]["DRIFT"], 1)

    def test_exit_code_is_embedded_when_given(self):
        self.assertEqual(self.data["exit_code"], 1)

    def test_blocks_since_fork(self):
        self.assertEqual(self.data["blocks_since_fork"], 1000)

    def test_check_rows_carry_status_and_values(self):
        row = self.data["checks"][1]
        self.assertEqual(row["status"], "DRIFT")
        self.assertIn("detail", row)

    def test_addresses_are_checksummed(self):
        self.assertEqual(
            self.data["checks"][0]["address"], "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        )


class TestMarkdownReport(unittest.TestCase):
    def test_has_a_heading_and_a_table(self):
        text = format_markdown(sample_report(Status.PASS))
        self.assertIn("### Live state verification", text)
        self.assertIn("| Check | Read | Expected | Observed | Status |", text)

    def test_states_the_block_and_the_time_it_was_checked(self):
        text = format_markdown(sample_report())
        self.assertIn("block 21000000", text)
        self.assertIn("2024-10-01T00:00:00Z", text)
        self.assertIn("2024-10-02T00:00:00Z", text)  # checked_at

    def test_states_the_chain_id(self):
        self.assertIn("chain id 1", format_markdown(sample_report()))

    def test_mentions_the_poc_and_fork_block(self):
        text = format_markdown(sample_report())
        self.assertIn("test/VaultExploit.t.sol", text)
        self.assertIn("forks at block 20999000", text)

    def test_drift_is_bolded_so_it_cannot_be_skimmed_past(self):
        self.assertIn("**DRIFT**", format_markdown(sample_report(Status.DRIFT)))

    def test_one_row_per_check(self):
        text = format_markdown(sample_report(Status.PASS, Status.PASS, Status.DRIFT))
        rows = [line for line in text.splitlines() if line.startswith("| check")]
        self.assertEqual(len(rows), 3)

    def test_accepted_drift_is_listed_with_its_justification(self):
        text = format_markdown(sample_report(Status.DRIFT_ALLOWED))
        self.assertIn("Accepted drift", text)
        self.assertIn("known and harmless", text)

    def test_states_that_the_tool_is_read_only(self):
        text = format_markdown(sample_report())
        self.assertIn("read-only", text)
        self.assertIn("no keys", text)

    def test_names_the_rpc_methods_used_as_evidence(self):
        text = format_markdown(sample_report())
        for method in ("eth_call", "eth_getStorageAt", "eth_getBalance", "eth_getCode"):
            self.assertIn(method, text)

    def test_pipes_in_values_are_escaped(self):
        report = sample_report()
        report.results[0].name = "weird | name"
        self.assertIn("weird \\| name", format_markdown(report))


class TestRenderDispatch(unittest.TestCase):
    def test_each_format(self):
        report = sample_report()
        self.assertIn("fork-state-guard", render_report(report, "text"))
        self.assertIn('"tool"', render_report(report, "json"))
        self.assertIn("###", render_report(report, "markdown"))

    def test_unknown_format(self):
        with self.assertRaises(ValueError):
            render_report(sample_report(), "yaml")


class TestEmptyEdgeCases(unittest.TestCase):
    def test_a_report_with_an_unknown_timestamp_renders(self):
        report = sample_report()
        report.block_timestamp = None
        self.assertIn("unknown", format_text(report))

    def test_a_report_without_a_label_renders(self):
        report = sample_report()
        report.label = ""
        self.assertIn("fork-state-guard", format_text(report))


if __name__ == "__main__":
    unittest.main()
