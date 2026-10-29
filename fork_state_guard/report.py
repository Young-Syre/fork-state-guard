"""Report rendering: aligned text, JSON, and a paste-ready markdown block."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .verify import CheckResult, Report, Status

__all__ = ["format_text", "format_json", "format_markdown", "render_report", "VERDICTS"]

TOOL_NAME = "fork-state-guard"
TOOL_URL = "https://github.com/Young-Syre/fork-state-guard"

VERDICTS = {
    "verified": "VERIFIED -- every declared assumption still holds at this block.",
    "drift": "DRIFT -- at least one declared assumption no longer holds. "
    "The PoC's preconditions have changed.",
    "error": "INCOMPLETE -- at least one assumption could not be evaluated.",
}


def _iso(timestamp: int | None) -> str:
    if timestamp is None:
        return "unknown"
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verdict_key(report: Report) -> str:
    if report.errored:
        return "error"
    if report.drifted:
        return "drift"
    return "verified"


def _header_rows(report: Report) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if report.manifest_path:
        rows.append(("manifest", report.manifest_path))
    rows.append(("endpoint", report.endpoint or "unknown"))
    chain = str(report.chain_id) if report.chain_id is not None else "unreported"
    if report.declared_chain_id is not None:
        chain += f" (manifest declares {report.declared_chain_id})"
    rows.append(("chain id", chain))
    rows.append(("block", f"{report.block_number}  ({_iso(report.block_timestamp)})"))
    if report.fork_block is not None:
        delta = report.blocks_since_fork
        rows.append(
            ("poc fork block", f"{report.fork_block}  ({delta} blocks before this check)")
        )
    if report.poc:
        rows.append(("poc", report.poc))
    rows.append(("checked at", _iso(report.checked_at)))
    return rows


# --------------------------------------------------------------------------
# text
# --------------------------------------------------------------------------


def format_text(report: Report, *, color: bool = False) -> str:
    """Aligned plain-text report."""
    paint = _painter(color)
    lines: list[str] = []

    title = f"{TOOL_NAME}"
    if report.label:
        title += f"  --  {report.label}"
    lines.append(title)
    lines.append("=" * len(title))
    lines.append("")

    header = _header_rows(report)
    width = max(len(key) for key, _ in header)
    for key, value in header:
        lines.append(f"  {key.ljust(width)}   {value}")
    if report.notes:
        lines.append("")
        lines.append(f"  note: {report.notes}")
    lines.append("")

    if report.results:
        columns = [
            ("STATUS", [r.status for r in report.results]),
            ("CHECK", [r.name for r in report.results]),
            ("TARGET", [r.target for r in report.results]),
            ("OBSERVED", [r.actual for r in report.results]),
        ]
        widths = [max(len(title), *(len(v) for v in values)) for title, values in columns]
        lines.append(
            "  "
            + "  ".join(title.ljust(w) for (title, _), w in zip(columns, widths)).rstrip()
        )
        lines.append("  " + "  ".join("-" * w for w in widths))
        for result in report.results:
            cells = [result.status, result.name, result.target, result.actual]
            row = "  ".join(cell.ljust(w) for cell, w in zip(cells, widths)).rstrip()
            lines.append("  " + paint(result.status, row))
        lines.append("")

    problems = [r for r in report.results if r.status != Status.PASS]
    if problems:
        lines.append("  Details")
        lines.append("  " + "-" * 7)
        for result in problems:
            lines.append(f"  [{result.status}] {result.name}  ({result.target})")
            lines.append(f"      expected  {result.expected}")
            lines.append(f"      observed  {result.actual}")
            if result.detail:
                lines.append(f"      {_wrap_detail(result.detail)}")
            if result.justification:
                lines.append(f"      allow_drift: {result.justification}")
            if result.note:
                lines.append(f"      note: {result.note}")
            lines.append("")

    counts = report.counts
    summary = "  ".join(
        f"{status}: {counts[status]}" for status in Status.ALL if counts[status]
    )
    lines.append(f"  {len(report.results)} check(s) at block {report.block_number}   {summary}")
    lines.append("")
    verdict = VERDICTS[_verdict_key(report)]
    lines.append("  " + paint(
        Status.PASS if report.verified else Status.DRIFT, verdict
    ))
    return "\n".join(lines) + "\n"


def _wrap_detail(detail: str, width: int = 86) -> str:
    """Soft-wrap a detail message, indenting continuation lines."""
    words = detail.split()
    out: list[str] = []
    line = ""
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return ("\n      ").join(out)


_COLORS = {
    Status.PASS: "\033[32m",
    Status.DRIFT: "\033[31m",
    Status.DRIFT_ALLOWED: "\033[33m",
    Status.ERROR: "\033[35m",
}


def _painter(color: bool):
    if not color:
        return lambda status, text: text

    def paint(status: str, text: str) -> str:
        code = _COLORS.get(status)
        return f"{code}{text}\033[0m" if code else text

    return paint


# --------------------------------------------------------------------------
# json
# --------------------------------------------------------------------------


def report_to_dict(report: Report, *, exit_code: int | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "tool": TOOL_NAME,
        "label": report.label,
        "manifest": report.manifest_path,
        "endpoint": report.endpoint,
        "chain_id": report.chain_id,
        "declared_chain_id": report.declared_chain_id,
        "block_number": report.block_number,
        "block_timestamp": report.block_timestamp,
        "block_time_utc": _iso(report.block_timestamp),
        "checked_at": report.checked_at,
        "checked_at_utc": _iso(report.checked_at),
        "poc": report.poc,
        "fork_block": report.fork_block,
        "blocks_since_fork": report.blocks_since_fork,
        "notes": report.notes,
        "verified": report.verified,
        "verdict": _verdict_key(report),
        "counts": report.counts,
        "checks": [result.as_dict() for result in report.results],
    }
    if exit_code is not None:
        data["exit_code"] = exit_code
    return data


def format_json(report: Report, *, exit_code: int | None = None) -> str:
    return json.dumps(report_to_dict(report, exit_code=exit_code), indent=2) + "\n"


# --------------------------------------------------------------------------
# markdown
# --------------------------------------------------------------------------


def format_markdown(report: Report) -> str:
    """A block to paste into a vulnerability report as evidence that the
    PoC's on-chain preconditions were verified against live state."""
    lines: list[str] = []
    title = report.label or "on-chain preconditions"
    lines.append(f"### Live state verification -- {title}")
    lines.append("")

    chain = str(report.chain_id) if report.chain_id is not None else "unreported"
    lines.append(
        f"Verified at **block {report.block_number}** "
        f"({_iso(report.block_timestamp)}) on **chain id {chain}**, "
        f"checked {_iso(report.checked_at)}."
    )
    if report.fork_block is not None:
        lines.append("")
        lines.append(
            f"The PoC forks at block {report.fork_block}, "
            f"{report.blocks_since_fork} blocks before this check."
        )
    if report.poc:
        lines.append("")
        lines.append(f"PoC: `{report.poc}`")
    lines.append("")

    lines.append("| Check | Read | Expected | Observed | Status |")
    lines.append("| --- | --- | --- | --- | --- |")
    for result in report.results:
        lines.append(
            "| {name} | `{target}` | {expected} | {actual} | {status} |".format(
                name=_md(result.name),
                target=result.target,
                expected=_md_value(result.expected),
                actual=_md_value(result.actual),
                status=_md_status(result),
            )
        )
    lines.append("")

    for result in report.results:
        if result.status == Status.DRIFT_ALLOWED and result.justification:
            lines.append(
                f"- Accepted drift in **{_md(result.name)}**: {_md(result.justification)}"
            )
    if any(r.status == Status.DRIFT_ALLOWED for r in report.results):
        lines.append("")

    lines.append(f"**{VERDICTS[_verdict_key(report)]}**")
    lines.append("")
    lines.append(
        f"<sub>Generated by [{TOOL_NAME}]({TOOL_URL}) -- read-only JSON-RPC state "
        f"verification. The tool holds no keys and sends no transactions; every "
        f"value above was read with `eth_call`, `eth_getStorageAt`, "
        f"`eth_getBalance` and `eth_getCode` at the stated block.</sub>"
    )
    return "\n".join(lines) + "\n"


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def _md_value(text: str) -> str:
    cleaned = _md(text)
    if cleaned in ("-", ""):
        return "-"
    return f"`{cleaned}`" if " " not in cleaned else cleaned


_MD_STATUS = {
    Status.PASS: "PASS",
    Status.DRIFT: "**DRIFT**",
    Status.DRIFT_ALLOWED: "DRIFT (accepted)",
    Status.ERROR: "**ERROR**",
}


def _md_status(result: CheckResult) -> str:
    return _MD_STATUS.get(result.status, result.status)


def render_report(report: Report, fmt: str, *, color: bool = False, exit_code: int | None = None) -> str:
    """Render ``report`` in the requested format."""
    if fmt == "text":
        return format_text(report, color=color)
    if fmt == "json":
        return format_json(report, exit_code=exit_code)
    if fmt == "markdown":
        return format_markdown(report)
    raise ValueError(f"unknown format {fmt!r}; choose from: text, json, markdown")
