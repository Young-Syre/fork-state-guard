"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, exitcodes
from .manifest import ManifestError, load_manifest
from .proxy import describe_slots
from .report import render_report
from .rpc import DEFAULT_BACKOFF, DEFAULT_RETRIES, DEFAULT_TIMEOUT, HttpTransport, RpcClient, RpcTransportError
from .scaffold import example_manifest
from .verify import ChainMismatch, Report, verify

__all__ = ["main", "build_parser"]

PROG = "fork-state-guard"

RPC_ENV_VARS = ("FORK_STATE_GUARD_RPC", "ETH_RPC_URL")

EPILOG = f"""exit codes:
  {exitcodes.OK}   {exitcodes.DESCRIPTIONS[exitcodes.OK]}
  {exitcodes.DRIFT}   {exitcodes.DESCRIPTIONS[exitcodes.DRIFT]}
  {exitcodes.RPC_UNREACHABLE}   {exitcodes.DESCRIPTIONS[exitcodes.RPC_UNREACHABLE]}
  {exitcodes.MANIFEST_ERROR}   {exitcodes.DESCRIPTIONS[exitcodes.MANIFEST_ERROR]}
  {exitcodes.CHECK_ERROR}   {exitcodes.DESCRIPTIONS[exitcodes.CHECK_ERROR]}
  {exitcodes.USAGE}  {exitcodes.DESCRIPTIONS[exitcodes.USAGE]}

The RPC endpoint comes from --rpc, else ${RPC_ENV_VARS[0]}, else ${RPC_ENV_VARS[1]}.
This tool is read-only: it never signs or sends anything.
"""


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that exits with 64 on usage errors, so the usage code
    cannot be confused with 2 (RPC unreachable)."""

    def error(self, message: str):  # noqa: D102
        self.print_usage(sys.stderr)
        self.exit(exitcodes.USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description=(
            "Verify that the on-chain assumptions a PoC depends on still hold "
            "against live chain state."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    check = subparsers.add_parser(
        "check",
        help="verify a manifest against live chain state",
        description="Verify a manifest against live chain state.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check.add_argument("manifest", help="path to the TOML manifest")
    check.add_argument(
        "--rpc",
        metavar="URL",
        help=f"JSON-RPC endpoint (default: ${RPC_ENV_VARS[0]} or ${RPC_ENV_VARS[1]})",
    )
    check.add_argument(
        "--block",
        default="latest",
        metavar="N",
        help="block number to read at, or 'latest' (default: latest)",
    )
    check.add_argument(
        "--format",
        dest="fmt",
        choices=("text", "json", "markdown"),
        default="text",
        help="output format (default: text)",
    )
    check.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to a file instead of stdout",
    )
    check.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per-request timeout (default: {DEFAULT_TIMEOUT:g})",
    )
    check.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        metavar="N",
        help=f"attempts per request before giving up (default: {DEFAULT_RETRIES})",
    )
    check.add_argument(
        "--backoff",
        type=float,
        default=DEFAULT_BACKOFF,
        metavar="SECONDS",
        help=f"base delay for exponential backoff (default: {DEFAULT_BACKOFF:g})",
    )
    check.add_argument(
        "--ignore-chain-id",
        action="store_true",
        help="do not abort when the endpoint's chain id differs from the manifest's",
    )
    check.add_argument(
        "--no-color", action="store_true", help="never colorize the text report"
    )

    init = subparsers.add_parser(
        "init",
        help="write a commented example manifest",
        description="Write a commented example manifest to get started.",
    )
    init.add_argument(
        "path",
        nargs="?",
        default="fork-state-guard.toml",
        help="where to write it (default: fork-state-guard.toml; '-' for stdout)",
    )
    init.add_argument(
        "-f", "--force", action="store_true", help="overwrite an existing file"
    )

    subparsers.add_parser(
        "slots",
        help="print the proxy storage slots this tool reads",
        description=(
            "Print the well-known proxy storage slots and how each is derived. "
            "Every value is computed from keccak256 at runtime, not pasted in."
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return exitcodes.USAGE
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "slots":
        return _cmd_slots()
    return _cmd_check(args)


def _cmd_init(args: argparse.Namespace) -> int:
    text = example_manifest()
    if args.path == "-":
        sys.stdout.write(text)
        return exitcodes.OK

    path = Path(args.path)
    if path.exists() and not args.force:
        print(
            f"{PROG}: {path} already exists (pass --force to overwrite)",
            file=sys.stderr,
        )
        return exitcodes.USAGE
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        print(f"{PROG}: cannot write {path}: {exc}", file=sys.stderr)
        return exitcodes.USAGE
    print(f"wrote {path}")
    print(f"edit it, then run: {PROG} check {path} --rpc <endpoint>")
    return exitcodes.OK


def _cmd_slots() -> int:
    rows = describe_slots()
    headers = ("STANDARD", "ROLE", "DERIVATION", "SLOT")
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))
    ]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip())
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip())
    return exitcodes.OK


def _resolve_rpc(args: argparse.Namespace) -> str | None:
    if args.rpc:
        return args.rpc
    for name in RPC_ENV_VARS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return exitcodes.MANIFEST_ERROR

    rpc_url = _resolve_rpc(args)
    if not rpc_url:
        print(
            f"{PROG}: no RPC endpoint; pass --rpc URL or set "
            f"${RPC_ENV_VARS[0]} / ${RPC_ENV_VARS[1]}",
            file=sys.stderr,
        )
        return exitcodes.USAGE

    try:
        transport = HttpTransport(
            rpc_url,
            timeout=args.timeout,
            retries=args.retries,
            backoff=args.backoff,
        )
    except RpcTransportError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return exitcodes.USAGE

    client = RpcClient(transport)

    try:
        report = verify(
            manifest,
            client,
            block=args.block,
            ignore_chain_id=args.ignore_chain_id,
        )
    except ChainMismatch as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return exitcodes.MANIFEST_ERROR
    except RpcTransportError as exc:
        print(f"{PROG}: RPC unreachable: {exc}", file=sys.stderr)
        print(
            f"{PROG}: nothing was verified -- this is not a statement about "
            f"chain state",
            file=sys.stderr,
        )
        return exitcodes.RPC_UNREACHABLE
    except ValueError as exc:  # e.g. an unparseable --block
        print(f"{PROG}: {exc}", file=sys.stderr)
        return exitcodes.USAGE

    code = exit_code_for(report)
    color = _use_color(args)
    text = render_report(report, args.fmt, color=color, exit_code=code)

    if args.output:
        try:
            Path(args.output).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"{PROG}: cannot write {args.output}: {exc}", file=sys.stderr)
            return exitcodes.USAGE
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)

    return code


def exit_code_for(report: Report) -> int:
    """Map a report to its exit code.

    An unevaluable check outranks drift: "I could not tell" is a worse place
    to be than "I know this moved", because only the first one can be
    mistaken for a clean run by a careless reader.
    """
    if report.errored:
        return exitcodes.CHECK_ERROR
    if report.drifted:
        return exitcodes.DRIFT
    return exitcodes.OK


def _use_color(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False) or args.fmt != "text":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if args.output:
        return False
    return sys.stdout.isatty()


def run() -> None:
    """Console-script entry point."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    run()
