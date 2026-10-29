"""fork-state-guard -- verify a PoC's on-chain assumptions against live state.

A smart-contract PoC is written against a forked chain state and then rots.
This package declares those assumptions in a manifest and checks every one of
them against a live JSON-RPC endpoint, so a report never ships claiming a
precondition that production no longer has.

Strictly read-only: it holds no keys, builds no transactions, and only ever
issues eth_chainId, eth_blockNumber, eth_getBlockByNumber, eth_call,
eth_getStorageAt, eth_getBalance and eth_getCode.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .abi import decode_single, encode_call, function_selector
from .address import to_checksum_address
from .keccak import keccak256, keccak256_hex
from .manifest import Manifest, ManifestError, load_manifest, parse_manifest
from .report import format_json, format_markdown, format_text
from .rpc import HttpTransport, RpcClient, RpcResponseError, RpcTransportError
from .verify import ChainMismatch, CheckResult, Report, Status, verify

__all__ = [
    "__version__",
    "keccak256",
    "keccak256_hex",
    "function_selector",
    "encode_call",
    "decode_single",
    "to_checksum_address",
    "Manifest",
    "ManifestError",
    "load_manifest",
    "parse_manifest",
    "HttpTransport",
    "RpcClient",
    "RpcTransportError",
    "RpcResponseError",
    "verify",
    "Report",
    "CheckResult",
    "Status",
    "ChainMismatch",
    "format_text",
    "format_json",
    "format_markdown",
]
