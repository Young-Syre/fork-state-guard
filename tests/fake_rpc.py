"""A fake JSON-RPC transport, so the suite never touches the network.

Keyed on exactly what the production client sends, which means these tests
also pin the request shape: calldata, slot formatting and the block tag all
have to be right for a lookup to hit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fork_state_guard.rpc import RpcTransportError


@dataclass
class RpcErrorSpec:
    """Instructs the fake transport to answer with a JSON-RPC error object."""

    message: str
    code: int = -32000
    data: Any = None


@dataclass
class FakeTransport:
    """Answers the read-only methods fork-state-guard uses.

    ``calls`` is keyed by ``(address, calldata_hex)``, ``storage`` by
    ``(address, slot_int)``; addresses are lowercased on lookup.
    """

    chain_id: int | None = 1
    block_number: int = 21_000_000
    timestamp: int | None = 1_727_740_800  # 2024-10-01T00:00:00Z
    calls: dict[tuple[str, str], Any] = field(default_factory=dict)
    storage: dict[tuple[str, int], Any] = field(default_factory=dict)
    balances: dict[str, Any] = field(default_factory=dict)
    code: dict[str, Any] = field(default_factory=dict)
    default_code: str = "0x60006000"
    unsupported: tuple[str, ...] = ()
    requests: list[dict[str, Any]] = field(default_factory=list)
    safe_url = "https://fake.invalid"

    # -- helpers ---------------------------------------------------------

    @property
    def methods_used(self) -> list[str]:
        return [request["method"] for request in self.requests]

    @property
    def blocks_requested(self) -> set[str]:
        tags = set()
        for request in self.requests:
            params = request.get("params") or []
            for param in params:
                if isinstance(param, str) and param.startswith("0x") and len(param) <= 10:
                    tags.add(param)
        return tags

    # -- transport -------------------------------------------------------

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(payload)
        method = payload["method"]
        params = payload.get("params") or []
        request_id = payload.get("id")

        if method in self.unsupported:
            return self._error(request_id, RpcErrorSpec(f"method {method} not supported", -32601))

        try:
            result = self._dispatch(method, params)
        except RpcTransportError:
            raise
        if isinstance(result, RpcErrorSpec):
            return self._error(request_id, result)
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _dispatch(self, method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            if self.chain_id is None:
                return RpcErrorSpec("eth_chainId not supported", -32601)
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.block_number)
        if method == "eth_getBlockByNumber":
            if self.timestamp is None:
                return None
            return {"number": params[0], "timestamp": hex(self.timestamp)}
        if method == "eth_call":
            key = (params[0]["to"].lower(), params[0]["data"].lower())
            if key not in self.calls:
                return "0x"  # no such function here: empty return data
            return self.calls[key]
        if method == "eth_getStorageAt":
            key = (params[0].lower(), int(params[1], 16))
            return self.storage.get(key, "0x" + "00" * 32)
        if method == "eth_getBalance":
            value = self.balances.get(params[0].lower(), 0)
            return value if isinstance(value, RpcErrorSpec) else hex(value)
        if method == "eth_getCode":
            return self.code.get(params[0].lower(), self.default_code)
        return RpcErrorSpec(f"unexpected method {method}", -32601)

    @staticmethod
    def _error(request_id: Any, spec: RpcErrorSpec) -> dict[str, Any]:
        error: dict[str, Any] = {"code": spec.code, "message": spec.message}
        if spec.data is not None:
            error["data"] = spec.data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


def word(value: int | str) -> str:
    """A 32-byte hex word, as a node would return it."""
    if isinstance(value, str):
        body = value[2:] if value[:2].lower() == "0x" else value
        return "0x" + body.rjust(64, "0").lower()
    return "0x" + format(value, "064x")


def addr_word(address: str) -> str:
    """An address, right-aligned in a 32-byte word."""
    body = address[2:] if address[:2].lower() == "0x" else address
    return "0x" + body.rjust(64, "0").lower()


def string_word(text: str) -> str:
    """ABI-encoded return data for a single dynamic ``string``."""
    raw = text.encode("utf-8")
    padded = raw + b"\x00" * ((32 - len(raw) % 32) % 32)
    return (
        "0x"
        + format(32, "064x")
        + format(len(raw), "064x")
        + padded.hex()
    )
