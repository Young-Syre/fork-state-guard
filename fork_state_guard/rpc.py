"""JSON-RPC over HTTP using only the standard library.

Two failure modes are kept strictly apart, because they mean different things
to someone about to file a report:

* ``RpcTransportError`` -- the endpoint could not be reached or did not answer
  usefully (DNS, TLS, timeout, HTTP 5xx, rate limit, malformed JSON). You
  learned nothing about the chain. Retried with backoff, then surfaced as
  exit code 2.
* ``RpcResponseError`` -- the endpoint answered with a JSON-RPC error object.
  The node is fine; the request was rejected (a reverting ``eth_call``, an
  unsupported method, a pruned historical block). That is a result, not an
  outage, and is reported per-check as ERROR.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Protocol

__all__ = [
    "RpcError",
    "RpcTransportError",
    "RpcResponseError",
    "Transport",
    "HttpTransport",
    "RpcClient",
    "redact_url",
]

DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 0.5
USER_AGENT = "fork-state-guard (read-only chain state verifier)"

# HTTP statuses worth retrying: rate limits and transient server-side faults.
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504, 522, 524})


class RpcError(Exception):
    """Base class for RPC failures."""


class RpcTransportError(RpcError):
    """The endpoint could not be reached, or returned an unusable response."""


class RpcResponseError(RpcError):
    """The endpoint returned a JSON-RPC error object."""

    def __init__(self, message: str, *, code: int | None = None, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


def redact_url(url: str) -> str:
    """Return ``url`` with any path, query or userinfo removed.

    Provider URLs routinely embed an API key in the path or query string, and
    this tool's output is meant to be pasted into a vulnerability report. Only
    scheme and host ever reach the output.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<rpc endpoint>"
    if not parts.scheme or not parts.hostname:
        return "<rpc endpoint>"
    host = parts.hostname
    if parts.port:
        host = f"{host}:{parts.port}"
    suffix = "/..." if parts.path not in ("", "/") or parts.query else ""
    return f"{parts.scheme}://{host}{suffix}"


class Transport(Protocol):
    """Anything that can carry one JSON-RPC request object and return the
    decoded response object. Tests inject a fake implementation so the suite
    never touches the network."""

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - protocol
        ...


class HttpTransport:
    """POST JSON-RPC to an HTTP(S) endpoint, retrying transport faults."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise RpcTransportError(
                f"RPC endpoint must be an http(s) URL, got {parts.scheme or url!r}"
            )
        self.url = url
        self.timeout = timeout
        self.retries = max(1, int(retries))
        self.backoff = max(0.0, float(backoff))
        self._sleep = sleep

    @property
    def safe_url(self) -> str:
        return redact_url(self.url)

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        last_error: str = "unknown error"

        for attempt in range(self.retries):
            if attempt:
                self._sleep(self.backoff * (2 ** (attempt - 1)))
            request = urllib.request.Request(
                self.url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read()[:200].decode("utf-8", "replace").strip()
                except Exception:  # noqa: BLE001 - diagnostics only
                    detail = ""
                last_error = f"HTTP {exc.code} from {self.safe_url}" + (
                    f": {detail}" if detail else ""
                )
                if exc.code not in _RETRYABLE_STATUS:
                    raise RpcTransportError(last_error) from exc
                continue
            except urllib.error.URLError as exc:
                last_error = f"cannot reach {self.safe_url}: {exc.reason}"
                continue
            except (socket.timeout, TimeoutError):
                last_error = f"timed out after {self.timeout:g}s talking to {self.safe_url}"
                continue
            except OSError as exc:
                last_error = f"cannot reach {self.safe_url}: {exc}"
                continue

            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError:
                preview = raw[:120].decode("utf-8", "replace").strip()
                last_error = f"{self.safe_url} returned non-JSON: {preview!r}"
                continue

            if not isinstance(decoded, dict):
                last_error = f"{self.safe_url} returned a {type(decoded).__name__}, expected an object"
                continue

            return decoded

        raise RpcTransportError(f"{last_error} (after {self.retries} attempt(s))")


class RpcClient:
    """Typed wrappers over the handful of read-only methods this tool needs."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self._next_id = 0

    @property
    def endpoint(self) -> str:
        return getattr(self.transport, "safe_url", "<injected transport>")

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params if params is not None else [],
        }
        response = self.transport.send(payload)

        if "error" in response and response["error"] is not None:
            error = response["error"]
            if isinstance(error, dict):
                raise RpcResponseError(
                    str(error.get("message", error)),
                    code=error.get("code"),
                    data=error.get("data"),
                )
            raise RpcResponseError(str(error))

        if "result" not in response:
            raise RpcTransportError(
                f"{method} response contained neither 'result' nor 'error'"
            )
        return response["result"]

    # -- block / chain ----------------------------------------------------

    def chain_id(self) -> int:
        return _to_int(self.call("eth_chainId"), "eth_chainId")

    def block_number(self) -> int:
        return _to_int(self.call("eth_blockNumber"), "eth_blockNumber")

    def block_timestamp(self, block: str) -> int | None:
        """Return the unix timestamp of ``block``, or None if unavailable."""
        result = self.call("eth_getBlockByNumber", [block, False])
        if not isinstance(result, dict) or "timestamp" not in result:
            return None
        try:
            return _to_int(result["timestamp"], "block timestamp")
        except RpcTransportError:
            return None

    # -- state reads ------------------------------------------------------

    def eth_call(self, to: str, data: bytes, block: str) -> bytes:
        result = self.call(
            "eth_call", [{"to": to, "data": "0x" + data.hex()}, block]
        )
        return _to_bytes(result, "eth_call")

    def get_storage_at(self, address: str, slot: int | str, block: str) -> bytes:
        slot_hex = slot if isinstance(slot, str) else hex(slot)
        result = self.call("eth_getStorageAt", [address, slot_hex, block])
        raw = _to_bytes(result, "eth_getStorageAt")
        return raw.rjust(32, b"\x00")[-32:]

    def get_balance(self, address: str, block: str) -> int:
        return _to_int(self.call("eth_getBalance", [address, block]), "eth_getBalance")

    def get_code(self, address: str, block: str) -> bytes:
        return _to_bytes(self.call("eth_getCode", [address, block]), "eth_getCode")


def _to_int(value: Any, what: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value[:2].lower() == "0x" else int(value, 10)
        except ValueError:
            pass
    raise RpcTransportError(f"{what} returned a value that is not a quantity: {value!r}")


def _to_bytes(value: Any, what: str) -> bytes:
    if not isinstance(value, str) or value[:2].lower() != "0x":
        raise RpcTransportError(f"{what} returned a value that is not hex data: {value!r}")
    body = value[2:]
    if len(body) % 2:
        body = "0" + body
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise RpcTransportError(f"{what} returned malformed hex: {value!r}") from exc
