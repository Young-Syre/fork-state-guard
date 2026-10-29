"""Transport behaviour: retries, backoff, and the error taxonomy.

``urllib.request.urlopen`` is replaced with a stub, so nothing here opens a
socket.
"""

from __future__ import annotations

import io
import json
import socket
import unittest
import urllib.error
from unittest import mock

from fork_state_guard import rpc
from fork_state_guard.rpc import (
    HttpTransport,
    RpcClient,
    RpcResponseError,
    RpcTransportError,
    redact_url,
)


class FakeResponse(io.BytesIO):
    """Minimal stand-in for an http.client.HTTPResponse context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def ok_response(result="0x1"):
    return FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode())


class RecordingSleep:
    def __init__(self):
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


class TestRedaction(unittest.TestCase):
    """RPC URLs routinely carry an API key, and this tool's output is meant
    to be pasted into a report."""

    def test_api_key_in_path_is_stripped(self):
        self.assertEqual(
            redact_url("https://eth-mainnet.g.alchemy.com/v2/SECRET"),
            "https://eth-mainnet.g.alchemy.com/...",
        )

    def test_query_string_is_stripped(self):
        self.assertNotIn("def", redact_url("https://rpc.example/v3/abc?key=def"))

    def test_userinfo_is_stripped(self):
        self.assertNotIn("hunter2", redact_url("https://user:hunter2@rpc.example/x"))

    def test_plain_host_is_kept_whole(self):
        self.assertEqual(redact_url("http://127.0.0.1:8545"), "http://127.0.0.1:8545")

    def test_garbage_url(self):
        self.assertEqual(redact_url("not a url"), "<rpc endpoint>")


class TestHttpTransportConstruction(unittest.TestCase):
    def test_rejects_non_http_scheme(self):
        with self.assertRaises(RpcTransportError):
            HttpTransport("ws://localhost:8546")

    def test_rejects_nonsense(self):
        with self.assertRaises(RpcTransportError):
            HttpTransport("localhost:8545")

    def test_safe_url_never_leaks_the_path(self):
        transport = HttpTransport("https://rpc.example/v2/SECRET")
        self.assertNotIn("SECRET", transport.safe_url)


class TestRetries(unittest.TestCase):
    def transport(self, **kwargs) -> tuple[HttpTransport, RecordingSleep]:
        sleep = RecordingSleep()
        kwargs.setdefault("retries", 3)
        kwargs.setdefault("backoff", 0.5)
        return HttpTransport("https://rpc.example/key", sleep=sleep, **kwargs), sleep

    def test_succeeds_after_transient_failures(self):
        transport, sleep = self.transport()
        attempts = [
            urllib.error.URLError("connection reset"),
            urllib.error.URLError("connection reset"),
            ok_response(),
        ]
        with mock.patch.object(rpc.urllib.request, "urlopen", side_effect=attempts) as opener:
            result = transport.send({"method": "eth_chainId", "id": 1})
        self.assertEqual(result["result"], "0x1")
        self.assertEqual(opener.call_count, 3)

    def test_backoff_is_exponential(self):
        transport, sleep = self.transport()
        attempts = [urllib.error.URLError("x"), urllib.error.URLError("x"), ok_response()]
        with mock.patch.object(rpc.urllib.request, "urlopen", side_effect=attempts):
            transport.send({"method": "eth_chainId", "id": 1})
        # One sleep before each retry: base, then base * 2.
        self.assertEqual(sleep.delays, [0.5, 1.0])

    def test_gives_up_after_the_retry_budget(self):
        transport, _ = self.transport(retries=2)
        with mock.patch.object(
            rpc.urllib.request, "urlopen", side_effect=urllib.error.URLError("down")
        ) as opener:
            with self.assertRaises(RpcTransportError) as ctx:
                transport.send({"method": "eth_chainId", "id": 1})
        self.assertEqual(opener.call_count, 2)
        self.assertIn("after 2 attempt(s)", str(ctx.exception))

    def test_timeout_is_a_transport_error(self):
        transport, _ = self.transport(retries=1)
        with mock.patch.object(rpc.urllib.request, "urlopen", side_effect=socket.timeout()):
            with self.assertRaises(RpcTransportError) as ctx:
                transport.send({"method": "eth_chainId", "id": 1})
        self.assertIn("timed out", str(ctx.exception))

    def test_rate_limit_is_retried(self):
        transport, _ = self.transport()
        error = urllib.error.HTTPError("https://rpc.example", 429, "Too Many", {}, io.BytesIO(b""))
        self.addCleanup(error.close)
        with mock.patch.object(
            rpc.urllib.request, "urlopen", side_effect=[error, ok_response()]
        ) as opener:
            transport.send({"method": "eth_chainId", "id": 1})
        self.assertEqual(opener.call_count, 2)

    def test_client_error_is_not_retried(self):
        transport, _ = self.transport()
        error = urllib.error.HTTPError(
            "https://rpc.example", 401, "Unauthorized", {}, io.BytesIO(b"bad key")
        )
        self.addCleanup(error.close)
        with mock.patch.object(rpc.urllib.request, "urlopen", side_effect=error) as opener:
            with self.assertRaises(RpcTransportError) as ctx:
                transport.send({"method": "eth_chainId", "id": 1})
        self.assertEqual(opener.call_count, 1)
        self.assertIn("HTTP 401", str(ctx.exception))

    def test_http_error_message_does_not_leak_the_key(self):
        transport, _ = self.transport()
        error = urllib.error.HTTPError(
            "https://rpc.example/key", 401, "Unauthorized", {}, io.BytesIO(b"nope")
        )
        self.addCleanup(error.close)
        with mock.patch.object(rpc.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RpcTransportError) as ctx:
                transport.send({"method": "eth_chainId", "id": 1})
        self.assertNotIn("/key", str(ctx.exception))

    def test_non_json_body_is_a_transport_error(self):
        transport, _ = self.transport(retries=1)
        with mock.patch.object(
            rpc.urllib.request,
            "urlopen",
            return_value=FakeResponse(b"<html>502 Bad Gateway</html>"),
        ):
            with self.assertRaises(RpcTransportError) as ctx:
                transport.send({"method": "eth_chainId", "id": 1})
        self.assertIn("non-JSON", str(ctx.exception))

    def test_request_is_a_post_with_json_content_type(self):
        transport, _ = self.transport()
        with mock.patch.object(
            rpc.urllib.request, "urlopen", return_value=ok_response()
        ) as opener:
            transport.send({"method": "eth_chainId", "id": 1, "params": []})
        request = opener.call_args[0][0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(request.data)["method"], "eth_chainId")


class TestClientErrorTaxonomy(unittest.TestCase):
    class Scripted:
        safe_url = "https://scripted.invalid"

        def __init__(self, response):
            self.response = response
            self.sent = []

        def send(self, payload):
            self.sent.append(payload)
            return dict(self.response, id=payload.get("id"))

    def client(self, response) -> tuple[RpcClient, "TestClientErrorTaxonomy.Scripted"]:
        transport = self.Scripted(response)
        return RpcClient(transport), transport

    def test_json_rpc_error_object_becomes_a_response_error(self):
        client, _ = self.client({"error": {"code": -32000, "message": "execution reverted"}})
        with self.assertRaises(RpcResponseError) as ctx:
            client.call("eth_call", [])
        self.assertEqual(ctx.exception.code, -32000)
        self.assertIn("execution reverted", str(ctx.exception))

    def test_a_response_with_neither_result_nor_error_is_a_transport_error(self):
        client, _ = self.client({"jsonrpc": "2.0"})
        with self.assertRaises(RpcTransportError):
            client.call("eth_chainId", [])

    def test_request_ids_increment(self):
        client, transport = self.client({"result": "0x1"})
        client.call("eth_chainId")
        client.call("eth_blockNumber")
        self.assertEqual([p["id"] for p in transport.sent], [1, 2])

    def test_jsonrpc_version_is_set(self):
        client, transport = self.client({"result": "0x1"})
        client.call("eth_chainId")
        self.assertEqual(transport.sent[0]["jsonrpc"], "2.0")

    def test_quantities_are_decoded_from_hex(self):
        client, _ = self.client({"result": "0x14"})
        self.assertEqual(client.block_number(), 20)

    def test_non_quantity_result_is_a_transport_error(self):
        client, _ = self.client({"result": {"unexpected": True}})
        with self.assertRaises(RpcTransportError):
            client.block_number()

    def test_non_hex_data_result_is_a_transport_error(self):
        client, _ = self.client({"result": "not hex"})
        with self.assertRaises(RpcTransportError):
            client.eth_call("0x" + "11" * 20, b"\x01", "latest")

    def test_storage_results_are_left_padded_to_a_word(self):
        client, _ = self.client({"result": "0x01"})
        word = client.get_storage_at("0x" + "11" * 20, 0, "latest")
        self.assertEqual(len(word), 32)
        self.assertEqual(word[-1], 1)

    def test_odd_length_hex_is_tolerated(self):
        client, _ = self.client({"result": "0x1"})
        self.assertEqual(client.get_code("0x" + "11" * 20, "latest"), b"\x01")

    def test_eth_call_sends_hex_calldata(self):
        client, transport = self.client({"result": "0x" + "00" * 32})
        client.eth_call("0x" + "11" * 20, b"\x8d\xa5\xcb\x5b", "0x10")
        params = transport.sent[0]["params"]
        self.assertEqual(params[0]["data"], "0x8da5cb5b")
        self.assertEqual(params[1], "0x10")


if __name__ == "__main__":
    unittest.main()
