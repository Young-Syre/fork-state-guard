"""Selectors against known values, and encode/decode round-trips."""

from __future__ import annotations

import unittest

from fork_state_guard.abi import (
    AbiError,
    SignatureError,
    canonical_signature,
    decode_single,
    encode_argument,
    encode_call,
    function_selector,
    parse_signature,
)


class TestSelectors(unittest.TestCase):
    """Selectors every Ethereum developer can recite -- the point of pinning
    these is that a keccak bug would show up here first."""

    KNOWN = {
        "transfer(address,uint256)": "a9059cbb",
        "owner()": "8da5cb5b",
        "balanceOf(address)": "70a08231",
        "totalSupply()": "18160ddd",
        "approve(address,uint256)": "095ea7b3",
        "transferFrom(address,address,uint256)": "23b872dd",
        "allowance(address,address)": "dd62ed3e",
        "decimals()": "313ce567",
        "implementation()": "5c60da1b",
        "paused()": "5c975abb",
    }

    def test_known_selectors(self):
        for signature, expected in self.KNOWN.items():
            with self.subTest(signature=signature):
                self.assertEqual(function_selector(signature).hex(), expected)

    def test_selector_is_four_bytes(self):
        self.assertEqual(len(function_selector("owner()")), 4)

    def test_uint_alias_produces_the_same_selector(self):
        # transfer(address,uint) is the same function as
        # transfer(address,uint256); only the canonical spelling hashes right.
        self.assertEqual(
            function_selector("transfer(address,uint)"),
            function_selector("transfer(address,uint256)"),
        )

    def test_whitespace_is_ignored(self):
        self.assertEqual(
            function_selector(" transfer( address , uint256 ) "),
            function_selector("transfer(address,uint256)"),
        )

    def test_canonical_signature(self):
        self.assertEqual(
            canonical_signature("transfer(address,uint)"), "transfer(address,uint256)"
        )


class TestSignatureParsing(unittest.TestCase):
    def test_no_arguments(self):
        self.assertEqual(parse_signature("owner()"), ("owner", []))

    def test_several_arguments(self):
        self.assertEqual(
            parse_signature("transferFrom(address,address,uint256)"),
            ("transferFrom", ["address", "address", "uint256"]),
        )

    def test_rejects_missing_parentheses(self):
        with self.assertRaises(SignatureError):
            parse_signature("owner")

    def test_rejects_empty_signature(self):
        with self.assertRaises(SignatureError):
            parse_signature("")

    def test_rejects_tuple_arguments(self):
        with self.assertRaises(SignatureError):
            parse_signature("f((uint256,uint256))")

    def test_rejects_dynamic_argument_types(self):
        with self.assertRaises(SignatureError) as ctx:
            parse_signature("f(string)")
        self.assertIn("not supported", str(ctx.exception))

    def test_rejects_array_arguments(self):
        with self.assertRaises(SignatureError):
            parse_signature("f(uint256[])")

    def test_rejects_unknown_type(self):
        with self.assertRaises(SignatureError):
            parse_signature("f(widget)")

    def test_rejects_bad_integer_width(self):
        with self.assertRaises(SignatureError):
            parse_signature("f(uint257)")
        with self.assertRaises(SignatureError):
            parse_signature("f(uint7)")

    def test_rejects_bad_fixed_bytes_width(self):
        with self.assertRaises(SignatureError):
            parse_signature("f(bytes33)")


class TestEncoding(unittest.TestCase):
    ADDRESS = "0xde709f2102306220921060314715629080e2fb77"

    def test_encode_call_with_no_args_is_just_the_selector(self):
        self.assertEqual(encode_call("owner()").hex(), "8da5cb5b")

    def test_encode_transfer_calldata(self):
        data = encode_call("transfer(address,uint256)", [self.ADDRESS, 10**18])
        self.assertEqual(
            data.hex(),
            "a9059cbb"
            "000000000000000000000000de709f2102306220921060314715629080e2fb77"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        )

    def test_calldata_length_is_selector_plus_one_word_per_argument(self):
        self.assertEqual(len(encode_call("balanceOf(address)", [self.ADDRESS])), 4 + 32)
        self.assertEqual(
            len(encode_call("allowance(address,address)", [self.ADDRESS, self.ADDRESS])),
            4 + 64,
        )

    def test_address_is_left_padded(self):
        word = encode_argument("address", self.ADDRESS)
        self.assertEqual(word[:12], bytes(12))
        self.assertEqual(word[12:].hex(), self.ADDRESS[2:])

    def test_fixed_bytes_is_right_padded(self):
        word = encode_argument("bytes4", "0xdeadbeef")
        self.assertEqual(word.hex(), "deadbeef" + "00" * 28)

    def test_bool_encoding(self):
        self.assertEqual(encode_argument("bool", True).hex(), "00" * 31 + "01")
        self.assertEqual(encode_argument("bool", False).hex(), "00" * 32)

    def test_large_uint_from_string(self):
        # uint256 values exceed TOML's 64-bit integers, so strings are the
        # documented way to write them.
        big = 2**255 + 1
        self.assertEqual(
            encode_argument("uint256", str(big)), big.to_bytes(32, "big")
        )

    def test_uint_from_hex_string(self):
        self.assertEqual(encode_argument("uint256", "0xff"), (255).to_bytes(32, "big"))

    def test_negative_int_is_twos_complement(self):
        self.assertEqual(encode_argument("int256", -1).hex(), "ff" * 32)

    def test_rejects_out_of_range_uint(self):
        with self.assertRaises(AbiError):
            encode_argument("uint8", 256)

    def test_rejects_negative_uint(self):
        with self.assertRaises(AbiError):
            encode_argument("uint256", -1)

    def test_rejects_out_of_range_int(self):
        with self.assertRaises(AbiError):
            encode_argument("int8", 128)

    def test_rejects_bool_for_uint(self):
        with self.assertRaises(AbiError):
            encode_argument("uint256", True)

    def test_rejects_wrong_length_fixed_bytes(self):
        with self.assertRaises(AbiError):
            encode_argument("bytes32", "0xdeadbeef")

    def test_rejects_bad_address_argument(self):
        with self.assertRaises(AbiError):
            encode_argument("address", "0xnope")

    def test_rejects_wrong_argument_count(self):
        with self.assertRaises(AbiError) as ctx:
            encode_call("balanceOf(address)", [])
        self.assertIn("1 argument", str(ctx.exception))


class TestDecoding(unittest.TestCase):
    def test_decode_uint256(self):
        self.assertEqual(decode_single("uint256", (10**18).to_bytes(32, "big")), 10**18)

    def test_decode_max_uint256(self):
        self.assertEqual(decode_single("uint256", b"\xff" * 32), 2**256 - 1)

    def test_decode_address(self):
        raw = bytes(12) + bytes.fromhex("de709f2102306220921060314715629080e2fb77")
        self.assertEqual(
            decode_single("address", raw), "0xde709f2102306220921060314715629080e2fb77"
        )

    def test_decode_bool(self):
        self.assertIs(decode_single("bool", bytes(31) + b"\x01"), True)
        self.assertIs(decode_single("bool", bytes(32)), False)

    def test_decode_bytes32(self):
        self.assertEqual(decode_single("bytes32", b"\x11" * 32), "0x" + "11" * 32)

    def test_decode_negative_int(self):
        self.assertEqual(decode_single("int256", b"\xff" * 32), -1)

    def test_decode_string(self):
        data = (32).to_bytes(32, "big") + (3).to_bytes(32, "big") + b"DAI" + bytes(29)
        self.assertEqual(decode_single("string", data), "DAI")

    def test_decode_long_string_spanning_words(self):
        text = "Dai Stablecoin, a long-ish name crossing one word boundary"
        raw = text.encode()
        padded = raw + bytes((32 - len(raw) % 32) % 32)
        data = (32).to_bytes(32, "big") + len(raw).to_bytes(32, "big") + padded
        self.assertEqual(decode_single("string", data), text)

    def test_decode_dynamic_bytes(self):
        data = (32).to_bytes(32, "big") + (4).to_bytes(32, "big") + bytes.fromhex("deadbeef") + bytes(28)
        self.assertEqual(decode_single("bytes", data), "0xdeadbeef")

    def test_decode_empty_bytes(self):
        data = (32).to_bytes(32, "big") + (0).to_bytes(32, "big")
        self.assertEqual(decode_single("bytes", data), "0x")

    def test_empty_return_data_is_an_error_with_a_useful_message(self):
        with self.assertRaises(AbiError) as ctx:
            decode_single("uint256", b"")
        self.assertIn("empty return data", str(ctx.exception))

    def test_dirty_address_is_rejected(self):
        # A uint256 that happens to be large is not an address.
        with self.assertRaises(AbiError):
            decode_single("address", b"\xff" * 32)

    def test_dirty_bool_is_rejected(self):
        with self.assertRaises(AbiError):
            decode_single("bool", (7).to_bytes(32, "big"))

    def test_short_return_data_is_rejected(self):
        with self.assertRaises(AbiError):
            decode_single("uint256", b"\x01\x02")

    def test_uint_too_wide_for_declared_type_is_rejected(self):
        with self.assertRaises(AbiError):
            decode_single("uint8", (999).to_bytes(32, "big"))

    def test_truncated_dynamic_data_is_rejected(self):
        data = (32).to_bytes(32, "big") + (64).to_bytes(32, "big") + b"short"
        with self.assertRaises(AbiError):
            decode_single("bytes", data)

    def test_invalid_utf8_string_is_rejected(self):
        data = (32).to_bytes(32, "big") + (2).to_bytes(32, "big") + b"\xff\xfe" + bytes(30)
        with self.assertRaises(AbiError):
            decode_single("string", data)

    def test_unsupported_return_type_is_rejected(self):
        with self.assertRaises(AbiError):
            decode_single("widget", bytes(32))


class TestRoundTrips(unittest.TestCase):
    def test_static_types_round_trip(self):
        cases = [
            ("address", "0xde709f2102306220921060314715629080e2fb77"),
            ("uint256", 0),
            ("uint256", 2**256 - 1),
            ("uint8", 255),
            ("int256", -(2**255)),
            ("int256", 2**255 - 1),
            ("bool", True),
            ("bool", False),
            ("bytes32", "0x" + "ab" * 32),
            ("bytes4", "0xdeadbeef"),
        ]
        for type_name, value in cases:
            with self.subTest(type=type_name, value=value):
                encoded = encode_argument(type_name, value)
                self.assertEqual(len(encoded), 32)
                self.assertEqual(decode_single(type_name, encoded), value)


if __name__ == "__main__":
    unittest.main()
