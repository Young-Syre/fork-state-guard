"""EIP-55 checksums against the test vectors in the EIP itself."""

from __future__ import annotations

import unittest

from fork_state_guard.address import (
    AddressError,
    addresses_equal,
    is_checksum_address,
    is_hex_address,
    normalize_address,
    to_checksum_address,
)

# The exact vectors listed in EIP-55.
EIP55_VECTORS = [
    # all caps
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    # all lower
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    # normal
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


class TestChecksum(unittest.TestCase):
    def test_eip55_vectors_from_lowercase(self):
        for address in EIP55_VECTORS:
            with self.subTest(address=address):
                self.assertEqual(to_checksum_address(address.lower()), address)

    def test_eip55_vectors_are_idempotent(self):
        for address in EIP55_VECTORS:
            with self.subTest(address=address):
                self.assertEqual(to_checksum_address(address), address)

    def test_eip55_vectors_validate(self):
        for address in EIP55_VECTORS:
            with self.subTest(address=address):
                self.assertTrue(is_checksum_address(address))

    def test_wrong_case_fails_validation(self):
        # Flipping one letter's case must invalidate the checksum.
        self.assertFalse(is_checksum_address("0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))

    def test_lowercase_address_is_not_checksummed(self):
        self.assertFalse(is_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))

    def test_accepts_address_without_0x_prefix(self):
        self.assertEqual(
            to_checksum_address("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        )


class TestNormalize(unittest.TestCase):
    def test_normalizes_to_lowercase_with_prefix(self):
        self.assertEqual(
            normalize_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        )

    def test_rejects_short_address(self):
        with self.assertRaises(AddressError) as ctx:
            normalize_address("0xdead")
        self.assertIn("20 bytes", str(ctx.exception))

    def test_rejects_long_address(self):
        with self.assertRaises(AddressError):
            normalize_address("0x" + "ab" * 21)

    def test_rejects_non_hex(self):
        with self.assertRaises(AddressError):
            normalize_address("0x" + "z" * 40)

    def test_rejects_non_string(self):
        with self.assertRaises(AddressError):
            normalize_address(12345)

    def test_is_hex_address(self):
        self.assertTrue(is_hex_address("0x" + "ab" * 20))
        self.assertTrue(is_hex_address("ab" * 20))
        self.assertFalse(is_hex_address("0x" + "ab" * 19))
        self.assertFalse(is_hex_address(None))
        self.assertFalse(is_hex_address("not an address"))


class TestComparison(unittest.TestCase):
    def test_case_insensitive_equality(self):
        self.assertTrue(
            addresses_equal(
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            )
        )

    def test_different_addresses_are_unequal(self):
        self.assertFalse(addresses_equal("0x" + "11" * 20, "0x" + "22" * 20))

    def test_unparseable_side_is_unequal_not_an_error(self):
        self.assertFalse(addresses_equal("0x" + "11" * 20, "garbage"))


if __name__ == "__main__":
    unittest.main()
