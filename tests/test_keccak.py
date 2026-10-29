"""Keccak-256 against the official vectors, plus a differential test that
pins the permutation itself."""

from __future__ import annotations

import hashlib
import random
import unittest

from fork_state_guard import keccak as keccak_module
from fork_state_guard.keccak import Keccak256, keccak256, keccak256_hex


class TestKeccakOfficialVectors(unittest.TestCase):
    """Vectors published for Keccak-256 (NOT SHA3-256)."""

    VECTORS = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"testing": "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
        b"The quick brown fox jumps over the lazy dog": (
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        ),
        b"The quick brown fox jumps over the lazy dog.": (
            "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"
        ),
    }

    def test_official_vectors(self):
        for data, expected in self.VECTORS.items():
            with self.subTest(data=data):
                self.assertEqual(keccak256_hex(data), expected)

    def test_empty_input_is_the_canonical_ethereum_constant(self):
        self.assertEqual(
            keccak256_hex(b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_digest_is_32_bytes(self):
        self.assertEqual(len(keccak256(b"anything")), 32)

    def test_hex_prefix_option(self):
        self.assertTrue(keccak256_hex(b"", prefix=True).startswith("0x"))
        self.assertEqual(len(keccak256_hex(b"", prefix=True)), 66)

    def test_is_not_sha3_256(self):
        """The whole reason this module exists: hashlib's sha3_256 differs."""
        self.assertNotEqual(keccak256(b""), hashlib.sha3_256(b"").digest())
        self.assertNotEqual(keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_rejects_non_bytes(self):
        with self.assertRaises(TypeError):
            keccak256("a string")  # type: ignore[arg-type]

    def test_accepts_bytearray_and_memoryview(self):
        self.assertEqual(keccak256(bytearray(b"abc")), keccak256(b"abc"))
        self.assertEqual(keccak256(memoryview(b"abc")), keccak256(b"abc"))


class TestKeccakBlockBoundaries(unittest.TestCase):
    """The rate is 136 bytes; absorption bugs hide at the boundaries."""

    def test_lengths_around_the_rate_boundary_differ(self):
        digests = {keccak256(b"a" * length) for length in (134, 135, 136, 137, 271, 272, 273)}
        self.assertEqual(len(digests), 7)

    def test_long_input_is_stable(self):
        # A 4 KiB input exercises ~30 absorption rounds.
        self.assertEqual(keccak256_hex(b"z" * 4096), keccak256_hex(b"z" * 4096))

    def test_differential_against_hashlib_sha3(self):
        """Keccak-256 and SHA3-256 share the Keccak-f[1600] permutation, the
        lane layout, the 136-byte rate and the sponge; they differ only in the
        padding domain byte (0x01 vs 0x06).

        So: run this module's own permutation and absorption with SHA3's pad
        byte and require a byte-exact match with hashlib across many input
        lengths. Any error in the permutation, the rotation offsets, the lane
        mapping or the multi-block loop would break this, which gives the
        implementation an independent reference beyond the fixed vectors.
        """

        def sha3_256_via_our_sponge(data: bytes) -> bytes:
            rate = keccak_module._RATE_BYTES
            lanes = [[0] * 5 for _ in range(5)]
            blocks = len(data) // rate
            for index in range(blocks):
                keccak_module._absorb_block(lanes, data[index * rate : (index + 1) * rate])
            tail = bytearray(data[blocks * rate :])
            tail.append(0x06)  # SHA3 domain byte instead of Keccak's 0x01
            tail += b"\x00" * (rate - len(tail))
            tail[rate - 1] |= 0x80
            keccak_module._absorb_block(lanes, bytes(tail))
            return keccak_module._squeeze(lanes)

        rng = random.Random(20261029)
        lengths = [0, 1, 2, 31, 32, 33, 63, 135, 136, 137, 200, 271, 272, 273, 500, 1000, 4096]
        for length in lengths:
            data = bytes(rng.getrandbits(8) for _ in range(length))
            with self.subTest(length=length):
                self.assertEqual(
                    sha3_256_via_our_sponge(data), hashlib.sha3_256(data).digest()
                )


class TestKeccakHashlibShapedWrapper(unittest.TestCase):
    def test_update_matches_one_shot(self):
        hasher = Keccak256()
        hasher.update(b"abc")
        self.assertEqual(hasher.hexdigest(), keccak256_hex(b"abc"))

    def test_incremental_updates_concatenate(self):
        hasher = Keccak256(b"a")
        hasher.update(b"b").update(b"c")
        self.assertEqual(hasher.digest(), keccak256(b"abc"))

    def test_copy_is_independent(self):
        original = Keccak256(b"a")
        clone = original.copy()
        clone.update(b"b")
        self.assertEqual(original.hexdigest(), keccak256_hex(b"a"))
        self.assertEqual(clone.hexdigest(), keccak256_hex(b"ab"))

    def test_advertised_parameters(self):
        self.assertEqual(Keccak256.digest_size, 32)
        self.assertEqual(Keccak256.block_size, 136)


if __name__ == "__main__":
    unittest.main()
