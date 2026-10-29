"""Proxy slot constants, derived and compared against published values."""

from __future__ import annotations

import unittest

from fork_state_guard import proxy
from fork_state_guard.keccak import keccak256


class TestPublishedSlots(unittest.TestCase):
    """The EIP-1967 slots are published in the EIP. Deriving them and
    matching the published constants proves the derivation end to end."""

    def test_eip1967_implementation_slot(self):
        self.assertEqual(
            proxy.EIP1967_IMPLEMENTATION.hex,
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        )

    def test_eip1967_admin_slot(self):
        self.assertEqual(
            proxy.EIP1967_ADMIN.hex,
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
        )

    def test_eip1967_beacon_slot(self):
        self.assertEqual(
            proxy.EIP1967_BEACON.hex,
            "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
        )

    def test_eip1967_slots_are_hash_minus_one(self):
        for slot, preimage in (
            (proxy.EIP1967_IMPLEMENTATION, b"eip1967.proxy.implementation"),
            (proxy.EIP1967_ADMIN, b"eip1967.proxy.admin"),
            (proxy.EIP1967_BEACON, b"eip1967.proxy.beacon"),
        ):
            with self.subTest(preimage=preimage):
                self.assertEqual(
                    slot.slot, int.from_bytes(keccak256(preimage), "big") - 1
                )

    def test_eip1822_slot_is_the_plain_hash_of_PROXIABLE(self):
        self.assertEqual(
            proxy.EIP1822_IMPLEMENTATION.slot,
            int.from_bytes(keccak256(b"PROXIABLE"), "big"),
        )

    def test_oz_legacy_slots_are_plain_hashes(self):
        self.assertEqual(
            proxy.OZ_LEGACY_IMPLEMENTATION.slot,
            int.from_bytes(keccak256(b"org.zeppelinos.proxy.implementation"), "big"),
        )
        self.assertEqual(
            proxy.OZ_LEGACY_ADMIN.slot,
            int.from_bytes(keccak256(b"org.zeppelinos.proxy.admin"), "big"),
        )

    def test_slots_are_all_distinct(self):
        slots = [slot.slot for slot in proxy.ALL_SLOTS]
        self.assertEqual(len(slots), len(set(slots)))

    def test_slot_hex_is_32_bytes(self):
        for slot in proxy.ALL_SLOTS:
            with self.subTest(slot=slot.label):
                self.assertEqual(len(slot.hex), 66)


class TestSlotSelection(unittest.TestCase):
    def test_auto_probes_every_implementation_standard(self):
        standards = {slot.standard for slot in proxy.implementation_slots("auto")}
        self.assertEqual(standards, {"eip1967", "eip1822", "oz-legacy"})

    def test_eip1967_first_in_auto_order(self):
        self.assertEqual(proxy.implementation_slots("auto")[0].standard, "eip1967")

    def test_single_standard_selection(self):
        slots = proxy.implementation_slots("eip1822")
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].standard, "eip1822")

    def test_eip1822_defines_no_admin_slot(self):
        self.assertEqual(proxy.admin_slots("eip1822"), ())

    def test_unknown_standard_is_rejected(self):
        with self.assertRaises(ValueError):
            proxy.implementation_slots("eip9999")

    def test_describe_slots_rows(self):
        rows = proxy.describe_slots()
        self.assertEqual(len(rows), len(proxy.ALL_SLOTS))
        self.assertTrue(all(len(row) == 4 for row in rows))
        self.assertIn("keccak256('eip1967.proxy.implementation') - 1", rows[0])


if __name__ == "__main__":
    unittest.main()
