# SPDX-License-Identifier: GPL-3.0-or-later
"""Firewall allocation must inspect complete nested inventories without caching."""
import unittest

from wg_program_split.inventory import _nft_usage
from wg_program_split.errors import NetworkError

MARK = {'meta': {'key': 'mark'}}
ZONE = {'ct': {'key': 'zone'}}


class NftInventoryTests(unittest.TestCase):
    def test_combines_masks_and_zones_across_nested_rules(self):
        rules = [
            {'match': {'left': {'&': [MARK, 0xff00]}, 'right': 0x100}},
            {'mangle': {'key': MARK, 'value': {'|': [{'&': [MARK, 0xfffffff0]}, 0x20]}}},
            {'mangle': {'key': ZONE, 'value': 7}},
            {'match': {'left': ZONE, 'right': 12}},
            {'counter': {'packets': 500, 'bytes': 10000}},
            {'xt': {'name': 'MARK', 'opaque': MARK}},
        ]
        self.assertEqual(_nft_usage({'nftables': [{'rule': {'expr': rules}}]}), (0xff2f, {7, 12}))

    def test_all_mark_bits_do_not_hide_unknown_expressions(self):
        full = {'mangle': {'key': MARK, 'value': 1}}
        for bad in [MARK, ZONE, {'match': {'left': {'^': [MARK, 1]}, 'right': 2}},
                    {'mangle': {'key': MARK, 'value': {'map': 'dynamic'}}}]:
            for entries in ([full, bad], [bad, full]):
                with self.subTest(entries=entries), self.assertRaises(NetworkError):
                    _nft_usage(entries)

    def test_repeated_scan_observes_changed_live_input(self):
        rule = {'match': {'left': {'&': [MARK, 1]}, 'right': 1}}
        self.assertEqual(_nft_usage([rule]), (1, set()))
        rule['match']['left']['&'][1] = 8
        self.assertEqual(_nft_usage([rule]), (8, set()))

    def test_large_foreign_inventory_keeps_late_mark_and_zone(self):
        rules = [{'rule': {'expr': [{'counter': {'packets': i, 'bytes': i * 64}},
                                   {'accept': None}]}} for i in range(2000)]
        rules += [{'mangle': {'key': ZONE, 'value': 65535}}, {'match': {'left': MARK, 'right': 1}}]
        self.assertEqual(_nft_usage(rules), (0xffffffff, {65535}))

    def test_invalid_zone_is_still_rejected(self):
        with self.assertRaises(NetworkError):
            _nft_usage({'mangle': {'key': ZONE, 'value': 65536}})


if __name__ == '__main__':
    unittest.main()
