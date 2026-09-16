# SPDX-License-Identifier: GPL-3.0-or-later
"""Packet-mark bits inventoried from iptables dumps of either flavour."""
import unittest

from wg_program_split import network


TAILSCALE = """*mangle
-A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -m connmark ! --mark 0x0/0xff0000 -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
-A OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000
-A ts-forward -i tailscale0 -j MARK --set-xmark 0x40000/0xff0000
-A ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
COMMIT
"""


class LegacyMaskTests(unittest.TestCase):
    def test_tailscale_iptables_nft_rules_use_only_their_mask(self):
        self.assertEqual(network._legacy_mask(TAILSCALE), 0xff0000)

    def test_connmark_restore_without_nfmask_claims_every_bit(self):
        self.assertEqual(network._legacy_mask('-A PREROUTING -j CONNMARK --restore-mark\n'), 0xffffffff)

    def test_connmark_writes_to_the_conntrack_mark_use_no_packet_bits(self):
        text = '-A OUTPUT -j CONNMARK --set-xmark 0x1/0x1\n-A OUTPUT -m connmark --mark 0x2/0x2 -j ACCEPT\n'
        self.assertEqual(network._legacy_mask(text), 0)

    def test_mark_target_and_match_bits(self):
        text = ('-A OUTPUT -j MARK --set-xmark 0x10/0x10\n-A OUTPUT -j MARK --or-mark 0x20\n'
                '-A OUTPUT -j MARK --and-mark 0xfffffff0\n-A OUTPUT -m mark --mark 0x40/0xc0 -j ACCEPT\n')
        self.assertEqual(network._legacy_mask(text), 0x10 | 0x20 | 0xf | 0xc0)

    def test_unrecognized_mark_line_is_refused(self):
        with self.assertRaises(network.NetworkError):
            network._legacy_mask('-A OUTPUT -j MARK --unknown 1\n')

    def test_opaque_extensions_need_the_nft_dump(self):
        entries = [{'rule': {'expr': [{'xt': {'type': 'target', 'name': 'MARK'}}]}}]
        self.assertTrue(network._opaque_marks(entries))
        self.assertFalse(network._opaque_marks([{'rule': {'expr': [{'xt': {'type': 'match', 'name': 'conntrack'}}]}}]))
        with self.assertRaises(network.NetworkError):
            network._require_mark_visibility(entries, {'iptables-legacy-save': ''})
        network._require_mark_visibility(entries, {'iptables-nft-save': '', 'ip6tables-nft-save': ''})


if __name__ == '__main__':
    unittest.main()
