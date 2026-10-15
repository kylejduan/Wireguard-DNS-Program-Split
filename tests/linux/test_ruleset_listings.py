# SPDX-License-Identifier: GPL-3.0-or-later
"""Reused nf_tables listings and memoized ruleset analysis; no system changes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wg_program_split import inventory, network, ownership
from test_network import BOOT, PROFILE, Kernel


class CachedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wgps-listing-test-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        state, wireguard = root / 'state', root / 'wireguard'
        state.mkdir(mode=0o700)
        wireguard.mkdir(mode=0o700)
        self.fd = ownership.open_private_dir(state, owner_uid=os.getuid())
        self.addCleanup(os.close, self.fd)
        self.kernel = Kernel()
        self.net = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT,
                                   wireguard_root=wireguard, owner_uid=os.getuid())

    def test_cached_ruleset_listings_still_catch_a_foreign_edit_at_the_next_check(self):
        """A health check reuses nf_tables listings only while the kernel's
        ruleset generation is unchanged; any transaction (here, foreign mark
        and zone rules or a flush) is seen by the very next check."""
        generation = [1]
        listings = inventory.RulesetListings(lambda: generation[0])

        def runner(argv, *, input=None):
            argv = tuple(argv)
            if input is None and argv in listings.COMMANDS:
                return listings(argv, lambda: self.kernel(argv))
            if argv[:2] == ('nft', '-f') or argv[:2] == ('nft', 'delete'):
                generation[0] += 1  # The kernel commits a transaction.
            return self.kernel(argv, input=input)
        self.net.runner = runner
        self.net.prepare(guard_blocked=True)
        self.assertTrue(self.net.health().ready)
        listed = sum(call == ('nft', '-j', 'list', 'ruleset') for call in self.kernel.calls)
        self.assertTrue(self.net.health().ready)
        self.assertEqual(sum(call == ('nft', '-j', 'list', 'ruleset') for call in self.kernel.calls), listed)
        self.kernel.nft['nftables'].append({'rule': {'family': 'inet', 'table': 'foreign', 'expr': [
            {'mangle': {'key': {'ct': {'key': 'zone'}}, 'value': 1}}]}})
        generation[0] += 1
        self.assertIn('allocation:foreign', self.net.health().changed)
        self.kernel.nft['nftables'].pop()
        self.kernel.nft_save = '*mangle\n-A OUTPUT -j MARK --or-mark 0x1000000\nCOMMIT\n'
        generation[0] += 1  # An iptables-nft edit is an nf_tables transaction too.
        self.assertIn('allocation:foreign', self.net.health().changed)
        self.kernel.nft_save = ''
        generation[0] += 1
        self.assertTrue(self.net.health().ready)
        self.kernel.nft['nftables'] = []  # A foreign flush of the whole ruleset.
        generation[0] += 1
        self.assertIn('nft_table:wg_program_split', self.net.health().missing)

    def test_an_unchanged_ruleset_is_analysed_once_and_a_changed_one_again(self):
        self.net.prepare(guard_blocked=True)
        network._foreign_nft.cache_clear()
        with patch('wg_program_split.network._nft_usage', wraps=network._nft_usage) as usage:
            for _ in range(3):
                self.assertTrue(self.net.health().ready)
            self.assertEqual(usage.call_count, 1)
            self.kernel.nft['nftables'].append({'rule': {'family': 'inet', 'table': 'foreign', 'expr': [
                {'mangle': {'key': {'meta': {'key': 'mark'}}, 'value': 0x1000000}}]}})
            self.assertIn('allocation:foreign', self.net.health().changed)
            self.assertEqual(usage.call_count, 2)
            self.kernel.nft['nftables'].append({'rule': {'family': 'inet', 'table': 'foreign', 'expr': [
                {'xt': {'type': 'target', 'name': 'MARK'}}]}})
            self.kernel.nft_save = None
            with patch('wg_program_split.inventory.shutil.which', lambda tool, path=None: None if 'nft-save' in tool else tool):
                for _ in range(2):  # An unsupported ruleset fails every check, never from a cache.
                    with self.assertRaises(network.NetworkError):
                        self.net.health()


def rules(name, flags=None):
    table = {'family': 'inet', 'name': name, 'handle': 1, **({'flags': flags} if flags else {})}
    return json.dumps({'nftables': [{'metainfo': {'json_schema_version': 1}}, {'table': table}]})


class RulesetListingTests(unittest.TestCase):
    def setUp(self):
        self.generation, self.runs = [5], []
        self.listings = inventory.RulesetListings(self.read)

    def read(self):
        if self.generation[0] is None:
            raise OSError('netlink unavailable')
        return self.generation[0]

    def list(self, name='rules', during=None, flags=None, argv=('nft', '-j', 'list', 'ruleset')):
        def run():
            self.runs.append(name)
            if during is not None:
                self.generation[0] = during
            return rules(name, flags)
        return json.loads(self.listings(argv, run))['nftables'][1]['table']['name']

    def test_listing_is_reused_only_at_the_generation_it_was_bracketed_by(self):
        self.assertEqual(self.list('first'), 'first')
        self.assertEqual(self.list('second'), 'first')
        self.assertEqual(self.runs, ['first'])
        self.generation[0] = 6
        self.assertEqual(self.list('third'), 'third')
        self.assertEqual(self.runs, ['first', 'third'])

    def test_listing_raced_by_a_transaction_or_without_a_generation_is_never_reused(self):
        self.assertEqual(self.list('raced', during=6), 'raced')
        self.assertEqual(self.list('after'), 'after')
        self.generation[0] = None
        self.assertEqual(self.list('unavailable'), 'unavailable')
        self.assertEqual(self.list('again'), 'again')
        self.generation[0] = 6
        self.assertEqual(self.list('fresh'), 'fresh')
        self.assertEqual(self.runs, ['raced', 'after', 'unavailable', 'again', 'fresh'])

    def test_owner_bound_table_disables_reuse_until_it_is_gone(self):
        """The kernel deletes an owner-bound table when its socket closes,
        without a new generation: while one is listed, nothing is reused."""
        save = ('iptables-nft-save',)
        for flags in ('owner', ['owner', 'persist']):
            self.runs.clear()
            self.assertEqual(self.list('owned', flags=flags), 'owned')
            self.assertEqual(self.list('owned-again', flags=flags), 'owned-again')
            self.assertEqual(self.list('save', argv=save), 'save')
            self.assertEqual(self.list('save-again', argv=save), 'save-again')
            # Same generation, table silently deleted: seen at once.
            self.assertEqual(self.list('gone'), 'gone')
            self.assertEqual(self.list('reused'), 'gone')
            self.assertEqual(self.list('save-fresh', argv=save), 'save-fresh')
            self.assertEqual(self.list('save-reused', argv=save), 'save-fresh')
            self.assertEqual(self.runs, ['owned', 'owned-again', 'save', 'save-again', 'gone', 'save-fresh'])
            self.generation[0] += 1
        self.assertEqual(self.list('unparsable', flags=None), 'unparsable')
        self.listings.entries[('nft', '-j', 'list', 'ruleset')] = (self.generation[0], 'not json')
        self.listings.owner_free = None
        self.assertEqual(self.list('relisted'), 'relisted')

    def test_legacy_dump_runs_only_when_legacy_tables_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            names = Path(directory) / 'ip_tables_names'
            spawned = []
            with patch.dict(inventory._LEGACY_TABLES, {'iptables-legacy-save': str(names)}), \
                    patch.object(inventory, '_spawn', lambda argv, input: spawned.append(argv) or 'dump'):
                self.assertEqual(inventory.run_command(('iptables-legacy-save',)), '')
                names.write_text('')
                self.assertEqual(inventory.run_command(('iptables-legacy-save',)), '')
                names.write_text('mangle\n')
                self.assertEqual(inventory.run_command(('iptables-legacy-save',)), 'dump')
            self.assertEqual(spawned, [('iptables-legacy-save',)])
