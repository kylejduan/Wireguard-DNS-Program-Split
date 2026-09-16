# SPDX-License-Identifier: GPL-3.0-or-later
"""Network adapter contract tests; an argv-aware kernel fixture performs no I/O."""
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wg_program_split.config import parse_profile
from wg_program_split import network, ownership


BOOT = '11111111-2222-4333-8444-555555555555'
PRIVATE = base64.b64encode(b'a' * 32).decode()
PUBLIC = base64.b64encode(b'b' * 32).decode()
LOCAL_PUBLIC = base64.b64encode(b'c' * 32).decode()
PRESHARED = base64.b64encode(b'd' * 32).decode()
PROFILE = parse_profile(f'''[Interface]
PrivateKey = {PRIVATE}
Address = 10.20.0.2/32
DNS = 10.20.0.1
[Peer]
PublicKey = {PUBLIC}
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.8:51820
''')


class Kernel:
    def __init__(self):
        self.links = [{'ifindex': 1, 'ifname': 'lo', 'mtu': 65536},
                      {'ifindex': 2, 'ifname': 'eth0', 'mtu': 1500}]
        self.rules = [{'priority': 0, 'src': 'all', 'table': 'local'},
                      {'priority': 32766, 'src': 'all', 'table': 'main'},
                      {'priority': 32767, 'src': 'all', 'table': 'default'}]
        self.rules6 = [{'priority': 0, 'src': 'all', 'table': 'local'},
                       {'priority': 32766, 'src': 'all', 'table': 'main'}]
        self.routes = [{'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'eth0', 'table': 'main'}]
        self.nft = {'nftables': []}
        self.wgmarks = ''
        self.dump = None
        self.legacy = ''
        self.conntrack = ''
        self.calls = []
        self.fail_prefix = None
        self.configured = False
        self.localnet = '0'
        self.addresses = []
        self.nft_script = ''
        self.next_ifindex = 7

    def wireguard_dump(self):
        if not self.configured:
            return '(none)\t(none)\t0\toff\n'
        return (f'{PRIVATE}\t{LOCAL_PUBLIC}\t51821\t0x2000000\n'
                f'{PUBLIC}\t{PRESHARED}\t192.0.2.8:51820\t0.0.0.0/0\t0\t10\t20\toff\n')

    def __call__(self, argv, *, input=None):
        argv = tuple(argv)
        self.calls.append(argv)
        if self.fail_prefix and argv[:len(self.fail_prefix)] == self.fail_prefix:
            raise RuntimeError('injected output with PrivateKey=' + PRIVATE)
        if argv == ('ip', '-j', '-d', 'link', 'show'):
            return json.dumps(self.links)
        if argv == ('ip', '-j', '-4', 'rule', 'show'):
            return json.dumps(self.rules)
        if argv == ('ip', '-j', '-6', 'rule', 'show'):
            return json.dumps(self.rules6)
        if argv == ('ip', '-j', '-4', 'route', 'show', 'table', 'all'):
            return json.dumps(self.routes)
        if argv[:5] == ('ip', '-j', '-4', 'route', 'get'):
            return json.dumps([{'dst': argv[5], 'gateway': '192.0.2.1', 'dev': 'eth0', 'prefsrc': '192.0.2.2'}])
        if argv == ('nft', '-j', 'list', 'ruleset'):
            return json.dumps(self.nft)
        if argv == ('wg', 'show', 'all', 'fwmark'):
            return self.wgmarks
        if argv == ('conntrack', '-L', '-o', 'extended'):
            return self.conntrack
        if argv in (('iptables-legacy-save',), ('ip6tables-legacy-save',)):
            return self.legacy
        if argv in (('iptables-nft-save',), ('ip6tables-nft-save',)):
            return getattr(self, 'nft_save', '')
        if argv == ('ip', '-j', '-4', 'address', 'show', 'dev', 'wgps0'):
            return json.dumps([{'addr_info': self.addresses}])
        if argv == ('wg', 'show', 'wgps0', 'dump'):
            return self.dump if self.dump is not None else self.wireguard_dump()
        if argv[:3] == ('ip', '-4', 'route') and argv[3] in ('add', 'delete'):
            args = list(argv[4:])
            state = {'dst': 'default', 'table': int(args[args.index('table') + 1]),
                     'metric': int(args[args.index('metric') + 1]), 'protocol': 'static'}
            if args[0] == 'unreachable':
                state['type'] = 'unreachable'
            if 'dev' in args:
                state.update(dev=args[args.index('dev') + 1], prefsrc=args[args.index('src') + 1])
            if argv[3] == 'add':
                if state in self.routes:
                    raise RuntimeError('already exists')
                self.routes.append(state)
            else:
                self.routes.remove(state)
            return ''
        if argv[:3] == ('ip', '-4', 'rule') and argv[3] in ('add', 'delete'):
            args = list(argv[4:])
            mark, mask = args[args.index('fwmark') + 1].split('/')
            state = {'priority': int(args[args.index('priority') + 1]), 'src': 'all',
                     'fwmark': mark, 'fwmask': mask, 'table': int(args[args.index('table') + 1])}
            if argv[3] == 'add':
                self.rules.append(state)
            else:
                self.rules.remove(state)
            return ''
        if argv[:3] == ('ip', 'link', 'add'):
            if any(x['ifname'] == 'wgps0' for x in self.links):
                raise RuntimeError('already exists')
            self.links.append({'ifindex': self.next_ifindex, 'ifname': 'wgps0', 'mtu': 1420,
                               'flags': [], 'linkinfo': {'info_kind': 'wireguard'}})
            self.next_ifindex += 1
            return ''
        if argv[:3] == ('ip', 'link', 'set'):
            link = next(x for x in self.links if x['ifname'] == 'wgps0')
            if 'alias' in argv:
                link['ifalias'] = argv[argv.index('alias') + 1]
            if 'mtu' in argv:
                link['mtu'] = int(argv[argv.index('mtu') + 1])
            if 'up' in argv:
                link['flags'] = ['UP']
            return ''
        if argv[:3] == ('ip', 'link', 'delete'):
            self.links = [x for x in self.links if x['ifname'] != 'wgps0']
            self.routes = [x for x in self.routes if x.get('dev') != 'wgps0']
            self.addresses = []
            self.configured, self.localnet = False, '0'
            return ''
        if argv[:4] == ('ip', '-4', 'address', 'add'):
            address, prefix = argv[4].split('/')
            self.addresses = [{'family': 'inet', 'local': address, 'prefixlen': int(prefix),
                               'noprefixroute': 'noprefixroute' in argv}]
            return ''
        if argv[:3] == ('wg', 'setconf', 'wgps0'):
            path = Path(argv[3])
            if path.is_symlink() or path.stat().st_mode & 0o777 != 0o600:
                raise RuntimeError('unsafe configuration')
            body = path.read_text()
            if ('PrivateKey = ' + PRIVATE not in body or 'AllowedIPs = 0.0.0.0/0' not in body or
                    'FwMark = 0x2000000' not in body):
                raise RuntimeError('wrong configuration')
            self.configured = True
            return ''
        if argv[:2] == ('sysctl', '-n'):
            return self.localnet
        if argv[:2] == ('sysctl', '-w'):
            if argv[2] != 'net.ipv4.conf.wgps0.route_localnet=1':
                raise RuntimeError('foreign sysctl')
            self.localnet = '1'
            return ''
        if argv == ('nft', '-c', '-f', '-'):
            return ''
        if argv == ('nft', '-f', '-'):
            if self.nft['nftables']:
                raise RuntimeError('already exists')
            self.nft_script = input
            # nft keeps metadata of the initial table creation. An empty create
            # followed by a same-name add block does not install its comment.
            marker = re.search(r'create table inet wg_program_split \{\s*comment "([^"]+)"', input)
            self.nft['nftables'] = [
                {'table': {'family': 'inet', 'name': 'wg_program_split', 'handle': 10,
                           **({'comment': marker[1]} if marker else {})}},
                {'chain': {'family': 'inet', 'table': 'wg_program_split', 'name': 'egress', 'handle': 11}},
                {'rule': {'family': 'inet', 'table': 'wg_program_split', 'chain': 'egress', 'handle': 12,
                          'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}}]
            return ''
        if argv == ('nft', 'delete', 'table', 'inet', 'wg_program_split'):
            self.nft['nftables'] = []
            return ''
        if argv[:3] == ('conntrack', '-D', '--zone'):
            self.conntrack = ''
            return ''
        if argv[:3] == ('conntrack', '-L', '--zone'):
            return self.conntrack
        raise AssertionError('unexpected command ' + str(argv))


class AllocationTests(unittest.TestCase):
    def test_boot_allocation_requires_no_underlay_but_transport_preflight_does(self):
        kernel = Kernel()
        kernel.routes = []
        kernel.fail_prefix = ('ip', '-j', '-4', 'route', 'get')
        inventory = network.inspect(PROFILE, runner=kernel, require_underlay=False)
        self.assertEqual((inventory.underlay, inventory.mtu), ('', 0))
        self.assertEqual(network.allocate(inventory).zone, 1)
        self.assertFalse(any(c[:5] == kernel.fail_prefix for c in kernel.calls))
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel)
        kernel.legacy = '-A OUTPUT -j MARK --unknown-mark-behavior 12\n'
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel, require_underlay=False)

    def test_empty_owned_inventory_selects_mask_before_foreign_routing_and_preserves_local(self):
        kernel = Kernel()
        original = list(kernel.rules)
        allocation = network.allocate(network.inspect(PROFILE, runner=kernel))
        self.assertEqual((allocation.mask, allocation.mark, allocation.outer_mark),
                         (0x03000000, 0x01000000, 0x02000000))
        self.assertEqual((allocation.routing_table, allocation.priority, allocation.zone), (57000, 1, 1))
        self.assertEqual(kernel.rules, original)
        self.assertFalse(any('add' in call or 'delete' in call for call in kernel.calls))

    def test_allocation_accounts_for_rule_nft_wg_mark_masks_tables_and_zones(self):
        kernel = Kernel()
        kernel.rules.insert(1, {'priority': 100, 'table': 57000, 'fwmark': '0x1000000', 'fwmask': '0x1000000'})
        kernel.nft['nftables'].append({'rule': {'expr': [{'match': {'op': '==',
            'left': {'&': [{'meta': {'key': 'mark'}}, 0x02000000]}, 'right': 0}}]}})
        kernel.wgmarks = 'other\t0x1\n'
        kernel.conntrack = 'udp 17 23 src=192.0.2.2 dst=192.0.2.3 zone=1\n'
        allocation = network.allocate(network.inspect(PROFILE, runner=kernel))
        self.assertEqual(allocation.mask & 0x03000001, 0)
        self.assertEqual(allocation.mask.bit_count(), 2)
        self.assertEqual((allocation.routing_table, allocation.zone), (57001, 2))
        self.assertLess(allocation.priority, 100)

    def test_tailscale_mask_preserving_assignment_does_not_consume_unrelated_bits(self):
        kernel = Kernel()
        kernel.nft['nftables'].append({'rule': {'expr': [{'mangle': {
            'key': {'meta': {'key': 'mark'}},
            'value': {'|': [{'&': [{'meta': {'key': 'mark'}}, 0xff00ffff]}, 0x40000]}}}]}})
        self.assertEqual(network.allocate(network.inspect(PROFILE, runner=kernel)).mask, 0x03000000)

    def test_unknown_mark_expression_or_legacy_mark_action_fails_preflight(self):
        for malformed in ({'meta': {'key': 'mark'}},
                          {'mangle': {'key': {'meta': {'key': 'mark'}}, 'value': {'map': 'dynamic'}}}):
            kernel = Kernel()
            kernel.nft['nftables'] = [{'rule': {'expr': [malformed]}}]
            with self.subTest(expr=malformed), self.assertRaises(network.NetworkError):
                network.inspect(PROFILE, runner=kernel)
        kernel = Kernel()
        kernel.legacy = '-A OUTPUT -j MARK --unknown-mark-behavior 12\n'
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel)

    def test_foreign_fixed_names_and_wireguard_default_are_never_adopted(self):
        for resource in ('link', 'table', 'full-tunnel'):
            kernel = Kernel()
            if resource == 'link':
                kernel.links.append({'ifindex': 8, 'ifname': 'wgps0', 'mtu': 1420,
                                     'linkinfo': {'info_kind': 'wireguard'}})
            elif resource == 'table':
                kernel.nft['nftables'] = [{'table': {'family': 'inet', 'name': 'wg_program_split', 'handle': 9}}]
            else:
                kernel.links.append({'ifindex': 8, 'ifname': 'oldvpn', 'mtu': 1420,
                                     'linkinfo': {'info_kind': 'wireguard'}})
                kernel.routes.append({'dst': 'default', 'dev': 'oldvpn', 'table': 51820})
            with self.subTest(resource=resource), self.assertRaises(network.NetworkError):
                network.inspect(PROFILE, runner=kernel)
            self.assertFalse(any('delete' in call for call in kernel.calls))

    def test_no_local_rule_no_early_priority_and_oversize_mtu_fail(self):
        kernel = Kernel()
        kernel.rules = []
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel)
        kernel = Kernel()
        kernel.rules.insert(1, {'priority': 1, 'table': 52})
        with self.assertRaises(network.NetworkError):
            network.allocate(network.inspect(PROFILE, runner=kernel))
        with self.assertRaises(network.NetworkError):
            network.inspect(replace(PROFILE, mtu=1500), runner=Kernel())

    def test_legacy_reserved_zones_and_path_mtu_are_considered(self):
        kernel = Kernel()
        kernel.legacy = '-A OUTPUT -j CT --zone 1\n'
        self.assertEqual(network.allocate(network.inspect(PROFILE, runner=kernel)).zone, 2)
        kernel.legacy = '-A OUTPUT -j CT --zone mark\n'
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel)
        def low_pmtu(argv, *, input=None):
            result = kernel(argv, input=input)
            if tuple(argv[:5]) == ('ip', '-j', '-4', 'route', 'get'):
                return json.dumps([dict(json.loads(result)[0], metrics=[{'mtu': 1400}])])
            return result
        kernel.legacy = ''
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=low_pmtu)

    def test_malformed_inventory_fails_with_adapter_error(self):
        kernel = Kernel()
        kernel.links = ['unexpected']
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel)
        kernel = Kernel()
        kernel.rules.append({'priority': 0, 'table': 52})
        with self.assertRaises(network.NetworkError):
            network.inspect(PROFILE, runner=kernel)

    def test_directly_connected_endpoint_keeps_unlisted_router_requirement(self):
        kernel = Kernel()
        def endpoint_on_link(argv, *, input=None):
            result = kernel(argv, input=input)
            if tuple(argv) == ('ip', '-j', '-4', 'route', 'get', PROFILE.endpoint_host):
                value = json.loads(result)[0]
                del value['gateway']
                return json.dumps([value])
            return result
        self.assertEqual(network.inspect(PROFILE, runner=endpoint_on_link).underlay, 'eth0')

    def test_runner_redacts_stderr_timeout_and_argv(self):
        for result in (subprocess.CompletedProcess(['wg'], 1, '', 'PrivateKey=' + PRIVATE),
                       subprocess.TimeoutExpired(['wg', PRIVATE], 1, output=PRIVATE)):
            with self.subTest(kind=type(result).__name__):
                kwargs = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
                with patch('wg_program_split.inventory.subprocess.run', **kwargs):
                    with self.assertRaises(network.NetworkError) as error:
                        network.run_command(('wg', 'show', 'all', 'fwmark'))
                self.assertNotIn(PRIVATE, str(error.exception))


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wgps-network-test-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state, self.wireguard = self.root / 'state', self.root / 'wireguard'
        self.state.mkdir(mode=0o700)
        self.wireguard.mkdir(mode=0o700)
        self.fd = ownership.open_private_dir(self.state, owner_uid=os.getuid())
        self.addCleanup(os.close, self.fd)
        self.kernel = Kernel()
        self.net = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT,
                                   wireguard_root=self.wireguard, owner_uid=os.getuid())

    def test_guard_precondition_and_preflight_failure_do_not_acquire_anything(self):
        with self.assertRaises(network.NetworkError):
            self.net.prepare(guard_blocked=False)
        self.assertEqual(self.kernel.calls, [])
        self.kernel.links.append({'ifname': 'wgps0'})
        with self.assertRaises(network.NetworkError):
            self.net.prepare(guard_blocked=True)
        self.assertFalse((self.state / 'receipt.json').exists())

    def test_prepare_has_fail_closed_order_private_config_and_counter_stable_health(self):
        receipt = self.net.prepare(guard_blocked=True)
        self.assertEqual(ownership.read_receipt(self.fd), receipt)
        self.assertTrue(self.net.health().ready)
        self.assertFalse(self.net.health().missing or self.net.health().changed)
        calls = self.kernel.calls
        fallback = next(i for i, c in enumerate(calls) if c[:4] == ('ip', '-4', 'route', 'add'))
        policy = next(i for i, c in enumerate(calls) if c[:4] == ('ip', '-4', 'rule', 'add'))
        firewall = calls.index(('nft', '-f', '-'))
        link = next(i for i, c in enumerate(calls) if c[:3] == ('ip', 'link', 'add'))
        self.assertLess(fallback, policy)
        self.assertLess(policy, firewall)
        self.assertLess(firewall, link)
        self.assertIn('create table inet wg_program_split', self.kernel.nft_script)
        self.assertEqual(list(self.wireguard.iterdir()), [])
        self.assertNotIn(PRIVATE, (self.state / 'receipt.json').read_text())
        self.assertNotIn(PRIVATE, str(calls))
        address = next(c for c in calls if c[:4] == ('ip', '-4', 'address', 'add'))
        self.assertIn('noprefixroute', address)
        counter = self.kernel.nft['nftables'][2]['rule']['expr'][0]['counter']
        counter.update(packets=1000, bytes=50000)
        self.assertEqual(self.net.health().changed, ())

    def test_dump_preserves_receipt_fields_without_secrets_or_repeated_getters(self):
        receipt = self.net.prepare(guard_blocked=True)
        identity = next(r.identity for r in receipt.resources if r.kind == 'interface')
        expected = {'public_key_sha256': hashlib.sha256(LOCAL_PUBLIC.encode()).hexdigest(),
                    'fwmark': 0x2000000, 'peers': [[PUBLIC]],
                    'endpoints': [[PUBLIC, '192.0.2.8:51820']],
                    'allowed-ips': [[PUBLIC, '0.0.0.0/0']],
                    'persistent-keepalive': [[PUBLIC, 'off']]}
        self.assertEqual({k: identity[k] for k in expected}, expected)
        self.kernel.calls.clear()
        self.assertTrue(self.net.health().ready)
        self.assertEqual([c for c in self.kernel.calls if c[:3] == ('wg', 'show', 'wgps0')],
                         [('wg', 'show', 'wgps0', 'dump')])
        self.assertIn(('wg', 'show', 'all', 'fwmark'), self.kernel.calls)
        self.kernel.dump = (self.kernel.wireguard_dump().replace(PRESHARED, '(none)')
                            .replace('\t51821\t', '\t51822\t')
                            .replace('\t0\t10\t20\t', '\t12345\t1000\t2000\t'))
        self.assertTrue(self.net.health().ready)  # Volatile dump fields are not receipt identities.
        for secret in (PRIVATE, PRESHARED):
            self.assertNotIn(secret, (self.state / 'receipt.json').read_text())
            self.assertNotIn(secret, str(self.kernel.calls))

    def test_dump_changes_to_each_owned_configuration_field_fail_health(self):
        self.net.prepare(guard_blocked=True)
        original = self.kernel.wireguard_dump()
        for old, new in ((LOCAL_PUBLIC, PUBLIC), ('0x2000000', 'off'),
                         (PUBLIC, LOCAL_PUBLIC), ('192.0.2.8:51820', '(none)'),
                         ('0.0.0.0/0', '192.0.2.0/24,2001:db8::/32'),
                         ('\t20\toff', '\t20\t25')):
            with self.subTest(field=old):
                self.kernel.dump = original.replace(old, new)
                health = self.net.health()
                self.assertFalse(health.ready)
                self.assertIn('interface:wgps0', health.changed)

    def test_malformed_dump_never_allows_readiness_or_discloses_output(self):
        self.net.prepare(guard_blocked=True)
        original = self.kernel.wireguard_dump()
        header, peer = original.splitlines()
        for value in ('', header + '\n\n' + peer, 'wgps0\t' + original,
                      original + peer + '\n', original.replace('\t10\t', '\tbad\t'),
                      original.replace('\t51821\t', '\t65536\t'),
                      original.replace('0x2000000', '0x100000000'),
                      original.replace('\t20\toff', '\t20\t65536'),
                      original.replace(LOCAL_PUBLIC, 'invalid-key'),
                      header + '\n' + peer + '\textra\n'):
            with self.subTest(case=len(value)):
                self.kernel.dump = value
                with self.assertRaises(network.NetworkError) as caught:
                    self.net.health()
                for secret in (PRIVATE, PRESHARED):
                    self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(ownership.read_receipt(self.fd), self.net.receipt)

    def test_dump_empty_interface_and_peer_none_normalize_like_individual_getters(self):
        self.net.prepare(guard_blocked=True)
        resource = next(r for r in self.net.receipt.resources if r.kind == 'interface')
        self.kernel.dump = '(none)\t(none)\t0\toff\n'
        observed = self.net._observe(resource, self.net._snapshot())
        self.assertEqual(observed['public_key_sha256'], hashlib.sha256(b'(none)').hexdigest())
        self.assertEqual(observed['fwmark'], 0)
        for field in ('peers', 'endpoints', 'allowed-ips', 'persistent-keepalive'):
            self.assertEqual(observed[field], [])
        self.kernel.dump += f'{PUBLIC}\t(none)\t(none)\t(none)\t0\t0\t0\toff\n'
        observed = self.net._observe(resource, self.net._snapshot())
        self.assertEqual(observed['endpoints'], [[PUBLIC, '(none)']])
        self.assertEqual(observed['allowed-ips'], [[PUBLIC, '(none)']])
        self.assertEqual(observed['persistent-keepalive'], [[PUBLIC, 'off']])
        self.kernel.dump = self.kernel.wireguard_dump().replace('0.0.0.0/0', '192.0.2.0/24,2001:db8::/32')
        observed = self.net._observe(resource, self.net._snapshot())
        self.assertEqual(observed['allowed-ips'], [[PUBLIC, '192.0.2.0/24', '2001:db8::/32']])

    def test_identity_swap_blocks_every_destructive_command(self):
        self.net.prepare(guard_blocked=True)
        next(x for x in self.kernel.links if x['ifname'] == 'wgps0')['ifindex'] = 77
        self.kernel.calls.clear()
        self.assertIn('interface:wgps0', self.net.health().changed)
        self.assertNotIn(('wg', 'show', 'wgps0', 'dump'), self.kernel.calls)
        before = len(self.kernel.calls)
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertFalse(any('delete' in c or '-D' in c for c in self.kernel.calls[before:]))

    def test_missing_is_distinct_and_disable_only_removes_owned_resources_and_zone(self):
        self.net.prepare(guard_blocked=True)
        foreign_routes = [x for x in self.kernel.routes if x.get('table') == 'main']
        self.kernel.routes = [x for x in self.kernel.routes if x.get('metric') != 10]
        self.assertIn('route:preferred', self.net.health().missing)
        receipt = self.net.disable(guard_blocked=True)
        self.assertEqual(receipt.resources, ())
        self.assertEqual(self.kernel.routes, foreign_routes)
        self.assertEqual([x['priority'] for x in self.kernel.rules], [0, 32766, 32767])
        self.assertIn(('conntrack', '-D', '--zone', '1'), self.kernel.calls)
        self.assertNotIn(('conntrack', '-F'), self.kernel.calls)

    def test_configuration_failure_retains_journal_then_scoped_rollback(self):
        self.kernel.fail_prefix = ('wg', 'setconf')
        with self.assertRaises(network.NetworkError) as error:
            self.net.prepare(guard_blocked=True)
        self.assertNotIn(PRIVATE, str(error.exception))
        self.assertTrue(any(r.kind == 'private_file' for r in self.net.receipt.resources))
        self.assertFalse(self.net.health().ready)
        self.assertTrue(self.kernel.nft['nftables'])
        self.kernel.fail_prefix = None
        self.net.disable(guard_blocked=True)
        self.assertEqual(self.net.receipt.resources, ())
        self.assertEqual(list(self.wireguard.iterdir()), [])

    def test_successful_command_without_effective_delete_retains_ownership_record(self):
        self.net.prepare(guard_blocked=True)
        original = self.net.runner
        def ignore_delete(argv, *, input=None):
            if tuple(argv[:3]) == ('ip', 'link', 'delete'):
                return ''
            return original(argv, input=input)
        self.net.runner = ignore_delete
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertTrue(any(r.kind == 'interface' for r in self.net.receipt.resources))

    def test_empty_completed_receipt_is_not_ready_and_can_be_inspected(self):
        self.net.prepare(guard_blocked=True)
        receipt = self.net.disable(guard_blocked=True)
        recovered = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT, receipt=receipt)
        self.assertFalse(recovered.health().ready)
        self.assertEqual(recovered.disable(guard_blocked=True), receipt)

    def test_nft_replacement_and_private_file_symlink_are_never_deleted(self):
        self.kernel.fail_prefix = ('wg', 'setconf')
        with self.assertRaises(network.NetworkError):
            self.net.prepare(guard_blocked=True)
        config = next(self.wireguard.glob('*/wg.conf'))
        config.unlink()
        config.symlink_to(self.state / 'receipt.json')
        self.kernel.fail_prefix = None
        self.kernel.nft['nftables'][0]['table']['handle'] += 1
        health = self.net.health()
        self.assertIn('private_file:configuration', health.changed)
        self.assertIn('nft_table:wg_program_split', health.changed)
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertTrue(config.is_symlink())

    def test_failed_receipt_publication_retains_uncertain_acquisition(self):
        original = ownership.write_receipt
        count = 0
        def fail_second(fd, receipt, *, expected=None):
            nonlocal count
            count += 1
            if count == 2:
                raise ownership.OwnershipError('injected receipt failure')
            return original(fd, receipt, expected=expected)
        with patch('wg_program_split.network.own.write_receipt', side_effect=fail_second):
            with self.assertRaises(network.NetworkError):
                self.net.prepare(guard_blocked=True)
        self.assertTrue(any(r.get('type') == 'unreachable' for r in self.kernel.routes))
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertFalse(any('delete' in c for c in self.kernel.calls))

    def test_same_boot_recovery_compares_live_state_and_foreign_boot_is_rejected(self):
        receipt = self.net.prepare(guard_blocked=True)
        recovered = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT,
            wireguard_root=self.wireguard, owner_uid=os.getuid(), receipt=receipt)
        self.assertEqual(recovered.health().changed, ())
        with self.assertRaises(ownership.OwnershipError):
            network.Network(PROFILE, self.fd, runner=self.kernel,
                boot_id='22222222-2222-4333-8444-555555555555', receipt=receipt)

    def test_foreign_route_inside_reserved_table_is_changed_and_preserved(self):
        self.net.prepare(guard_blocked=True)
        foreign = {'dst': '192.0.2.0/24', 'dev': 'eth0', 'table': 57000}
        self.kernel.routes.append(foreign)
        self.assertIn('routing_table:foreign', self.net.health().changed)
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertIn(foreign, self.kernel.routes)

    def test_empty_zone_cleanup_error_requires_successful_empty_readback(self):
        self.net.prepare(guard_blocked=True)
        self.kernel.fail_prefix = ('conntrack', '-D')
        self.net.disable(guard_blocked=True)
        self.assertIn(('conntrack', '-L', '--zone', '1', '-o', 'extended'), self.kernel.calls)

    def test_deleted_zone_with_remaining_flows_is_not_forgotten_on_command_failure(self):
        self.net.prepare(guard_blocked=True)
        self.kernel.conntrack = 'udp 17 30 src=10.20.0.2 dst=10.20.0.1 zone=1\n'
        self.kernel.fail_prefix = ('conntrack', '-D')
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertTrue(any(r.kind == 'conntrack_zone' for r in self.net.receipt.resources))
        self.assertTrue(self.kernel.nft['nftables'])

    def test_broken_symlink_ancestor_is_changed_instead_of_missing_configuration(self):
        self.kernel.fail_prefix = ('wg', 'setconf')
        with self.assertRaises(network.NetworkError):
            self.net.prepare(guard_blocked=True)
        self.wireguard.rename(self.root / 'retained-wireguard')
        self.wireguard.symlink_to(self.root / 'missing-root')
        health = self.net.health()
        self.assertIn('private_directory:configuration', health.changed)
        self.assertIn('private_file:configuration', health.changed)

    def test_new_foreign_mark_and_zone_claims_make_health_unready(self):
        self.net.prepare(guard_blocked=True)
        self.kernel.nft['nftables'].append({'rule': {'family': 'inet', 'table': 'foreign', 'expr': [
            {'mangle': {'key': {'ct': {'key': 'zone'}}, 'value': 1}}]}})
        self.assertIn('allocation:foreign', self.net.health().changed)
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.kernel.nft['nftables'].pop()
        self.kernel.legacy = '-A OUTPUT -j MARK --or-mark 0x1000000\n'
        self.assertIn('allocation:foreign', self.net.health().changed)
        self.assertFalse(self.net.health().ready)

    def test_private_receipt_path_must_match_exact_attempt_directory(self):
        self.kernel.fail_prefix = ('wg', 'setconf')
        with self.assertRaises(network.NetworkError):
            self.net.prepare(guard_blocked=True)
        record = next(r for r in self.net.receipt.resources if r.kind == 'private_directory')
        bad = replace(record, identity={**record.identity, 'path': str(self.wireguard / 'foreign')})
        receipt = replace(self.net.receipt, resources=tuple(bad if r == record else r for r in self.net.receipt.resources))
        with self.assertRaises(network.NetworkError):
            network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT,
                            wireguard_root=self.wireguard, owner_uid=os.getuid(), receipt=receipt)

    def test_changed_profile_cannot_reuse_previous_firewall_readiness(self):
        receipt = self.net.prepare(guard_blocked=True)
        for profile in (replace(PROFILE, resolver='10.20.0.9'),
                        replace(PROFILE, private_key=base64.b64encode(b'd' * 32).decode()),
                        replace(PROFILE, preshared_key=base64.b64encode(b'e' * 32).decode())):
            with self.subTest(profile=profile):
                recovered = network.Network(profile, self.fd, runner=self.kernel, boot_id=BOOT,
                    wireguard_root=self.wireguard, owner_uid=os.getuid(), receipt=receipt)
                health = recovered.health()
                self.assertFalse(health.ready)
                self.assertIn('nft_table:wg_program_split', health.changed)
        self.assertTrue(self.net.health().ready)

    def test_new_ipv6_rule_mark_collision_blocks_readiness_and_cleanup(self):
        self.net.prepare(guard_blocked=True)
        self.kernel.rules6.append({'priority': 200, 'table': 52,
                                  'fwmark': '0x1000000', 'fwmask': '0x1000000'})
        health = self.net.health()
        self.assertFalse(health.ready)
        self.assertIn('allocation:foreign', health.changed)
        before = len(self.kernel.calls)
        with self.assertRaises(network.NetworkError):
            self.net.disable(guard_blocked=True)
        self.assertFalse(any('delete' in c or '-D' in c for c in self.kernel.calls[before:]))

    def _repair_fixture(self, *, delete_interface=False):
        receipt = self.net.prepare(guard_blocked=True)
        self.anchors = tuple(r for r in receipt.resources if r.kind in ('rule', 'nft_table', 'conntrack_zone')
                             or (r.kind, r.name) == ('route', 'fallback'))
        self.kernel.conntrack = 'udp 17 30 src=10.20.0.2 dst=10.20.0.1 zone=1\n'
        if delete_interface:
            self.kernel(('ip', 'link', 'delete', 'dev', 'wgps0'))
        else:
            self.kernel.routes = [r for r in self.kernel.routes if r.get('metric') != 10]
        self.kernel.calls.clear()
        return receipt

    def _assert_anchors_retained(self):
        self.assertTrue(all(r in self.net.receipt.resources for r in self.anchors))
        self.assertEqual(self.kernel.conntrack, 'udp 17 30 src=10.20.0.2 dst=10.20.0.1 zone=1\n')
        self.assertFalse(any('delete' in c or '-D' in c or c[:2] == ('nft', '-f') for c in self.kernel.calls))

    def test_repair_healthy_network_is_noop(self):
        receipt = self.net.prepare(guard_blocked=True)
        self.kernel.calls.clear()
        self.assertEqual(self.net.repair_missing(guard_blocked=True), receipt)
        self.assertFalse(any('add' in c or 'set' in c or 'setconf' in c or '-w' in c for c in self.kernel.calls))

    def test_repair_empty_completed_receipt_is_refused(self):
        self.net.prepare(guard_blocked=True)
        receipt = self.net.disable(guard_blocked=True)
        recovered = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT, receipt=receipt)
        self.kernel.calls.clear()
        with self.assertRaises(network.NetworkError):
            recovered.repair_missing(guard_blocked=True)
        self.assertEqual(self.kernel.calls, [])

    def test_repair_missing_preferred_route_keeps_flow_zone_and_safety_anchors(self):
        receipt = self._repair_fixture()
        repaired = self.net.repair_missing(guard_blocked=True)
        self.assertTrue(self.net.health().ready)
        self.assertEqual(repaired.attempt_id, receipt.attempt_id)
        self.assertEqual(ownership.read_receipt(self.fd), repaired)
        self.assertFalse(any(c[:3] == ('ip', 'link', 'add') for c in self.kernel.calls))
        self._assert_anchors_retained()

    def test_repair_deleted_interface_records_new_birth_without_flushing_existing_flows(self):
        receipt = self._repair_fixture(delete_interface=True)
        old_index = next(r.identity['ifindex'] for r in receipt.resources if r.kind == 'interface')
        repaired = self.net.repair_missing(guard_blocked=True)
        self.assertTrue(self.net.health().ready)
        self.assertNotEqual(next(r.identity['ifindex'] for r in repaired.resources if r.kind == 'interface'), old_index)
        self.assertEqual(list(self.wireguard.iterdir()), [])
        self.assertEqual(ownership.read_receipt(self.fd), repaired)
        self._assert_anchors_retained()

    def test_repair_rejects_foreign_interface_without_any_mutation(self):
        self._repair_fixture(delete_interface=True)
        self.kernel.links.append({'ifname': 'wgps0', 'ifindex': 99, 'mtu': 1500})
        with self.assertRaises(network.NetworkError):
            self.net.repair_missing(guard_blocked=True)
        self.assertFalse(any('add' in c or 'set' in c for c in self.kernel.calls))
        self._assert_anchors_retained()

    def test_repair_requires_all_safety_anchors_present(self):
        self._repair_fixture()
        for attribute, replacement in (
                ('routes', [r for r in self.kernel.routes if r.get('metric') != 32760]),
                ('rules', [r for r in self.kernel.rules if r.get('priority') != 1]),
                ('nft', {'nftables': []})):
            previous = getattr(self.kernel, attribute)
            setattr(self.kernel, attribute, replacement)
            try:
                with self.subTest(missing=attribute), self.assertRaises(network.NetworkError):
                    self.net.repair_missing(guard_blocked=True)
            finally:
                setattr(self.kernel, attribute, previous)
        self.assertFalse(any('add' in c for c in self.kernel.calls))
        self._assert_anchors_retained()

    def test_repair_checks_blocked_guard_receipt_cas_and_current_underlay(self):
        receipt = self._repair_fixture()
        with self.assertRaises(network.NetworkError):
            self.net.repair_missing(guard_blocked=False)
        changed = replace(receipt, resources=receipt.resources[:-1])
        ownership.write_receipt(self.fd, changed, expected=receipt)
        with self.assertRaises(network.NetworkError):
            self.net.repair_missing(guard_blocked=True)
        ownership.write_receipt(self.fd, receipt, expected=changed)
        self.kernel.links[1]['mtu'] = 1400
        with self.assertRaises(network.NetworkError):
            self.net.repair_missing(guard_blocked=True)
        self.assertFalse(any('add' in c for c in self.kernel.calls))
        self._assert_anchors_retained()

    def test_repair_failed_fence_publication_never_starts_recreation(self):
        self._repair_fixture()
        with patch('wg_program_split.network.own.write_receipt', side_effect=ownership.OwnershipError('fault')):
            with self.assertRaises(network.NetworkError):
                self.net.repair_missing(guard_blocked=True)
        self.assertFalse(any('add' in c for c in self.kernel.calls))
        self._assert_anchors_retained()

    def test_repair_route_birth_without_receipt_capture_is_not_adopted_after_restart(self):
        self._repair_fixture()
        original, count = ownership.write_receipt, 0
        def fail_capture(fd, receipt, *, expected=None):
            nonlocal count
            count += 1
            if count == 2:
                raise ownership.OwnershipError('after route creation')
            return original(fd, receipt, expected=expected)
        with patch('wg_program_split.network.own.write_receipt', side_effect=fail_capture):
            with self.assertRaises(network.NetworkError):
                self.net.repair_missing(guard_blocked=True)
        recovered = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT,
            wireguard_root=self.wireguard, owner_uid=os.getuid(), receipt=ownership.read_receipt(self.fd))
        self.assertIn('route:preferred', recovered.health().changed)
        with self.assertRaises(network.NetworkError):
            recovered.repair_missing(guard_blocked=True)
        with self.assertRaises(network.NetworkError):
            recovered.disable(guard_blocked=True)
        self._assert_anchors_retained()

    def test_repair_configuration_failure_retains_guarding_resources_and_private_evidence(self):
        self._repair_fixture(delete_interface=True)
        self.kernel.fail_prefix = ('wg', 'setconf')
        with self.assertRaises(network.NetworkError) as error:
            self.net.repair_missing(guard_blocked=True)
        self.assertNotIn(PRIVATE, str(error.exception))
        self.assertTrue(any(r.kind == 'private_file' for r in self.net.receipt.resources))
        self.assertFalse(self.net.health().ready)
        self._assert_anchors_retained()

    def test_repair_exclusive_create_race_never_adopts_the_appearing_interface(self):
        self._repair_fixture(delete_interface=True)
        def race(argv, *, input=None):
            if argv[:3] == ('ip', 'link', 'add'):
                self.kernel.links.append({'ifname': 'wgps0', 'ifindex': 99, 'mtu': 1500})
            return self.kernel(argv, input=input)
        self.net.runner = race
        with self.assertRaises(network.NetworkError):
            self.net.repair_missing(guard_blocked=True)
        self.assertTrue(self.net.uncertain)
        self.assertFalse(any(c[:3] == ('ip', 'link', 'set') for c in self.kernel.calls))
        self.assertIn('interface:wgps0', self.net.health().changed)
        self._assert_anchors_retained()

    def test_repair_fence_before_failed_create_allows_retry_only_when_still_missing(self):
        self._repair_fixture()
        self.kernel.fail_prefix = ('ip', '-4', 'route', 'add')
        with self.assertRaises(network.NetworkError):
            self.net.repair_missing(guard_blocked=True)
        self.kernel.fail_prefix = None
        recovered = network.Network(PROFILE, self.fd, runner=self.kernel, boot_id=BOOT,
            wireguard_root=self.wireguard, owner_uid=os.getuid(), receipt=ownership.read_receipt(self.fd))
        self.assertEqual(recovered.health().missing, ('route:preferred',))
        recovered.repair_missing(guard_blocked=True)
        self.assertTrue(recovered.health().ready)
        self.net = recovered
        self._assert_anchors_retained()


if __name__ == '__main__':
    unittest.main()
