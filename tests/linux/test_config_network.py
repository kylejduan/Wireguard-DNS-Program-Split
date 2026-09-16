# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict configuration and real filesystem ownership boundaries; no network I/O."""
import base64
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

from wg_program_split import config, ownership


KEY = base64.b64encode(bytes(range(1, 33))).decode()
PUBLIC = base64.b64encode(bytes(range(33, 65))).decode()
PSK = base64.b64encode(bytes(range(65, 97))).decode()
BOOT = '11111111-2222-4333-8444-555555555555'
OTHER_BOOT = '66666666-7777-4888-8999-aaaaaaaaaaaa'
PROFILE = f'''[Interface]
PrivateKey = {KEY}
Address = 10.20.0.2/32
DNS = 10.20.0.1
[Peer]
PublicKey = {PUBLIC}
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.8:51820
'''


class TemporaryFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wgps-config-test-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def executable(self, name='program', machine=None):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        machine = machine or {'x86_64': 62, 'aarch64': 183}[platform.machine()]
        header = bytearray(64)
        header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', header, 16, 3, machine, 1)
        struct.pack_into('<H', header, 52, 64)
        path.write_bytes(header)
        path.chmod(0o700)
        return path


class ProfileTests(unittest.TestCase):
    def test_parsed_values_are_immutable_and_secrets_are_redacted(self):
        profile = config.parse_profile(PROFILE + f'PresharedKey = {PSK}\n')
        self.assertEqual((profile.address, profile.resolver, profile.endpoint_host,
                          profile.endpoint_port, profile.mtu, profile.persistent_keepalive),
                         ('10.20.0.2/32', '10.20.0.1', '192.0.2.8', 51820, 1420, 0))
        self.assertEqual(profile.private_key, KEY)
        for key in (KEY, PUBLIC, PSK):
            self.assertNotIn(key, repr(profile))
        with self.assertRaises(FrozenInstanceError):
            profile.mtu = 1500

    def test_explicit_mtu_keepalive_and_comments(self):
        text = PROFILE.replace('DNS =', 'MTU = 1500\nDNS =')
        text += 'PersistentKeepalive = 25 # explicit setting\n'
        profile = config.parse_profile(text)
        self.assertEqual((profile.mtu, profile.persistent_keepalive), (1500, 25))

    def test_rejects_utf8_profile_larger_than_runtime_byte_limit(self):
        text = PROFILE + '#' + 'é' * 40000
        self.assertLess(len(text), 65536)
        self.assertGreater(len(text.encode('utf-8')), 65536)
        with self.assertRaises(config.ConfigError) as error:
            config.parse_profile(text)
        self.assertNotIn(KEY, str(error.exception))

    def test_accepts_exact_utf8_byte_boundary_and_rejects_one_byte_more(self):
        prefix = PROFILE + '#'
        remaining = 65536 - len(prefix.encode('utf-8'))
        text = prefix + 'é' * (remaining // 2) + 'x' * (remaining % 2)
        self.assertEqual(len(text.encode('utf-8')), 65536)
        self.assertEqual(config.parse_profile(text), config.parse_profile(PROFILE))
        with self.assertRaises(config.ConfigError):
            config.parse_profile(text + 'x')

    def test_rejects_unencodable_profile_comments_without_exposing_input(self):
        for character in ('\ud800', '\udcff'):
            text = PROFILE + '# sensitive-comment-' + character
            with self.subTest(codepoint=ord(character)):
                with self.assertRaises(config.ConfigError) as error:
                    config.parse_profile(text)
                for secret in (KEY, PUBLIC, 'sensitive-comment', text):
                    self.assertNotIn(secret, str(error.exception))

    def test_rejects_duplicate_unknown_and_wg_quick_fields(self):
        additions = [f'PublicKey = {PUBLIC}', '[Peer]', '[Other]', '[DEFAULT]',
                     'Table = auto', 'FwMark = 1', 'SaveConfig = true',
                     'PreUp = unsafe', 'PostUp = unsafe', 'PreDown = unsafe',
                     'PostDown = unsafe', 'Unknown = value']
        for extra in additions:
            with self.subTest(extra=extra.split('=')[0]):
                with self.assertRaises(config.ConfigError):
                    config.parse_profile(PROFILE + extra + '\n')
        with self.assertRaises(config.ConfigError):
            config.parse_profile(PROFILE.replace('[Peer]', '[Interface]'))

    def test_rejects_invalid_keys_without_echoing_input(self):
        for key in ('sensitive-secret-text', KEY[:-1], base64.b64encode(b'x' * 31).decode(),
                    base64.b64encode(b'\0' * 32).decode(), KEY + '='):
            with self.subTest(length=len(key)):
                for field, old in (('PrivateKey', KEY), ('PublicKey', PUBLIC)):
                    with self.assertRaises(config.ConfigError) as error:
                        config.parse_profile(PROFILE.replace(f'{field} = {old}', f'{field} = {key}'))
                    self.assertNotIn(key, str(error.exception))
                    self.assertNotIn(PROFILE, str(error.exception))
        with self.assertRaises(config.ConfigError) as error:
            config.parse_profile(PROFILE + 'SECRET-INPUT-WITHOUT-EQUALS')
        self.assertNotIn('SECRET-INPUT', str(error.exception))

    def test_rejects_unsafe_ipv4_and_nonliteral_endpoint(self):
        for resolver in ('127.0.0.53', '0.1.2.3', '224.0.0.1', '255.255.255.255',
                         '240.0.0.1', '169.254.1.1', '::1', 'resolver.example',
                         '10.20.0.1, 10.20.0.3'):
            with self.subTest(resolver=resolver), self.assertRaises(config.ConfigError):
                config.parse_profile(PROFILE.replace('DNS = 10.20.0.1', f'DNS = {resolver}'))
        for endpoint in ('vpn.example:51820', '[::1]:51820', '192.0.2.8:0',
                         '192.0.2.8:65536', '192.0.2.8', '192.0.2.8:1:2'):
            with self.subTest(endpoint=endpoint), self.assertRaises(config.ConfigError):
                config.parse_profile(PROFILE.replace('192.0.2.8:51820', endpoint))

    def test_rejects_partial_routes_multiple_addresses_and_invalid_numbers(self):
        changes = [('0.0.0.0/0', '10.0.0.0/8'), ('0.0.0.0/0', '0.0.0.0/0, ::/0'),
                   ('10.20.0.2/32', '10.20.0.2/32, 10.20.0.3/32'),
                   ('10.20.0.2/32', '10.20.0.2'), ('10.20.0.2/32', '::1/128')]
        for old, new in changes:
            with self.subTest(value=new), self.assertRaises(config.ConfigError):
                config.parse_profile(PROFILE.replace(old, new))
        for extra in ('PersistentKeepalive = -1', 'PersistentKeepalive = 65536',
                      'PersistentKeepalive = true', 'PersistentKeepalive = 1.5'):
            with self.subTest(extra=extra), self.assertRaises(config.ConfigError):
                config.parse_profile(PROFILE + extra)
        for value in ('0', '575', '65536', '1e3'):
            with self.subTest(mtu=value), self.assertRaises(config.ConfigError):
                config.parse_profile(PROFILE.replace('DNS =', f'MTU = {value}\nDNS ='))
        with self.assertRaises(config.ConfigError):
            config.parse_profile(PROFILE.replace('DNS = 10.20.0.1\n', ''))


class SettingsTests(TemporaryFiles):
    def settings(self, paths):
        return json.dumps({'schema_version': 1, 'included_executables': list(map(str, paths))})

    def test_canonical_paths_serialize_deterministically_without_profile_fields(self):
        a, b = self.executable('a'), self.executable('b')
        settings = config.parse_settings(self.settings([b, a]))
        self.assertEqual(settings.included_executables, (str(a), str(b)))
        serialized = config.settings_json(settings)
        self.assertEqual(json.loads(serialized), {'schema_version': 1,
                         'included_executables': [str(a), str(b)]})
        self.assertEqual(serialized, config.settings_json(config.parse_settings(self.settings([a, b]))))
        self.assertNotIn(KEY, serialized)
        with self.assertRaises(FrozenInstanceError):
            settings.schema_version = 2

    def test_symlink_dotdot_follows_filesystem_semantics_and_duplicates_reject(self):
        executable = self.executable('real/program')
        (self.root / 'real/subdir').mkdir()
        (self.root / 'alias').symlink_to(self.root / 'real/subdir', target_is_directory=True)
        spelled = str(self.root / 'alias') + '/../program'
        self.assertEqual(config.canonical_executable(spelled), str(executable))
        with self.assertRaises(config.ConfigError):
            config.parse_settings(self.settings([executable, spelled]))

    def test_delete_identity_does_not_follow_replacement_or_require_file(self):
        path = self.executable()
        stored = str(path)
        path.unlink()
        self.assertEqual(config.policy_path(stored), stored)
        other = self.executable('replacement')
        path.symlink_to(other)
        self.assertEqual(config.policy_path(stored), stored)
        for value in (stored + '/..', str(self.root) + '//program', './program', '/' + stored, stored + '\x00'):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                config.policy_path(value)

    def test_recovery_loads_stored_policy_when_image_is_missing_or_replaced_by_symlink(self):
        path = self.executable('selected')
        text = self.settings([path])
        path.unlink()
        self.assertEqual(config.parse_policy(text).included_executables, (str(path),))
        with self.assertRaises(config.ConfigError):
            config.parse_settings(text)
        replacement = self.executable('unlisted-replacement')
        path.symlink_to(replacement)
        self.assertEqual(config.parse_policy(text).included_executables, (str(path),))
        self.assertEqual(config.parse_settings(text).included_executables, (str(replacement),))
        self.assertEqual(json.loads(config.settings_json(config.parse_policy(text))),
                         {'schema_version': 1, 'included_executables': [str(path)]})
        for paths in ([str(path), str(path)], [str(self.root) + '/./selected']):
            with self.subTest(paths=paths), self.assertRaises(config.ConfigError):
                config.parse_policy(self.settings(paths))

    def test_rejects_bad_json_schema_types_and_excess_entries(self):
        cases = ['{"schema_version":1,"schema_version":1,"included_executables":[]}',
                 '{"schema_version":true,"included_executables":[]}',
                 '{"schema_version":2,"included_executables":[]}',
                 '{"schema_version":1,"included_executables":[],"dns_listen_port":53053}',
                 '{"schema_version":1,"included_executables":[null]}',
                 '{"schema_version":1,"included_executables":NaN}', '[]', '{}', '{']
        for text in cases:
            with self.subTest(text=text), self.assertRaises(config.ConfigError):
                config.parse_settings(text)
        with self.assertRaises(config.ConfigError):
            config.parse_settings(self.settings(['/missing'] * 1025))

    def test_rejects_scripts_nonexecutables_wrong_arch_and_short_elf(self):
        bad = self.root / 'bad'
        for data, mode in ((b'#!/bin/sh\nexit 0\n', 0o700), (b'\x7fELF', 0o700)):
            bad.write_bytes(data)
            bad.chmod(mode)
            with self.assertRaises(config.ConfigError):
                config.canonical_executable(str(bad))
        path = self.executable('noexec')
        path.chmod(0o600)
        with self.assertRaises(config.ConfigError):
            config.canonical_executable(str(path))
        with self.assertRaises(config.ConfigError):
            config.canonical_executable(str(self.executable('wrong-arch', machine=3)))
        with self.assertRaises(config.ConfigError):
            config.canonical_executable(str(self.root))

    def test_invalid_path_encoding_is_a_redacted_config_error(self):
        value = str(self.root) + '/\ud800'
        for parser in (config.parse_settings, config.parse_policy):
            with self.subTest(parser=parser.__name__), self.assertRaises(config.ConfigError):
                parser(self.settings([value]))
        raw_byte_path = self.executable(os.fsdecode(b'program-\xff'))
        for parser in (config.parse_settings, config.parse_policy):
            self.assertEqual(parser(self.settings([raw_byte_path])).included_executables,
                             (str(raw_byte_path),))


class OwnershipTests(TemporaryFiles):
    def setUp(self):
        super().setUp()
        self.state = self.root / 'state'
        self.uid = os.getuid()

    def opened(self, create=True):
        fd = ownership.open_private_dir(self.state, create=create, owner_uid=self.uid)
        self.addCleanup(os.close, fd)
        return fd

    def test_creates_private_leaf_and_read_validation_does_not_repair_foreign_mode(self):
        self.opened()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.state.chmod(0o755)
        with self.assertRaises(ownership.OwnershipError):
            self.opened(create=False)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)
        missing = self.root / 'missing'
        with self.assertRaises(ownership.OwnershipError):
            ownership.open_private_dir(missing, owner_uid=self.uid)
        self.assertFalse(missing.exists())

    def test_refuses_symlink_components_writable_parent_and_wrong_owner(self):
        self.opened()
        alias = self.root / 'alias'
        alias.symlink_to(self.state, target_is_directory=True)
        for path in (alias, alias / 'child'):
            with self.subTest(path=path), self.assertRaises(ownership.OwnershipError):
                ownership.open_private_dir(path, create=True, owner_uid=self.uid)
        with self.assertRaises(ownership.OwnershipError):
            ownership.open_private_dir(self.state, owner_uid=self.uid + 1)
        self.root.chmod(0o777)
        with self.assertRaises(ownership.OwnershipError):
            ownership.open_private_dir(self.state, owner_uid=self.uid)
        self.root.chmod(0o700)

    def test_lock_is_exclusive_and_persistent_without_stealing_foreign_files(self):
        self.opened()
        with ownership.locked_state(self.state, owner_uid=self.uid):
            with self.assertRaises(ownership.OwnershipError):
                with ownership.locked_state(self.state, owner_uid=self.uid):
                    self.fail('second lock was acquired')
        with ownership.locked_state(self.state, owner_uid=self.uid):
            pass
        lock = self.state / '.lock'
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        lock.unlink()
        (self.state / '.lock').symlink_to(self.root / 'foreign')
        with self.assertRaises(ownership.OwnershipError):
            with ownership.locked_state(self.state, owner_uid=self.uid):
                pass
        self.assertFalse((self.root / 'foreign').exists())

    def test_exclusive_file_birth_and_hash_reject_tampering_and_same_name_replacement(self):
        fd = self.opened()
        identity = ownership.create_owned_file(fd, 'policy.json', b'policy\n')
        self.assertEqual(identity.sha256, hashlib.sha256(b'policy\n').hexdigest())
        self.assertEqual(identity.size, 7)
        ownership.verify_file(fd, 'policy.json', identity)
        with self.assertRaises(ownership.OwnershipError):
            ownership.create_owned_file(fd, 'policy.json', b'changed')
        (self.state / 'policy.json').rename(self.state / 'old')
        (self.state / 'policy.json').write_bytes(b'policy\n')
        (self.state / 'policy.json').chmod(0o600)
        with self.assertRaises(ownership.OwnershipError):
            ownership.verify_file(fd, 'policy.json', identity)
        self.assertEqual((self.state / 'policy.json').read_bytes(), b'policy\n')

    def test_file_identity_refuses_links_special_files_and_unsafe_names(self):
        fd = self.opened()
        identity = ownership.create_owned_file(fd, 'owned', b'one')
        (self.state / 'sym').symlink_to('owned')
        os.link(self.state / 'owned', self.state / 'hard')
        os.mkfifo(self.state / 'fifo', 0o600)
        for name in ('sym', 'owned', 'hard', 'fifo', '../escape', '/absolute'):
            with self.subTest(name=name), self.assertRaises(ownership.OwnershipError):
                ownership.file_identity(fd, name)
        self.assertEqual(identity.size, 3)

    def test_receipt_create_update_and_boot_attempt_validation(self):
        self.opened()
        with ownership.locked_state(self.state, owner_uid=self.uid) as fd:
            receipt = ownership.new_receipt(boot_id=BOOT)
            ownership.write_receipt(fd, receipt)
            self.assertEqual(ownership.read_receipt(fd), receipt)
            ownership.validate_receipt(receipt, boot_id=BOOT, attempt_id=receipt.attempt_id)
            with self.assertRaises(ownership.OwnershipError):
                ownership.validate_receipt(receipt, boot_id=OTHER_BOOT, attempt_id=receipt.attempt_id)
            with self.assertRaises(ownership.OwnershipError):
                ownership.validate_receipt(receipt, boot_id=BOOT, attempt_id=OTHER_BOOT)
            owned = ownership.create_owned_file(fd, 'policy', b'{}\n')
            updated = replace(receipt, files=(owned,))
            ownership.write_receipt(fd, updated, expected=receipt)
            self.assertEqual(ownership.read_receipt(fd), updated)
            with self.assertRaises(ownership.OwnershipError):
                ownership.write_receipt(fd, receipt, expected=receipt)
            self.assertEqual(ownership.read_receipt(fd), updated)

    def test_receipt_refuses_foreign_birth_and_malformed_or_unsafe_json(self):
        fd = self.opened()
        receipt = ownership.new_receipt(boot_id=BOOT)
        file = self.state / 'receipt.json'
        for data in ('{}', '{"schema_version":1,"schema_version":1}',
                     '{"sensitive":"never-echo-this"}', 'NaN'):
            file.write_text(data)
            file.chmod(0o600)
            with self.assertRaises(ownership.OwnershipError) as error:
                ownership.read_receipt(fd)
            self.assertNotIn('never-echo-this', str(error.exception))
            with self.assertRaises(ownership.OwnershipError):
                ownership.write_receipt(fd, receipt)
            self.assertEqual(file.read_text(), data)
        file.unlink()
        file.symlink_to(self.root / 'foreign')
        with self.assertRaises(ownership.OwnershipError):
            ownership.read_receipt(fd)
        self.assertFalse((self.root / 'foreign').exists())

    def test_failed_atomic_update_preserves_old_receipt_and_cleans_own_temp(self):
        self.opened()
        with ownership.locked_state(self.state, owner_uid=self.uid) as fd:
            receipt = ownership.new_receipt(boot_id=BOOT)
            ownership.write_receipt(fd, receipt)
            changed = replace(receipt, files=(ownership.create_owned_file(fd, 'policy', b'{}'),))
            before = set(self.state.iterdir())
            with patch('wg_program_split.ownership.os.replace', side_effect=OSError('injected publish failure')):
                with self.assertRaises(ownership.OwnershipError):
                    ownership.write_receipt(fd, changed, expected=receipt)
            self.assertEqual(ownership.read_receipt(fd), receipt)
            self.assertEqual(set(self.state.iterdir()), before)

    def test_live_resource_identity_requires_same_attempt_boot_and_observed_identity(self):
        fd = self.opened()
        receipt = replace(ownership.new_receipt(boot_id=BOOT), resources=(
            ownership.ResourceIdentity('conntrack_zone', 'dns', {'zone': 41234}),
            ownership.ResourceIdentity('interface', 'wgps0', {'ifindex': 73}),
        ))
        ownership.write_receipt(fd, receipt)
        loaded = ownership.read_receipt(fd)
        ownership.verify_resource(loaded, 'interface', 'wgps0', {'ifindex': 73},
                                  boot_id=BOOT, attempt_id=receipt.attempt_id)
        for kind, name, live in (('interface', 'wgps0', {'ifindex': 74}),
                                 ('interface', 'foreign', {'ifindex': 73}),
                                 ('conntrack_zone', 'dns', {'zone': 41235})):
            with self.subTest(kind=kind, name=name), self.assertRaises(ownership.OwnershipError):
                ownership.verify_resource(loaded, kind, name, live,
                                          boot_id=BOOT, attempt_id=receipt.attempt_id)
        with self.assertRaises(ownership.OwnershipError):
            ownership.verify_resource(loaded, 'interface', 'wgps0', {'ifindex': 73},
                                      boot_id=OTHER_BOOT, attempt_id=receipt.attempt_id)

    def test_receipt_does_not_admit_unknown_resource_kinds_or_private_profile_data(self):
        fd = self.opened()
        receipt = ownership.new_receipt(boot_id=BOOT)
        for resource in (ownership.ResourceIdentity('shell', 'run', {'command': 'never-run'}),
                         ownership.ResourceIdentity('interface', 'wgps0', {'PrivateKey': KEY})):
            with self.subTest(kind=resource.kind), self.assertRaises(ownership.OwnershipError) as error:
                ownership.write_receipt(fd, replace(receipt, resources=(resource,)))
            self.assertNotIn(KEY, str(error.exception))
        self.assertFalse((self.state / 'receipt.json').exists())

    def test_private_wireguard_birth_identities_roundtrip_without_file_contents(self):
        fd = self.opened()
        receipt = ownership.new_receipt(boot_id=BOOT)
        private = ownership.create_owned_file(fd, 'wg.conf', b'placeholder only')
        resources = (
            ownership.ResourceIdentity('private_directory', 'configuration',
                {'path': '/etc/wireguard/wgps-' + receipt.attempt_id,
                 'device': 1, 'inode': 2, 'owner_uid': 0, 'mode': 448}),
            ownership.ResourceIdentity('private_file', 'configuration',
                {'directory_device': 1, 'directory_inode': 2,
                 'file': asdict(private)}),
        )
        stored = replace(receipt, resources=resources)
        ownership.write_receipt(fd, stored)
        self.assertEqual(ownership.read_receipt(fd), stored)
        for kind in ('private_file', 'private_directory'):
            bad = replace(stored, resources=(ownership.ResourceIdentity(kind, 'configuration',
                          {'PrivateKey': KEY}),))
            with self.assertRaises(ownership.OwnershipError):
                ownership.write_receipt(fd, bad, expected=stored)

    def test_failure_after_receipt_publication_requires_readback_not_automatic_rollback(self):
        fd = self.opened()
        receipt = ownership.new_receipt(boot_id=BOOT)
        ownership.write_receipt(fd, receipt)
        changed = replace(receipt, files=(ownership.create_owned_file(fd, 'policy', b'{}'),))
        fsync = os.fsync

        def fail_directory_sync(target):
            if target == fd:
                raise OSError('injected directory fsync failure')
            fsync(target)

        with patch('wg_program_split.ownership.os.fsync', side_effect=fail_directory_sync):
            with self.assertRaises(ownership.OwnershipError):
                ownership.write_receipt(fd, changed, expected=receipt)
        self.assertEqual(ownership.read_receipt(fd), changed)
        self.assertEqual({p.name for p in self.state.iterdir()}, {'policy', 'receipt.json'})

    def test_resource_json_rejects_tuples_before_publication_and_preserves_cas_roundtrip(self):
        fd = self.opened()
        receipt = ownership.new_receipt(boot_id=BOOT)
        tuple_resource = ownership.ResourceIdentity('route', 'default', {'hops': (1, 2)})
        with self.assertRaises(ownership.OwnershipError):
            ownership.write_receipt(fd, replace(receipt, resources=(tuple_resource,)))
        self.assertFalse((self.state / 'receipt.json').exists())
        list_resource = ownership.ResourceIdentity('route', 'default', {'hops': [1, 2]})
        recorded = replace(receipt, resources=(list_resource,))
        ownership.write_receipt(fd, recorded)
        self.assertEqual(ownership.read_receipt(fd), recorded)
        ownership.write_receipt(fd, recorded, expected=recorded)

    def test_live_resource_comparison_rejects_boolean_integer_equivalence_and_nonjson_values(self):
        receipt = replace(ownership.new_receipt(boot_id=BOOT), resources=(
            ownership.ResourceIdentity('interface', 'wgps0', {'ifindex': 1}),))
        for live in ({'ifindex': True}, {'ifindex': 1.0}, {'ifindex': (1,)},
                     {'ifindex': object()}, {'PrivateKey': KEY}, None):
            with self.subTest(type=type(live).__name__), self.assertRaises(ownership.OwnershipError):
                ownership.verify_resource(receipt, 'interface', 'wgps0', live,
                                          boot_id=BOOT, attempt_id=receipt.attempt_id)

    def test_receipt_cas_distinguishes_nested_boolean_from_integer_identity(self):
        fd = self.opened()
        receipt = replace(ownership.new_receipt(boot_id=BOOT), resources=(
            ownership.ResourceIdentity('interface', 'wgps0', {'observed': {'ifindex': 1}}),))
        ownership.write_receipt(fd, receipt)
        wrong_expected = replace(receipt, resources=(ownership.ResourceIdentity(
            'interface', 'wgps0', {'observed': {'ifindex': True}}),))
        with self.assertRaises(ownership.OwnershipError):
            ownership.write_receipt(fd, receipt, expected=wrong_expected)
        self.assertEqual(ownership.read_receipt(fd), receipt)


if __name__ == '__main__':
    unittest.main()
