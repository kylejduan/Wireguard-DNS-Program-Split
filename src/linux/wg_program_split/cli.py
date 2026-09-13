"""Include-only command line; installed entrypoint runs in Python isolated mode."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from .config import parse_profile, parse_settings
from .install import install, uninstall, verify_units

SERVICE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def _service_units():
    units = verify_units()
    for unit in units:
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '-p', 'FragmentPath', '-p', 'DropInPaths'],
                                check=True, capture_output=True, text=True, timeout=30, env=SERVICE_ENV)
        observed = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if (observed.get('FragmentPath') != '/usr/lib/systemd/system/' + unit or
                observed.get('DropInPaths') != ''):
            raise RuntimeError('service has foreign overrides; refusing service control')
    return units


def _services(*operation):
    units = _service_units()
    subprocess.run(['/usr/bin/systemctl', *operation, *units], check=True, timeout=60,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=SERVICE_ENV)


def _parser():
    parser = argparse.ArgumentParser(prog='wg-program-split')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('validate', 'plan', 'install'):
        command = commands.add_parser(name)
        command.add_argument('--profile', required=True, type=Path)
        command.add_argument('--settings', required=True, type=Path)
        if name == 'install':
            command.add_argument('--artifacts', type=Path, default=Path(sys.argv[0]).resolve().parent)
    for name in ('activate', 'status', 'check', 'disable', 'uninstall', 'guard', 'daemon'):
        commands.add_parser(name)
    include = commands.add_parser('include').add_subparsers(dest='operation', required=True)
    include.add_parser('list')
    for name in ('add', 'remove'):
        include.add_parser(name).add_argument('path')
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command in ('validate', 'plan', 'install'):
            profile_text, settings_text = args.profile.read_text(), args.settings.read_text()
            profile, settings = parse_profile(profile_text), parse_settings(settings_text)
            if args.command == 'validate':
                result = {'valid': True, 'mode': 'include', 'included': len(settings.included_executables)}
            elif args.command == 'plan':
                result = {'mode': 'include', 'included_executables': list(settings.included_executables),
                          'vpn_dns': profile.resolver, 'address': profile.address, 'mtu': profile.mtu,
                          'unlisted': 'existing host routing and DNS', 'activation': 'separate',
                          'restart_required': 'processes already running when protection is activated or enrolled'}
            else:
                from .preflight import check_host
                check_host()
                result = install(args.artifacts, profile_text, settings_text)
                subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=SERVICE_ENV)
        else:
            from .controller import Controller
            controller = Controller()
            if args.command == 'include':
                method = getattr(controller, 'include_' + args.operation)
                result = method() if args.operation == 'list' else method(args.path)
            elif args.command == 'daemon':
                controller.watch()
                return 0
            elif args.command == 'uninstall':
                _services('disable', '--now')
                controller.disable()
                result = uninstall()
                subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=SERVICE_ENV)
            elif args.command == 'disable':
                _services('disable', '--now')
                result = controller.disable()
            elif args.command == 'activate':
                _service_units()
                try:
                    _services('enable', '--now')
                    result = controller.activate()
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    try:
                        _services('stop')
                    finally:
                        controller.guard()
                    raise
                result = controller.status()
            else:
                result = getattr(controller, args.command)()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'wg-program-split: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
