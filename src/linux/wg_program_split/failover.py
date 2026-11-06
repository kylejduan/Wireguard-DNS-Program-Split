# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded, operator-supplied WireGuard peers. No discovery or key generation."""
from dataclasses import replace
import json
import math
import time

from .config import ConfigError, _ipv4, _key, _number, _pairs, _reject_constant


MAX_PEERS = 8
FAILURES_BEFORE_SWITCH = 3
SWITCH_INTERVAL = 30


def parse_peers(text, primary):
    """Every candidate retains the primary's client identity, resolver and MTU."""
    try:
        data = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ConfigError('invalid failover JSON') from None
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'peers'} or
            type(data['schema_version']) is not int or data['schema_version'] != 1 or
            not isinstance(data['peers'], list) or not 1 <= len(data['peers']) < MAX_PEERS):
        raise ConfigError('failover requires one to seven backup peers')
    peers = [primary]
    seen = {(primary.public_key, primary.endpoint_host, primary.endpoint_port)}
    for item in data['peers']:
        if not isinstance(item, dict) or set(item) != {'public_key', 'endpoint'}:
            raise ConfigError('invalid failover peer fields')
        if not isinstance(item['public_key'], str) or not isinstance(item['endpoint'], str):
            raise ConfigError('invalid failover peer values')
        endpoint = item['endpoint'].split(':')
        if len(endpoint) != 2:
            raise ConfigError('failover endpoint requires numeric IPv4 and port')
        public = _key(item['public_key'])
        host, port = _ipv4(endpoint[0]), _number(endpoint[1], 1, 65535)
        identity = (public, host, port)
        if identity in seen:
            raise ConfigError('duplicate failover peer')
        seen.add(identity)
        peers.append(replace(primary, public_key=public, endpoint_host=host, endpoint_port=port))
    return tuple(peers)


def initial_state():
    return {'active': 0, 'pending': None, 'failures': 0, 'retry_after': 0.0}


def validate_state(state):
    if (not isinstance(state, dict) or set(state) != {'active', 'pending', 'failures', 'retry_after'} or
            type(state['active']) is not int or not 0 <= state['active'] < MAX_PEERS or
            (state['pending'] is not None and
             (type(state['pending']) is not int or not 0 <= state['pending'] < MAX_PEERS or
              state['pending'] == state['active'])) or
            type(state['failures']) is not int or not 0 <= state['failures'] <= FAILURES_BEFORE_SWITCH or
            type(state['retry_after']) not in (int, float) or
            not math.isfinite(state['retry_after']) or state['retry_after'] < 0):
        raise ConfigError('invalid failover journal')


def boot_seconds():
    # Shared across process restarts; independent of wall-clock adjustments.
    # The enclosing journal's boot ID prevents reuse after a machine restart.
    return time.clock_gettime(time.CLOCK_BOOTTIME)
