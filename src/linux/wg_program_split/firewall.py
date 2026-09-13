"""Owned kernel DNS translation and egress rules; never edit host DNS."""
from dataclasses import dataclass
from ipaddress import IPv4Address
import re


@dataclass(frozen=True)
class Firewall:
    address: str
    resolver: str
    interface: str = 'wgps0'
    table: str = 'wg_program_split'
    mask: int = 0x00ff0000
    mark: int = 0x00010000
    zone: int = 57001

    def __post_init__(self):
        for name, limit in ((self.interface, 15), (self.table, 32)):
            if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]*', name) or len(name) > limit:
                raise ValueError('invalid owned interface/table name')
        for value in (self.address, self.resolver):
            addr = IPv4Address(value)
            if addr.is_unspecified or addr.is_loopback or addr.is_multicast or int(addr) == 0xffffffff:
                raise ValueError('address must be unicast non-loopback IPv4')
        if not (0 < self.mask <= 0xffffffff and 0 < self.mark <= 0xffffffff) or self.mark & ~self.mask:
            raise ValueError('nonzero mark must fit owned mask')
        if not isinstance(self.zone, int) or isinstance(self.zone, bool) or not 0 < self.zone <= 65535:
            raise ValueError('conntrack zone must be a nonzero u16')

    def render(self):
        selected = f'meta mark & {self.mask:#x} == {self.mark:#x}'
        return f'''table inet {self.table} {{
 chain vpn_zone_output {{ type filter hook output priority raw; policy accept;
  meta nfproto ipv4 {selected} ip daddr != 127.0.0.0/8 ct zone set {self.zone}
  meta nfproto ipv4 {selected} udp dport 53 ct zone set {self.zone}
  meta nfproto ipv4 {selected} tcp dport 53 ct zone set {self.zone}
 }}
 chain vpn_zone_input {{ type filter hook prerouting priority raw; policy accept;
  iifname "{self.interface}" ct zone set {self.zone}
 }}
 chain dns_output {{ type nat hook output priority dstnat; policy accept;
  meta nfproto ipv4 {selected} udp dport 53 counter dnat ip to {self.resolver}:53
  meta nfproto ipv4 {selected} tcp dport 53 counter dnat ip to {self.resolver}:53
 }}
 chain vpn_source {{ type nat hook postrouting priority srcnat; policy accept;
  meta nfproto ipv4 {selected} oifname "{self.interface}" counter snat ip to {self.address}
 }}
 chain egress {{ type filter hook postrouting priority filter; policy accept;
  meta nfproto ipv6 {selected} counter drop
  {selected} oifname "{self.interface}" accept
  {selected} oifname "lo" ip daddr 127.0.0.0/8 accept
  {selected} counter drop
 }}
 chain loopback_input {{ type filter hook input priority filter; policy accept;
  iifname "{self.interface}" ip daddr 127.0.0.0/8 ct state established ct status snat ip saddr {self.resolver} udp sport 53 accept
  iifname "{self.interface}" ip daddr 127.0.0.0/8 ct state established ct status snat ip saddr {self.resolver} tcp sport 53 accept
  iifname "{self.interface}" ip daddr 127.0.0.0/8 counter drop
 }}
}}
'''
