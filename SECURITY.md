# Security policy

## Supported versions

Only the latest commit on `main` is maintained while the project is experimental.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories rather than a public issue. Do not include real WireGuard profiles, private keys, public IP addresses, logs containing local paths, or other personal network data.

## Deployment warning

This software runs PowerShell as SYSTEM, installs WFP state, changes NRPT and DNS-cache policy, and stores a WireGuard private key locally. Review the source, verify dependency signatures, and test on a non-critical machine before relying on it. Persistent WFP filters protect selected IPv4 payloads and block their non-loopback IPv6 while enabled. Ordinary DNS can fall back to the physical resolver if the dispatcher cannot recover; see [limitations](docs/limitations.md). This is not a hardened anonymity product. Optional [physical network recovery](docs/network-recovery.md) can restart explicitly enrolled adapters and keeps private, bounded diagnostic records.
