# Security policy

## Supported versions

Only the latest commit on `main` is maintained while the project is experimental.

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories rather than a public issue. Do not include real WireGuard profiles, private keys, public IP addresses, logs containing local paths, or other personal network data.

## Deployment warning

This software runs PowerShell as SYSTEM, installs WFP state, changes NRPT and DNS-cache policy, and stores a WireGuard private key locally. Review the source, verify dependency signatures, and test on a non-critical machine before relying on it. The current design has documented fail-open payload cases and is not a hardened anonymity or kill-switch product.
