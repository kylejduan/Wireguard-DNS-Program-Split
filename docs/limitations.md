# Limitations

- IPv4 only. A host with working IPv6 can leak selected-process IPv6 on the physical path. Do not deploy until the host has no usable IPv6 default route, or add separately audited per-application IPv6 blocking.
- Ordinary Windows DNS only. Application-owned DoH, DoT, DoQ, raw DNS sockets, and hard-coded IP addresses are payload traffic; they are not rewritten to the profile DNS.
- Exact executable paths only. Child, helper, service, launcher, and updater processes require their own entries.
- Existing sockets keep their route until closed.
- Dynamic WFP objects disappear when `wfp-probe.exe` exits. The controller normally recreates them, but the interruption is fail-open for payload.
- Stopping or disabling the project restores ordinary direct access. This is not a persistent kill switch.
- DNS process attribution depends on an undocumented-in-this-project Windows DNS Client ETW event shape and can change in future Windows builds.
- A missing process hint is fail-closed for that DNS query (`SERVFAIL`), but a direct query already in flight during a near-simultaneous same-name/type selected lookup may have reached the physical resolver or Windows cache.
- DNS response TTLs are zeroed and Windows DNS cache TTL is capped while active. This improves separation but increases query count.
- Dispatcher logs contain queried names, process IDs, and executable paths, are readable only by SYSTEM/Administrators, and grow until the dispatcher restarts. Treat them as sensitive and rotate or remove them when needed.
- Selected and unlisted applications still share the Windows DNS Client service, loopback dispatcher, host, and administrator trust boundary. This is operational isolation, not a formal security boundary.
- LAN destinations follow the Windows route table. No automatic LAN bypass policy is added, and selected-process LAN behavior depends on the supplied PIA callout implementation; validate it for the intended topology.
- Only one physical default route/DNS source is selected. The controller detects changes every 30 seconds and restarts the stack, so multi-homed, roaming, captive-portal, and rapidly changing adapter setups can experience a short outage and still require live validation.
- Third-party WireGuard DLL and PIA driver compatibility is version-sensitive and outside this project's release process.
