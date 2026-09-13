# Contributing

Issues and focused pull requests are welcome.

1. Do not commit profiles, keys, endpoints, real network settings, logs, binaries, drivers, or personal executable paths.
2. Keep the Windows 11 and native Ubuntu 26.04/kernel 7.0 support boundaries explicit. Both implementations currently cover IPv4 payloads; broader claims require actual traffic tests.
3. Run `./tests/run.sh` for Windows and `./tests/run-linux.sh` for Linux. Routing/kernel changes also require the explicit disposable-VM suite described in [Linux development](docs/linux.md).
4. Target 500 lines per source/test file, keep files below 1,000 lines, and prefer native kernel facilities over new runtime dependencies.
5. Document any change to routing, DNS attribution, failure behavior, or privileged state ownership.

Contributions are accepted under GPL-3.0-or-later.
