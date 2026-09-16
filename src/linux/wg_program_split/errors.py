# SPDX-License-Identifier: GPL-3.0-or-later
"""Network error type shared by the inventory parsers and the network adapter."""


class NetworkError(RuntimeError):
    """A bounded operation failed; never include command output or profile data."""
