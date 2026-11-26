"""aegis — Linux runtime shielding engine (temporary eBPF/seccomp shields).

A zero-dependency, pure-Python control plane that turns a declarative
shield policy into concrete enforcement artifacts across multiple Linux
backends (seccomp / eBPF / AppArmor / nftables) — plus a cross-platform
audit backend for dry-run validation.

Inspired by OpenAI + Cisco's open-source "Shirudo": temporarily shield a
running Linux service from exploit attempts while a patch is being
deployed, without restarting the service.
"""

from aegis.version import __version__  # noqa: F401
from aegis.api import Aegis  # noqa: F401

__all__ = ["Aegis", "__version__"]
