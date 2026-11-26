"""Enforcement backends. Each turns an IR into concrete artifacts."""

from aegis.backend.base import Artifact, Backend
from aegis.backend.factory import BackendFactory, compile_policy

__all__ = ["Artifact", "Backend", "BackendFactory", "compile_policy"]
