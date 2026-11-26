"""Natural-language -> shield policy generation (deterministic parser + LLM hook)."""

from aegis.nlgen.parser import NlParser
from aegis.nlgen.compiler import compile_intent

__all__ = ["NlParser", "compile_intent"]
