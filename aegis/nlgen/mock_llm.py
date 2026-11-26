"""Deterministic mock LLM for NL generation (fully offline, reproducible)."""

from aegis.utils.rng import DeterministicRNG


class MockLLM:
    """A stand-in for an LLM that returns deterministic, scripted responses.

    Used to validate the NL pipeline end-to-end without any network or API key.
    A real LLM adapter can replace it by implementing ``generate(prompt) -> str``.
    """

    def __init__(self, skill: float = 1.0):
        self.skill = skill
        self.rng = DeterministicRNG("aegis-mock-llm")

    def generate(self, prompt: str, **kwargs) -> str:
        # The mock echoes a canonical policy fragment; in real use the prompt
        # template drives a model to emit YAML. Here we keep it deterministic.
        return self.rng.choice([
            "block outbound traffic",
            "deny execve and fork",
            "make the filesystem read-only",
        ])
