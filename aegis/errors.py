"""Exception hierarchy for aegis runtime shielding engine."""


class AegisError(Exception):
    """Base class for all aegis errors."""


class ConfigError(AegisError):
    """Configuration is missing or invalid."""


class PolicyError(AegisError):
    """Shield policy is invalid or semantically inconsistent."""


class CompileError(AegisError):
    """Failed to compile a policy into a backend artifact."""


class BackendError(AegisError):
    """A backend could not apply or remove a shield."""


class SignatureError(AegisError):
    """Signature knowledge base or matching failed."""


class NlGenError(AegisError):
    """Natural-language policy generation failed."""


class UnsupportedPlatformError(AegisError):
    """Requested enforcement requires a platform/privilege not available here."""
