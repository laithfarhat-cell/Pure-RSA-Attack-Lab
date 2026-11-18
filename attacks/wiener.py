"""Check the size of an owner-held private exponent; no public-key recovery."""

from core.key_policy import private_exponent_too_small

from .finding import Finding


def check(n: int, d: int) -> Finding:
    if private_exponent_too_small(n, d):
        return Finding(
            True, "The supplied private exponent is below or at the generation floor."
        )
    return Finding(False, "The supplied private exponent exceeds the generation floor.")
