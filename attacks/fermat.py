"""Check prime separation at key generation, with both factors already known."""

from core.key_policy import primes_too_close

from .finding import Finding


def check(p: int, q: int) -> Finding:
    if primes_too_close(p, q):
        return Finding(True, "The supplied prime gap is inside the near-square margin.")
    return Finding(False, "The supplied prime gap exceeds the near-square margin.")
