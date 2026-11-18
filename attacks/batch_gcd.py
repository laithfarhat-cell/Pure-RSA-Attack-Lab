"""Provisioning-time reuse check on known prime pairs, not a public-modulus scanner."""

from collections.abc import Iterable

from .finding import Finding


def check(prime_pairs: Iterable[tuple[int, int]]) -> Finding:
    seen: set[int] = set()
    for p, q in prime_pairs:
        if min(p, q) < 2:
            raise ValueError("expected owner-supplied prime factors")
        if p == q or p in seen or q in seen:
            return Finding(True, "A supplied prime component occurs more than once.")
        seen.update((p, q))
    return Finding(False, "All supplied prime components are distinct.")
