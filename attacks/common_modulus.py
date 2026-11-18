"""Inventory check: one modulus must not be provisioned with multiple exponents."""

from collections.abc import Iterable

from core.rsa_engine import PublicKey

from .finding import Finding


def check(keys: Iterable[PublicKey]) -> Finding:
    exponents: dict[int, set[int]] = {}
    for key in keys:
        exponents.setdefault(key.n, set()).add(key.e)
    reused = sum(len(values) > 1 for values in exponents.values())
    if reused:
        return Finding(
            True, f"Moduli associated with multiple public exponents: {reused}."
        )
    return Finding(False, "No supplied modulus has multiple public exponents.")
