"""Generation sanity checks on owner-known parameters (not a security certificate)."""


def primes_too_close(p: int, q: int) -> bool:
    """Exact comparison with the lab's 2 * (p*q)**(1/4) separation margin."""
    if min(p, q) < 2:
        raise ValueError("expected two positive prime factors")
    return (p - q) ** 4 <= 16 * p * q


def private_exponent_too_small(n: int, d: int) -> bool:
    """Conservative generation floor: d must exceed 2**floor(bit_length(n)/2)."""
    if n < 3 or d < 1:
        raise ValueError("expected a positive private exponent and modulus")
    return d <= 1 << (n.bit_length() // 2)
