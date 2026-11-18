"""Integer arithmetic for the RSA lab. No floating-point approximations."""

import math
import secrets
from collections.abc import Iterable

DEFAULT_ROUNDS = 40
_SMALL_PRIMES = (
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
)


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Return base**exponent modulo a positive modulus by square-and-multiply."""
    if modulus <= 0 or exponent < 0:
        raise ValueError("modulus must be positive and exponent nonnegative")
    result = 1 % modulus
    base %= modulus
    while exponent:
        if exponent & 1:
            result = result * base % modulus
        base = base * base % modulus
        exponent >>= 1
    return result


def gcd(a: int, b: int) -> int:
    """Nonnegative greatest common divisor; gcd(0, 0) = 0."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that g = gcd(a, b) = a*x + b*y."""
    old_r, r = abs(a), abs(b)
    old_x, x, old_y, y = 1, 0, 0, 1
    while r:
        quotient, remainder = divmod(old_r, r)
        old_r, r = r, remainder
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return old_r, old_x if a >= 0 else -old_x, old_y if b >= 0 else -old_y


def mod_inverse(value: int, modulus: int) -> int:
    """Multiplicative inverse in Z/modulus, in the interval [0, modulus)."""
    if modulus < 2:
        raise ValueError("inverse requires a modulus greater than one")
    divisor, coefficient, _ = egcd(value, modulus)
    if divisor != 1:
        raise ValueError("multiplicative inverse does not exist")
    return coefficient % modulus


def crt(residues: Iterable[int], moduli: Iterable[int]) -> int:
    """Least nonnegative simultaneous residue for pairwise coprime moduli > 1."""
    result, product = 0, 1
    for residue, modulus in zip(residues, moduli, strict=True):
        # Add a multiple of product: all previously established residues stay put.
        scale = (residue - result) * mod_inverse(product, modulus) % modulus
        result += product * scale
        product *= modulus
    if product == 1:
        raise ValueError("CRT requires at least one congruence")
    return result


def nth_root(n: int, k: int) -> int:
    """Floor of the k-th root of a nonnegative integer, including at perfect powers."""
    if n < 0 or k < 1:
        raise ValueError("root requires n >= 0 and k >= 1")
    if n < 2 or k == 1:
        return n
    if k == 2:
        return math.isqrt(n)
    if k >= n.bit_length():
        return 1
    low, high = 1, 1 << ((n.bit_length() + k - 1) // k)
    while high - low > 1:
        mid = (low + high) // 2
        if mid**k <= n:
            low = mid
        else:
            high = mid
    return low


def is_probable_prime(n: int, rounds: int = DEFAULT_ROUNDS) -> bool:
    """Trial division followed by strong Miller–Rabin with independent random bases."""
    if rounds < 1:
        raise ValueError("Miller–Rabin requires at least one round")
    if n < 2:
        return False
    for prime in _SMALL_PRIMES:
        if n % prime == 0:
            return n == prime
        if prime * prime > n:
            return True

    # n - 1 = odd * 2**s. A prime admits only the roots +1 and -1 of unity
    # of order dividing two, which constrains this repeated-squaring chain.
    odd, s = n - 1, 0
    while odd % 2 == 0:
        odd //= 2
        s += 1
    for _ in range(rounds):
        base = 2 + secrets.randbelow(n - 3)
        x = mod_pow(base, odd, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rounds: int = DEFAULT_ROUNDS) -> int:
    """Sample odd, exact-width candidates from the OS CSPRNG until one passes."""
    if bits < 2 or rounds < 1:
        raise ValueError("prime generation requires at least two bits and one round")
    high_bit = 1 << (bits - 1)
    while True:
        candidate = secrets.randbits(bits) | high_bit | 1
        if is_probable_prime(candidate, rounds):
            return candidate
