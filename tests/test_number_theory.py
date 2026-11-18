import math

import pytest

from core import number_theory as nt


@pytest.mark.parametrize("modulus", [1, 2, 13, 100, 2**127 - 1])
def test_mod_pow_matches_integer_oracle(modulus):
    for base in (-97, 0, 1, 13, 2**129):
        for exponent in (0, 1, 2, 19, 257):
            assert nt.mod_pow(base, exponent, modulus) == pow(base, exponent, modulus)


def test_bezout_identity_with_signs_and_zero():
    for a in (-84, -1, 0, 1, 24, 84):
        for b in (-60, 0, 1, 60, 240):
            g, x, y = nt.egcd(a, b)
            assert a * x + b * y == g == nt.gcd(a, b) == math.gcd(a, b)
    assert nt.mod_inverse(-3, 11) == 7


@pytest.mark.parametrize(
    ("residues", "moduli"), [([2, 3, 2], [3, 5, 7]), ([-1, 34], [9, 8]), ([90], [11])]
)
def test_crt_range_and_all_residues(residues, moduli):
    x = nt.crt(iter(residues), iter(moduli))
    assert 0 <= x < math.prod(moduli)
    assert all(x % m == r % m for r, m in zip(residues, moduli))


@pytest.mark.parametrize(
    ("residues", "moduli"),
    [([], []), ([0, 1], [2]), ([1], [2, 3]), ([1, 2], [6, 9]), ([0], [1])],
)
def test_crt_rejects_bad_systems(residues, moduli):
    with pytest.raises(ValueError):
        nt.crt(residues, moduli)


@pytest.mark.parametrize("k", [1, 2, 3, 7, 41])
def test_floor_root_immediately_around_perfect_powers(k):
    for base in (1, 2, 19, 2**67 + 3):
        for n in (base**k - 1, base**k, base**k + 1):
            r = nt.nth_root(n, k)
            assert r**k <= n < (r + 1) ** k
    assert nt.nth_root(10, 10**10) == 1


@pytest.mark.parametrize(
    ("fn", "args"),
    [
        (nt.mod_pow, (2, -1, 7)),
        (nt.mod_pow, (2, 3, 0)),
        (nt.mod_inverse, (3, 1)),
        (nt.mod_inverse, (8, 12)),
        (nt.nth_root, (-1, 3)),
        (nt.nth_root, (1, 0)),
        (nt.generate_prime, (1,)),
        (nt.generate_prime, (17, 0)),
        (nt.is_probable_prime, (2, 0)),
    ],
)
def test_arithmetic_domain_errors(fn, args):
    with pytest.raises(ValueError):
        fn(*args)


def test_primality_engine_rejects_composites_beyond_trial_division(monkeypatch):
    draws = []

    def base_two(limit):
        draws.append(limit)
        return 0

    monkeypatch.setattr(nt.secrets, "randbelow", base_two)
    for n in (-3, 0, 1, 4, 561, 1105, 1009 * 1013, 1009**2):
        assert not nt.is_probable_prime(n)
    for n in (2, 3, 5, 251):
        assert nt.is_probable_prime(n)
    draws.clear()
    assert nt.is_probable_prime(2**31 - 1)
    assert draws == [2**31 - 4] * 40
    draws.clear()
    assert nt.is_probable_prime(2**31 - 1, rounds=7)
    assert len(draws) == 7


@pytest.mark.parametrize("bits", [2, 7, 31, 65])
def test_generate_prime_exact_width(bits):
    p = nt.generate_prime(bits)
    assert p.bit_length() == bits and p % 2 == 1
    assert nt.is_probable_prime(p)
