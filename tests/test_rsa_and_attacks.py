"""RSA correctness, RFC 8017 encoding and the six *defensive* weakness lessons."""

import hashlib
import math

import pytest

from attacks import batch_gcd, common_modulus, fermat, hastad, malleability, wiener
from attacks.lessons import LESSONS
from core import rsa_engine as rsa
from core.number_theory import is_probable_prime


def test_keygen_invariants(keypair):
    pub, key = keypair
    assert pub == key.public_key
    assert pub.n == key.p * key.q and key.p != key.q
    assert pub.n.bit_length() == 1025 and pub.size_bytes == 129
    assert key.p.bit_length() == 512 and key.q.bit_length() == 513
    assert is_probable_prime(key.p) and is_probable_prime(key.q)
    lam = math.lcm(key.p - 1, key.q - 1)
    assert pub.e == 65537 and math.gcd(pub.e, lam) == 1
    assert pub.e * key.d % lam == 1 and 0 < key.d < lam
    assert key.dp == key.d % (key.p - 1) and key.dq == key.d % (key.q - 1)
    assert key.q_inv * key.q % key.p == 1
    assert not fermat.check(key.p, key.q).flagged
    assert not wiener.check(pub.n, key.d).flagged
    assert str(key.p) not in repr(key)


def test_custom_exponent_and_minimum_size():
    public, private = rsa.generate_keypair(512, e=17)
    assert public.n.bit_length() == 512 and public.e == 17
    assert rsa.decrypt_textbook(rsa.encrypt_textbook(42, public), private) == 42
    with pytest.raises(ValueError, match="too short"):
        rsa.encrypt_oaep(b"", public)


@pytest.mark.parametrize(
    ("bits", "e", "rounds"),
    [(511, 65537, 40), (512, 1, 40), (512, 4, 40), (512, 2**511 + 1, 40), (512, 17, 0)],
)
def test_invalid_keygen_parameters(bits, e, rounds):
    with pytest.raises(ValueError):
        rsa.generate_keypair(bits, e, rounds)


@pytest.mark.parametrize(
    ("p", "q", "e"), [(61, 61, 17), (2, 61, 17), (61, 55, 17), (61, 53, 15)]
)
def test_reject_invalid_imported_factors_or_exponent(p, q, e):
    with pytest.raises(ValueError):
        rsa.PrivateKey.from_primes(p, q, e)


def test_direct_crt_and_builtin_pow_agree_including_nonunits(keypair):
    public, private = keypair
    for message in (0, 1, 42, private.p, private.q, public.n - 1):
        c = rsa.encrypt_textbook(message, public)
        assert c == pow(message, public.e, public.n)
        assert rsa.decrypt_textbook(c, private) == message
        assert rsa.decrypt_textbook(c, private, use_crt=False) == message
        assert pow(c, private.d, public.n) == message
    for invalid in (-1, public.n, public.n + 1):
        with pytest.raises(ValueError):
            rsa.encrypt_textbook(invalid, public)
        with pytest.raises(ValueError):
            rsa.decrypt_textbook(invalid, private)


def test_private_operation_retries_noninvertible_blinder(keypair, monkeypatch):
    public, key = keypair
    choices = iter([key.p - 2, 0])  # r = p (reject), then r = 2.
    monkeypatch.setattr(rsa.secrets, "randbelow", lambda n: next(choices))
    assert rsa.decrypt_textbook(rsa.encrypt_textbook(123, public), key) == 123


def test_result_check_never_releases_faulty_crt_output(keypair, monkeypatch):
    pub, key = keypair
    sealed = rsa.encrypt_oaep(b"check", pub)
    monkeypatch.setattr(rsa, "_crt_pow", lambda value, private: 0)
    with pytest.raises(rsa.DecryptionError, match="private operation failed"):
        rsa.decrypt_textbook(1, key)
    with pytest.raises(rsa.DecryptionError, match="^OAEP decryption failed$"):
        rsa.decrypt_oaep(sealed, key)


def test_sha256_mgf1_fixed_vector_crossing_block_boundary():
    assert rsa.mgf1(b"field-notes", 47).hex() == (
        "f9a2d43fe6789d63a7c111cdb70550923dcb644b765508451166ef6399ab40e3"
        "b355280c7cf19443678a2ea8cd7e41"
    )
    assert rsa.mgf1(b"", 0) == b""
    for length in (-1, rsa.HASH_LEN * (1 << 32) + 1):
        with pytest.raises(ValueError):
            rsa.mgf1(b"", length)


def test_oaep_fixed_encoding_vector(monkeypatch):
    # RFC 8017 layout; reference digest blocks independently computed with OpenSSL.
    # Deterministic entropy is confined to this test, never offered by the public API.
    monkeypatch.setattr(rsa.secrets, "token_bytes", lambda size: bytes(range(size)))
    expected = bytes.fromhex(
        "00d709dc8aff1881ebbe5b3c59d1fb207b07539f752f302e4cf5e2ea2cd2ba153"
        "eaad415ace325583e38ce71e5f7c11f4c0f18edd90a8ebfb72d354843e88e1f1"
        "e04a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12d5195ec3697"
    )
    assert rsa.oaep_encode(b"\x00RSA\xff", 96, b"lab/1") == expected
    assert rsa.oaep_decode(expected, b"lab/1") == b"\x00RSA\xff"


def test_oaep_payload_boundaries_and_randomization(keypair):
    public, private = keypair
    capacity = public.size_bytes - 66
    for message in (b"", b"\x00\x01\x00\xff", bytes(range(capacity))):
        first = rsa.encrypt_oaep(message, public, b"context")
        second = rsa.encrypt_oaep(message, public, b"context")
        assert len(first) == public.size_bytes and first != second
        assert rsa.decrypt_oaep(first, private, b"context") == message
        assert rsa.decrypt_oaep(second, private, b"context") == message
    with pytest.raises(ValueError, match="capacity"):
        rsa.encrypt_oaep(bytes(capacity + 1), public)
    assert rsa.oaep_decode(rsa.oaep_encode(b"", 66)) == b""


def test_oaep_rejects_tampering_with_one_public_error(keypair):
    public, private = keypair
    c = rsa.encrypt_oaep(b"memo", public, b"context")
    changed = c[:-1] + bytes([c[-1] ^ 1])
    for ciphertext, label in [
        (changed, b"context"),
        (c[:-1], b"context"),
        (c + b"\x00", b"context"),
        (c, b"other label"),
        (public.n.to_bytes(public.size_bytes, "big"), b"context"),
    ]:
        with pytest.raises(rsa.DecryptionError, match="^OAEP decryption failed$"):
            rsa.decrypt_oaep(ciphertext, private, label)


@pytest.mark.parametrize(
    ("prefix", "padding"), [(0, b"\x00\x00"), (0, b"\x02\x01"), (1, b"\x00\x01")]
)
def test_decoder_validates_separator_zero_fill_and_prefix(prefix, padding, monkeypatch):
    # Isolate the decoder's structural validation from the mask generation step.
    monkeypatch.setattr(rsa, "mgf1", lambda seed, length: bytes(length))
    block = bytes([prefix]) + bytes(32) + hashlib.sha256(b"").digest() + padding
    with pytest.raises(rsa.DecryptionError, match="^OAEP decryption failed$"):
        rsa.oaep_decode(block)


@pytest.mark.parametrize(
    "rule", ["fermat", "wiener", "hastad", "common-mod", "batch-gcd", "malleability"]
)
def test_lessons_distinguish_risky_configuration_and_control(rule):
    lesson = LESSONS[rule]
    assert lesson.risk_case().flagged
    assert not lesson.control().flagged
    assert lesson.remedy


def test_private_parameter_policy_boundaries():
    assert fermat.check(1009, 1013).flagged
    assert not fermat.check(1009, 1601).flagged
    n = 101 * 197
    floor = 1 << (n.bit_length() // 2)
    assert wiener.check(n, floor).flagged
    assert not wiener.check(n, floor + 1).flagged


def test_delivery_check_groups_by_payload_and_distinct_unpadded_key():
    single = hastad.Delivery("memo", "A", "textbook")
    other = hastad.Delivery("memo", "B", "oaep")
    assert not hastad.check(
        [single, single, other, hastad.Delivery("log", "B", "textbook")]
    ).flagged
    assert hastad.check(
        [single, other, hastad.Delivery("memo", "C", "textbook")]
    ).flagged


def test_inventory_checks_use_only_supplied_components():
    key = rsa.PublicKey(101 * 197, 17)
    assert not common_modulus.check([key, key]).flagged
    assert common_modulus.check([key, rsa.PublicKey(key.n, 3)]).flagged
    result = batch_gcd.check([(1009, 1013), (1019, 1021), (1031, 1009)])
    assert result.flagged and "1009" not in result.detail
    assert batch_gcd.check([(101, 101)]).flagged
    assert not batch_gcd.check([(1009, 1013), (1019, 1021)]).flagged


def test_oaep_does_not_authenticate_sender():
    assert malleability.check("oaep", sender_authenticated=False).flagged
    assert not malleability.check("oaep", sender_authenticated=True).flagged
    assert malleability.check("textbook", sender_authenticated=True).flagged
