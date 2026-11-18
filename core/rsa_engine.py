"""Two-prime RSA and RSAES-OAEP (RFC 8017, SHA-256 for both hashes).

Textbook operations expose integer representatives for study. Neither Python
integers nor the padding decoder provide constant-time execution guarantees.
"""

import hashlib
import math
import secrets
from dataclasses import dataclass

from .key_policy import primes_too_close, private_exponent_too_small
from .number_theory import (
    DEFAULT_ROUNDS,
    gcd,
    generate_prime,
    is_probable_prime,
    mod_inverse,
    mod_pow,
)

DEFAULT_E = 65537
HASH_LEN = hashlib.sha256().digest_size
_OAEP_ERROR = "OAEP decryption failed"


class DecryptionError(ValueError):
    """A ciphertext could not be decrypted and validated."""


@dataclass(frozen=True, slots=True)
class PublicKey:
    n: int
    e: int = DEFAULT_E

    def __post_init__(self) -> None:
        if self.n < 5 or self.n % 2 == 0:
            raise ValueError("RSA modulus must be odd and greater than three")
        if not 3 <= self.e < self.n or self.e % 2 == 0 or gcd(self.e, self.n) != 1:
            raise ValueError("invalid RSA public exponent")

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True, slots=True, repr=False)
class PrivateKey:
    """Derived key material. Use generate_keypair or from_primes to construct."""

    public_key: PublicKey
    p: int
    q: int
    d: int
    dp: int
    dq: int
    q_inv: int

    @classmethod
    def from_primes(cls, p: int, q: int, e: int = DEFAULT_E) -> "PrivateKey":
        """Validate imported factors; derive all other fields, never trust cached CRT values."""
        if not is_probable_prime(p) or not is_probable_prime(q):
            raise ValueError("RSA factors must be probable primes")
        return cls._from_probable_primes(p, q, e)

    @classmethod
    def _from_probable_primes(cls, p: int, q: int, e: int) -> "PrivateKey":
        # Imported factors have been checked by from_primes; generated ones
        # have already passed the primality engine. Do not run it twice.
        if min(p, q) <= 2 or p == q:
            raise ValueError("RSA requires distinct odd prime factors")
        public = PublicKey(p * q, e)
        d = mod_inverse(e, math.lcm(p - 1, q - 1))
        return cls(public, p, q, d, d % (p - 1), d % (q - 1), mod_inverse(q, p))


def _rsa_prime(bits: int, e: int, rounds: int) -> int:
    while True:
        prime = generate_prime(bits, rounds)
        if gcd(e, prime - 1) == 1 and e % prime != 0:
            return prime


def generate_keypair(
    bits: int = 2048, e: int = DEFAULT_E, rounds: int = DEFAULT_ROUNDS
) -> tuple[PublicKey, PrivateKey]:
    """Generate an exact-width modulus; sizes below 2048 are for lab exercises only."""
    if bits < 512:
        raise ValueError("the lab minimum modulus width is 512 bits")
    if e < 3 or e % 2 == 0 or e.bit_length() >= bits:
        raise ValueError("e must be odd, at least 3, and fit in bits - 1 bits")
    if rounds < 1:
        raise ValueError("Miller–Rabin requires at least one round")
    while True:
        p = _rsa_prime(bits // 2, e, rounds)
        q = _rsa_prime(bits - bits // 2, e, rounds)
        n = p * q
        if n.bit_length() != bits or primes_too_close(p, q):
            continue
        private = PrivateKey._from_probable_primes(p, q, e)
        if not private_exponent_too_small(n, private.d):
            return private.public_key, private


def _check_representative(value: int, n: int) -> None:
    if not isinstance(value, int) or not 0 <= value < n:
        raise ValueError("RSA representative must be an integer in [0, n)")


def encrypt_textbook(message: int, key: PublicKey) -> int:
    """Raw deterministic RSA public operation. Not a secure message encoding."""
    _check_representative(message, key.n)
    return mod_pow(message, key.e, key.n)


def _crt_pow(value: int, key: PrivateKey) -> int:
    mp = mod_pow(value, key.dp, key.p)
    mq = mod_pow(value, key.dq, key.q)
    return mq + key.q * ((key.q_inv * (mp - mq)) % key.p)


def decrypt_textbook(ciphertext: int, key: PrivateKey, *, use_crt: bool = True) -> int:
    """Raw private operation, blinded and checked. The direct path is for comparison."""
    n, e = key.public_key.n, key.public_key.e
    _check_representative(ciphertext, n)
    while True:
        r = secrets.randbelow(n - 3) + 2
        if gcd(r, n) == 1:
            break
    blinded = ciphertext * mod_pow(r, e, n) % n
    value = _crt_pow(blinded, key) if use_crt else mod_pow(blinded, key.d, n)
    message = value * mod_inverse(r, n) % n
    if mod_pow(message, e, n) != ciphertext:
        raise DecryptionError("RSA private operation failed")
    return message


def mgf1(seed: bytes, length: int) -> bytes:
    """RFC 8017 B.2.1, with SHA-256 and four-octet big-endian counters."""
    if not 0 <= length <= HASH_LEN * (1 << 32):
        raise ValueError("mask length outside the MGF1 domain")
    blocks = (length + HASH_LEN - 1) // HASH_LEN
    return b"".join(
        hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        for counter in range(blocks)
    )[:length]


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """Encode a byte string to a k-octet OAEP block with a fresh secret seed."""
    capacity = k - 2 * HASH_LEN - 2
    if capacity < 0:
        raise ValueError("modulus is too short for SHA-256 OAEP")
    if len(message) > capacity:
        raise ValueError(f"message exceeds SHA-256 OAEP capacity ({capacity} bytes)")
    db = (
        hashlib.sha256(label).digest()
        + bytes(capacity - len(message))
        + b"\x01"
        + message
    )
    seed = secrets.token_bytes(HASH_LEN)
    masked_db = _xor(db, mgf1(seed, len(db)))
    masked_seed = _xor(seed, mgf1(masked_db, HASH_LEN))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, label: bytes = b"") -> bytes:
    """Validate the whole padding structure before releasing any message bytes."""
    if len(encoded) < 2 * HASH_LEN + 2:
        raise DecryptionError(_OAEP_ERROR)
    masked_seed, masked_db = encoded[1 : 1 + HASH_LEN], encoded[1 + HASH_LEN :]
    seed = _xor(masked_seed, mgf1(masked_db, HASH_LEN))
    db = _xor(masked_db, mgf1(seed, len(masked_db)))
    hash_ok = secrets.compare_digest(db[:HASH_LEN], hashlib.sha256(label).digest())
    invalid = encoded[0] != 0 or not hash_ok
    start = None
    for index in range(HASH_LEN, len(db)):
        if start is None:
            if db[index] == 1:
                start = index + 1
            elif db[index] != 0:
                invalid = True
    if invalid or start is None:
        raise DecryptionError(_OAEP_ERROR)
    return db[start:]


def encrypt_oaep(message: bytes, key: PublicKey, label: bytes = b"") -> bytes:
    """RSAES-OAEP encryption. Ciphertext is always exactly key.size_bytes long."""
    k = key.size_bytes
    encoded = oaep_encode(message, k, label)
    ciphertext = encrypt_textbook(int.from_bytes(encoded, "big"), key)
    return ciphertext.to_bytes(k, "big")


def decrypt_oaep(ciphertext: bytes, key: PrivateKey, label: bytes = b"") -> bytes:
    """RSAES-OAEP decryption. Length, range, RSA and padding failures share one error."""
    k = key.public_key.size_bytes
    if len(ciphertext) != k or k < 2 * HASH_LEN + 2:
        raise DecryptionError(_OAEP_ERROR)
    value = int.from_bytes(ciphertext, "big")
    if value >= key.public_key.n:
        raise DecryptionError(_OAEP_ERROR)
    try:
        encoded = decrypt_textbook(value, key).to_bytes(k, "big")
    except DecryptionError:
        raise DecryptionError(_OAEP_ERROR) from None
    return oaep_decode(encoded, label)
