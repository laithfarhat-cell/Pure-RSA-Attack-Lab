"""Contrasting, fixed policy inputs for the CLI. None is a ciphertext challenge."""

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

from core.rsa_engine import PublicKey

from . import batch_gcd, common_modulus, fermat, hastad, malleability, wiener
from .finding import Finding


@dataclass(frozen=True, slots=True)
class Lesson:
    title: str
    inputs: str
    criterion: str
    remedy: str
    risk_case: Callable[[], Finding]
    control: Callable[[], Finding]


LESSONS = {
    "fermat": Lesson(
        "Prime separation · Fermat",
        "Two prime factors already known to the key generator.",
        "Flag if the fourth power of their gap is at most 16 times their product.",
        "Sample both primes independently; discard pairs inside the separation margin.",
        partial(fermat.check, 101, 103),
        partial(fermat.check, 101, 197),
    ),
    "wiener": Lesson(
        "Private exponent size · Wiener",
        "A modulus and its owner-supplied private exponent.",
        "Flag if d is at most 2 raised to floor(modulus bits / 2).",
        "Derive d from the public exponent and reject unusually small d; use CRT for speed.",
        partial(wiener.check, 101 * 197, 3),
        partial(wiener.check, 101 * 197, 1009),
    ),
    "hastad": Lesson(
        "Broadcast reuse · Håstad",
        "One logical payload label, three recipient key IDs, and a declared padding mode.",
        "Group unpadded deliveries by label. Flag a group with multiple distinct keys.",
        "Use a fresh OAEP encoding per encryption, including for identical messages.",
        partial(
            hastad.check, tuple(hastad.Delivery("notice", k, "textbook") for k in "ABC")
        ),
        partial(
            hastad.check, tuple(hastad.Delivery("notice", k, "oaep") for k in "ABC")
        ),
    ),
    "common-mod": Lesson(
        "Modulus ownership · Common modulus",
        "Public (modulus, exponent) records from a provisioning inventory.",
        "Group by modulus. Flag a group with multiple distinct exponents.",
        "Provision an independent keypair per owner; changing only the exponent is not rotation.",
        partial(
            common_modulus.check, (PublicKey(101 * 197, 3), PublicKey(101 * 197, 17))
        ),
        partial(
            common_modulus.check, (PublicKey(101 * 197, 3), PublicKey(107 * 179, 17))
        ),
    ),
    "batch-gcd": Lesson(
        "Prime reuse · Shared component",
        "Prime pairs already held by a local key provisioner, not a pool of public moduli.",
        "Flag a component that occurs twice, regardless of position in the pair.",
        "Fix the entropy source and replace all affected keys; never log the prime values.",
        partial(batch_gcd.check, ((101, 197), (179, 101))),
        partial(batch_gcd.check, ((101, 197), (179, 107))),
    ),
    "malleability": Lesson(
        "Payload integrity · Malleability",
        "Encoding and sender-authentication policy of a command receiver.",
        "Flag textbook encoding or a sender whose identity is not authenticated.",
        "Use OAEP for encryption and an authenticated protocol before acting on the value.",
        partial(malleability.check, "textbook", sender_authenticated=False),
        partial(malleability.check, "oaep", sender_authenticated=True),
    ),
}
