"""Measure equivalent, checked private operations; do not time prime generation."""

import secrets
from dataclasses import dataclass
from statistics import median
from time import perf_counter_ns

from core.rsa_engine import decrypt_textbook, encrypt_textbook, generate_keypair


@dataclass(frozen=True, slots=True)
class Measurement:
    bits: int
    direct_ms: float
    crt_ms: float

    @property
    def speedup(self) -> float:
        return self.direct_ms / self.crt_ms


def measure(bits: int, iterations: int) -> Measurement:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    public, private = generate_keypair(bits)
    timings: dict[bool, list[float]] = {False: [], True: []}
    # Round 0 warms both paths. Alternate the order thereafter to mitigate drift.
    for i in range(iterations + 1):
        message = 2 + secrets.randbelow(public.n - 3)
        ciphertext = encrypt_textbook(message, public)
        for use_crt in (False, True) if i % 2 == 0 else (True, False):
            start = perf_counter_ns()
            actual = decrypt_textbook(ciphertext, private, use_crt=use_crt)
            elapsed = perf_counter_ns() - start
            if actual != message:
                raise RuntimeError(
                    "benchmark decryption disagrees with original message"
                )
            if i:
                timings[use_crt].append(elapsed / 1_000_000)
    return Measurement(bits, median(timings[False]), median(timings[True]))
