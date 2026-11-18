"""Small, non-secret result shared by all six checks."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    flagged: bool
    detail: str
