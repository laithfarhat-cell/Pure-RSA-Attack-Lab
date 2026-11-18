"""Check declared message reuse across recipients without examining message contents."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from .finding import Finding


@dataclass(frozen=True, slots=True)
class Delivery:
    # Logical labels supplied by the workflow owner, not messages or their hashes.
    payload_id: str
    recipient_key_id: str
    mode: Literal["oaep", "textbook"]

    def __post_init__(self) -> None:
        if not self.payload_id or not self.recipient_key_id:
            raise ValueError("delivery labels must be nonempty")
        if self.mode not in ("oaep", "textbook"):
            raise ValueError("unknown encryption mode")


def check(deliveries: Iterable[Delivery]) -> Finding:
    recipients: dict[str, set[str]] = {}
    for delivery in deliveries:
        if delivery.mode == "textbook":
            recipients.setdefault(delivery.payload_id, set()).add(
                delivery.recipient_key_id
            )
    reused = sum(len(keys) > 1 for keys in recipients.values())
    if reused:
        return Finding(
            True, f"Unpadded payload labels sent to multiple recipient keys: {reused}."
        )
    return Finding(False, "No cross-recipient reuse of an unpadded payload label.")
