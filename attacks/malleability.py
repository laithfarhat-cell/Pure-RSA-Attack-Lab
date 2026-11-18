"""Policy for a recipient that acts on a decrypted value as a trusted command."""

from typing import Literal

from .finding import Finding


def check(mode: Literal["oaep", "textbook"], *, sender_authenticated: bool) -> Finding:
    if mode == "textbook":
        return Finding(
            True, "Textbook encoding gives no ciphertext integrity guarantee."
        )
    if mode != "oaep":
        raise ValueError("unknown encryption mode")
    if not sender_authenticated:
        return Finding(
            True, "OAEP is selected, but the command's sender is not authenticated."
        )
    return Finding(
        False, "OAEP and independent sender authentication are both declared."
    )
