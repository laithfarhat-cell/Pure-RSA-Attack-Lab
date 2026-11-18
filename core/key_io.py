"""Versioned, local JSON key files. Private records are NOT encrypted at rest."""

import json
import os
import re
from collections.abc import Iterable
from contextlib import ExitStack
from functools import partial
from pathlib import Path

from .rsa_engine import PrivateKey, PublicKey

_PRIVATE = "rsa-lab/private-v1"
_PUBLIC = "rsa-lab/public-v1"
# Keep local file/CLI resource limits separate from the integer arithmetic API.
MAX_FILE_BITS = 8192
_MAX_JSON_BYTES = 16 * 1024


def _record(kind: str, **fields: int) -> bytes:
    document = {"format": kind, **{name: format(x, "x") for name, x in fields.items()}}
    return (json.dumps(document, indent=2) + "\n").encode("ascii")


def write_new_files(files: Iterable[tuple[Path, bytes, int]]) -> None:
    """Exclusive creation; on an ordinary failure roll back only files we created."""
    with ExitStack() as rollback:
        for path, data, mode in files:
            with open(path, "xb", opener=partial(os.open, mode=mode)) as stream:
                rollback.callback(path.unlink, missing_ok=True)
                stream.write(data)
        rollback.pop_all()


def save_keypair(key: PrivateKey, private_path: Path, public_path: Path) -> None:
    if key.public_key.n.bit_length() > MAX_FILE_BITS:
        raise ValueError(f"JSON key files support up to {MAX_FILE_BITS} bits")
    private = _record(_PRIVATE, e=key.public_key.e, p=key.p, q=key.q)
    public = _record(_PUBLIC, n=key.public_key.n, e=key.public_key.e)
    write_new_files(((private_path, private, 0o600), (public_path, public, 0o644)))


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate field in key file")
        result[name] = value
    return result


def _read_fields(path: Path, kind: str, names: tuple[str, ...]) -> dict[str, int]:
    with path.open("rb") as stream:
        data = stream.read(_MAX_JSON_BYTES + 1)
    if len(data) > _MAX_JSON_BYTES:
        raise ValueError("key file is too large")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields)
    except (ValueError, RecursionError):
        raise ValueError("invalid key JSON") from None
    if not isinstance(document, dict) or document.get("format") != kind:
        raise ValueError(f"expected a {kind} key file")
    if document.keys() != {"format", *names}:
        raise ValueError("missing or unexpected key fields")
    fields = {}
    for name in names:
        value = document[name]
        if (
            not isinstance(value, str)
            or len(value) > (MAX_FILE_BITS + 3) // 4
            or not re.fullmatch(r"[1-9a-f][0-9a-f]*", value)
        ):
            raise ValueError(
                "key integers must be bounded, canonical lowercase hex strings"
            )
        fields[name] = int(value, 16)
    return fields


def load_public_key(path: Path) -> PublicKey:
    return PublicKey(**_read_fields(path, _PUBLIC, ("n", "e")))


def load_private_key(path: Path) -> PrivateKey:
    fields = _read_fields(path, _PRIVATE, ("p", "q", "e"))
    if (fields["p"] * fields["q"]).bit_length() > MAX_FILE_BITS:
        raise ValueError("private modulus exceeds key file limit")
    return PrivateKey.from_primes(**fields)
