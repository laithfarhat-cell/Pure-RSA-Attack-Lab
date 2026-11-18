import pytest

from core.key_io import save_keypair
from core.rsa_engine import generate_keypair


@pytest.fixture(scope="session")
def keypair():
    # Leave space for SHA-256 OAEP, and exercise ceil(bit_length / 8).
    return generate_keypair(bits=1025)


@pytest.fixture
def key_paths(tmp_path, keypair):
    private, public = tmp_path / "owner.json", tmp_path / "recipient.json"
    save_keypair(keypair[1], private, public)
    return private, public
