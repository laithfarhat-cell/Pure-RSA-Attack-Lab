import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from cli.lab_cli import main
from core.key_io import load_private_key, load_public_key, save_keypair

ENTRY = Path(__file__).resolve().parents[1] / "main.py"


def test_key_files_round_trip_and_separate_secrets(keypair, key_paths):
    private, public = key_paths
    assert load_public_key(public) == keypair[0]
    assert load_private_key(private) == keypair[1]
    assert set(json.loads(public.read_bytes())) == {"format", "n", "e"}
    if os.name == "posix":
        assert stat.S_IMODE(private.stat().st_mode) & 0o077 == 0
    with pytest.raises(ValueError, match="public-v1"):
        load_public_key(private)
    with pytest.raises(ValueError, match="private-v1"):
        load_private_key(public)


def test_no_clobber_and_rollback_on_second_path_collision(keypair, tmp_path):
    private, public = tmp_path / "private", tmp_path / "public"
    public.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        save_keypair(keypair[1], private, public)
    assert not private.exists() and public.read_bytes() == b"existing"
    private.write_bytes(b"existing private")
    with pytest.raises(FileExistsError):
        save_keypair(keypair[1], private, tmp_path / "other")
    assert (
        private.read_bytes() == b"existing private"
        and not (tmp_path / "other").exists()
    )


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b"{",
        b"\xff",
        b"x" * 17000,
        b'{"format":"rsa-lab/public-v1","n":"f","n":"b","e":"3"}',
        b'{"format":"rsa-lab/public-v1","n":"f","e":3}',
        b'{"format":"rsa-lab/public-v1","n":"0xf","e":"3"}',
        b'{"format":"rsa-lab/public-v1","n":"b","e":"3","p":"2"}',
    ],
)
def test_invalid_key_files(tmp_path, data):
    path = tmp_path / "invalid"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        load_public_key(path)


def test_cli_keygen(tmp_path, capsys):
    path = tmp_path / "example.json"
    assert main(["keygen", "--bits", "512", "--out", str(path)]) == 0
    public = load_public_key(tmp_path / "example.public.json")
    assert public == load_private_key(path).public_key
    assert public.n.bit_length() == 512
    assert "unencrypted" in capsys.readouterr().out


def test_cli_default_oaep_binary_stdio_and_label(key_paths, tmp_path):
    private, public = key_paths
    # Exercise the actual entry point from outside the repo; stdout is data only.
    message = b"\x00\xffterminal\n\x00"
    proc = subprocess.run(
        [
            sys.executable,
            str(ENTRY),
            "encrypt",
            "--key",
            str(public),
            "--label",
            "context",
        ],
        cwd=tmp_path,
        input=message,
        capture_output=True,
        check=True,
    )
    assert len(base64.b64decode(proc.stdout.strip(), validate=True)) == 129
    opened = subprocess.run(
        [
            sys.executable,
            str(ENTRY),
            "decrypt",
            "--key",
            str(private),
            "--label",
            "context",
        ],
        cwd=tmp_path,
        input=proc.stdout,
        capture_output=True,
        check=True,
    )
    assert opened.stdout == message


def test_cli_textbook_files_and_no_overwrite(key_paths, tmp_path, capsys):
    private, public = key_paths
    ciphertext, result = tmp_path / "ciphertext", tmp_path / "result"
    encrypt = [
        "encrypt",
        "--mode",
        "textbook",
        "--key",
        str(public),
        "--message",
        "42",
        "--out",
        str(ciphertext),
    ]
    assert main(encrypt) == 0
    saved = ciphertext.read_bytes()
    assert saved.strip().isdigit()
    assert main(encrypt) == 2
    assert ciphertext.read_bytes() == saved
    assert (
        main(
            [
                "decrypt",
                "--mode",
                "textbook",
                "--key",
                str(private),
                "--in",
                str(ciphertext),
                "--out",
                str(result),
            ]
        )
        == 0
    )
    assert result.read_bytes() == b"42\n"
    assert "lab use only" in capsys.readouterr().err


def test_cli_rejects_wrong_label_and_invalid_base64_without_writing(
    key_paths, tmp_path, capsys
):
    private, public = key_paths
    sealed, output = tmp_path / "sealed", tmp_path / "message"
    assert (
        main(
            [
                "encrypt",
                "--key",
                str(public),
                "--message",
                "مرحبا",
                "--label",
                "A",
                "--out",
                str(sealed),
            ]
        )
        == 0
    )
    for source in (["--in", str(sealed)], ["--ciphertext", "not base64!"]):
        assert (
            main(["decrypt", "--key", str(private), "--out", str(output), *source]) == 2
        )
        assert not output.exists()
        assert capsys.readouterr().err.strip() == "error: OAEP decryption failed"


def test_cli_lab_alias_and_telemetry(capsys):
    assert main(["attack", "--type", "all"]) == 0
    out = capsys.readouterr().out
    assert out.count("Risk case") == 6 and out.count("Control") == 6
    assert out.count("FLAG") == 6 and out.count("Action:") == 6
    assert "Input:" in out and "ms" in out


def test_cli_interactive_selection():
    result = subprocess.run(
        [sys.executable, str(ENTRY), "audit", "--choose"],
        input="wiener\n",
        text=True,
        capture_output=True,
        check=True,
    )
    assert "Wiener" in result.stdout and result.stdout.count("Risk case") == 1


def test_cli_benchmark_and_invalid_iterations(capsys):
    assert main(["benchmark", "--sizes", "512", "--iterations", "2"]) == 0
    text = capsys.readouterr().out
    assert "Direct (ms)" in text and "CRT (ms)" in text and "512" in text
    assert main(["benchmark", "--sizes", "512", "--iterations", "0"]) == 2
    assert "iterations must be positive" in capsys.readouterr().err
