"""Local CLI. Crypto commands keep their data stream separate from diagnostics."""

import argparse
import base64
import binascii
import sys
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter_ns

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from attacks.lessons import LESSONS
from core.key_io import (
    MAX_FILE_BITS,
    load_private_key,
    load_public_key,
    save_keypair,
    write_new_files,
)
from core.rsa_engine import (
    DecryptionError,
    decrypt_oaep,
    decrypt_textbook,
    encrypt_oaep,
    encrypt_textbook,
    generate_keypair,
)

from .benchmark import measure


def _bits(value: str) -> int:
    bits = int(value)
    if not 512 <= bits <= MAX_FILE_BITS:
        raise argparse.ArgumentTypeError(
            f"key width must be between 512 and {MAX_FILE_BITS}"
        )
    return bits


def _keygen(args: argparse.Namespace) -> None:
    console = Console(highlight=False)
    public_path = args.public_out or args.out.with_suffix(".public.json")
    if args.out == public_path:
        raise ValueError("private and public output paths must differ")
    with console.status(f"Generating a {args.bits}-bit keypair…"):
        _, private = generate_keypair(args.bits)
        save_keypair(private, args.out, public_path)
    lines = [
        f"Modulus: {args.bits} bits · e = {private.public_key.e}",
        f"Public:  {public_path}",
        f"Private: {args.out} (unencrypted; keep local)",
    ]
    if args.bits < 2048:
        lines.append("Sub-2048-bit key: arithmetic exercises only.")
    console.print(
        Panel(Text("\n".join(lines)), title="Keypair created", border_style="cyan")
    )


def _input(text: str | None, path: Path | None, limit: int, size_error: str) -> bytes:
    if text is not None:
        data = text.encode("utf-8")
    elif path is not None:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    else:
        data = sys.stdin.buffer.read(limit + 1)
    if len(data) > limit:
        raise ValueError(size_error)
    return data


def _decimal(data: bytes) -> int:
    digits = data.strip()
    if not digits.isdigit():
        raise ValueError("textbook mode expects one unsigned decimal integer")
    return int(digits)


def _output(data: bytes, path: Path | None) -> None:
    if path is None:
        sys.stdout.buffer.write(data)
    else:
        write_new_files(((path, data, 0o600),))


def _warn_textbook(label: str) -> None:
    if label:
        raise ValueError("labels are supported only in OAEP mode")
    Console(stderr=True).print(
        "Textbook RSA is deterministic and unauthenticated; lab use only."
    )


def _encrypt(args: argparse.Namespace) -> None:
    key = load_public_key(args.key)
    if args.mode == "oaep":
        data = _input(
            args.message,
            args.input,
            key.size_bytes,
            "message too large for one RSA block",
        )
        result = base64.b64encode(encrypt_oaep(data, key, args.label.encode("utf-8")))
    else:
        _warn_textbook(args.label)
        data = _input(
            args.message, args.input, 3 * key.size_bytes + 128, "integer input too long"
        )
        result = str(encrypt_textbook(_decimal(data), key)).encode("ascii")
    _output(result + b"\n", args.out)


def _decrypt(args: argparse.Namespace) -> None:
    key = load_private_key(args.key)
    k = key.public_key.size_bytes
    if args.mode == "oaep":
        data = _input(
            args.ciphertext, args.input, 4 * k + 128, "OAEP decryption failed"
        )
        try:
            ciphertext = base64.b64decode(data.strip(), validate=True)
        except binascii.Error:
            raise DecryptionError("OAEP decryption failed") from None
        result = decrypt_oaep(ciphertext, key, args.label.encode("utf-8"))
    else:
        _warn_textbook(args.label)
        data = _input(
            args.ciphertext, args.input, 3 * k + 128, "integer input too long"
        )
        result = f"{decrypt_textbook(_decimal(data), key)}\n".encode("ascii")
    _output(result, args.out)


def _audit(args: argparse.Namespace) -> None:
    console = Console()
    name = args.type
    if args.choose:
        try:
            name = Prompt.ask(
                "Review a weakness class",
                choices=[*LESSONS, "all"],
                default="all",
                console=console,
            )
        except EOFError:
            raise ValueError(
                "interactive selection requires input; use --type instead"
            ) from None
    console.print(
        "Local configuration review · fixed fixtures, no secret recovery.", style="bold"
    )
    console.print(
        "CLEAR means only that this particular check did not flag its input.\n"
    )
    for rule in LESSONS if name == "all" else [name]:
        lesson = LESSONS[rule]
        table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False, expand=True)
        table.add_column("Case", no_wrap=True)
        table.add_column("Result", no_wrap=True)
        table.add_column("Observation", ratio=1)
        table.add_column("ms", justify="right", no_wrap=True)
        body = Group(
            Text(f"Input: {lesson.inputs}"),
            Text(f"Rule: {lesson.criterion}"),
            table,
            Text(f"Action: {lesson.remedy}"),
        )
        panel = Panel(body, title=lesson.title, title_align="left", border_style="cyan")
        with Live(
            panel, console=console, auto_refresh=False, vertical_overflow="visible"
        ) as live:
            for label, run in [
                ("Risk case", lesson.risk_case),
                ("Control", lesson.control),
            ]:
                start = perf_counter_ns()
                finding = run()
                ms = (perf_counter_ns() - start) / 1_000_000
                status = (
                    Text("FLAG", style="bold red")
                    if finding.flagged
                    else Text("CLEAR", style="green")
                )
                table.add_row(label, status, Text(finding.detail), f"{ms:.4f}")
                if console.is_terminal:
                    live.refresh()
        console.print()


def _benchmark(args: argparse.Namespace) -> None:
    console = Console()
    if args.iterations < 1:
        raise ValueError("iterations must be positive")
    table = Table(
        title="RSA private operations · median per decryption", box=box.SIMPLE
    )
    for column in ("Bits", "Direct (ms)", "CRT (ms)", "Speedup"):
        table.add_column(column, justify="right")
    for bits in args.sizes:
        with console.status(f"Generating a {bits}-bit key and timing both paths…"):
            sample = measure(bits, args.iterations)
        table.add_row(
            str(bits),
            f"{sample.direct_ms:.3f}",
            f"{sample.crt_ms:.3f}",
            f"{sample.speedup:.2f}×",
        )
    console.print(table)
    console.print(
        f"{args.iterations} measured pair(s) per size. Both paths include blinding and "
        "verification; keygen, encryption, and one warm-up pair are excluded."
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rsa-lab", description="Pure Python RSA · local teaching lab"
    )
    subs = parser.add_subparsers(dest="command", required=True)
    gen = subs.add_parser(
        "keygen", help="create separate private and public JSON files"
    )
    gen.add_argument(
        "--bits", type=_bits, default=2048, help="modulus bits (default: 2048)"
    )
    gen.add_argument(
        "--out", type=Path, default=Path("keypair.json"), help="new private file"
    )
    gen.add_argument(
        "--public-out", type=Path, help="new public file (default: <stem>.public.json)"
    )
    gen.set_defaults(run=_keygen)

    for name, handler in [("encrypt", _encrypt), ("decrypt", _decrypt)]:
        sealing = name == "encrypt"
        cmd = subs.add_parser(
            name, help=f"{name} one short message or integer representative"
        )
        cmd.add_argument(
            "--key",
            required=True,
            type=Path,
            help=("public" if sealing else "private") + " JSON key",
        )
        cmd.add_argument(
            "--mode", choices=["oaep", "textbook"], default="oaep", help="default: oaep"
        )
        cmd.add_argument(
            "--label", default="", help="OAEP label as UTF-8 (default: empty)"
        )
        inputs = cmd.add_mutually_exclusive_group()
        if sealing:
            inputs.add_argument(
                "--message", help="UTF-8 message, or decimal integer in textbook mode"
            )
        else:
            inputs.add_argument(
                "--ciphertext",
                help="Base64 OAEP ciphertext, or textbook decimal integer",
            )
        inputs.add_argument(
            "--in", dest="input", type=Path, help="input file (default: stdin)"
        )
        cmd.add_argument("--out", type=Path, help="new output file (default: stdout)")
        cmd.set_defaults(run=handler)

    audit = subs.add_parser(
        "audit",
        aliases=["attack"],
        help="review six weakness classes on local fixtures",
    )
    selection = audit.add_mutually_exclusive_group()
    selection.add_argument(
        "--type", choices=[*LESSONS, "all"], default="all", help="default: all"
    )
    selection.add_argument(
        "--choose", action="store_true", help="choose a lesson interactively"
    )
    audit.set_defaults(run=_audit)

    bench = subs.add_parser(
        "benchmark", help="compare direct and CRT private operations"
    )
    bench.add_argument(
        "--sizes",
        type=_bits,
        nargs="+",
        default=[512, 1024, 2048],
        help="modulus widths in bits",
    )
    bench.add_argument(
        "--iterations", type=int, default=5, help="measured pairs per size (default: 5)"
    )
    bench.set_defaults(run=_benchmark)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments)
    try:
        args.run(args)
    except (ValueError, OSError) as exc:
        Console(stderr=True).print(Text(f"error: {exc}", style="red"))
        return 2
    except KeyboardInterrupt:
        return 130
    return 0
