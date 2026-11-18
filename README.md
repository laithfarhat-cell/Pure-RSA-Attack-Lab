# Pure RSA Lab

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Encoding: RFC 8017 OAEP](https://img.shields.io/badge/encoding-RFC%208017%20OAEP-006D77)
![CLI: Rich](https://img.shields.io/badge/CLI-Rich-7849A0)
![Test suite: pytest](https://img.shields.io/badge/tests-pytest-0A6EBD)

Follow a byte string from an OAEP data block through modular exponentiation and back. The arithmetic, prime generation, two-prime RSA, CRT recombination and OAEP codec are Python source you can read; the core uses no external crypto library. Rich is used only for the CLI.

**Scope:** this is a local teaching implementation, **not a production cryptographic provider**. The lab covers six historical attack classes as **defensive parameter and usage checks**. Each lesson runs a risky fixture and a control, shows what the check observed, and recommends a fix. It does not factor public keys, recover third-party secrets, or manipulate ciphertexts.

## First round trip

From the checkout, with Python 3.10 or newer:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p -m 700 lab-data

rsa-lab keygen --bits 2048 --out lab-data/keypair.json
rsa-lab encrypt --key lab-data/keypair.public.json --label notes/v1 \
    --message 'Measure twice.' --out lab-data/note.b64
rsa-lab decrypt --key lab-data/keypair.json --label notes/v1 \
    --in lab-data/note.b64 --out lab-data/note.txt
cat lab-data/note.txt
```

The recovered file is exactly `Measure twice.` with no added newline. The two key files have different purposes: **distribute only `keypair.public.json`**. Key files and `--out` files must be new; commands refuse to overwrite them. Use `--in` or stdin instead of `--message` to keep message text out of shell history and process arguments. Run `python main.py` in place of `rsa-lab` if working directly from source.

## CLI reference

| Command | Inputs and options | Result |
|---|---|---|
| `keygen` | `--bits B` (default 2048), `--out PATH` (default `keypair.json`), optional `--public-out PATH` | A private JSON record and `<stem>.public.json`; exact modulus width, including odd bit widths. |
| `encrypt` | `--key PUBLIC`, `--message TEXT` or `--in PATH` or stdin; `--mode oaep\|textbook`, `--label TEXT`, `--out PATH` | **OAEP by default.** One Base64 ciphertext plus newline, or an unsigned decimal integer plus newline in textbook mode. |
| `decrypt` | `--key PRIVATE`, `--ciphertext TEXT` or `--in PATH` or stdin; same mode, label and output options | Exact plaintext bytes for OAEP, or one decimal integer plus newline for textbook. No output file on a decryption error. |
| `audit` (alias `attack`) | `--type fermat\|wiener\|hastad\|common-mod\|batch-gcd\|malleability\|all` (default `all`), or `--choose` | Local configuration lessons: inputs, findings, check time in milliseconds and remediation. The alias runs the same checks, not exploits. |
| `benchmark` | `--sizes B [B ...]` (default 512 1024 2048), `--iterations R` (default 5) | Median direct and CRT decryption times in milliseconds and their ratio. |

`--message` and `--label` use UTF-8. File/stdin OAEP plaintext is **binary**; leading zeros and empty messages survive. A label defaults to empty and must match on decryption. A ciphertext input is a single Base64 or decimal token (surrounding whitespace is fine). Data commands default to stdout; warnings go to stderr. Use `rsa-lab <command> --help` for the parser's full usage.

### How much fits?

SHA-256 OAEP holds at most `ceil(modulus_bits / 8) - 66` bytes per ciphertext:

| Modulus | 512 bits | 1024 bits | 2048 bits | 4096 bits |
|---|---:|---:|---:|---:|
| OAEP capacity | Not usable | 62 bytes | 190 bytes | 446 bytes |

Oversized messages are rejected. There is no truncation, automatic chunking, or downgrade to textbook mode. For real bulk data, use a vetted hybrid encryption protocol. The integer API generates keys from 512 bits upward; the CLI and key-file format cap the modulus at 8192 bits. Sub-2048-bit keys are for arithmetic exercises only.

### Try the lessons

```sh
rsa-lab audit --choose
rsa-lab attack --type all
rsa-lab benchmark --sizes 512 1024 2048 --iterations 5
```

```text
RSA misuse                         What the local check inspects
|
+-- Key construction
|   +-- Fermat / close primes  ... Gap between two owner-known factors
|   `-- Wiener / small d       ... Owner-known private exponent size
|
+-- Key provisioning
|   +-- Common modulus         ... Same modulus, different public exponents
|   `-- Shared prime           ... Repeated components in supplied prime pairs
|
`-- Message handling
    +-- Håstad / broadcast     ... Unpadded payload label reused across keys
    `-- Malleability           ... Encoding and sender authentication policy
```

`FLAG` identifies a policy violation. `CLEAR` only means *this check* did not find one. For example, the broadcast lesson works with logical payload labels and recipient IDs, not message contents; the shared-prime lesson compares components **already known** to a provisioner, not factors discovered from a public inventory. Reports never include private values. Keep checks involving private components inside the key owner's process; do not centralize or log prime factors to run a lesson.

The benchmark uses one freshly generated key per size and the same ciphertext for each pair of comparisons. It warms both paths, alternates their order, validates every result, and excludes key generation and encryption from the timers. **Both** paths include blinding and result verification. The ratio is a measurement on your machine, not a promised speedup.

## Library map

| File | Start reading here for… |
|---|---|
| [`core/number_theory.py`](core/number_theory.py) | Square-and-multiply, signed Bézout coefficients, inverses, coprime CRT, floor roots, trial division and Miller–Rabin (40 random rounds by default). |
| [`core/rsa_engine.py`](core/rsa_engine.py) | Exact-width key generation with $e=65537$, Carmichael's function, reference and CRT private operations, SHA-256 MGF1 and RSAES-OAEP. |
| [`core/key_io.py`](core/key_io.py) | Versioned JSON records with canonical lowercase hex integers. Only `p`, `q`, `e` are stored in the private record; `d` and CRT values are derived on load. |
| [`attacks/`](attacks/) | Six independent `check(...)` functions and the contrasting fixture pairs used in the CLI. |
| [`cli/`](cli/) | `argparse`, Rich reports, and the paired benchmark. |
| [`THEORY.md`](THEORY.md) | Proofs of RSA correctness for **all** representatives and of CRT recombination; OAEP layout, probabilistic guarantees and limits of the six checks. |

```python
from core.rsa_engine import generate_keypair, encrypt_oaep, decrypt_oaep

public, private = generate_keypair(2048)
sealed = encrypt_oaep(b"\x00binary note", public, label=b"notes/v1")
assert decrypt_oaep(sealed, private, label=b"notes/v1") == b"\x00binary note"
```

For arithmetic, `encrypt_textbook(m, public)` and `decrypt_textbook(c, private)` accept integers in `[0, N)` only. The latter uses CRT by default; `use_crt=False` selects full-modulus exponentiation. Neither raw operation is a message-security scheme.

## Test and package

```sh
python -m pytest -q
# For an editable development install: python -m pip install -e '.[test]'
docker build -t pure-rsa-lab .
docker run --rm pure-rsa-lab audit --type wiener
```

The suite exercises arithmetic boundaries, prime generation, nonunit representatives, CRT/direct agreement, fixed SHA-256 MGF1 and OAEP encodings, randomized OAEP round trips, malformed blocks, wrong labels, key-file isolation, CLI pipes, and risk/control results for every lesson. CI runs pytest on Python 3.10 and 3.13. The Docker image installs runtime dependencies only and runs as a non-root user; files written inside a disposable container are not persistent.

## Security and ethical use

Use the lab with throwaway keys and data you control. Private output is **unencrypted JSON**, created with mode `0600` on POSIX in a directory you should protect. Do not commit it; `.gitignore` covers `lab-data/` and default key names, not arbitrary custom paths. The core uses OS randomness, blinding, result verification and one public OAEP decoding error. None makes Python big-integer arithmetic constant-time or provides secure memory erasure. OAEP does **not** authenticate the sender. For production, use a maintained, reviewed cryptographic provider, an authenticated protocol, and managed key storage; do not expose this lab as a decryption service.
