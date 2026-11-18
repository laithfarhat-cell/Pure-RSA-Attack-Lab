# The mathematics behind the lab

The cryptographic path runs from `generate_prime` to `generate_keypair`, then from `oaep_encode` through an integer RSA operation and back through `oaep_decode`. This note states the invariants at those boundaries. The final section explains what the six defensive checks can and cannot conclude.

## 1. Exact arithmetic

Write $[a]_s$ for the unique residue of $a$ in $[0,s)$. No operation in the key or message path uses floating point.

- **Square-and-multiply.** To compute $b^a \bmod s$, `mod_pow` maintains $R B^t \equiv b^a \pmod s$, initially with $R=1$, $B=[b]_s$, $t=a$. Write $t=2u+v$ with $v\in\{0,1\}$. Replacing $(R,B,t)$ by $([RB^v]_s,[B^2]_s,u)$ preserves the invariant. When $t=0$, $R$ is the answer. This needs $O(\log(a+1))$ modular multiplications for positive $a$ and also handles $a=0$.
- **Bézout coefficients.** Euclid's step $(r,s)\mapsto(s,r-\lfloor r/s\rfloor s)$ preserves the gcd. Start the two rows with the coefficient pairs $(1,0),(0,1)$ for the two input magnitudes. Applying the same row operations to the coefficients keeps each remainder a linear combination of the inputs. The last nonzero remainder is the gcd; restoring the input signs gives $ax+by=\gcd(a,b)$. In particular, when $\gcd(a,s)=1$, $[x]_s$ is the inverse of $a$ modulo $s$.
- **Integer roots.** For $n\ge2$, degree $k\ge1$, a strict upper bound for the root is $2^{\lceil\operatorname{bitlength}(n)/k\rceil}$. Binary search preserves $l^k\le n<h^k$. Adjacent bounds imply $l=\lfloor\sqrt[k]{n}\rfloor$, even immediately below a huge perfect power. `nth_root` handles zero and one separately and dispatches square roots to `math.isqrt`.

### Chinese remaindering

Suppose $x$ satisfies all congruences seen so far, modulo their product $M$. To add $x'\equiv a\pmod s$ with $\gcd(M,s)=1$, set

$$
t=[(a-x)M^{-1}]_s,\qquad x'=x+Mt.
$$

Then $x'$ preserves the old residues and has the new one. If $0\le x<M$, then $0\le x'<Ms$. Any two solutions differ by a multiple of both $M$ and $s$, hence by a multiple of $Ms$: this proves uniqueness. Induction starting with $x=0,M=1$ proves `crt`. The API rejects empty systems, mismatched lengths, moduli below two, and noncoprime moduli rather than silently solving a different problem.

## 2. From random bits to a keypair

`generate_prime` draws bits with `secrets.randbits`, fixes the high and low bits (exact width, odd candidate), and trial-divides by small primes. For a remaining candidate $n$, write $n-1=2^s u$ with $u$ odd. Miller–Rabin draws independent uniform bases from $[2,n-2]$.

**Why a rejection proves compositeness.** In a prime field, Fermat's little theorem gives $a^{n-1}=1$. Starting at $a^u$ and squaring $s$ times must therefore end at 1. The only square roots of 1 are $1$ and $-1$, since $(x-1)(x+1)=0$ in a field. Unless the sequence starts at 1, the term immediately before its first 1 must be $-1$. A base violating this condition is a witness to compositeness. Passing is *not* a primality proof. The Miller–Rabin bound for a **fixed odd composite** is at most $4^{-k}$ acceptance probability over $k$ independent rounds; the default 40 gives $2^{-80}$. This is not a posterior probability about an entire keypair.

For distinct odd probable primes $p,q$, form

$$
N=pq,\quad \lambda=\operatorname{lcm}(p-1,q-1),\quad d=[e^{-1}]_\lambda.
$$

The generator samples the two factors independently at widths $\lfloor b/2\rfloor$ and $\lceil b/2\rceil$, rejecting candidates incompatible with $e$. It retries until the product has exactly $b$ bits, the factors satisfy the gap policy, and the exponent satisfies the size policy below. The default $e=65537$ is public; **only** $(N,e)$ belongs in the public record. The private JSON file stores $p,q,e$; import checks primality and reconstructs $N,d$ and all CRT parameters rather than trusting redundant fields.

## 3. Proof of RSA correctness, including nonunits

Encryption on integer representatives is $c=[m^e]_N$ for $0\le m<N$. By construction $ed=1+t\lambda$. For a unit modulo $N$, reduction to the two prime fields gives $m^\lambda=1$ in each and hence modulo $N$ (Carmichael's theorem here). Thus $m^{ed}\equiv m\pmod N$. Euler's totient $(p-1)(q-1)$ would also be a common exponent, but its least common multiple counterpart suffices.

What if $m$ is *not* a unit? Fix $r\in\{p,q\}$. If $r\mid m$, both $m^{ed}$ and $m$ are zero modulo $r$. Otherwise, $r-1\mid\lambda$ and Fermat's little theorem gives $m^{ed}\equiv m\pmod r$. This covers both cases for each prime. By CRT uniqueness the residues agree modulo $N$, and taking the canonical representative returns **exactly** $m$. There is no coprimality restriction on the input message.

### CRT private operation

Precompute $d_p=[d]_{p-1}$, $d_q=[d]_{q-1}$, and $v=[q^{-1}]_p$. For a private-operation input $c$, compute

$$
u_p=[c^{d_p}]_p,\quad u_q=[c^{d_q}]_q,\quad h=[(u_p-u_q)v]_p,\quad u=u_q+qh.
$$

Modulo $q$, the result is $u_q$. Modulo $p$, $qv\equiv1$, so it is $u_p$. These are also the residues of $c^d$: exponent reduction is valid for units, and both reduced exponents are positive since $d$ is invertible modulo $p-1$ and $q-1$, each greater than one. Zero residues therefore remain zero. Since $0\le u<N$, uniqueness proves $u=[c^d]_N$.

This replaces one full-width exponentiation with two approximately half-width ones; the inverses do **not** need to be recomputed for each CRT recombination. Both benchmark paths randomize the private-operation input, remove the blinding internally, and check $m^e\equiv c\pmod N$ before returning. A failed check discards the result. Under a simple quadratic multiplication model the exponentiation work alone tends toward a fourfold reduction, **not** a guarantee of fourfold wall-clock speed. Python's multiplication algorithms, blinding, verification, and interpreter overhead all matter.

## 4. RSAES-OAEP at the octet boundary

This follows [RFC 8017 §§7.1 and B.2.1](https://www.rfc-editor.org/rfc/rfc8017), with SHA-256 for the label hash and MGF1. Let $k=\lceil\operatorname{bitlength}(N)/8\rceil$ **octets** and $h=32$. Denote concatenation by `||` and exclusive-or by `XOR`.

```text
DB         = SHA256(label) || zero padding || 01 || message
seed       = 32 fresh random octets
maskedDB   = DB   XOR MGF1(seed,     k - h - 1)
maskedSeed = seed XOR MGF1(maskedDB, h)
EM         = 00 || maskedSeed || maskedDB
```

Here `00` and `01` are individual octets, not text. MGF1 concatenates `SHA256(input || counter)` digests with a four-octet big-endian counter starting at zero and truncates to the requested length. `DB` has length $k-h-1$; hence the zero padding has length $k-2h-2-|M|$. The capacity is **$k-66$ bytes**, 190 bytes for a 2048-bit modulus. A 512-bit modulus cannot even encode an empty message with this hash. Negative capacity and overlength messages are errors, not a reason to truncate or switch to textbook mode.

The leading zero ensures the big-endian integer encoding of `EM` is less than $N$. The public operation produces a ciphertext of **exactly $k$ octets**, including leading zeros when necessary. After the private operation, decoding unmasks the seed using `maskedDB`, then unmasks `DB` with that seed. XOR being self-inverse proves that an intact encoding recovers both originals. The decoder requires the leading zero, matching label hash, zero-only padding and a `01` delimiter; everything after that delimiter is the original byte string, including any zeros.

Decryption rejects length/range errors, failed private-operation verification, label mismatch and malformed padding without returning plaintext. There is one public OAEP decryption error. This does **not** make a Python implementation constant-time or a network decryption service safe. The label binds context but does not authenticate a sender. Anyone with the public key can encrypt a new message.

## 5. Reading the defensive lessons

The names are historical weakness classes. The checks inspect the prerequisite at provisioning or design time; **none** accepts a ciphertext challenge or attempts secret recovery.

| Class | Mathematical or protocol concern | What the check actually establishes |
|---|---|---|
| Fermat | The difference-of-squares identity $(a-b)(a+b)=a^2-b^2$ explains the near-square shape of products of close odd primes. | With both factors already known, test $(p-q)^4\le16N$ using only integers. This is a teaching margin, not a sufficient test of key strength. |
| Wiener | Legendre's approximation theorem says a reduced fraction $a/b$ within $1/(2b^2)$ of a real number is a continued-fraction convergent of that number. Exceptionally small private exponents can expose approximation structure under additional RSA parameter assumptions. | Check the **known** $d$ against the conservative generation floor $2^{\lfloor\operatorname{bitlength}(N)/2\rfloor}$. A flag is not a conclusion that a particular recovery theorem applies; in particular $ed\equiv1\pmod\lambda$ need not imply $ed\equiv1\pmod{\varphi(N)}$. |
| Håstad | Sending the same deterministic representative to different moduli preserves algebraic relationships instead of making the encryptions independent. Small broadcast exponents make this especially dangerous. | Flag a logical payload label used in textbook mode for multiple distinct recipient key IDs. This is an early warning, not a test of a particular exponent or number of ciphertexts. |
| Common modulus | Different exponents do not give independent key ownership when the modulus is the same. | Group public records by modulus. More than one exponent in a group is a provisioning error. Identical duplicate records alone do not trip this rule. |
| Shared prime / batch GCD | Independent keys should not share prime components. Reuse points to a provisioning or entropy failure. | Compare **already supplied** prime components for equality in local memory; report a boolean finding, not the factor. No public-modulus factor search. |
| Malleability | The raw RSA map preserves multiplication and supplies neither integrity nor origin authentication. | For a receiver acting on a value, flag textbook encoding or missing sender authentication. Even OAEP is not a substitute for an authenticated protocol. |

The control cases are counterexamples to the specific risky configuration, **not security certifications**. A verifier that needs real assurance must also address key size, entropy, side channels, secure storage, authenticated protocols and lifecycle management.
