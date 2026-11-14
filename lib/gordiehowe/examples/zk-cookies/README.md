# zk-cookies state relation

`state.h` ports `zk_cred_logic/state.circom` to GordieHowe. It validates a
signed old state and signed server response, applies the original geohash,
fingerprint and age policies, produces the RAPPOR response and nullifiers,
and publishes a commitment to the updated state.

## Domains

The relation has two GordieHowe domains:

- `H`, the binary domain, performs the selected application hash, the state
  transition, geohash/fingerprint/age checks, RAPPOR, and the SHAKE
  computations required by ML-DSA.
- `A`, the native ML-DSA field, performs the algebra for both ML-DSA-44
  signatures.

Each signature's `w1` and challenge are joined across the two domains by a
GordieHowe MAC crossing. Both signatures use the public
`server_public_key`, so changing the server key requires a new statement but
does not require recompiling the relation.

## Public statement

- ML-DSA-44 server public key
- old-state nullifier (32 bytes)
- server-response nullifier (32 bytes)
- new-state commitment (32 bytes)
- RAPPOR response (16 bits)

The state, request values, randomness, fingerprints and signatures are
private witness values.

## Canonical encoding

Integers use fixed-width little-endian encoding. IP addresses are `uint32`,
geohashes and the state counter are `uint64`, and PRF seeds, nonces and
commitment randomness are 32 bytes. A fingerprint is two 32-byte
little-endian blocks; each block's high six bits must be zero, leaving the
original 250 bits per block. The year of birth is two ASCII bytes.

Every application-level hash call hashes:

```text
u16le(tag length) || tag || u64le(payload length) || payload
```

The tags are defined beside their calls in `state.h` and
`state_builders.h`. ML-DSA signs the 32-byte initial-state commitment and the
32-byte server-response digest under an empty context. ML-DSA's
standards-mandated SHAKE hashing is never replaced by the application-hash
policy.

## Hash policies

`state_hash.h` is the application-hash boundary. A policy provides a 32-byte
host hash and its matching circuit gadget. The built-in policies are
`hashes::Poseidon2b` (the default), `hashes::Blake3`, `hashes::Blake2s`, and
`hashes::Sha256`.
The relation and every matching host builder take the policy as a template
argument. For example:

```c++
auto relation = state<P, hashes::Blake2s>(env, history_length);
auto output = host::outputs<hashes::Blake2s>(witness);
```

The state-transition logic does not depend on the concrete hash.

### Poseidon2b instance

`lib/poseidon2b.h` implements the paper's `n=128`, `t=6`, `x^7`,
`(R_F,R_P)=(8,58)` permutation with the checked-in Binius round constants and
linear-layer tables. It uses sponge-pi with capacity 2, rate 4, and a
two-field-element (256-bit) digest. The implementation is available only for
the narrow `GF(2^128)` profile; selecting Poseidon2b with the wide profile
fails before relation construction.

The parameter sources are the repository's
[`papers/poseidon2b.pdf`](../../../../papers/poseidon2b.pdf) and the pinned
[`poseidon2b_x7_128_768.rs`](https://github.com/Poseidon-Hash/Poseidon2b/blob/7072a9438cf48f1b38ad0092cda5452626914068/binius_poseidon2b/crates/circuits/src/hades/poseidon2b_x7_128_768.rs)
reference table.

The application interface is byte-oriented. It appends byte `0x01`, pads with
zero bytes to a 16-byte field element, and interprets each element in
little-endian polynomial-basis order before applying sponge-pi's field-element
padding and `mu` separation. This byte encoding and GordieHowe's field basis
are part of the zk-cookies hash definition, so its digest is not intended to be
byte-compatible with Binius's tower-field serialization.

Each `x^7` S-box is the quadratic addition chain `x^2`, `x^4`, `x^6`, `x^7`.
Only the S-box output is committed; the four products are wires in a small GKR
computation. S-box inputs and linear layers are affine views of the committed
outputs. A shared basis with explicit field coefficients flattens the 58
partial rounds without committing round-state checkpoints or expanding nested
symbolic linear layers. Each permutation therefore materializes 106 full-field
S-box outputs, down from 926 full-field witnesses in the earlier quadratic-triple
implementation. The commitment boundary at each S-box keeps circuit depth
independent of the number of rounds and sponge blocks. Digest bits are still
committed separately and constrained to encode the final two field elements.

The encoded hash input is an uncommitted derived Bit view, using GordieHowe's
existing `bit_from_unchecked` API. One native witness generator packs it into
field words once and computes every permutation's S-box outputs in a single
committed array (`sboxes`, shaped `[blocks, 106]`). This stores the same S-box
outputs as before; GKR independently checks every output against the original
symbolic input and the preceding outputs. No host cache persists across proofs,
and the derived input adds no committed coordinates or new trust assumptions.
The input is already a Bit expression. No upstream compiler or prover changes
are needed.

## Construction

`state(env, history_length)` uses Poseidon2b and compiles a relation for a
fixed history shape. `state<P, Hash>(env, history_length)` selects another
policy. For example, lengths 5 and 25 produce separate compiled relations.
Optional `StateConfig` values change the original policy constants; its
defaults are the Circom circuit's 20 shared geohash bits, similarity strictly
above 400 of 500 bits, and RAPPOR thresholds 127 and 191.

`state_builders.h` contains the matching host-side encoding, state update,
hashing, RAPPOR calculation, public-statement builder, and decoded-signature
assignment helper.

The first-empty-slot selector uses parallel prefixes of nonzero-slot flags
(`arith::prefix_and`), followed by the current slot's zero flag. This preserves
the original semantics, including holes, duplicate IPs, a zero new IP, and
nonzero geohashes beside zero IPs. Prefix depth is logarithmic in history
length. The update applies tensor-wide muxes and a slice/append shift rather
than building one concatenation per history entry; the remaining selector
views are joined in a balanced tree. Zero-slot predicates are also an
uncommitted derived Bit view, evaluated once for all witness generators.

BLAKE3 and BLAKE2s use field addition for XOR in the binary domain. Each
hash's witness is generated with native `uint32_t` arithmetic and committed as
packed arrays of addition results and chaining values. Addition constraints
are vectorized across compression operations. BLAKE3 implements the standard
1024-byte chunk tree, so application messages are not limited to one chunk.

## Benchmark runner

The benchmark executable takes the compiled state-history shape through
`--history-length` (default `5`). For example, after configuring the build:

```sh
cmake --build build --target zk_cookies_state_bench -j4
./build/bench/zk_cookies_state_bench bench \
  --history-length 5 --profile narrow --reps 1
```

Use `--hash blake3`, `--hash poseidon2b`, `--hash blake2s`, or `--hash sha256`
to compare the same relation and witness with a different application hash.
The default is `poseidon2b`, which requires `--profile narrow`:

```sh
for hash in blake3 poseidon2b blake2s sha256; do
  ./build/bench/zk_cookies_state_bench bench \
    --history-length 5 --profile narrow --hash "$hash" --reps 1
done
```

The runner also supports the standard `serve` and `report` commands and emits
the selected hash in `GH_ZK_COOKIES_CONFIG` and `GH_ZK_COOKIES_SIZE`. Run
`./build/bench/zk_cookies_state_bench bench --help` for all flags.

The port deliberately preserves the original zero-sentinel behavior: it
does not add constraints requiring nonzero history entries to be contiguous,
requiring `new_ip` to be nonzero, or tying a zero IP slot to a zero geohash.
