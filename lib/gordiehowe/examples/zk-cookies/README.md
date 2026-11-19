# zk-cookies circuits

The former `state.h`, `state_builders.h`, `zk_cookies_state_bench` and
`zk_cookies_state_test` are now named `zk_cookies_credential_history.h`,
`zk_cookies_credential_history_builders.h`, `zk_cookies_credential_history_bench`
and `zk_cookies_credential_history_test`. The circuit factory is
`zk_cookies_credential_history`. Existing credential-history hash domain tags
and byte encodings are unchanged by the rename.

All four circuits validate a signed old state and a signed server response,
produce nullifiers and a RAPPOR response, and commit to the updated state.
Each has a correspondingly named `.h`, `_builders.h`, `_bench.cc`, and
`_test.cc` file in this directory.

| Circuit factory / benchmark prefix | Original Circom source | Configurable size |
| --- | --- | --- |
| `zk_cookies_credential_history` | `zk_cred_logic/state.circom` | IP/geohash history |
| `zk_cookies_single_attribution` | `zk_cred_attribution_single_logic/state.circom` | Attribution history and IP/geohash history |
| `zk_cookies_multi_attribution` | `zk_cred_attribution_chain_logic/state.circom` | Attribution history and IP/geohash history |
| `zk_cookies_streaming` | `zk_cred_streaming_logic/state_streaming.circom` | Fixed circuit size; counter is witness data |

`zk_cookies_common.h` shares signature verification and the optimized history
policies. `zk_cookies_attribution.h` shares the two attribution relations;
their named headers select the search policy. Matching host functions share
the same encodings and hash policy.

## Domains

Every relation has two GordieHowe domains:

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

Streaming also exposes the updated sum, counter, average, and fingerprint,
as the original streaming circuit did. Other state, request values,
randomness and signatures are private witness values.

## Canonical encoding

Integers use fixed-width little-endian encoding. IP addresses are `uint32`,
geohashes and the state counter are `uint64`, and PRF seeds, nonces and
commitment randomness are 32 bytes. A fingerprint is two 32-byte
little-endian blocks; each block's high six bits must be zero, leaving the
original 250 bits per block for credential history and attribution.
Streaming stores the fingerprint as opaque bytes without similarity or
padding checks. The year of birth is two ASCII bytes.

Attribution values are opaque 16-byte UUIDs: all 128 bits are preserved in
the supplied byte order, without UUID version/variant restrictions or BN254
reduction. `AttributionValue` is separate from the 32-byte hash digest type.
`attribution_value(uint64_t)` zero-extends a little-endian integer for the
original example query values. Both circuit and host code use
`kAttributionBytes` / `kAttributionBits` for the history and request widths.
The state and server-response hash tags are now `attribution-state/v2` and
`attribution-server-response/v2` under `zk-cookies/`. This replaces the former
32-byte encoding; attribution commitments, signatures and proofs from that
encoding must be regenerated. Benchmark configuration records include
`attribution_bits=128`.
Streaming uses a 128-bit unsigned sum (`GeohashSum`, two little-endian
`uint64_t` limbs), and 64-bit unsigned counters and averages.

Every application-level hash call hashes:

```text
u16le(tag length) || tag || u64le(payload length) || payload
```

Tags are defined beside their calls in the circuit and builder headers.
Credential history retains its existing tags and payload encoding.
Attribution state payloads begin with `u32le(IP history length)` and
`u32le(attribution history length)`, followed by IPs, geohashes, fingerprint,
year of birth, attribution values, seed and counter. Streaming encodes sum,
counter, average, fingerprint, year of birth and seed. The new variants have
distinct state and server-response tags. Both attribution variants share
their encoding, as in Circom.

ML-DSA signs the 32-byte initial-state commitment and the
32-byte server-response digest under an empty context. ML-DSA's
standards-mandated SHAKE hashing is never replaced by the application-hash
policy.

## Hash policies

`zk_cookies_hash.h` is the application-hash boundary. A policy provides a 32-byte
host hash and its matching circuit gadget. The built-in policies are
`hashes::Poseidon2b` (the default), `hashes::Blake3`, `hashes::Blake2s`, and
`hashes::Sha256`.
The relation and every matching host builder take the policy as a template
argument. For example:

```c++
auto relation = zk_cookies_credential_history<P, hashes::Blake2s>(env, history_length);
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

`zk_cookies_credential_history(env, history_length)` uses Poseidon2b and compiles a relation for a
fixed history shape. `zk_cookies_credential_history<P, Hash>(env, history_length)` selects another
policy. For example, lengths 5 and 25 produce separate compiled relations.
Optional `CredentialHistoryConfig` values change the original policy constants; its
defaults are the Circom circuit's 20 shared geohash bits, similarity strictly
above 400 of 500 bits, and RAPPOR thresholds 127 and 191.

`zk_cookies_credential_history_builders.h` contains the matching host-side encoding, state update,
hashing, RAPPOR calculation, public-statement builder, and decoded-signature
assignment helper.

The other factories are:

```c++
auto single = zk_cookies_single_attribution<P, Hash>(env, attribution_length, ip_length);
auto multi = zk_cookies_multi_attribution<P, Hash>(env, attribution_length, ip_length);
auto streaming = zk_cookies_streaming<P, Hash>(env);
```

IP history defaults to 5 for attribution. `AttributionConfig` contains the
shared `policy`, a `search_value` (default `123456`), and `search_chain`
(default `[15,16,17,18]`). These queries are construction parameters, not
public or private inputs. Single attribution requires a matching old history
entry. Multi attribution deliberately preserves Circom's OR within each
window and exclusion of the final possible window: a single correctly
positioned equality is sufficient. Its history must be longer than the
nonempty query (at least 5 for the default four values). Both variants always
prepend the new attribution and drop the last entry, including when the IP
was already present. A history of length 1 is supported for single attribution.

Streaming checks both old and new averages with exact integer inequalities
`average * counter <= sum < average * counter + counter`. This requires a
positive old counter. Sum and counter updates reject overflow. Geohash
comparison uses the top configured bits of the 64-bit average and request
(20 by default), without a cold-start bypass. Unlike the history variants,
streaming has no fingerprint-similarity check; its Bloom filter contains only
the old counter and old average. `StreamingConfig` controls geohash precision
and RAPPOR thresholds.

## Scaling

The first-empty-slot selector uses parallel prefixes of nonzero-slot flags
(`arith::prefix_and`), followed by the current slot's zero flag. This preserves
the original semantics, including holes, duplicate IPs, a zero new IP, and
nonzero geohashes beside zero IPs. Prefix depth is logarithmic in history
length. The update applies tensor-wide muxes and a slice/append shift rather
than building one concatenation per history entry; the remaining selector
views are joined in a balanced tree. Zero-slot predicates are also an
uncommitted derived Bit view, evaluated once for all witness generators.

Attribution shifts are single slice/append views, and searches use vectorized
equalities and balanced reductions. For the default fixed four-value query,
search work is linear in history length and depth is logarithmic. The two
full-state hashes reuse the native per-hash witness generator described above,
so they do not repeatedly pack the whole history for each sponge block.

Streaming's 64-by-64 multiplication uses quadratic bit partial products and a
balanced tree of committed 128-bit sums, with six addition levels. Comparisons
are balanced bit reductions. Updates carry an extra bit and constrain it to
zero. Its circuit and witness work are independent of the counter's value;
there is no loop over past requests or division witness.

BLAKE3 and BLAKE2s use field addition for XOR in the binary domain. Each
hash's witness is generated with native `uint32_t` arithmetic and committed as
packed arrays of addition results and chaining values. Addition constraints
are vectorized across compression operations. BLAKE3 implements the standard
1024-byte chunk tree, so application messages are not limited to one chunk.

## Benchmark runners

The benchmark executable takes the compiled state-history shape through
`--history-length` (default `5`). For example, after configuring the build:

```sh
cmake --build build --target \
  zk_cookies_credential_history_bench \
  zk_cookies_single_attribution_bench \
  zk_cookies_multi_attribution_bench \
  zk_cookies_streaming_bench -j4

GH_THREADS=multi ./build/bench/zk_cookies_credential_history_bench bench \
  --history-length 5 --profile narrow --reps 1

GH_THREADS=multi ./build/bench/zk_cookies_single_attribution_bench bench \
  --history-length 100 --ip-history-length 5 --reps 1

GH_THREADS=multi ./build/bench/zk_cookies_multi_attribution_bench bench \
  --history-length 100 --ip-history-length 5 --reps 1

GH_THREADS=multi ./build/bench/zk_cookies_streaming_bench bench \
  --state-counter 100 --reps 1
```

Use `--hash blake3`, `--hash poseidon2b`, `--hash blake2s`, or `--hash sha256`
to compare the same relation and witness with a different application hash.
All runners default to `--hash poseidon2b --profile narrow`. Explicitly
selecting `--profile wide --hash poseidon2b` fails before circuit construction.
The other hashes support both profiles. For example:

```sh
for hash in blake3 poseidon2b blake2s sha256; do
  ./build/bench/zk_cookies_credential_history_bench bench \
    --history-length 5 --profile narrow --hash "$hash" --reps 1
done
```

Every runner also supports the standard `serve` and `report` commands and emits
the variant, selected hash and history sizes in `GH_ZK_COOKIES_CONFIG` and
`GH_ZK_COOKIES_SIZE`. Streaming's `--state-counter` changes the example witness,
not the compiled shape. Run
`./build/bench/zk_cookies_credential_history_bench bench --help` for all flags.

The port deliberately preserves the original zero-sentinel behavior: it
does not add constraints requiring nonzero history entries to be contiguous,
requiring `new_ip` to be nonzero, or tying a zero IP slot to a zero geohash.
