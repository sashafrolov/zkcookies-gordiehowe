# zk-cookies state relation

`state.h` ports `zk_cred_logic/state.circom` to GordieHowe. It validates a
signed old state and signed server response, applies the original geohash,
fingerprint and age policies, produces the RAPPOR response and nullifiers,
and publishes a commitment to the updated state.

## Domains

The relation has two GordieHowe domains:

- `H`, the binary domain, performs BLAKE2s-256, the state transition,
  geohash/fingerprint/age checks, RAPPOR, and the SHAKE computations required
  by ML-DSA.
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

Every application-level BLAKE2s call hashes:

```text
u16le(tag length) || tag || u64le(payload length) || payload
```

The tags are defined beside their calls in `state.h` and
`state_builders.h`. ML-DSA signs the 32-byte initial-state commitment and
the 32-byte server-response digest under an empty context. ML-DSA's
standards-mandated SHAKE hashing is not replaced by BLAKE2s.

## Construction

`state(env, history_length)` compiles a relation for a fixed history shape.
For example, lengths 5 and 25 produce separate compiled relations. Optional
`StateConfig` values change the original policy constants; its defaults are
the Circom circuit's 20 shared geohash bits, similarity strictly above 400
of 500 bits, and RAPPOR thresholds 127 and 191.

`state_builders.h` contains the matching host-side encoding, state update,
hashing, RAPPOR calculation, public-statement builder, and decoded-signature
assignment helper.

BLAKE2s uses field addition for XOR in the binary domain. Each hash's
witness is generated with native `uint32_t` arithmetic and committed as
packed arrays of addition results and chaining values. Addition constraints
are vectorized across message blocks, and the final digest has its own
small array for subsequent hashes to read. These are circuit and witness
construction choices; the hash, canonical encoding, and state policies are
unchanged.

## Benchmark runner

The benchmark executable takes the compiled state-history shape through
`--history-length` (default `5`). For example, after configuring the build:

```sh
cmake --build build --target zk_cookies_state_bench -j4
./build/bench/zk_cookies_state_bench bench \
  --history-length 5 --profile narrow --reps 1
```

It also supports the standard `serve` and `report` commands. Run
`./build/bench/zk_cookies_state_bench bench --help` for the benchmark flags.

The port deliberately preserves the original zero-sentinel behavior: it
does not add constraints requiring nonzero history entries to be contiguous,
requiring `new_ip` to be nonzero, or tying a zero IP slot to a zero geohash.
