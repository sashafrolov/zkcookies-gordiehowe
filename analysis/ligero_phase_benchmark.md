# Ligero commit/open phase benchmark

Measured 2026-11-11 on an Apple M3 MacBook Air (4 performance + 4
efficiency cores, 16 GiB), using AppleClang 21, a Release build, and
`-march=native`.

## What is measured

This repository exposes Ligero as the commitment layer for a witness vector;
it does not expose a standalone `open(polynomial, point)` API.  The benchmark
therefore treats the witness vector as the coefficients `a[i]` of a polynomial
and proves the native dense linear relation

`p(z) = sum_i a[i] z^i`.

The relation is supplied through `LigeroProver::Accumulator`, avoiding a
materialized list of 2^24 sparse constraint records while exercising the same
linear opening path.  The measured configuration is:

- GF(2^128), SHA-256, LCH14 Reed-Solomon encoder
- 2^24 = 16,777,216 coefficients
- inverse code rate 4 and 189 opened columns
- default `LigeroMode` (one LDT repetition and untested masks)
- no quadratic constraints
- `block = 5,461`, `block_enc = 32,768`, 3,183 witness rows, and 3,186
  total rows

The coefficient vector occupies 0.250 GiB, the prover tableau 1.556 GiB, and
the opening's linear vector another 0.250 GiB.  The resulting in-memory proof
is about 9.57 MiB.

## Single-thread result

One cold run was discarded, followed by five fresh-process trials.  The
median commit-compute time was **2.036 s**, the median prover opening time was
**0.603 s**, and the median verifier time was **0.814 s**.  The ranges were
1.950–2.231 s, 0.549–1.531 s, and 0.781–1.134 s respectively.  This fanless
machine was not CPU-pinned, so the opening and verifier have visible
scheduling/thermal outliers.

The following phase values come from the trial at (or nearest) each median;
child phases are shown inside their parent and are not added twice.

### Commit computation (2,035.96 ms)

| Phase | Time (ms) | Notes |
|---|---:|---|
| Reed-Solomon row encoding | 714.99 | All blinding and witness row extensions |
| Other row layout | 16.35 | Randomizers, coefficient copies, clearing, bookkeeping |
| Merkle leaf nonces | 0.28 | CSPRNG output for 21,847 leaves |
| Merkle leaf/column hashing | 1,303.09 | Hashes each encoded extension column |
| Merkle internal tree | 1.25 | Hashes the internal nodes |
| Total | **2,035.96** | Transcript root write is below 0.001 ms |

Merkle hashing is about 64% of commit computation; Reed-Solomon encoding is
about 35%; all remaining layout work is below 1%.  Allocating and
value-initializing the 1.556 GiB prover tableau is deliberately reported
separately by the executable (median about 85 ms after the cold run).

### Prover opening (602.79 ms)

| Phase | Time (ms) | Notes |
|---|---:|---|
| LDT response | 16.98 | Random linear combination of committed rows |
| Linear-vector setup | 64.38 | Sizes/clears the 0.250 GiB `A` vector |
| Linear-row assembly | 93.26 | Includes the dense `z^i` relation accumulator (about 73 ms) |
| Dot-product response | 399.55 | Encodes the linear rows and combines them with tableau rows |
| Quadratic-mask response | 0.02 | No quadratic constraints in this benchmark |
| Extract opened columns | 27.95 | Gathers 189 entries from every committed row |
| Build compressed Merkle paths | 0.42 | Nonces plus compressed authentication paths |
| Transcript/other | 0.24 | Remaining Fiat-Shamir and small-vector work |
| Total | **602.79** | |

The dot-product response is the dominant prover-opening phase.  Merkle path
construction itself is negligible; gathering the opened tableau columns is
the material part of the final open step.

### Verifier opening (814.19 ms)

| Phase | Time (ms) |
|---|---:|
| Transcript replay | 0.32 |
| Merkle verification | 8.14 |
| LDT column + response checks | 0.67 |
| Linear-row assembly | 75.03 |
| Encode linear rows at opened columns | 724.76 |
| Linear column + response checks | 0.91 |
| Quadratic checks | 0.29 |
| Other | 4.07 |
| Total | **814.19** |

## Parallel observation

With `--threads 8`, one warm-up was discarded and five fresh-process trials
were measured.  The medians were **500.60 ms** for commit, **391.42 ms** for
the prover opening, and **299.78 ms** for verification.  Relative to the
single-thread medians, these are speedups of 4.1x, 1.5x, and 2.7x.

The major prover setup medians were 121.84 ms for allocating the tableau and
0.88 ms for allocating the proof.  Measuring allocation, commit, proof
allocation, and opening together in each process gave an end-to-end prover
median of **957.12 ms**, excluding coefficient generation and computation of
the claimed evaluation.

### Eight-thread commit (500.60 ms)

| Phase | Time (ms) |
|---|---:|
| Reed-Solomon row encoding | 177.63 |
| Other row layout | 18.30 |
| Merkle leaf nonces | 0.28 |
| Merkle leaf/column hashing | 304.01 |
| Merkle internal tree | 0.38 |
| Total | **500.60** |

### Eight-thread prover opening (391.42 ms)

| Phase | Time (ms) |
|---|---:|
| LDT response | 10.45 |
| Linear-vector setup | 67.67 |
| Linear-row assembly | 161.75 |
| └ Dense relation accumulator | 131.31 |
| Dot-product response | 143.96 |
| Quadratic-mask response | 0.01 |
| Extract opened columns | 7.14 |
| Build compressed Merkle paths | 0.18 |
| Transcript/other | 0.27 |
| Total | **391.42** |

The accumulator is a nested part of linear-row assembly and is not added a
second time.  It generates the powers of the evaluation point sequentially;
the row encodings, tableau combinations, and column extraction use the thread
pool.  This serial relation construction and linear-vector initialization
limit opening's speedup.

### Eight-thread verifier opening (299.78 ms)

| Phase | Time (ms) |
|---|---:|
| Transcript replay | 0.75 |
| Merkle verification | 2.88 |
| LDT column + response checks | 1.75 |
| Linear-row assembly | 106.42 |
| └ Dense relation accumulator | 102.95 |
| Encode linear rows at opened columns | 177.43 |
| Linear column + response checks | 1.06 |
| Quadratic checks | 0.58 |
| Other | 8.93 |
| Total | **299.78** |

Commit ranged from 448.93 to 1,367.76 ms, opening from 261.89 to 475.04 ms,
and verification from 274.85 to 374.81 ms.  The commit maximum was a clear
scheduling outlier.  This fanless M3 has four performance and four efficiency
cores, and the standalone run was not CPU-pinned; use affinity controls on a
benchmarking host for publication-quality parallel numbers.

## Running it

```sh
./benchmarks/ligero_phases.sh --log-coefficients 24 --threads 1
./benchmarks/ligero_phases.sh --log-coefficients 24 --threads 8
```

The wrapper builds only `ligero_phase_bench` in Release mode.  The executable
also accepts `--coefficients`, `--rate-inverse`, `--queries`, and
`--no-verify`.  `RESULT` lines give setup and total times; `PQ_PHASE` lines
give the detailed phase timings.  Parent timings include their displayed
children—for example, `bin.ligero.encode` includes `bin.ligero.rs`.
