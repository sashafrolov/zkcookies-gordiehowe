// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Phase benchmark for the Ligero polynomial-commitment path over GF(2^128).
// It commits to COEFFICIENTS field elements, then proves the dense linear
// claim p(z) = sum_i coefficients[i] z^i through Ligero's accumulator API.
//
// The PQ_PHASE lines are emitted by util/prover_profile.h.  Parent phases
// include their more detailed child phases; for example, bin.ligero.encode
// includes bin.ligero.rs, and bin.ligero.merkle includes the three
// merkle.commit.* phases.

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "gordiehowe/threads.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "ligero/ligero_verifier.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/diagnostics.h"
#include "util/parallel.h"
#include "util/prover_profile.h"

namespace proofs {
namespace {

using Field = GF2_128<>;
using Elt = Field::Elt;
using ReedSolomonFactory = LCH14ReedSolomonFactory<Field>;
using Clock = std::chrono::steady_clock;

struct Options {
  size_t coefficients = size_t{1} << 20;
  size_t rate_inverse = 4;
  size_t queries = 189;
  size_t threads = 1;
  bool verify = true;
};

[[noreturn]] void usage(const char *program, const char *error = nullptr) {
  FILE *out = error == nullptr ? stdout : stderr;
  if (error != nullptr) std::fprintf(out, "%s: %s\n", program, error);
  std::fprintf(
      out,
      "usage: %s [OPTION...]\n"
      "Benchmark Ligero commit/open phases over GF(2^128).\n\n"
      "  --coefficients N       polynomial coefficient count (default 2^20)\n"
      "  --log-coefficients L   set the coefficient count to 2^L\n"
      "  --rate-inverse R       code inverse rate (default 4)\n"
      "  --queries Q            opened columns / ZK randomizers (default 189)\n"
      "  --threads T            worker threads including the caller (default 1)\n"
      "  --no-verify            do not run the verifier after opening\n"
      "  -h, --help             show this help\n\n"
      "Example: %s --log-coefficients 24 --threads 8\n",
      program, program);
  std::exit(error == nullptr ? 0 : 2);
}

size_t number(std::string_view text, const char *what, const char *program) {
  uint64_t value = 0;
  const char *begin = text.data();
  const char *end = begin + text.size();
  const auto [at, error] = std::from_chars(begin, end, value);
  if (error != std::errc{} || at != end || value == 0 ||
      value > std::numeric_limits<size_t>::max()) {
    std::string message = std::string(what) + " must be a positive integer";
    usage(program, message.c_str());
  }
  return static_cast<size_t>(value);
}

Options parse(int argc, char **argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    auto next = [&](const char *what) -> std::string_view {
      if (++i == argc) {
        std::string message = std::string("missing value for ") + what;
        usage(argv[0], message.c_str());
      }
      return argv[i];
    };
    if (arg == "-h" || arg == "--help") usage(argv[0]);
    if (arg == "--no-verify") {
      o.verify = false;
    } else if (arg == "--coefficients") {
      o.coefficients =
          number(next("--coefficients"), "coefficient count", argv[0]);
    } else if (arg == "--log-coefficients") {
      const size_t log = number(next("--log-coefficients"),
                                "coefficient logarithm", argv[0]);
      if (log >= std::numeric_limits<size_t>::digits) {
        usage(argv[0], "coefficient logarithm is too large");
      }
      o.coefficients = size_t{1} << log;
    } else if (arg == "--rate-inverse") {
      o.rate_inverse = number(next("--rate-inverse"), "inverse rate", argv[0]);
    } else if (arg == "--queries") {
      o.queries = number(next("--queries"), "query count", argv[0]);
    } else if (arg == "--threads") {
      o.threads = number(next("--threads"), "thread count", argv[0]);
    } else {
      std::string message = "unknown option " + std::string(arg);
      usage(argv[0], message.c_str());
    }
  }
  return o;
}

double milliseconds(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
}

template <class Fn>
double timed(Fn &&fn) {
  const auto start = Clock::now();
  fn();
  return milliseconds(start);
}

template <class Fn>
double profiled(const char *phase, size_t coefficients, Fn &&fn) {
  profiling::Session session(phase, "GF(2^128)", coefficients, 0);
  return timed(std::forward<Fn>(fn));
}

double gib(size_t count, size_t element_size) {
  return static_cast<double>(count) * static_cast<double>(element_size) /
         static_cast<double>(uint64_t{1} << 30);
}

// SplitMix64 is only used to make a repeatable, nontrivial benchmark
// polynomial.  Protocol blinding still comes from SecureRandomEngine.
uint64_t splitmix64(uint64_t &state) {
  uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

size_t proof_storage_bytes(const LigeroProof<Field> &proof) {
  return (proof.y_ldt.size() + proof.y_dot.size() + proof.y_quad_0.size() +
          proof.y_quad_2.size() + proof.req.size()) *
             sizeof(Elt) +
         proof.merkle.nonce.size() * sizeof(BasicMerkleNonce<>) +
         proof.merkle.path.size() * sizeof(Digest);
}

int run(const Options &o) {
  diagnostics::Options diagnostics;
  diagnostics.profile = true;
  diagnostics::set(diagnostics);

  // Field construction does real precomputation, so time a fresh instance
  // separately rather than hiding it in the first protocol phase.
  std::unique_ptr<Field> field;
  const double actual_field_setup_ms =
      timed([&] { field = std::make_unique<Field>(); });
  const Field &F = *field;
  ReedSolomonFactory rs_factory(F);

  std::unique_ptr<LigeroParam<Field>> param;
  const double parameter_ms = timed([&] {
    param = std::make_unique<LigeroParam<Field>>(
        o.coefficients, /*nq=*/0, o.rate_inverse, o.queries);
  });
  const auto &p = *param;
  const size_t tableau_elements = p.nrow * p.block_enc;
  const size_t linear_elements = p.nwqrow * p.w;

  std::printf(
      "CONFIG field=GF(2^128) coefficients=%zu rate_inverse=%zu queries=%zu "
      "threads=%zu verify=%s\n",
      o.coefficients, o.rate_inverse, o.queries, o.threads,
      o.verify ? "yes" : "no");
  std::printf(
      "LAYOUT block=%zu dblock=%zu block_enc=%zu extension_columns=%zu "
      "witnesses_per_row=%zu witness_rows=%zu total_rows=%zu\n",
      p.block, p.dblock, p.block_enc, p.block_ext, p.w, p.nwrow, p.nrow);
  std::printf(
      "MEMORY coefficients_gib=%.3f tableau_gib=%.3f linear_vector_gib=%.3f\n",
      gib(o.coefficients, sizeof(Elt)),
      gib(tableau_elements, sizeof(Elt)),
      gib(linear_elements, sizeof(Elt)));
  std::printf("RESULT phase=field_setup ms=%.3f\n", actual_field_setup_ms);
  std::printf("RESULT phase=parameter_selection ms=%.3f\n", parameter_ms);
  std::vector<Elt> coefficients;
  const double coefficient_init_ms = timed([&] {
    coefficients.resize(o.coefficients);
    uint64_t state = 0x6c696765726f3234ULL;
    for (Elt &coefficient : coefficients) {
      coefficient = F.of_scalar_field(
          {splitmix64(state), splitmix64(state)});
    }
  });
  const Elt point = F.of_scalar_field(2);
  Elt claimed = F.zero();
  const double evaluation_ms = timed([&] {
    for (size_t i = coefficients.size(); i-- > 0;) {
      claimed = F.mulf(claimed, point);
      F.add(claimed, coefficients[i]);
    }
  });
  std::printf("RESULT phase=coefficient_initialization ms=%.3f\n",
              coefficient_init_ms);
  std::printf("RESULT phase=claimed_evaluation_setup ms=%.3f\n",
              evaluation_ms);

  std::unique_ptr<gordiehowe::internal::TaskPool> pool;
  const double thread_pool_ms = timed([&] {
    if (o.threads > 1) {
      pool = std::make_unique<gordiehowe::internal::TaskPool>(o.threads - 1);
    }
  });
  parallel::Scope parallel_scope(pool.get());
  std::printf("RESULT phase=thread_pool_setup ms=%.3f\n", thread_pool_ms);

  std::unique_ptr<LigeroProver<Field, ReedSolomonFactory>> prover;
  const double prover_setup_ms = timed([&] {
    prover = std::make_unique<LigeroProver<Field, ReedSolomonFactory>>(p);
  });
  std::printf("RESULT phase=prover_allocation ms=%.3f\n", prover_setup_ms);

  SecureRandomEngine rng;
  const ProofSeed seed = ProofSeed::draw(rng);
  const uint8_t label[] = "ligero-phase-bench";
  Transcript prover_transcript(label, sizeof(label) - 1, seed);
  LigeroCommitment<Field> commitment;

  const double commit_compute_ms = profiled(
      "ligero.commit", o.coefficients, [&] {
        prover->commit_compute(commitment, coefficients.data(),
                               /*subfield_boundary=*/0,
                               /*lqc=*/nullptr, rs_factory, rng, F);
      });
  const double commit_transcript_ms = timed(
      [&] { prover->commit_write(commitment, prover_transcript); });
  std::printf("RESULT phase=commit_compute ms=%.3f\n", commit_compute_ms);
  std::printf("RESULT phase=commit_transcript ms=%.3f\n",
              commit_transcript_ms);

  std::unique_ptr<LigeroProof<Field>> proof;
  const double proof_setup_ms =
      timed([&] { proof = std::make_unique<LigeroProof<Field>>(&p); });
  std::printf("RESULT phase=proof_allocation ms=%.3f\n", proof_setup_ms);

  // One dense linear claim, p(point) = claimed.  Generating the powers of
  // point is intentionally inside Ligero's rows phase: it is opening work,
  // not benchmark setup.
  const typename LigeroProver<Field, ReedSolomonFactory>::Accumulator accum =
      [&](Elt *A, const Elt *alphal) {
        Elt power = F.one();
        for (size_t i = 0; i < o.coefficients; ++i) {
          F.add(A[i], F.mulf(alphal[0], power));
          power = F.mulf(power, point);
        }
      };

  const double opening_ms = profiled("ligero.open", o.coefficients, [&] {
    prover->prove(*proof, prover_transcript, /*nl=*/1, /*nllterm=*/0,
                  /*llterm=*/nullptr, /*lqc=*/nullptr, rs_factory, F, &accum);
  });
  std::printf("RESULT phase=opening_prover ms=%.3f\n", opening_ms);
  std::printf("RESULT phase=proof_storage bytes=%zu mib=%.3f\n",
              proof_storage_bytes(*proof),
              static_cast<double>(proof_storage_bytes(*proof)) /
                  static_cast<double>(uint64_t{1} << 20));

  if (o.verify) {
    Transcript verifier_transcript(label, sizeof(label) - 1, seed);
    const Elt claimed_values[] = {claimed};
    const char *why = "verification did not run";
    bool ok = false;
    const double verify_ms =
        profiled("ligero.verify", o.coefficients, [&] {
          LigeroVerifier<Field, ReedSolomonFactory>::receive_commitment(
              commitment, verifier_transcript);
          ok = LigeroVerifier<Field, ReedSolomonFactory>::verify(
              &why, p, commitment, *proof, verifier_transcript, /*nl=*/1,
              /*nllterm=*/0, /*llterm=*/nullptr, claimed_values,
              /*lqc=*/nullptr, rs_factory, F, &accum);
        });
    std::printf("RESULT phase=opening_verifier ms=%.3f status=%s reason=%s\n",
                verify_ms, ok ? "ok" : "failed", why);
    if (!ok) return 1;
  }

  std::printf(
      "NOTE PQ_PHASE parent timings include their child timings; subtract "
      "bin.ligero.rs from bin.ligero.encode for non-RS layout work.\n");
  return 0;
}

}  // namespace
}  // namespace proofs

int main(int argc, char **argv) {
  try {
    return proofs::run(proofs::parse(argc, argv));
  } catch (const std::bad_alloc &) {
    std::fprintf(stderr,
                 "ligero_phase_bench: allocation failed; reduce "
                 "--log-coefficients or --coefficients\n");
    return 1;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "ligero_phase_bench: %s\n", e.what());
    return 1;
  }
}
