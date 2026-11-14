// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// The zk-cookies state relation's benchmark executable:
// zk_cookies_state_bench COMMAND [FLAG...].
//   serve    a report_bench worker (bench_hook.h, bench/harness.h)
//   bench    the same records and --reps proofs without report_bench
//   report   the compile report and each domain's sizes
// Every command takes --history-length, which fixes the compiled relation's
// state-history shape, and --hash, which selects its application hash.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "bench/bench_hook.h"
#include "bench/cli.h"
#include "gordiehowe/examples/mldsa/mldsa_native_testing.h"
#include "gordiehowe/examples/mldsa/mldsa_openssl_testing.h"
#include "gordiehowe/examples/zk-cookies/state_builders.h"

namespace proofs::gordiehowe::examples::zk_cookies {
namespace {

namespace hook = examples::bench_hook;

void add_history_length_flag(bench::Flags &f) {
  f.flag("history-length", "5",
         "the number of IP/geohash entries in the compiled state history");
}

void add_hash_flag(bench::Flags &f) {
  f.flag("hash", hashes::Default::kId,
         "application hash: blake3, poseidon2b, blake2s, or sha256");
}

size_t history_length(const bench::Flags &f) {
  const uint64_t n = f.num("history-length");
  if (n == 0)
    throw bench::UsageError("--history-length must be at least 1");
  if (n > std::numeric_limits<size_t>::max())
    throw bench::UsageError("--history-length does not fit in size_t");
  return static_cast<size_t>(n);
}

Fingerprint fingerprint(size_t flipped) {
  Fingerprint out{};
  for (size_t bit = 0; bit < flipped; ++bit) {
    const size_t local = bit % kFingerprintBitsPerBlock;
    out[bit / kFingerprintBitsPerBlock][local / 8] |= uint8_t(1) << (local % 8);
  }
  return out;
}

StateWitness<Value> benchmark_witness(size_t n) {
  StateWitness<Value> w = state_witness_shape(n);
  w.initial_state.last_fingerprint = fingerprint(0);
  w.initial_state.year_of_birth = {'0', '0'};
  for (size_t i = 0; i < 32; ++i) {
    w.initial_state.users_prf_seed[i] = uint8_t(3 * i + 1);
    w.initial_commitment_randomness[i] = uint8_t(5 * i + 2);
    w.new_rappor_nonce[i] = uint8_t(7 * i + 3);
    w.new_state_commitment_randomness[i] = uint8_t(11 * i + 4);
  }
  w.new_ip = 3232235526u;
  w.new_geohash = 3856082809388864ull;
  // 99 changed bits leaves 401 of 500 equal, the strict original bound.
  w.new_fingerprint = fingerprint(99);
  return w;
}

mldsa::Signature decoded_signature(const std::vector<uint8_t> &pk,
                                   const std::vector<uint8_t> &message,
                                   const std::vector<uint8_t> &signature) {
  ml_dsa::MlDsa44SignatureExample ex;
  ex.pkey = pk;
  ex.msg = message;
  ex.sig = signature;
  const mldsa::support::Existing<MLDSA> existing(ex);
  if (!existing.ok)
    throw std::runtime_error("benchmark ML-DSA signature rejected");
  return existing.signature();
}

struct Instance {
  StateStatement<Value> statement;
  StateWitness<Value> witness;
};

template <class Hash> Instance benchmark_instance(size_t n) {
  std::array<uint8_t, 32> key_seed{};
  for (size_t i = 0; i < key_seed.size(); ++i)
    key_seed[i] = uint8_t(i);
  const auto key = mldsa::support::mldsa_key<MLDSA>(key_seed);
  const auto pk = mldsa::support::mldsa_public<MLDSA>(key);

  auto witness = benchmark_witness(n);
  const auto [initial_message, response_message] =
      host::signature_messages<Hash>(witness);
  const auto initial_bytes =
      mldsa::support::mldsa_sign<MLDSA>(key, initial_message, {});
  const auto response_bytes =
      mldsa::support::mldsa_sign<MLDSA>(key, response_message, {});
  set_signature(witness.initial_state_signature,
                decoded_signature(pk, initial_message, initial_bytes));
  set_signature(witness.server_response_signature,
                decoded_signature(pk, response_message, response_bytes));
  auto statement = state_statement(pk, host::outputs<Hash>(witness));
  return {std::move(statement), std::move(witness)};
}

// The state system at history length --history-length, compiled and handed
// to FN with its statement, witness factory and setup record.
template <class P, class Hash, class Fn>
void with_system(const bench::Flags &f, Fn fn) {
  using Sys = typename mldsa::Env<P>::Sys;
  const size_t n = history_length(f);
  const Instance x = benchmark_instance<Hash>(n);
  const mldsa::Env<P> env;
  const std::string config =
      std::string("zk-cookies-state-") + Hash::kId + "-" + std::to_string(n);
  hook::Setup su{config.c_str(), P::kId};
  const auto t0 = hook::Clock::now();
  const auto relation = state<P, Hash>(env, n);
  const auto &typed = relation.template typed<Sys>();
  su.build = hook::ms_since(t0) - typed.compile_ms();
  su.compile = typed.compile_ms();
  const auto compiled = typed.compiled_ptr();
  const auto statement = typed.statement(x.statement);
  std::printf("GH_ZK_COOKIES_CONFIG profile=%s hash=%s history_length=%zu\n",
              P::kId, Hash::kId, n);
  fn(*compiled, statement, [&] { return typed.witness(x.witness); }, su);
}

template <class P, class Fn>
void with_selected_hash(const bench::Flags &f, Fn fn) {
  const std::string hash = f.str("hash");
  if (hash == hashes::Poseidon2b::kId) {
    if constexpr (hashes::Poseidon2b::template supports<
                      typename P::HashField>) {
      with_system<P, hashes::Poseidon2b>(f, fn);
      return;
    } else {
      throw bench::UsageError(
          "--hash poseidon2b supports only --profile narrow");
    }
  }
  if (hash == hashes::Blake2s::kId) {
    with_system<P, hashes::Blake2s>(f, fn);
    return;
  }
  if (hash == hashes::Blake3::kId) {
    with_system<P, hashes::Blake3>(f, fn);
    return;
  }
  if (hash == hashes::Sha256::kId) {
    with_system<P, hashes::Sha256>(f, fn);
    return;
  }
  throw bench::UsageError("unknown --hash '" + hash +
                          "' (expected blake3, poseidon2b, blake2s, or "
                          "sha256)");
}

auto systems(const bench::Flags &f) {
  return [&f](auto p, auto fn) { with_selected_hash<decltype(p)>(f, fn); };
}

int report(const bench::Flags &f) {
  const std::string profile = bench::apply_common_flags(f);
  param_sets::with_profile(profile, [&](auto p) {
    with_selected_hash<decltype(p)>(f, [&](const auto &compiled, const auto &,
                                           auto, const hook::Setup &) {
      const std::string r = compiled.report();
      std::printf("%s", r.c_str());
      for (const char *domain : {"A", "H"}) {
        const auto size = mldsa::support::domain_size(r, domain);
        std::printf("GH_ZK_COOKIES_SIZE profile=%s hash=%s history_length=%zu "
                    "domain=%s layers=%zu quad=%zu inputs=%zu public=%zu "
                    "committed=%zu nw=%zu nq=%zu affine=%zu\n",
                    decltype(p)::kId, f.str("hash").c_str(), history_length(f),
                    domain, size.layers, size.quad, size.inputs, size.publics,
                    size.committed, size.nw, size.nq, size.affine);
      }
    });
  });
  return 0;
}

} // namespace
} // namespace proofs::gordiehowe::examples::zk_cookies

int main(int argc, char **argv) {
  namespace app = proofs::gordiehowe::examples::zk_cookies;
  namespace hook = proofs::gordiehowe::examples::bench_hook;
  using proofs::bench::Flags;
  return proofs::bench::run_commands(
      argc, argv, "The zk-cookies state relation's benches.",
      {{"serve", "a report_bench worker",
        [](Flags &f) {
          hook::add_serve_flags(f);
          app::add_history_length_flag(f);
          app::add_hash_flag(f);
        },
        [](const Flags &f) { return hook::serve_command(f, app::systems(f)); }},
       {"bench", "the worker's records and --reps proofs, alone",
        [](Flags &f) {
          hook::add_bench_flags(f);
          app::add_history_length_flag(f);
          app::add_hash_flag(f);
        },
        [](const Flags &f) { return hook::bench_command(f, app::systems(f)); }},
       {"report", "the compile report and each domain's sizes",
        [](Flags &f) {
          proofs::bench::add_common_flags(f);
          app::add_history_length_flag(f);
          app::add_hash_flag(f);
        },
        app::report}});
}
