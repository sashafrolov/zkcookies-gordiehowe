// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Common CLI and reporting for all four benchmark executables.
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_BENCH_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_BENCH_H_

#include <cstdio>
#include <limits>
#include "bench/bench_hook.h"
#include "bench/cli.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_testing.h"

namespace proofs::gordiehowe::examples::zk_cookies::benchmark {
namespace hook = examples::bench_hook;
enum class Kind { kCredentialHistory, kSingleAttribution, kMultiAttribution,
                  kStreaming };
template <Kind K> constexpr const char *name() {
  if constexpr (K == Kind::kCredentialHistory) return "credential-history";
  if constexpr (K == Kind::kSingleAttribution) return "single-attribution";
  if constexpr (K == Kind::kMultiAttribution) return "multi-attribution";
  return "streaming";
}
struct ShapeOptions {
  size_t history_length = 0;
  size_t ip_history_length = 0;
  uint64_t state_counter = 0;
};
template <Kind K> ShapeOptions shape(const bench::Flags &f) {
  ShapeOptions s;
  if constexpr (K == Kind::kStreaming) {
    s.state_counter = f.num("state-counter");
    if (s.state_counter == 0 || s.state_counter == UINT64_MAX)
      throw bench::UsageError("--state-counter must lie in [1, 2^64-2]");
  } else {
    const auto n = f.num("history-length");
    if (n == 0 || n > UINT32_MAX)
      throw bench::UsageError("--history-length must lie in [1, 2^32-1]");
    s.history_length = size_t(n);
    s.ip_history_length = s.history_length;
    if constexpr (K != Kind::kCredentialHistory) {
      const auto ips = f.num("ip-history-length");
      if (ips == 0 || ips > UINT32_MAX)
        throw bench::UsageError("--ip-history-length must lie in [1, 2^32-1]");
      s.ip_history_length = size_t(ips);
    }
    if constexpr (K == Kind::kMultiAttribution)
      if (n <= 4) throw bench::UsageError("multi attribution needs --history-length >= 5");
  }
  return s;
}

// The standard common flags, with this application's narrow profile default.
// Keep this small adapter local rather than changing upstream bench/cli.h.
inline void add_application_common_flags(bench::Flags &f) {
  std::string names;
  for (const auto &[n, member] : bench::diagnostic_names())
    names += std::string(names.empty() ? "" : ",") + n;
  f.flag("profile", "narrow", "the field profile (its kId)")
      .flag("seed", "", "fixed-seed proofs, each printing GH_PROOF_DIGEST")
      .toggle("serial-commitments", "commit domains on the calling thread")
      .flag("diagnostics", "", "diagnostic switches: " + names)
      .flag("rate-requests", "", "append placement rate requests to this file");
}
template <Kind K> void add_flags(bench::Flags &f, bool hook_flags, bool reps) {
  add_application_common_flags(f);
  if (hook_flags) hook::add_hook_flags(f);
  if (reps) f.flag("reps", "3", "the proofs to time");
  f.flag("hash", hashes::Default::kId,
         "application hash: poseidon2b, blake2s, sha256, or blake3");
  if constexpr (K == Kind::kStreaming) {
    f.flag("state-counter", "100", "the initial streaming counter (fixed circuit size)");
  } else {
    f.flag("history-length", "5", K == Kind::kCredentialHistory
        ? "the number of IP/geohash history entries"
        : "the number of 128-bit UUID attribution history entries");
    if constexpr (K != Kind::kCredentialHistory)
      f.flag("ip-history-length", "5", "the number of IP/geohash history entries");
  }
}

template <Kind K, class Hash> auto instance(const ShapeOptions &s) {
  if constexpr (K == Kind::kCredentialHistory) {
    auto w = testing::credential_history_witness(s.history_length);
    const auto pk = testing::sign<Hash>(w);
    return std::make_pair(credential_history_statement(pk, host::outputs<Hash>(w)), w);
  } else if constexpr (K == Kind::kStreaming) {
    auto w = testing::streaming_witness(s.state_counter);
    const auto pk = testing::sign<Hash>(w);
    return std::make_pair(streaming_statement(pk, host::outputs<Hash>(w)), w);
  } else {
    constexpr auto mode = K == Kind::kSingleAttribution
                              ? AttributionMode::kSingle : AttributionMode::kMulti;
    auto w = testing::attribution_witness(s.history_length, s.ip_history_length, mode);
    const auto pk = testing::sign<Hash>(w);
    return std::make_pair(update_statement<AttributionStatement<Value>>(
                              pk, host::outputs<Hash>(w)), w);
  }
}
template <Kind K, class P, class Hash>
auto relation(const mldsa::Env<P> &env, const ShapeOptions &s) {
  if constexpr (K == Kind::kCredentialHistory)
    return zk_cookies_credential_history<P, Hash>(env, s.history_length);
  else if constexpr (K == Kind::kSingleAttribution)
    return zk_cookies_single_attribution<P, Hash>(env, s.history_length, s.ip_history_length);
  else if constexpr (K == Kind::kMultiAttribution)
    return zk_cookies_multi_attribution<P, Hash>(env, s.history_length, s.ip_history_length);
  else
    return zk_cookies_streaming<P, Hash>(env);
}
template <Kind K, class P, class Hash, class Fn>
void with_system(const bench::Flags &f, Fn fn) {
  using Sys = typename mldsa::Env<P>::Sys;
  const auto s = shape<K>(f);
  const auto x = instance<K, Hash>(s);
  const mldsa::Env<P> env;
  std::string config = std::string("zk-cookies-") + name<K>() + "-" + Hash::kId;
  if constexpr (K != Kind::kStreaming) {
    config += "-" + std::to_string(s.history_length);
    if constexpr (K != Kind::kCredentialHistory)
      config += "-ips-" + std::to_string(s.ip_history_length);
  }
  hook::Setup su{config.c_str(), P::kId};
  const auto t0 = hook::Clock::now();
  const auto rel = relation<K, P, Hash>(env, s);
  const auto &typed = rel.template typed<Sys>();
  su.build = hook::ms_since(t0) - typed.compile_ms();
  su.compile = typed.compile_ms();
  const auto compiled = typed.compiled_ptr();
  const auto statement = typed.statement(x.first);
  std::printf("GH_ZK_COOKIES_CONFIG variant=%s profile=%s hash=%s "
              "history_length=%zu ip_history_length=%zu state_counter=%llu",
              name<K>(), P::kId, Hash::kId, s.history_length,
              s.ip_history_length, static_cast<unsigned long long>(s.state_counter));
  if constexpr (K == Kind::kSingleAttribution || K == Kind::kMultiAttribution)
    std::printf(" attribution_bits=%zu", kAttributionBits);
  std::printf("\n");
  fn(*compiled, statement, [&] { return typed.witness(x.second); }, su);
}
template <Kind K, class P, class Fn>
void with_hash(const bench::Flags &f, Fn fn) {
  const auto hash = f.str("hash");
  if (hash == hashes::Poseidon2b::kId) {
    if constexpr (hashes::Poseidon2b::template supports<typename P::HashField>)
      with_system<K, P, hashes::Poseidon2b>(f, fn);
    else
      throw bench::UsageError("--hash poseidon2b supports only --profile narrow");
  } else if (hash == hashes::Blake2s::kId) {
    with_system<K, P, hashes::Blake2s>(f, fn);
  } else if (hash == hashes::Blake3::kId) {
    with_system<K, P, hashes::Blake3>(f, fn);
  } else if (hash == hashes::Sha256::kId) {
    with_system<K, P, hashes::Sha256>(f, fn);
  } else {
    throw bench::UsageError("unknown --hash '" + hash + "'");
  }
}
template <Kind K> auto systems(const bench::Flags &f) {
  return [&f](auto p, auto fn) { with_hash<K, decltype(p)>(f, fn); };
}
template <Kind K> int report(const bench::Flags &f) {
  const auto profile = bench::apply_common_flags(f);
  param_sets::with_profile(profile, [&](auto p) {
    with_hash<K, decltype(p)>(f, [&](const auto &compiled, const auto &,
                                     auto, const hook::Setup &) {
      const auto r = compiled.report();
      std::printf("%s", r.c_str());
      for (const char *domain : {"A", "H"}) {
        const auto size = mldsa::support::domain_size(r, domain);
        std::printf("GH_ZK_COOKIES_SIZE variant=%s profile=%s hash=%s "
                    "history_length=%zu ip_history_length=%zu domain=%s "
                    "layers=%zu quad=%zu inputs=%zu public=%zu committed=%zu "
                    "nw=%zu nq=%zu affine=%zu\n", name<K>(), decltype(p)::kId,
                    f.str("hash").c_str(), shape<K>(f).history_length,
                    shape<K>(f).ip_history_length, domain, size.layers,
                    size.quad, size.inputs, size.publics, size.committed,
                    size.nw, size.nq, size.affine);
      }
    });
  });
  return 0;
}
template <Kind K> int main(int argc, char **argv) {
  using bench::Flags;
  return bench::run_commands(argc, argv,
      std::string("zk-cookies ") + name<K>() + " benchmarks",
      {{"serve", "a report_bench worker",
        [](Flags &f) { add_flags<K>(f, true, false); },
        [](const Flags &f) { return hook::serve_command(f, systems<K>(f)); }},
       {"bench", "benchmark with --reps proofs",
        [](Flags &f) { add_flags<K>(f, true, true); },
        [](const Flags &f) { return hook::bench_command(f, systems<K>(f)); }},
       {"report", "the compile report and each domain's sizes",
        [](Flags &f) { add_flags<K>(f, false, false); }, report<K>}});
}
} // namespace proofs::gordiehowe::examples::zk_cookies::benchmark
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_BENCH_H_
