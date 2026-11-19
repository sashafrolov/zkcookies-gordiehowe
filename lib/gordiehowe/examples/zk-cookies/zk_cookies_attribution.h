// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// Shared relation for the single and multi attribution Circom ports.
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_H_

#include <limits>
#include "gordiehowe/examples/zk-cookies/zk_cookies_common.h"

namespace proofs::gordiehowe::examples::zk_cookies {

// Opaque UUID bytes. Preserve all 128 bits without imposing a UUID version or
// variant. Hash digests, seeds and nonces continue to use the 32-byte Digest.
inline constexpr size_t kAttributionBytes = 16;
inline constexpr size_t kAttributionBits = 8 * kAttributionBytes;
using AttributionValue = std::array<uint8_t, kAttributionBytes>;
inline AttributionValue attribution_value(uint64_t n) {
  AttributionValue value{};
  for (size_t i = 0; i < 8; ++i) value[i] = uint8_t(n >> (8 * i));
  return value;
}

enum class AttributionMode { kSingle, kMulti };
struct AttributionConfig {
  CredentialHistoryConfig policy{};
  AttributionValue search_value = attribution_value(123456);
  std::vector<AttributionValue> search_chain = {
      attribution_value(15), attribution_value(16),
      attribution_value(17), attribution_value(18)};
};

template <template <class> class F> struct AttributionState {
  F<std::vector<uint32_t>> ips;
  F<std::vector<uint64_t>> geohashes;
  F<Fingerprint> last_fingerprint;
  F<std::array<uint8_t, 2>> year_of_birth;
  F<std::vector<AttributionValue>> attribution_history;
  F<Digest> users_prf_seed;
  F<uint64_t> state_counter;
};
template <template <class> class F>
using AttributionStatement = CredentialHistoryStatement<F>;
template <template <class> class F> struct AttributionWitness {
  AttributionState<F> initial_state;
  F<Digest> initial_commitment_randomness;
  SignatureWitness<F> initial_state_signature;
  F<uint32_t> new_ip;
  F<uint64_t> new_geohash;
  F<Digest> new_rappor_nonce;
  F<AttributionValue> new_attribution_value;
  SignatureWitness<F> server_response_signature;
  F<Digest> new_state_commitment_randomness;
  F<Fingerprint> new_fingerprint;
};

inline AttributionWitness<Value> attribution_witness_shape(
    size_t history_length, size_t ip_history_length = 5) {
  AttributionWitness<Value> w{};
  w.initial_state.ips.resize(ip_history_length);
  w.initial_state.geohashes.resize(ip_history_length);
  w.initial_state.attribution_history.resize(history_length);
  return w;
}

namespace attribution_internal {
using namespace common_internal;

// v2 uses 16-byte UUIDs instead of the former 32-byte attribution values.
inline constexpr char kStateTag[] = "zk-cookies/attribution-state/v2";
inline constexpr char kResponseTag[] = "zk-cookies/attribution-server-response/v2";

inline void validate(AttributionMode mode, size_t n, size_t ips,
                      const AttributionConfig &config) {
  if (n == 0 || ips == 0 || n > std::numeric_limits<uint32_t>::max() ||
      ips > std::numeric_limits<uint32_t>::max())
    fail("attribution: history lengths must lie in [1, 2^32-1]");
  if (mode == AttributionMode::kMulti &&
      (config.search_chain.empty() || n <= config.search_chain.size()))
    fail("multi attribution: history must be longer than the nonempty chain");
  if (config.policy.geohash_shared_bits == 0 ||
      config.policy.geohash_shared_bits > 60 ||
      config.policy.fingerprint_threshold >= kFingerprintBits)
    fail("attribution: invalid history policy");
}

template <class F>
Expr<F, Bit> constant_value(Domain<F> &H, const AttributionValue &v) {
  return lib::keccak::constant_input(
      H, lib::keccak::constant_bytes({v.begin(), v.end()}));
}

// Vectorized equality and balanced reductions give O(n * chain_length)
// work and logarithmic depth. Preserve the original OR inside each window
// and the omitted final window; this deliberately does not require a chain.
template <class F>
Expr<F, Bit> search(Domain<F> &H, AttributionMode mode,
                    const Expr<F, Bit> &history,
                    const AttributionConfig &config) {
  if (mode == AttributionMode::kSingle)
    return (!(history ^ constant_value(H, config.search_value))).all(1).any(0);
  const size_t windows = history.dims().at(0) - config.search_chain.size();
  std::vector<Expr<F, Bit>> matches;
  for (size_t j = 0; j < config.search_chain.size(); ++j) {
    const auto entries = history.slice(j, j + windows, 0);
    matches.push_back(
        (!(entries ^ constant_value(H, config.search_chain[j])))
            .all(1).any(0).reshape({1}));
  }
  return balanced_concat(std::move(matches)).any(0);
}

template <class F>
Expr<F, Bit> updated_attributions(const Expr<F, Bit> &history,
                                  const Expr<F, Bit> &value) {
  return value.flat().reshape({1, kAttributionBits})
      .concat(history.slice(0, history.dims().at(0) - 1, 0), 0);
}

template <class Hash, class F>
Expr<F, Bit> state_digest(const Scope &s, Domain<F> &H,
                          const HistoryInputs<F> &in,
                          const Expr<F, Bit> &attributions) {
  const auto payload = lib::keccak::sponge_input(
      lib::keccak::constant_bytes(little_endian(in.ips.dims().at(0), 4)),
      lib::keccak::constant_bytes(little_endian(attributions.dims().at(0), 4)),
      in.ips.flat(), in.geohashes.flat(), in.fingerprint.flat(), in.yob.flat(),
      attributions.flat(), in.seed.flat(), in.counter.flat());
  return tagged_hash<Hash>(s, H, "digest", kStateTag, payload);
}

template <class Hash, class F>
Expr<F, Bit> response_digest(const Scope &s, Domain<F> &H,
                             const Expr<F, Bit> &ip,
                             const Expr<F, Bit> &geohash,
                             const Expr<F, Bit> &nonce,
                             const Expr<F, Bit> &value) {
  return tagged_hash<Hash>(s, H, "digest",
      kResponseTag,
      lib::keccak::sponge_input(ip.flat(), geohash.flat(), nonce.flat(),
                                value.flat()));
}
} // namespace attribution_internal

template <class P, class Hash = hashes::Default>
void attribution_relation(typename mldsa::Env<P>::Sys &cs,
                           const mldsa::Env<P> &env,
                           AttributionStatement<In> st, AttributionWitness<In> w,
                           AttributionMode mode, size_t n, size_t ips_length,
                           const AttributionConfig &config) {
  using HF = typename mldsa::Env<P>::HF;
  static_assert(Hash::template supports<HF>,
                "the selected zk-cookies hash does not support this profile");
  namespace ai = attribution_internal;
  ai::validate(mode, n, ips_length, config);
  auto &A = cs.domain(domain_profile<P>(env.af, env.rsa), "A");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
  const auto ips = H.priv(Bit{}, w.initial_state.ips);
  const auto geos = H.priv(Bit{}, w.initial_state.geohashes);
  const auto fp = H.priv(w.initial_state.last_fingerprint);
  const auto yob = H.priv(w.initial_state.year_of_birth);
  const auto seed = H.priv(w.initial_state.users_prf_seed);
  const auto counter = H.priv(Bit{}, w.initial_state.state_counter);
  const auto attrs = H.priv(w.initial_state.attribution_history);
  const auto old_rand = H.priv(w.initial_commitment_randomness);
  const auto new_ip = H.priv(Bit{}, w.new_ip);
  const auto new_geo = H.priv(Bit{}, w.new_geohash);
  const auto nonce = H.priv(w.new_rappor_nonce);
  const auto value = H.priv(w.new_attribution_value);
  const auto new_rand = H.priv(w.new_state_commitment_randomness);
  const auto new_fp = H.priv(w.new_fingerprint);
  const Expr<HF, Bit> history =
      Expr<HF, Bit>(attrs).reshape({n, kAttributionBits});
  ai::fingerprint_encoding(cs.scope("encoding.old"), Expr<HF, Bit>(fp));
  ai::fingerprint_encoding(cs.scope("encoding.new"), Expr<HF, Bit>(new_fp));
  ai::HistoryInputs<HF> in{ips, geos, fp, yob, seed, counter,
                           Expr<HF, Bit>(new_ip).flat(),
                           Expr<HF, Bit>(new_geo).flat(), nonce, new_fp};
  const auto old_digest = ai::state_digest<Hash>(cs.scope("old_state"), H,
                                                 in, history);
  const auto old_commitment = ai::state_commitment<Hash>(
      cs.scope("old_state_commitment"), H, old_rand, old_digest);
  assert_equal(old_digest, st.old_state_nullifier.bits(H).flat(),
               "old_state_nullifier");
  const auto response = ai::response_digest<Hash>(
      cs.scope("server_response"), H, new_ip, new_geo, nonce, value);
  assert_equal(ai::response_nullifier<Hash>(
                   cs.scope("server_response_nullifier"), H, seed, response),
               st.server_response_nullifier.bits(H).flat(),
               "server_response_nullifier");
  ai::verify_signatures(cs, A, H, st, w, old_commitment, response);
  assert_true(ai::search(H, mode, history, config), "attribution_search");
  const auto next = ai::history_transition<Hash>(
      cs.scope("policy"), H, config.policy, in,
      st.rappor_response.bits(H).flat());
  in.ips = next.ips;
  in.geohashes = next.geohashes;
  in.counter = next.counter;
  in.fingerprint = new_fp;
  const auto next_attrs = ai::updated_attributions(history, Expr<HF, Bit>(value));
  const auto next_digest = ai::state_digest<Hash>(
      cs.scope("updated_state"), H, in, next_attrs);
  assert_equal(ai::state_commitment<Hash>(
                   cs.scope("new_state_commitment"), H, new_rand, next_digest),
               st.new_state_commitment.bits(H).flat(), "new_state_commitment");
}

template <class P, class Hash = hashes::Default>
Relation<AttributionStatement<Value>, AttributionWitness<Value>>
attribution(const mldsa::Env<P> &env, AttributionMode mode, size_t history_length,
             size_t ip_history_length, const AttributionConfig &config,
             const BuildOptions &build) {
  attribution_internal::validate(mode, history_length, ip_history_length, config);
  const char *name = mode == AttributionMode::kSingle
                         ? "zk-cookies-single-attribution-"
                         : "zk-cookies-multi-attribution-";
  return compile<AttributionStatement, AttributionWitness>(
      build.profile(mldsa::compile_profile<P, MLDSA>()),
      [&env, mode, history_length, ip_history_length, config](
          typename mldsa::Env<P>::Sys &cs, AttributionStatement<In> st,
          AttributionWitness<In> w) {
        attribution_relation<P, Hash>(cs, env, st, w, mode, history_length,
                                      ip_history_length, config);
      },
      std::string(name) + Hash::kId, AttributionStatement<Value>{},
      attribution_witness_shape(history_length, ip_history_length), build.compile);
}

} // namespace proofs::gordiehowe::examples::zk_cookies
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_H_
