// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// Port of zk_cred_streaming_logic/state_streaming.circom, with exact unsigned
// integer averages instead of BN254 modular arithmetic.
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STREAMING_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STREAMING_H_

#include "gordiehowe/examples/zk-cookies/zk_cookies_common.h"

namespace proofs::gordiehowe::examples::zk_cookies {

// Little-endian 64-bit limbs; typed inputs remain portable fixed-width arrays.
using GeohashSum = std::array<uint64_t, 2>;
struct StreamingConfig {
  size_t geohash_shared_bits = 20;
  uint8_t rappor_p = 127;
  uint8_t rappor_q = 191;
};
template <template <class> class F> struct StreamingState {
  F<GeohashSum> geohash_sum;
  F<uint64_t> state_counter;
  F<uint64_t> avg_geohash;
  F<Fingerprint> last_fingerprint;
  F<std::array<uint8_t, 2>> year_of_birth;
  F<Digest> users_prf_seed;
};
template <template <class> class F> struct StreamingStatement {
  F<std::array<uint8_t, MLDSA::kPkBytes>> server_public_key;
  F<Digest> old_state_nullifier;
  F<Digest> server_response_nullifier;
  F<Digest> new_state_commitment;
  F<uint16_t> rappor_response;
  F<GeohashSum> new_geohash_sum;
  F<uint64_t> new_state_counter;
  F<uint64_t> new_avg_geohash;
  F<Fingerprint> new_last_fingerprint;
};
template <template <class> class F> struct StreamingWitness {
  StreamingState<F> initial_state;
  F<Digest> initial_commitment_randomness;
  SignatureWitness<F> initial_state_signature;
  F<uint64_t> new_geohash;
  F<Digest> new_rappor_nonce;
  SignatureWitness<F> server_response_signature;
  F<Digest> new_state_commitment_randomness;
  F<Fingerprint> new_fingerprint;
  F<uint64_t> next_avg_geohash;
};

namespace streaming_internal {
using namespace common_internal;

// A full 64x64 -> 128-bit unsigned product. Partial products are quadratic
// bit terms; pairwise committed additions give six bounded-depth levels.
// Each generator reads two fixed-size operands, never a growing history.
template <class F>
Expr<F, Bit> multiply64(const Scope &s, Domain<F> &H,
                        const Expr<F, Bit> &x, const Expr<F, Bit> &y) {
  if (x.size() != 64 || y.size() != 64)
    fail("streaming multiply64: two 64-bit words");
  const auto zero = H.constant(Bit{}, std::vector<uint64_t>(64, 0));
  std::vector<Expr<F, Bit>> rows;
  for (size_t i = 0; i < 64; ++i) {
    auto row = x & y.at(i);
    if (i != 0) row = zero.slice(0, i).concat(row);
    row = row.concat(zero.slice(0, 64 - i));
    rows.push_back(row);
  }
  size_t level = 0;
  while (rows.size() > 1) {
    std::vector<Expr<F, Bit>> next;
    for (size_t i = 0; i < rows.size(); i += 2)
      next.push_back(lib::arith::add(
          rows[i], rows[i + 1],
          s.name("level" + std::to_string(level) + ".sum" +
                 std::to_string(i / 2))));
    rows = std::move(next);
    ++level;
  }
  return rows.front();
}

// product <= sum < product + count is equivalent to floor(sum/count)=avg.
// For 64-bit avg and count, product+count < 2^128, even at their maxima.
// Balanced bit comparators avoid division circuits and remainder generators.
template <class F>
void average_check(const Scope &s, Domain<F> &H, const Expr<F, Bit> &sum,
                    const Expr<F, Bit> &count, const Expr<F, Bit> &avg) {
  const auto product = multiply64(s.scope("product"), H, avg, count);
  const auto upper = lib::arith::add(product, extend_word(H, count, 128),
                                     s.name("upper_bound"));
  assert_true(!(sum.from_bits() < product.from_bits()), s.name("lower"));
  assert_true(sum.from_bits() < Expr<F, Bit>(upper).from_bits(),
              s.name("upper"));
}

template <class F> struct StateBits {
  Expr<F, Bit> sum, counter, average, fingerprint, yob, seed;
};
template <class Hash, class F>
Expr<F, Bit> state_digest(const Scope &s, Domain<F> &H,
                          const StateBits<F> &in) {
  return tagged_hash<Hash>(s, H, "digest", "zk-cookies/streaming-state/v1",
      lib::keccak::sponge_input(in.sum.flat(), in.counter.flat(),
          in.average.flat(), in.fingerprint.flat(), in.yob.flat(),
          in.seed.flat()));
}
template <class Hash, class F>
Expr<F, Bit> response_digest(const Scope &s, Domain<F> &H,
                             const Expr<F, Bit> &geohash,
                             const Expr<F, Bit> &nonce) {
  return tagged_hash<Hash>(s, H, "digest",
      "zk-cookies/streaming-server-response/v1",
      lib::keccak::sponge_input(geohash.flat(), nonce.flat()));
}
template <class Hash, class F>
Expr<F, Bit> rappor(const Scope &s, Domain<F> &H, const StreamingConfig &config,
                    const StateBits<F> &in, const Expr<F, Bit> &nonce) {
  auto filter = H.constant(Bit{}, std::vector<uint64_t>(16, 0));
  filter = add_to_bloom<Hash>(s, H, "counter",
      "zk-cookies/bloom/state-counter/v1", filter, in.counter);
  filter = add_to_bloom<Hash>(s, H, "average",
      "zk-cookies/bloom/avg-geohash/v1", filter, in.average);
  return randomize_bloom<Hash>(s, H, config.rappor_p, config.rappor_q,
                                in.seed, nonce, in.counter, filter);
}

template <class F> struct UpdatedIntegers {
  Expr<F, Bit> sum, counter;
};
template <class F>
UpdatedIntegers<F> update_integers(const Scope &s, Domain<F> &H,
                                   const Expr<F, Bit> &sum,
                                   const Expr<F, Bit> &count,
                                   const Expr<F, Bit> &geohash) {
  const auto next_sum = lib::arith::add(extend_word(H, sum, 129),
      extend_word(H, geohash, 129), s.name("sum"));
  const auto one = extend_word(H, lib::arith::constant_word(H, 1, 64), 65);
  const auto next_count = lib::arith::add(extend_word(H, count, 65), one,
                                          s.name("counter"));
  assert_zero(Expr<F, Bit>(next_sum).at(128), s.name("sum_overflow"));
  assert_zero(Expr<F, Bit>(next_count).at(64), s.name("counter_overflow"));
  return {Expr<F, Bit>(next_sum).slice(0, 128),
          Expr<F, Bit>(next_count).slice(0, 64)};
}
} // namespace streaming_internal

template <class P, class Hash = hashes::Default>
void streaming_relation(typename mldsa::Env<P>::Sys &cs,
                         const mldsa::Env<P> &env, StreamingStatement<In> st,
                         StreamingWitness<In> w, const StreamingConfig &config) {
  using HF = typename mldsa::Env<P>::HF;
  static_assert(Hash::template supports<HF>,
                "the selected zk-cookies hash does not support this profile");
  namespace si = streaming_internal;
  if (config.geohash_shared_bits == 0 || config.geohash_shared_bits > 64)
    fail("streaming: geohash_shared_bits must lie in [1, 64]");
  auto &A = cs.domain(domain_profile<P>(env.af, env.rsa), "A");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
  const auto sum = H.priv(Bit{}, w.initial_state.geohash_sum);
  const auto counter = H.priv(Bit{}, w.initial_state.state_counter);
  const auto avg = H.priv(Bit{}, w.initial_state.avg_geohash);
  const auto fp = H.priv(w.initial_state.last_fingerprint);
  const auto yob = H.priv(w.initial_state.year_of_birth);
  const auto seed = H.priv(w.initial_state.users_prf_seed);
  const auto old_rand = H.priv(w.initial_commitment_randomness);
  const auto geo = H.priv(Bit{}, w.new_geohash);
  const auto nonce = H.priv(w.new_rappor_nonce);
  const auto new_rand = H.priv(w.new_state_commitment_randomness);
  const auto new_fp = H.priv(w.new_fingerprint);
  const auto next_avg = H.priv(Bit{}, w.next_avg_geohash);
  si::StateBits<HF> in{Expr<HF, Bit>(sum).flat(),
                       Expr<HF, Bit>(counter).flat(),
                       Expr<HF, Bit>(avg).flat(), fp, yob, seed};
  const auto old_digest = si::state_digest<Hash>(cs.scope("old_state"), H, in);
  const auto old_commitment = si::state_commitment<Hash>(
      cs.scope("old_state_commitment"), H, old_rand, old_digest);
  assert_equal(old_digest, st.old_state_nullifier.bits(H).flat(),
               "old_state_nullifier");
  const auto response = si::response_digest<Hash>(
      cs.scope("server_response"), H, geo, nonce);
  assert_equal(si::response_nullifier<Hash>(
                   cs.scope("server_response_nullifier"), H, seed, response),
               st.server_response_nullifier.bits(H).flat(),
               "server_response_nullifier");
  si::verify_signatures(cs, A, H, st, w, old_commitment, response);
  si::average_check(cs.scope("old_average"), H, in.sum, in.counter, in.average);
  const auto geo_word = Expr<HF, Bit>(geo).flat();
  const size_t lo = 64 - config.geohash_shared_bits;
  assert_equal(in.average.slice(lo, 64), geo_word.slice(lo, 64),
               "geohash_prefix");
  si::age_check(cs.scope("age"), H, yob);
  assert_equal(si::rappor<Hash>(cs.scope("rappor"), H, config, in,
                                Expr<HF, Bit>(nonce)),
               st.rappor_response.bits(H).flat(), "rappor_response");
  const auto next = si::update_integers(cs.scope("updated_state"), H,
                                        in.sum, in.counter, geo_word);
  in.sum = next.sum;
  in.counter = next.counter;
  in.average = Expr<HF, Bit>(next_avg).flat();
  in.fingerprint = new_fp;
  si::average_check(cs.scope("new_average"), H, in.sum, in.counter, in.average);
  // Streaming intentionally has no fingerprint-similarity policy. Its
  // fingerprints are opaque bytes and all updated-state fields remain public.
  assert_equal(in.sum, st.new_geohash_sum.bits(H).flat(), "new_geohash_sum");
  assert_equal(in.counter, st.new_state_counter.bits(H).flat(), "new_state_counter");
  assert_equal(in.average, st.new_avg_geohash.bits(H).flat(), "new_avg_geohash");
  assert_equal(in.fingerprint.flat(), st.new_last_fingerprint.bits(H).flat(),
               "new_last_fingerprint");
  const auto next_digest = si::state_digest<Hash>(cs.scope("new_state"), H, in);
  assert_equal(si::state_commitment<Hash>(
                   cs.scope("new_state_commitment"), H, new_rand, next_digest),
               st.new_state_commitment.bits(H).flat(), "new_state_commitment");
}

template <class P, class Hash = hashes::Default>
Relation<StreamingStatement<Value>, StreamingWitness<Value>>
zk_cookies_streaming(const mldsa::Env<P> &env, const StreamingConfig &config = {},
                     const BuildOptions &build = {}) {
  return compile<StreamingStatement, StreamingWitness>(
      build.profile(mldsa::compile_profile<P, MLDSA>()),
      [&env, config](typename mldsa::Env<P>::Sys &cs, StreamingStatement<In> st,
                      StreamingWitness<In> w) {
        streaming_relation<P, Hash>(cs, env, st, w, config);
      },
      std::string("zk-cookies-streaming-") + Hash::kId,
      StreamingStatement<Value>{}, StreamingWitness<Value>{}, build.compile);
}
} // namespace proofs::gordiehowe::examples::zk_cookies
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STREAMING_H_
