// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_TESTING_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_TESTING_H_

#include "gordiehowe/examples/zk-cookies/zk_cookies_testing.h"
#include "random/secure_random_engine.h"
#include <gtest/gtest.h>

namespace proofs::gordiehowe::examples::zk_cookies::testing {
inline void attribution_proof(AttributionMode mode) {
  using P = param_sets::ROMParams;
  const mldsa::Env<P> env;
  const size_t n = mode == AttributionMode::kSingle ? 3 : 6;
  auto w = attribution_witness(n, 3, mode);
  w.initial_state.ips = {7, 0, 8};
  w.initial_state.geohashes = {w.new_geohash, 123, w.new_geohash};
  const auto pk = sign(w);
  const auto st = update_statement<AttributionStatement<Value>>(pk, host::outputs(w));
  const auto relation = mode == AttributionMode::kSingle
      ? zk_cookies_single_attribution(env, n, 3)
      : zk_cookies_multi_attribution(env, n, 3);
  SecureRandomEngine rng;
  const auto proof = relation.prove(st, w, rng);
  EXPECT_TRUE(relation.verify(st, proof));
  auto wrong = st;
  wrong.new_state_commitment[31] ^= 0x80;
  EXPECT_FALSE(relation.verify(wrong, proof));
  wrong = st;
  wrong.rappor_response ^= 1;
  EXPECT_FALSE(relation.verify(wrong, proof));
  // Keep the output consistent with the changed request, but retain the old
  // signature. Only the server-signature binding should reject this witness.
  auto unsigned_w = w;
  unsigned_w.new_attribution_value.back() ^= 0x80;
  const auto unsigned_st = update_statement<AttributionStatement<Value>>(
      pk, host::outputs(unsigned_w));
  EXPECT_THROW(relation.prove(unsigned_st, unsigned_w, rng), std::runtime_error);
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.attribution_history[0], w.new_attribution_value);
  EXPECT_EQ(next.attribution_history[1], w.initial_state.attribution_history[0]);
  EXPECT_EQ(next.ips[1], w.new_ip);
}

inline void attribution_search(AttributionMode mode) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  const mldsa::Env<P> env;
  AttributionConfig config;
  // Exercise bit 127 of a UUID query, beyond the numeric helper's 64 bits.
  if (mode == AttributionMode::kSingle)
    config.search_value.back() = 0x80;
  else
    config.search_chain[0].back() = 0x80;
  const size_t n = mode == AttributionMode::kSingle ? 3 : 5;
  Sys cs("attribution-search");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
  const auto history = H.priv(Bit{}, "history", Shape{n, kAttributionBits});
  const auto expected = H.pub(Bit{}, "expected", 1);
  assert_equal(attribution_internal::search(
                   H, mode, Expr<HF, Bit>(history), config).reshape({1}),
               expected, "search").pin(Placement::kCircuit);
  const auto compiled = compile(cs);
  SecureRandomEngine rng;
  const auto check = [&](std::vector<AttributionValue> values, bool match) {
    EXPECT_EQ(host::attribution_matches(values, mode, config), match);
    std::vector<HF::Elt> bits;
    for (const auto &v : values)
      for (uint8_t byte : v)
        for (size_t i = 0; i < 8; ++i)
          bits.push_back(ct::bit_elt(env.hf, (byte >> i) & 1));
    Sys::Assignment st, w;
    st.set(expected, {ct::bit_elt(env.hf, match)});
    w.set(history, bits);
    const auto prep = compiled->prepare(st);
    const auto proof = prep.prove(w, rng);
    EXPECT_TRUE(prep.verify(proof));
  };
  std::vector<AttributionValue> values(n);
  check(values, false);
  if (mode == AttributionMode::kSingle) {
    values.back() = config.search_value;
    check(values, true);
    values.back().back() ^= 0x80;
    check(values, false);
  } else {
    values[0] = config.search_chain[0]; // One equality suffices (OR, not AND).
    check(values, true);
    values[0].back() ^= 0x80;
    check(values, false);
    values.assign(n, {});
    values[1] = attribution_value(16);
    check(values, true);
    values.assign(n, {});
    values[4] = attribution_value(18); // The final window is omitted.
    check(values, false);
    values.assign(n, {});
    values[1] = config.search_chain[0]; // Matches only the omitted window.
    check(values, false);
    values.assign(n, {});
    values[0] = attribution_value(16); // Right value, wrong position.
    check(values, false);
  }
}

inline void attribution_depth(AttributionMode mode) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  const mldsa::Env<P> env;
  for (size_t n : {64, 256, 1024}) {
    Sys cs("attribution-depth");
    auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
    const auto history = H.priv(Bit{}, "history", Shape{n, kAttributionBits});
    const auto value = H.priv(Bit{}, "value", kAttributionBits);
    const auto next = H.pub(Bit{}, "next", Shape{n, kAttributionBits});
    const auto match = H.pub(Bit{}, "match", 1);
    assert_equal(attribution_internal::updated_attributions(
                     Expr<HF, Bit>(history), Expr<HF, Bit>(value)),
                 next, "shift").pin(Placement::kCircuit);
    assert_equal(attribution_internal::search(
                     H, mode, Expr<HF, Bit>(history), {}).reshape({1}),
                 match, "search").pin(Placement::kCircuit);
    const auto compiled = compile(cs);
    size_t logn = 0;
    for (size_t m = 1; m < n; m *= 2) ++logn;
    EXPECT_LE(compiled->compiled_domain(0).plan().layers, logn + 16);
  }
}

inline void attribution_host_encoding() {
  auto w = attribution_witness(1, 1, AttributionMode::kSingle);
  const AttributionValue uuid{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  w.initial_state.attribution_history[0] = uuid;
  const auto encoded = host::encode_state(w.initial_state);
  // Two u32 lengths, one IP/geohash pair, fingerprint, year, UUID, seed,
  // counter. UUID bytes are stored verbatim, without 32-byte zero padding.
  EXPECT_EQ(encoded.size(), 8 + 12 + 64 + 2 + 16 + 32 + 8);
  EXPECT_TRUE(std::equal(uuid.begin(), uuid.end(),
                         encoded.begin() + 8 + 12 + 64 + 2));
  const auto before = host::state_digest(w.initial_state);
  w.initial_state.attribution_history[0].back() ^= 0x80;
  EXPECT_NE(before, host::state_digest(w.initial_state));
  const auto response = host::response_digest(
      w.new_ip, w.new_geohash, w.new_rappor_nonce, w.new_attribution_value);
  w.new_attribution_value.back() ^= 0x80;
  EXPECT_NE(response, host::response_digest(
      w.new_ip, w.new_geohash, w.new_rappor_nonce, w.new_attribution_value));
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.attribution_history.size(), 1);
  EXPECT_EQ(next.attribution_history[0], w.new_attribution_value);
}
} // namespace proofs::gordiehowe::examples::zk_cookies::testing
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_TESTING_H_
