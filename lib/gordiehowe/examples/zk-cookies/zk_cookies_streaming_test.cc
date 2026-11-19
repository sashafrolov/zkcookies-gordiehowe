// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#include "gordiehowe/examples/zk-cookies/zk_cookies_testing.h"
#include "random/secure_random_engine.h"
#include <gtest/gtest.h>

namespace proofs::gordiehowe::examples::zk_cookies {
namespace {
using P = param_sets::ROMParams;
using Sys = mldsa::Env<P>::Sys;
using HF = mldsa::Env<P>::HF;
std::vector<HF::Elt> bits(const HF &f, host::UInt128 n, size_t width) {
  std::vector<HF::Elt> out;
  for (size_t i = 0; i < width; ++i) out.push_back(ct::bit_elt(f, (n >> i) & 1));
  return out;
}

TEST(ZkCookiesStreaming, ProofWithLimbCarryAndNoFingerprintCheck) {
  const mldsa::Env<P> env;
  auto w = testing::streaming_witness(3);
  w.initial_state.avg_geohash = UINT64_MAX / 3;
  w.initial_state.geohash_sum = {UINT64_MAX, 0};
  w.new_geohash = w.initial_state.avg_geohash + 1;
  w.next_avg_geohash = w.initial_state.avg_geohash;
  for (auto &block : w.new_fingerprint) block.fill(0xff);
  const auto pk = testing::sign(w);
  const auto out = host::outputs(w);
  EXPECT_EQ(out.new_geohash_sum[1], 1);
  const auto st = streaming_statement(pk, out);
  const auto relation = zk_cookies_streaming(env);
  SecureRandomEngine rng;
  const auto proof = relation.prove(st, w, rng);
  EXPECT_TRUE(relation.verify(st, proof));
  auto wrong = st;
  wrong.new_geohash_sum[1] ^= 1;
  EXPECT_FALSE(relation.verify(wrong, proof));
  wrong = st;
  wrong.new_last_fingerprint[1][31] ^= 0x80;
  EXPECT_FALSE(relation.verify(wrong, proof));
  auto bad_average = w;
  ++bad_average.next_avg_geohash;
  const auto bad_st = streaming_statement(pk, host::outputs(bad_average));
  EXPECT_THROW(relation.prove(bad_st, bad_average, rng), std::runtime_error);
}

TEST(ZkCookiesStreaming, ExactAverageBoundariesAndFullWidthProduct) {
  const mldsa::Env<P> env;
  Sys cs("streaming-average-test");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
  const auto sum = H.pub(Bit{}, "sum", 128);
  const auto count = H.pub(Bit{}, "count", 64);
  const auto avg = H.pub(Bit{}, "avg", 64);
  streaming_internal::average_check(cs.scope("average"), H,
      Expr<HF, Bit>(sum), Expr<HF, Bit>(count), Expr<HF, Bit>(avg));
  const auto compiled = compile(cs);
  EXPECT_LE(compiled->compiled_domain(0).plan().layers, 32);
  SecureRandomEngine rng;
  const host::UInt128 max = UINT64_MAX;
  struct Case { host::UInt128 sum; uint64_t count, average; bool valid; };
  for (const auto &x : std::vector<Case>{
      {0, 1, 0, true}, {7, 3, 2, true}, {8, 3, 2, true},
      {9, 3, 2, false}, {5, 3, 2, false}, {0, 0, 0, false},
      {max * max + max - 1, UINT64_MAX, UINT64_MAX, true},
      {max * max + max, UINT64_MAX, UINT64_MAX, false}}) {
    Sys::Assignment st, w;
    st.set(sum, bits(env.hf, x.sum, 128));
    st.set(count, bits(env.hf, x.count, 64));
    st.set(avg, bits(env.hf, x.average, 64));
    const auto prep = compiled->prepare(st);
    if (x.valid) {
      const auto proof = prep.prove(w, rng);
      EXPECT_TRUE(prep.verify(proof));
    } else {
      try {
        const auto proof = prep.prove(w, rng);
        EXPECT_FALSE(prep.verify(proof));
      } catch (const std::runtime_error &) {
        // Rejection can occur during proving or verification.
      }
    }
  }
}

TEST(ZkCookiesStreaming, CircuitRejectsSumAndCounterOverflow) {
  const mldsa::Env<P> env;
  Sys cs("streaming-overflow-test");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
  // Bind the operands publicly. Unbound private operands could be repaired
  // by affine witness elimination to another, valid existential witness.
  const auto sum = H.pub(Bit{}, "sum", 128);
  const auto count = H.pub(Bit{}, "count", 64);
  const auto geo = H.pub(Bit{}, "geo", 64);
  const auto next = streaming_internal::update_integers(cs.scope("update"), H,
      Expr<HF, Bit>(sum), Expr<HF, Bit>(count), Expr<HF, Bit>(geo));
  const auto expected = H.pub(Bit{}, "expected_sum", 128);
  assert_equal(next.sum, expected, "sum");
  const auto compiled = compile(cs);
  SecureRandomEngine rng;
  const host::UInt128 max = ~host::UInt128(0);
  for (size_t i = 0; i < 3; ++i) {
    SCOPED_TRACE(i);
    const host::UInt128 old = i == 1 ? max : UINT64_MAX;
    const uint64_t counter = i == 2 ? UINT64_MAX : 3;
    Sys::Assignment st, w;
    st.set(expected, bits(env.hf, old + 1, 128));
    st.set(sum, bits(env.hf, old, 128));
    st.set(count, bits(env.hf, counter, 64));
    st.set(geo, bits(env.hf, 1, 64));
    const auto prep = compiled->prepare(st);
    if (i == 0) {
      const auto proof = prep.prove(w, rng);
      EXPECT_TRUE(prep.verify(proof));
    } else {
      try {
        const auto proof = prep.prove(w, rng);
        EXPECT_FALSE(prep.verify(proof));
      } catch (const std::runtime_error &) {
        // Rejection can occur during proving or verification.
      }
    }
  }
}

TEST(ZkCookiesStreaming, HostOverflowAndAverageChecks) {
  auto w = testing::streaming_witness();
  w.initial_state.state_counter = UINT64_MAX;
  EXPECT_THROW(host::updated_state(w), std::runtime_error);
  w.initial_state.state_counter = 3;
  w.initial_state.geohash_sum = {UINT64_MAX, UINT64_MAX};
  EXPECT_THROW(host::updated_state(w), std::runtime_error);
  EXPECT_THROW(host::streaming_average({0, 0}, 0), std::runtime_error);
  EXPECT_THROW(host::streaming_average({0, 1}, 1), std::runtime_error);
}
} // namespace
} // namespace proofs::gordiehowe::examples::zk_cookies
