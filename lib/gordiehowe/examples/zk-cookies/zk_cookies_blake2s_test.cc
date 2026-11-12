// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "gordiehowe/examples/shared/setup.h"
#include "gordiehowe/lib/blake2s.h"
#include "gordiehowe/relation.h"
#include "params/param_sets.h"
#include "random/secure_random_engine.h"
#include <gtest/gtest.h>

namespace proofs::gordiehowe::examples::zk_cookies {

namespace b2 = lib::blake2s;

template <template <class> class F>
struct BlakeStatement {
  F<b2::Digest> digest;
};

template <template <class> class F>
struct BlakeWitness {
  F<std::vector<uint8_t>> message;
};

namespace {

b2::Digest openssl_digest(const std::vector<uint8_t> &message) {
  b2::Digest out{};
  unsigned int size = 0;
  if (EVP_Digest(message.data(), message.size(), out.data(), &size,
                 EVP_blake2s256(), nullptr) != 1 || size != out.size())
    throw std::runtime_error("OpenSSL BLAKE2s-256 failed");
  return out;
}

std::vector<uint8_t> message(size_t bytes, uint8_t seed = 11) {
  std::vector<uint8_t> out(bytes);
  for (size_t i = 0; i < bytes; ++i) out[i] = uint8_t(37 * i + seed);
  return out;
}

template <class P>
auto blake_relation(const mldsa::Env<P> &env, size_t bytes) {
  using Sys = typename mldsa::Env<P>::Sys;
  return compile<BlakeStatement, BlakeWitness>(
      CompileProfile{},
      [&env, bytes](Sys &cs, BlakeStatement<In> st, BlakeWitness<In> w) {
        auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
        const auto msg = bytes == 0
                             ? H.constant(Bit{}, std::vector<uint64_t>{})
                             : Expr<typename mldsa::Env<P>::HF, Bit>(
                                   H.priv(w.message)).flat();
        const auto digest = b2::blake2s_256(cs, H, "hash", msg);
        assert_equal(digest, st.digest.bits(H).flat(), "digest");
      },
      "blake2s-test", BlakeStatement<Value>{},
      BlakeWitness<Value>{std::vector<uint8_t>(bytes)});
}

template <class P>
void prove_matches_openssl(size_t bytes) {
  mldsa::Env<P> env;
  const auto relation = blake_relation(env, bytes);
  SecureRandomEngine rng;
  // Reuse one compiled relation on two different messages, guarding
  // against stale trace data as well as padding and byte-order mistakes.
  for (uint8_t seed : {11, 93}) {
    const BlakeWitness<Value> w{message(bytes, seed)};
    const BlakeStatement<Value> st{openssl_digest(w.message)};
    EXPECT_EQ(b2::host::blake2s_256(w.message), st.digest);
    const auto proof = relation.prove(st, w, rng);
    EXPECT_TRUE(relation.verify(st, proof));
    auto wrong = st;
    wrong.digest[0] ^= 1;
    EXPECT_FALSE(relation.verify(wrong, proof));
  }
}

class ZkCookiesBlake2sCircuit : public ::testing::TestWithParam<size_t> {};

TEST_P(ZkCookiesBlake2sCircuit, MatchesOpenSsl) {
  prove_matches_openssl<param_sets::ROMParams>(GetParam());
}

INSTANTIATE_TEST_SUITE_P(BlockBoundaries, ZkCookiesBlake2sCircuit,
                        ::testing::Values(0, 1, 3, 63, 64, 65, 127, 128, 129,
                                          199));

TEST(ZkCookiesBlake2s, WideProfileMatchesOpenSsl) {
  prove_matches_openssl<param_sets::QROMParams>(129);
}

TEST(ZkCookiesBlake2s, TamperedTraceRejects) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  mldsa::Env<P> env;
  const auto relation = blake_relation(env, 129);
  const auto &typed = relation.typed<Sys>();
  const auto &nodes = typed.system().graph().nodes;
  const BlakeWitness<Value> witness{message(129)};
  const BlakeStatement<Value> statement{openssl_digest(witness.message)};
  const auto prep = typed.compiled().prepare(typed.statement(statement));
  SecureRandomEngine rng;

  // First partial sum, a later G result, an intermediate chaining word,
  // and the final digest: all trace regions must be constrained.
  const std::array<std::pair<const char *, size_t>, 4> edits{{
      {"hash.sums.words", 0}, {"hash.sums.words", 479},
      {"hash.h.words", 0}, {"hash.h_last.words", 7}}};
  for (const auto &[name, word] : edits) {
    bool hit = false;
    Sys::ProveOptions options;
    options.require_satisfied = false;
    options.tamper = [&](size_t id, Sys::Value &value) {
      if (nodes.at(id).name != name) return;
      auto &packed = std::get<std::vector<HF::Elt>>(value);
      // Each 32-bit trace word occupies two GF(2^16) cells.
      packed.at(2 * word) = env.hf.addf(packed.at(2 * word), env.hf.one());
      hit = true;
    };
    EXPECT_FALSE(prep.verify(
        prep.prove(typed.witness(witness), rng, options))) << word;
    EXPECT_TRUE(hit) << word;
  }
}

}  // namespace
}  // namespace proofs::gordiehowe::examples::zk_cookies
