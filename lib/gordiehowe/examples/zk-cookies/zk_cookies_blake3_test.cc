// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gordiehowe/examples/mldsa/mldsa_native.h"
#include "gordiehowe/examples/shared/setup.h"
#include "gordiehowe/lib/blake3.h"
#include "gordiehowe/relation.h"
#include "params/param_sets.h"
#include "random/secure_random_engine.h"
#include <gtest/gtest.h>

namespace proofs::gordiehowe::examples::zk_cookies {

namespace b3 = lib::blake3;

template <template <class> class F> struct Blake3Statement {
  F<b3::Digest> digest;
};

template <template <class> class F> struct Blake3Witness {
  F<std::vector<uint8_t>> message;
};

namespace {

std::string hex(const b3::Digest &digest) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(2 * digest.size());
  for (uint8_t byte : digest) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 15]);
  }
  return out;
}

// This is the input pattern used by the official BLAKE3 test vectors.
std::vector<uint8_t> official_message(size_t bytes) {
  std::vector<uint8_t> out(bytes);
  for (size_t i = 0; i < bytes; ++i)
    out[i] = uint8_t(i % 251);
  return out;
}

std::vector<uint8_t> message(size_t bytes, uint8_t seed) {
  std::vector<uint8_t> out(bytes);
  for (size_t i = 0; i < bytes; ++i)
    out[i] = uint8_t(37 * i + seed);
  return out;
}

template <class P>
auto blake3_relation(const mldsa::Env<P> &env, size_t bytes) {
  using Sys = typename mldsa::Env<P>::Sys;
  using HF = typename mldsa::Env<P>::HF;
  return compile<Blake3Statement, Blake3Witness>(
      CompileProfile{},
      [&env, bytes](Sys &cs, Blake3Statement<In> st, Blake3Witness<In> w) {
        auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
        const Expr<HF, Bit> msg =
            bytes == 0
                ? Expr<HF, Bit>(H.constant(Bit{}, std::vector<uint64_t>{}))
                : Expr<HF, Bit>(H.priv(w.message)).flat();
        const auto digest = b3::blake3_256(cs, H, "hash", msg);
        assert_equal(digest, st.digest.bits(H).flat(), "digest");
      },
      "blake3-test", Blake3Statement<Value>{},
      Blake3Witness<Value>{std::vector<uint8_t>(bytes)});
}

TEST(ZkCookiesBlake3, HostMatchesOfficialVectors) {
  struct Vector {
    size_t bytes;
    const char *digest;
  };
  const std::array<Vector, 14> vectors{{
      {0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
      {1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
      {63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"},
      {64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"},
      {65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"},
      {1023,
       "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"},
      {1024,
       "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"},
      {1025,
       "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"},
      {2048,
       "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"},
      {2049,
       "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"},
      {4096,
       "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"},
      {4097,
       "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"},
      {8193,
       "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"},
      {31744,
       "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"},
  }};
  for (const auto &v : vectors)
    EXPECT_EQ(hex(b3::host::blake3_256(official_message(v.bytes))), v.digest)
        << v.bytes;
  EXPECT_EQ(hex(b3::host::blake3_256({'a', 'b', 'c'})),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
}

template <class P> void prove_matches_host(size_t bytes) {
  mldsa::Env<P> env;
  const auto relation = blake3_relation(env, bytes);
  SecureRandomEngine rng;
  // Reusing the relation also checks that trace memoization is proof-local.
  for (uint8_t seed : {uint8_t(11), uint8_t(93)}) {
    const Blake3Witness<Value> witness{message(bytes, seed)};
    const Blake3Statement<Value> statement{
        b3::host::blake3_256(witness.message)};
    const auto proof = relation.prove(statement, witness, rng);
    EXPECT_TRUE(relation.verify(statement, proof));
    auto wrong = statement;
    wrong.digest[0] ^= 1;
    EXPECT_FALSE(relation.verify(wrong, proof));
  }
}

class ZkCookiesBlake3Circuit : public ::testing::TestWithParam<size_t> {};

TEST_P(ZkCookiesBlake3Circuit, MatchesHost) {
  prove_matches_host<param_sets::ROMParams>(GetParam());
}

INSTANTIATE_TEST_SUITE_P(BlockAndChunkBoundaries, ZkCookiesBlake3Circuit,
                         ::testing::Values(0, 1, 63, 64, 65, 1023, 1024, 1025,
                                           2049));

TEST(ZkCookiesBlake3, WideProfileMatchesHost) {
  prove_matches_host<param_sets::QROMParams>(1025);
}

TEST(ZkCookiesBlake3, TamperedTraceRejects) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  mldsa::Env<P> env;
  const auto relation = blake3_relation(env, 1025);
  const auto &typed = relation.template typed<Sys>();
  const auto &nodes = typed.system().graph().nodes;
  const Blake3Witness<Value> witness{message(1025, 11)};
  const Blake3Statement<Value> statement{b3::host::blake3_256(witness.message)};
  const auto prep = typed.compiled().prepare(typed.statement(statement));
  SecureRandomEngine rng;

  const std::array<std::pair<const char *, size_t>, 3> edits{{
      {"hash.sums.words", 0},
      {"hash.sums.words", b3::internal::kSumWords - 1},
      {"hash.cv.words", 0},
  }};
  for (const auto &[name, word] : edits) {
    bool hit = false;
    Sys::ProveOptions options;
    options.require_satisfied = false;
    options.tamper = [&](size_t id, Sys::Value &value) {
      if (nodes.at(id).name != name)
        return;
      auto &packed = std::get<std::vector<HF::Elt>>(value);
      // A 32-bit trace word occupies two GF(2^16) cells in this profile.
      packed.at(2 * word) = env.hf.addf(packed.at(2 * word), env.hf.one());
      hit = true;
    };
    EXPECT_FALSE(prep.verify(prep.prove(typed.witness(witness), rng, options)))
        << word;
    EXPECT_TRUE(hit) << word;
  }
}

} // namespace
} // namespace proofs::gordiehowe::examples::zk_cookies
