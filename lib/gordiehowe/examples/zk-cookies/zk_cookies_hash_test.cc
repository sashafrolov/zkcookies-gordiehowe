// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#include "gordiehowe/examples/zk-cookies/zk_cookies_hash.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gordiehowe/examples/mldsa/mldsa_native.h"
#include "gordiehowe/examples/shared/setup.h"
#include "gordiehowe/relation.h"
#include "params/param_sets.h"
#include "random/secure_random_engine.h"
#include <gtest/gtest.h>

namespace proofs::gordiehowe::examples::zk_cookies {
namespace {

std::string digest_hex(const hashes::Digest &d) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  for (uint8_t x : d) {
    out.push_back(kHex[x >> 4]);
    out.push_back(kHex[x & 15]);
  }
  return out;
}

TEST(ZkCookiesHashPolicies, HostHashesAreIndependent) {
  static_assert(std::is_same_v<hashes::Default, hashes::Poseidon2b>);
  static_assert(!hashes::Poseidon2b::supports<param_sets::QROMParams::HashField>);
  const std::vector<uint8_t> abc{'a', 'b', 'c'};
  const auto poseidon = hashes::Poseidon2b::host(abc);
  const auto blake2s = hashes::Blake2s::host(abc);
  const auto blake3 = hashes::Blake3::host(abc);
  const auto sha = hashes::Sha256::host(abc);
  EXPECT_NE(poseidon, blake2s);
  EXPECT_NE(poseidon, blake3);
  EXPECT_NE(poseidon, sha);
  EXPECT_NE(blake2s, blake3);
  EXPECT_NE(blake2s, sha);
  EXPECT_NE(blake3, sha);
  EXPECT_EQ(digest_hex(poseidon),
            "3a9351f3acc61bba300db172d8f14834feb564ee8bd5ca70d0ff041c6b46e4ac");
  EXPECT_EQ(digest_hex(hashes::Poseidon2b::host({})),
            "b4200ee5eb2d0ff43b0cf903ca04e9aaf9717da798e1f3af06e0c041beadbb1b");
  EXPECT_EQ(digest_hex(blake3),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
  EXPECT_EQ(digest_hex(sha),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

template <template <class> class F> struct HashStatement {
  F<hashes::Digest> digest;
};

template <template <class> class F> struct HashWitness {
  F<std::vector<uint8_t>> message;
};

auto poseidon_relation(const mldsa::Env<param_sets::ROMParams> &env,
                       size_t bytes, bool conditional = false) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  return compile<HashStatement, HashWitness>(
      CompileProfile{},
      [&env, bytes, conditional](Sys &cs, HashStatement<In> st, HashWitness<In> w) {
        auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
        Expr<HF, Bit> msg =
            bytes == 0
                ? Expr<HF, Bit>(H.constant(Bit{}, std::vector<uint64_t>{}))
                : Expr<HF, Bit>(H.priv(w.message)).flat();
        if (conditional)
          msg = msg.slice(0, 8).any(0).mux(msg, !msg);
        const auto digest = hashes::Poseidon2b::circuit(cs, H, "hash", msg);
        assert_equal(digest, st.digest.bits(H).flat(), "digest");
      },
      "poseidon2b-test", HashStatement<Value>{},
      HashWitness<Value>{std::vector<uint8_t>(bytes)});
}

TEST(ZkCookiesPoseidon2b, CircuitMatchesHostAcrossRateBoundary) {
  using P = param_sets::ROMParams;
  mldsa::Env<P> env;
  // Byte delimiter, field-word boundary, mu padding, and multiple blocks.
  for (size_t bytes : {0, 1, 15, 16, 47, 48, 63, 64, 65, 127, 128}) {
    const auto relation = poseidon_relation(env, bytes);
    // Reuse the compiled relation with different witnesses: the input view
    // must be evaluated anew for each proof.
    for (uint8_t seed : {uint8_t(11), uint8_t(93)}) {
      std::vector<uint8_t> message(bytes);
      for (size_t i = 0; i < bytes; ++i)
        message[i] = uint8_t(37 * i + seed);
      const HashWitness<Value> witness{message};
      const HashStatement<Value> statement{hashes::Poseidon2b::host(message)};
      SecureRandomEngine rng;
      const auto proof = relation.prove(statement, witness, rng);
      EXPECT_TRUE(relation.verify(statement, proof));
      auto wrong = statement;
      wrong.digest[0] ^= 1;
      EXPECT_FALSE(relation.verify(wrong, proof));
    }
  }
}

TEST(ZkCookiesPoseidon2b, SymbolicInputIsRecomputedForEachProof) {
  using P = param_sets::ROMParams;
  mldsa::Env<P> env;
  // A conditional input, like the state-history update, takes the general
  // expression evaluator. Reuse the relation across both selector branches.
  const auto relation = poseidon_relation(env, 129, /*conditional=*/true);
  SecureRandomEngine rng;
  for (uint8_t seed : {uint8_t(0), uint8_t(11), uint8_t(0), uint8_t(93)}) {
    std::vector<uint8_t> message(129);
    for (size_t i = 0; i < message.size(); ++i)
      message[i] = uint8_t(37 * i + seed);
    auto selected = message;
    if (message[0] == 0)
      for (auto &byte : selected)
        byte ^= 0xff;
    const HashWitness<Value> witness{message};
    const HashStatement<Value> statement{hashes::Poseidon2b::host(selected)};
    const auto proof = relation.prove(statement, witness, rng);
    EXPECT_TRUE(relation.verify(statement, proof));
  }
}

TEST(ZkCookiesPoseidon2b, OnlySboxOutputsAreMaterialized) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  mldsa::Env<P> env;
  const auto relation = poseidon_relation(env, 64);
  const auto &typed = relation.template typed<Sys>();
  const auto &nodes = typed.system().graph().nodes;
  const auto &plan = typed.compiled().compiled_domain(0).plan();
  size_t full_field_coordinates = 0;
  size_t input_views = 0;
  size_t trace_arrays = 0;
  for (size_t id = 0; id < nodes.size(); ++id) {
    const auto &node = nodes[id];
    if (node.name == "hash.message") {
      ++input_views;
      EXPECT_EQ(node.kind, Kind::kDerived);
      for (const auto &input : plan.inputs)
        EXPECT_FALSE(input.id == id &&
                     input.storage == DomainPlan::Input::kCell);
    }
    if (node.name.starts_with("hash.") && node.kind == Kind::kAdvice &&
        node.type.base == Base::kField) {
      EXPECT_EQ(node.name, "hash.sboxes");
      ++trace_arrays;
      full_field_coordinates += node.n;
    }
  }
  // A 64-byte message needs two rate-4 permutations after byte padding.
  EXPECT_EQ(full_field_coordinates, 2 * (8 * 6 + 58));
  EXPECT_EQ(input_views, 1);
  EXPECT_EQ(trace_arrays, 1);
}

TEST(ZkCookiesPoseidon2b, AllPermutationLanesMatchHost) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  namespace p2 = lib::poseidon2b;
  mldsa::Env<P> env;
  Sys cs("poseidon2b-permutation-test");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");
  const auto input = H.priv(Field{}, "input", p2::kStateSize);
  const auto output = H.pub(Field{}, "output", p2::kStateSize);
  std::array<Expr<HF, Field>, p2::kStateSize> state;
  for (size_t i = 0; i < state.size(); ++i)
    state[i] = Expr<HF, Field>(input).at(i).reshape({1});
  const auto result = p2::permutation(cs, H, "perm", state);
  for (size_t i = 0; i < state.size(); ++i)
    assert_equal(result[i], Expr<HF, Field>(output).at(i).reshape({1}),
                 "output" + std::to_string(i));
  const auto compiled = compile(cs);
  SecureRandomEngine rng;
  for (size_t example = 0; example < 3; ++example) {
    std::array<HF::Elt, p2::kStateSize> values;
    for (auto &value : values)
      value = example == 0 ? env.hf.zero() : rng.elt(env.hf);
    const auto expected = p2::permutation(env.hf, values);
    Sys::Assignment statement, witness;
    statement.set(output, std::vector<HF::Elt>(expected.begin(), expected.end()));
    witness.set(input, std::vector<HF::Elt>(values.begin(), values.end()));
    const auto prep = compiled->prepare(statement);
    EXPECT_TRUE(prep.verify(prep.prove(witness, rng)));
  }
}

TEST(ZkCookiesPoseidon2b, TamperedSboxOutputsReject) {
  using P = param_sets::ROMParams;
  using Sys = mldsa::Env<P>::Sys;
  using HF = mldsa::Env<P>::HF;
  mldsa::Env<P> env;
  const auto relation = poseidon_relation(env, 64);
  const auto &typed = relation.template typed<Sys>();
  const auto &nodes = typed.system().graph().nodes;
  const HashWitness<Value> witness{std::vector<uint8_t>(64, 0xa5)};
  const HashStatement<Value> statement{hashes::Poseidon2b::host(witness.message)};
  const auto prep = typed.compiled().prepare(typed.statement(statement));
  SecureRandomEngine rng;
  // Full rounds, both ends of the partial-round run, and a sponge crossing.
  for (size_t offset : {0, 24, 81, 105, 106, 211}) {
    bool hit = false;
    Sys::ProveOptions options;
    options.require_satisfied = false;
    options.tamper = [&](size_t id, Sys::Value &value) {
      if (nodes.at(id).name != "hash.sboxes")
        return;
      auto &v = std::get<std::vector<HF::Elt>>(value);
      v.at(offset) = env.hf.addf(v.at(offset), env.hf.one());
      hit = true;
    };
    EXPECT_FALSE(prep.verify(prep.prove(typed.witness(witness), rng, options)))
        << offset;
    EXPECT_TRUE(hit) << offset;
  }
}

} // namespace
} // namespace proofs::gordiehowe::examples::zk_cookies
