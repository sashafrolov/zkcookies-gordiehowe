// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#include "gordiehowe/examples/zk-cookies/state_builders.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gordiehowe/examples/mldsa/mldsa_native_testing.h"
#include "gordiehowe/examples/mldsa/mldsa_openssl_testing.h"
#include "params/param_sets.h"
#include "random/secure_random_engine.h"
#include <gtest/gtest.h>

namespace proofs::gordiehowe::examples::zk_cookies {
namespace {

std::string hex(const Digest &d) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  for (uint8_t x : d) {
    out.push_back(kHex[x >> 4]);
    out.push_back(kHex[x & 15]);
  }
  return out;
}

TEST(ZkCookiesBlake2s, Rfc7693Vectors) {
  EXPECT_EQ(hex(lib::blake2s::host::blake2s_256({})),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
  EXPECT_EQ(hex(lib::blake2s::host::blake2s_256({'a', 'b', 'c'})),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
}

Fingerprint fingerprint(size_t flipped) {
  Fingerprint out{};
  for (size_t bit = 0; bit < flipped; ++bit) {
    const size_t local = bit % kFingerprintBitsPerBlock;
    out[bit / kFingerprintBitsPerBlock][local / 8] |=
        uint8_t(1) << (local % 8);
  }
  return out;
}

StateWitness<Value> base_witness(size_t history_length) {
  StateWitness<Value> w = state_witness_shape(history_length);
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

TEST(ZkCookiesStateHost, ColdStartFillsFirstSlot) {
  const auto w = base_witness(5);
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.ips, (std::vector<uint32_t>{w.new_ip, 0, 0, 0, 0}));
  EXPECT_EQ(next.geohashes,
            (std::vector<uint64_t>{w.new_geohash, 0, 0, 0, 0}));
  EXPECT_EQ(next.state_counter, 1);
  EXPECT_EQ(host::fingerprint_similarity(w.initial_state.last_fingerprint,
                                         w.new_fingerprint),
            401);
}

TEST(ZkCookiesStateHost, ExistingIpLeavesHistoryUnchanged) {
  auto w = base_witness(5);
  w.initial_state.ips = {w.new_ip, 0, 0, 0, 0};
  w.initial_state.geohashes = {10, 0, 0, 0, 0};
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.ips, w.initial_state.ips);
  EXPECT_EQ(next.geohashes, w.initial_state.geohashes);
}

TEST(ZkCookiesStateHost, NewIpFillsFirstEmptySlot) {
  auto w = base_witness(5);
  w.initial_state.ips = {1, 2, 0, 0, 0};
  w.initial_state.geohashes = {10, 20, 0, 0, 0};
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.ips,
            (std::vector<uint32_t>{1, 2, w.new_ip, 0, 0}));
  EXPECT_EQ(next.geohashes,
            (std::vector<uint64_t>{10, 20, w.new_geohash, 0, 0}));
}

TEST(ZkCookiesStateHost, NewIpShiftsAFullHistory) {
  auto w = base_witness(5);
  w.initial_state.ips = {1, 2, 3, 4, 5};
  w.initial_state.geohashes = {10, 20, 30, 40, 50};
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.ips,
            (std::vector<uint32_t>{2, 3, 4, 5, w.new_ip}));
  EXPECT_EQ(next.geohashes,
            (std::vector<uint64_t>{20, 30, 40, 50, w.new_geohash}));
}

TEST(ZkCookiesStateHost, HistoryLengthIsConfigurable) {
  auto w = base_witness(3);
  w.initial_state.ips = {1, 2, 3};
  w.initial_state.geohashes = {10, 20, 30};
  const auto next = host::updated_state(w);
  EXPECT_EQ(next.ips, (std::vector<uint32_t>{2, 3, w.new_ip}));
  EXPECT_EQ(next.geohashes,
            (std::vector<uint64_t>{20, 30, w.new_geohash}));
  EXPECT_EQ(host::encode_state(next).size(),
            4 + 3 * sizeof(uint32_t) + 3 * sizeof(uint64_t) + 64 + 2 + 32 +
                sizeof(uint64_t));
}

mldsa::Signature decoded_signature(const std::vector<uint8_t> &pk,
                                   const std::vector<uint8_t> &message,
                                   const std::vector<uint8_t> &signature) {
  ml_dsa::MlDsa44SignatureExample ex;
  ex.pkey = pk;
  ex.msg = message;
  ex.sig = signature;
  const mldsa::support::Existing<MLDSA> existing(ex);
  if (!existing.ok) throw std::runtime_error("test ML-DSA signature rejected");
  return existing.signature();
}

// The complete two-domain relation on the smallest configurable history.
// This covers BLAKE2s, both ML-DSA signatures, both MAC crossings, policy
// checks, RAPPOR and the state transition in one proof.
TEST(ZkCookiesState, HonestProofVerifies) {
  std::array<uint8_t, 32> key_seed{};
  for (size_t i = 0; i < key_seed.size(); ++i) key_seed[i] = uint8_t(i);
  const auto key = mldsa::support::mldsa_key<MLDSA>(key_seed);
  const auto pk = mldsa::support::mldsa_public<MLDSA>(key);

  auto witness = base_witness(1);
  const auto [initial_message, response_message] =
      host::signature_messages(witness);
  const auto initial_bytes =
      mldsa::support::mldsa_sign<MLDSA>(key, initial_message, {});
  const auto response_bytes =
      mldsa::support::mldsa_sign<MLDSA>(key, response_message, {});
  set_signature(witness.initial_state_signature,
                decoded_signature(pk, initial_message, initial_bytes));
  set_signature(witness.server_response_signature,
                decoded_signature(pk, response_message, response_bytes));
  const auto statement = state_statement(pk, host::outputs(witness));

  mldsa::Env<param_sets::ROMParams> env;
  const auto relation = state(env, 1);
  SecureRandomEngine rng;
  const auto proof = relation.prove(statement, witness, rng);
  EXPECT_TRUE(relation.verify(statement, proof));

  auto wrong = statement;
  wrong.new_state_commitment[0] ^= 1;
  EXPECT_FALSE(relation.verify(wrong, proof));
}

}  // namespace
}  // namespace proofs::gordiehowe::examples::zk_cookies
