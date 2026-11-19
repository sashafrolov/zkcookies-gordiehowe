// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_COMMON_BUILDERS_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_COMMON_BUILDERS_H_

#include <algorithm>
#include <stdexcept>
#include <type_traits>
#include "gordiehowe/examples/zk-cookies/zk_cookies_common.h"

namespace proofs::gordiehowe::examples::zk_cookies {
namespace host {

template <class T> void append(std::vector<uint8_t> &out, T x) {
  static_assert(std::is_unsigned_v<T>, "state encoding uses unsigned values");
  for (size_t i = 0; i < sizeof(T); ++i)
    out.push_back(uint8_t(x >> (8 * i)));
}

template <size_t N>
void append(std::vector<uint8_t> &out, const std::array<uint8_t, N> &x) {
  out.insert(out.end(), x.begin(), x.end());
}

template <class Hash = hashes::Default>
Digest tagged_hash(const std::string &tag,
                   const std::vector<uint8_t> &payload) {
  std::vector<uint8_t> msg =
      common_internal::domain_header(tag, payload.size());
  msg.insert(msg.end(), payload.begin(), payload.end());
  return Hash::host(msg);
}

inline void validate_fingerprint(const Fingerprint &fingerprint) {
  for (const auto &block : fingerprint)
    if ((block.back() & 0xfcu) != 0)
      throw std::runtime_error(
          "state: a fingerprint block has bits above bit 249");
}

template <class Hash = hashes::Default>
Digest state_commitment(const std::array<uint8_t, 32> &randomness,
                        const Digest &state_hash) {
  std::vector<uint8_t> payload;
  append(payload, randomness);
  append(payload, state_hash);
  return tagged_hash<Hash>("zk-cookies/state-commitment/v1", payload);
}

template <class Hash = hashes::Default>
Digest response_nullifier(const std::array<uint8_t, 32> &seed,
                          const Digest &response) {
  std::vector<uint8_t> payload;
  append(payload, seed);
  append(payload, response);
  return tagged_hash<Hash>("zk-cookies/response-nullifier/v1", payload);
}

inline size_t fingerprint_similarity(const Fingerprint &a,
                                     const Fingerprint &b) {
  validate_fingerprint(a);
  validate_fingerprint(b);
  size_t same = 0;
  for (size_t block = 0; block < 2; ++block)
    for (size_t bit = 0; bit < kFingerprintBitsPerBlock; ++bit) {
      const uint8_t x = (a[block][bit / 8] >> (bit % 8)) & 1;
      const uint8_t y = (b[block][bit / 8] >> (bit % 8)) & 1;
      same += x == y;
    }
  return same;
}

template <class Hash = hashes::Default>
void add_to_bloom(uint16_t &filter, const std::string &tag, uint64_t value) {
  std::vector<uint8_t> payload;
  append(payload, value);
  const Digest d = tagged_hash<Hash>(tag, payload);
  filter |= uint16_t(1) << (d[0] & 0x0f);
  filter |= uint16_t(1) << (d[0] >> 4);
}

template <class Hash = hashes::Default>
uint16_t randomize_bloom(uint16_t filter, const Digest &seed,
                         const Digest &nonce, uint64_t counter,
                         uint8_t rappor_p, uint8_t rappor_q) {
  std::vector<uint8_t> p_payload;
  append(p_payload, seed);
  append(p_payload, nonce);
  append(p_payload, counter);
  const Digest p = tagged_hash<Hash>("zk-cookies/rappor-p/v1", p_payload);
  std::vector<uint8_t> q_payload;
  append(q_payload, seed);
  append(q_payload, p);
  const Digest q = tagged_hash<Hash>("zk-cookies/rappor-q/v1", q_payload);

  uint16_t out = 0;
  for (size_t i = 0; i < 16; ++i) {
    const bool original = ((filter >> i) & 1) != 0;
    const bool bit = original ? q[i] < rappor_q : p[i] < rappor_p;
    out |= uint16_t(bit) << i;
  }
  return out;
}

template <class Hash = hashes::Default, class Witness>
uint16_t history_rappor_response(const Witness &w,
                         const CredentialHistoryConfig &config = {}) {
  uint64_t distinct = 0;
  for (uint32_t ip : w.initial_state.ips)
    distinct += ip != 0;
  const uint64_t similarity = fingerprint_similarity(
      w.initial_state.last_fingerprint, w.new_fingerprint);

  uint16_t filter = 0;
  add_to_bloom<Hash>(filter, "zk-cookies/bloom/distinct-ips/v1", distinct);
  add_to_bloom<Hash>(filter, "zk-cookies/bloom/fingerprint-similarity/v1",
                     similarity);
  add_to_bloom<Hash>(filter, "zk-cookies/bloom/geohash-shared-bits/v1",
                     config.geohash_shared_bits);

  return randomize_bloom<Hash>(filter, w.initial_state.users_prf_seed,
                                w.new_rappor_nonce,
                                w.initial_state.state_counter,
                                config.rappor_p, config.rappor_q);
}

template <class Witness>
auto updated_history_state(const Witness &w) {
  auto out = w.initial_state;
  const auto found =
      std::find(out.ips.begin(), out.ips.end(), w.new_ip) != out.ips.end();
  if (!found) {
    const auto empty = std::find(out.ips.begin(), out.ips.end(), uint32_t(0));
    if (empty != out.ips.end()) {
      const size_t i = size_t(empty - out.ips.begin());
      out.ips[i] = w.new_ip;
      out.geohashes[i] = w.new_geohash;
    } else {
      std::move(out.ips.begin() + 1, out.ips.end(), out.ips.begin());
      std::move(out.geohashes.begin() + 1, out.geohashes.end(),
                out.geohashes.begin());
      out.ips.back() = w.new_ip;
      out.geohashes.back() = w.new_geohash;
    }
  }
  out.last_fingerprint = w.new_fingerprint;
  ++out.state_counter;
  return out;
}

struct UpdateOutputs {
  Digest old_state_nullifier{};
  Digest server_response_nullifier{};
  Digest new_state_commitment{};
  uint16_t rappor_response = 0;
};

} // namespace host

inline void set_signature(SignatureWitness<Value> &out,
                          const mldsa::Signature &signature) {
  mldsa::set_signature<MLDSA>(out, signature);
}


template <class Statement, class Outputs>
Statement update_statement(const std::vector<uint8_t> &pk,
                            const Outputs &outputs) {
  if (pk.size() != MLDSA::kPkBytes)
    throw std::runtime_error("zk-cookies: an ML-DSA-44 public key");
  Statement st{};
  std::copy(pk.begin(), pk.end(), st.server_public_key.begin());
  st.old_state_nullifier = outputs.old_state_nullifier;
  st.server_response_nullifier = outputs.server_response_nullifier;
  st.new_state_commitment = outputs.new_state_commitment;
  st.rappor_response = outputs.rappor_response;
  return st;
}

} // namespace proofs::gordiehowe::examples::zk_cookies
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_COMMON_BUILDERS_H_
