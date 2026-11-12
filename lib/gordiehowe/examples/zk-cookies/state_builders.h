// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// Host-side canonical encoding, hashing, state transition and input builders
// for state.h.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STATE_BUILDERS_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STATE_BUILDERS_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gordiehowe/examples/mldsa/mldsa_builders.h"
#include "gordiehowe/examples/zk-cookies/state.h"
#include "gordiehowe/lib/blake2s.h"

namespace proofs::gordiehowe::examples::zk_cookies {

namespace host {

template <class T>
void append(std::vector<uint8_t> &out, T x) {
  static_assert(std::is_unsigned_v<T>, "state encoding uses unsigned values");
  for (size_t i = 0; i < sizeof(T); ++i) out.push_back(uint8_t(x >> (8 * i)));
}

template <size_t N>
void append(std::vector<uint8_t> &out, const std::array<uint8_t, N> &x) {
  out.insert(out.end(), x.begin(), x.end());
}

inline Digest tagged_hash(const std::string &tag,
                          const std::vector<uint8_t> &payload) {
  std::vector<uint8_t> msg =
      state_internal::domain_header(tag, payload.size());
  msg.insert(msg.end(), payload.begin(), payload.end());
  return lib::blake2s::host::blake2s_256(msg);
}

inline void validate_fingerprint(const Fingerprint &fingerprint) {
  for (const auto &block : fingerprint)
    if ((block.back() & 0xfcu) != 0)
      throw std::runtime_error(
          "state: a fingerprint block has bits above bit 249");
}

inline std::vector<uint8_t> encode_state(
    const CredentialState<Value> &state) {
  if (state.ips.empty() || state.ips.size() != state.geohashes.size())
    throw std::runtime_error("state: IP/geohash history shape mismatch");
  validate_fingerprint(state.last_fingerprint);
  std::vector<uint8_t> out;
  append(out, uint32_t(state.ips.size()));
  for (uint32_t ip : state.ips) append(out, ip);
  for (uint64_t geohash : state.geohashes) append(out, geohash);
  for (const auto &block : state.last_fingerprint) append(out, block);
  append(out, state.year_of_birth);
  append(out, state.users_prf_seed);
  append(out, state.state_counter);
  return out;
}

inline Digest state_digest(const CredentialState<Value> &state) {
  return tagged_hash("zk-cookies/state/v1", encode_state(state));
}

inline Digest state_commitment(const std::array<uint8_t, 32> &randomness,
                               const Digest &state_hash) {
  std::vector<uint8_t> payload;
  append(payload, randomness);
  append(payload, state_hash);
  return tagged_hash("zk-cookies/state-commitment/v1", payload);
}

inline Digest response_digest(uint32_t ip, uint64_t geohash,
                              const std::array<uint8_t, 32> &nonce) {
  std::vector<uint8_t> payload;
  append(payload, ip);
  append(payload, geohash);
  append(payload, nonce);
  return tagged_hash("zk-cookies/server-response/v1", payload);
}

inline Digest response_nullifier(const std::array<uint8_t, 32> &seed,
                                 const Digest &response) {
  std::vector<uint8_t> payload;
  append(payload, seed);
  append(payload, response);
  return tagged_hash("zk-cookies/response-nullifier/v1", payload);
}

inline CredentialState<Value> updated_state(const StateWitness<Value> &w) {
  CredentialState<Value> out = w.initial_state;
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

inline void add_to_bloom(uint16_t &filter, const std::string &tag,
                         uint64_t value) {
  std::vector<uint8_t> payload;
  append(payload, value);
  const Digest d = tagged_hash(tag, payload);
  filter |= uint16_t(1) << (d[0] & 0x0f);
  filter |= uint16_t(1) << (d[0] >> 4);
}

inline uint16_t rappor_response(const StateWitness<Value> &w,
                                const StateConfig &config = {}) {
  uint64_t distinct = 0;
  for (uint32_t ip : w.initial_state.ips) distinct += ip != 0;
  const uint64_t similarity = fingerprint_similarity(
      w.initial_state.last_fingerprint, w.new_fingerprint);

  uint16_t filter = 0;
  add_to_bloom(filter, "zk-cookies/bloom/distinct-ips/v1", distinct);
  add_to_bloom(filter, "zk-cookies/bloom/fingerprint-similarity/v1",
               similarity);
  add_to_bloom(filter, "zk-cookies/bloom/geohash-shared-bits/v1",
               config.geohash_shared_bits);

  std::vector<uint8_t> p_payload;
  append(p_payload, w.initial_state.users_prf_seed);
  append(p_payload, w.new_rappor_nonce);
  append(p_payload, w.initial_state.state_counter);
  const Digest p = tagged_hash("zk-cookies/rappor-p/v1", p_payload);
  std::vector<uint8_t> q_payload;
  append(q_payload, w.initial_state.users_prf_seed);
  append(q_payload, p);
  const Digest q = tagged_hash("zk-cookies/rappor-q/v1", q_payload);

  uint16_t out = 0;
  for (size_t i = 0; i < 16; ++i) {
    const bool original = ((filter >> i) & 1) != 0;
    const bool bit = original ? q[i] < config.rappor_q
                              : p[i] < config.rappor_p;
    out |= uint16_t(bit) << i;
  }
  return out;
}

struct StateOutputs {
  Digest old_state_nullifier{};
  Digest server_response_nullifier{};
  Digest new_state_commitment{};
  uint16_t rappor_response = 0;
};

inline StateOutputs outputs(const StateWitness<Value> &w,
                            const StateConfig &config = {}) {
  StateOutputs out;
  out.old_state_nullifier = state_digest(w.initial_state);
  const Digest response =
      response_digest(w.new_ip, w.new_geohash, w.new_rappor_nonce);
  out.server_response_nullifier =
      response_nullifier(w.initial_state.users_prf_seed, response);
  const CredentialState<Value> next = updated_state(w);
  out.new_state_commitment = state_commitment(
      w.new_state_commitment_randomness, state_digest(next));
  out.rappor_response = host::rappor_response(w, config);
  return out;
}

inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
signature_messages(const StateWitness<Value> &w) {
  const Digest old = state_commitment(w.initial_commitment_randomness,
                                      state_digest(w.initial_state));
  const Digest response =
      response_digest(w.new_ip, w.new_geohash, w.new_rappor_nonce);
  return {std::vector<uint8_t>(old.begin(), old.end()),
          std::vector<uint8_t>(response.begin(), response.end())};
}

}  // namespace host

inline void set_signature(SignatureWitness<Value> &out,
                          const mldsa::Signature &signature) {
  mldsa::set_signature<MLDSA>(out, signature);
}

inline StateStatement<Value> state_statement(
    const std::vector<uint8_t> &server_public_key,
    const host::StateOutputs &outputs) {
  if (server_public_key.size() != MLDSA::kPkBytes)
    throw std::runtime_error("state_statement: an ML-DSA-44 public key");
  StateStatement<Value> st{};
  std::copy(server_public_key.begin(), server_public_key.end(),
            st.server_public_key.begin());
  st.old_state_nullifier = outputs.old_state_nullifier;
  st.server_response_nullifier = outputs.server_response_nullifier;
  st.new_state_commitment = outputs.new_state_commitment;
  st.rappor_response = outputs.rappor_response;
  return st;
}

}  // namespace proofs::gordiehowe::examples::zk_cookies

#endif  // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STATE_BUILDERS_H_
