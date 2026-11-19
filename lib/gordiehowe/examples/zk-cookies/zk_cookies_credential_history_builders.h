// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// Host-side canonical encoding, hashing, state transition and input builders
// for zk_cookies_credential_history.h.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_CREDENTIAL_HISTORY_BUILDERS_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_CREDENTIAL_HISTORY_BUILDERS_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "gordiehowe/examples/zk-cookies/zk_cookies_common_builders.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_credential_history.h"

namespace proofs::gordiehowe::examples::zk_cookies {

namespace host {

inline std::vector<uint8_t>
encode_state(const CredentialHistoryState<Value> &state) {
  if (state.ips.empty() || state.ips.size() != state.geohashes.size())
    throw std::runtime_error("state: IP/geohash history shape mismatch");
  validate_fingerprint(state.last_fingerprint);
  std::vector<uint8_t> out;
  append(out, uint32_t(state.ips.size()));
  for (uint32_t ip : state.ips)
    append(out, ip);
  for (uint64_t geohash : state.geohashes)
    append(out, geohash);
  for (const auto &block : state.last_fingerprint)
    append(out, block);
  append(out, state.year_of_birth);
  append(out, state.users_prf_seed);
  append(out, state.state_counter);
  return out;
}

template <class Hash = hashes::Default>
Digest state_digest(const CredentialHistoryState<Value> &state) {
  return tagged_hash<Hash>("zk-cookies/state/v1", encode_state(state));
}

template <class Hash = hashes::Default>
Digest response_digest(uint32_t ip, uint64_t geohash,
                       const std::array<uint8_t, 32> &nonce) {
  std::vector<uint8_t> payload;
  append(payload, ip);
  append(payload, geohash);
  append(payload, nonce);
  return tagged_hash<Hash>("zk-cookies/server-response/v1", payload);
}

inline CredentialHistoryState<Value>
updated_state(const CredentialHistoryWitness<Value> &w) {
  return updated_history_state(w);
}

template <class Hash = hashes::Default>
uint16_t rappor_response(const CredentialHistoryWitness<Value> &w,
                         const CredentialHistoryConfig &config = {}) {
  return history_rappor_response<Hash>(w, config);
}

using CredentialHistoryOutputs = UpdateOutputs;

template <class Hash = hashes::Default>
CredentialHistoryOutputs outputs(const CredentialHistoryWitness<Value> &w,
                                 const CredentialHistoryConfig &config = {}) {
  CredentialHistoryOutputs out;
  out.old_state_nullifier = state_digest<Hash>(w.initial_state);
  const Digest response =
      response_digest<Hash>(w.new_ip, w.new_geohash, w.new_rappor_nonce);
  out.server_response_nullifier =
      response_nullifier<Hash>(w.initial_state.users_prf_seed, response);
  const CredentialHistoryState<Value> next = updated_state(w);
  out.new_state_commitment = state_commitment<Hash>(
      w.new_state_commitment_randomness, state_digest<Hash>(next));
  out.rappor_response = host::rappor_response<Hash>(w, config);
  return out;
}

template <class Hash = hashes::Default>
std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
signature_messages(const CredentialHistoryWitness<Value> &w) {
  const Digest old = state_commitment<Hash>(
      w.initial_commitment_randomness, state_digest<Hash>(w.initial_state));
  const Digest response =
      response_digest<Hash>(w.new_ip, w.new_geohash, w.new_rappor_nonce);
  return {std::vector<uint8_t>(old.begin(), old.end()),
          std::vector<uint8_t>(response.begin(), response.end())};
}

} // namespace host

inline CredentialHistoryStatement<Value>
credential_history_statement(const std::vector<uint8_t> &server_public_key,
                             const host::CredentialHistoryOutputs &outputs) {
  if (server_public_key.size() != MLDSA::kPkBytes)
    throw std::runtime_error("credential_history_statement: an ML-DSA-44 public key");
  CredentialHistoryStatement<Value> st{};
  std::copy(server_public_key.begin(), server_public_key.end(),
            st.server_public_key.begin());
  st.old_state_nullifier = outputs.old_state_nullifier;
  st.server_response_nullifier = outputs.server_response_nullifier;
  st.new_state_commitment = outputs.new_state_commitment;
  st.rappor_response = outputs.rappor_response;
  return st;
}

} // namespace proofs::gordiehowe::examples::zk_cookies

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_CREDENTIAL_HISTORY_BUILDERS_H_
