// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_BUILDERS_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_BUILDERS_H_

#include "gordiehowe/examples/zk-cookies/zk_cookies_attribution.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_common_builders.h"

namespace proofs::gordiehowe::examples::zk_cookies::host {

inline std::vector<uint8_t> encode_state(const AttributionState<Value> &state) {
  if (state.ips.empty() || state.ips.size() != state.geohashes.size() ||
      state.attribution_history.empty())
    throw std::runtime_error("attribution: invalid history shape");
  validate_fingerprint(state.last_fingerprint);
  std::vector<uint8_t> out;
  append(out, uint32_t(state.ips.size()));
  append(out, uint32_t(state.attribution_history.size()));
  for (uint32_t ip : state.ips) append(out, ip);
  for (uint64_t geo : state.geohashes) append(out, geo);
  for (const auto &block : state.last_fingerprint) append(out, block);
  append(out, state.year_of_birth);
  for (const auto &value : state.attribution_history) append(out, value);
  append(out, state.users_prf_seed);
  append(out, state.state_counter);
  return out;
}

template <class Hash = hashes::Default>
Digest state_digest(const AttributionState<Value> &state) {
  return tagged_hash<Hash>(attribution_internal::kStateTag, encode_state(state));
}

template <class Hash = hashes::Default>
Digest response_digest(uint32_t ip, uint64_t geohash, const Digest &nonce,
                        const AttributionValue &value) {
  std::vector<uint8_t> out;
  append(out, ip);
  append(out, geohash);
  append(out, nonce);
  append(out, value);
  return tagged_hash<Hash>(attribution_internal::kResponseTag, out);
}

inline AttributionState<Value> updated_state(const AttributionWitness<Value> &w) {
  if (w.initial_state.attribution_history.empty())
    throw std::runtime_error("attribution: empty history");
  auto out = updated_history_state(w);
  std::move_backward(out.attribution_history.begin(),
                     out.attribution_history.end() - 1,
                     out.attribution_history.end());
  out.attribution_history[0] = w.new_attribution_value;
  return out;
}

inline bool attribution_matches(const std::vector<AttributionValue> &history,
                                 AttributionMode mode,
                                 const AttributionConfig &config = {}) {
  attribution_internal::validate(mode, history.size(), 1, config);
  if (mode == AttributionMode::kSingle)
    return std::find(history.begin(), history.end(), config.search_value) !=
           history.end();
  for (size_t i = 0; i < history.size() - config.search_chain.size(); ++i)
    for (size_t j = 0; j < config.search_chain.size(); ++j)
      if (history[i + j] == config.search_chain[j]) return true;
  return false;
}

template <class Hash = hashes::Default>
uint16_t rappor_response(const AttributionWitness<Value> &w,
                         const AttributionConfig &config = {}) {
  return history_rappor_response<Hash>(w, config.policy);
}

using AttributionOutputs = UpdateOutputs;
template <class Hash = hashes::Default>
AttributionOutputs outputs(const AttributionWitness<Value> &w,
                            const AttributionConfig &config = {}) {
  AttributionOutputs out;
  out.old_state_nullifier = state_digest<Hash>(w.initial_state);
  const auto response = response_digest<Hash>(
      w.new_ip, w.new_geohash, w.new_rappor_nonce, w.new_attribution_value);
  out.server_response_nullifier =
      response_nullifier<Hash>(w.initial_state.users_prf_seed, response);
  out.new_state_commitment = state_commitment<Hash>(
      w.new_state_commitment_randomness, state_digest<Hash>(updated_state(w)));
  out.rappor_response = rappor_response<Hash>(w, config);
  return out;
}

template <class Hash = hashes::Default>
std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
signature_messages(const AttributionWitness<Value> &w) {
  const auto old = state_commitment<Hash>(
      w.initial_commitment_randomness, state_digest<Hash>(w.initial_state));
  const auto response = response_digest<Hash>(
      w.new_ip, w.new_geohash, w.new_rappor_nonce, w.new_attribution_value);
  return {{old.begin(), old.end()}, {response.begin(), response.end()}};
}
} // namespace proofs::gordiehowe::examples::zk_cookies::host
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_ATTRIBUTION_BUILDERS_H_
