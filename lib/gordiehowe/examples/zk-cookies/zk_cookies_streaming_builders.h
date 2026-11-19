// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STREAMING_BUILDERS_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STREAMING_BUILDERS_H_

#include <limits>
#include "gordiehowe/examples/zk-cookies/zk_cookies_common_builders.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_streaming.h"

namespace proofs::gordiehowe::examples::zk_cookies {
namespace host {

using UInt128 = unsigned __int128;
inline UInt128 to_uint128(const GeohashSum &sum) {
  return UInt128(sum[0]) | (UInt128(sum[1]) << 64);
}
inline GeohashSum geohash_sum(UInt128 sum) {
  return {uint64_t(sum), uint64_t(sum >> 64)};
}
inline uint64_t streaming_average(const GeohashSum &sum, uint64_t count) {
  if (count == 0 || to_uint128(sum) / count > std::numeric_limits<uint64_t>::max())
    throw std::runtime_error("streaming: average needs a positive count and fits uint64");
  return uint64_t(to_uint128(sum) / count);
}

inline std::vector<uint8_t> encode_state(const StreamingState<Value> &state) {
  std::vector<uint8_t> out;
  append(out, state.geohash_sum[0]);
  append(out, state.geohash_sum[1]);
  append(out, state.state_counter);
  append(out, state.avg_geohash);
  for (const auto &block : state.last_fingerprint) append(out, block);
  append(out, state.year_of_birth);
  append(out, state.users_prf_seed);
  return out;
}
template <class Hash = hashes::Default>
Digest state_digest(const StreamingState<Value> &state) {
  return tagged_hash<Hash>("zk-cookies/streaming-state/v1", encode_state(state));
}
template <class Hash = hashes::Default>
Digest response_digest(uint64_t geohash, const Digest &nonce) {
  std::vector<uint8_t> out;
  append(out, geohash);
  append(out, nonce);
  return tagged_hash<Hash>("zk-cookies/streaming-server-response/v1", out);
}
inline StreamingState<Value> updated_state(const StreamingWitness<Value> &w) {
  auto out = w.initial_state;
  const UInt128 old_sum = to_uint128(out.geohash_sum);
  const UInt128 max_sum = ~UInt128(0);
  if (out.state_counter == std::numeric_limits<uint64_t>::max() ||
      max_sum - old_sum < w.new_geohash)
    throw std::runtime_error("streaming: state update overflows");
  out.geohash_sum = geohash_sum(old_sum + w.new_geohash);
  ++out.state_counter;
  out.avg_geohash = w.next_avg_geohash;
  out.last_fingerprint = w.new_fingerprint;
  return out;
}
template <class Hash = hashes::Default>
uint16_t rappor_response(const StreamingWitness<Value> &w,
                         const StreamingConfig &config = {}) {
  uint16_t filter = 0;
  add_to_bloom<Hash>(filter, "zk-cookies/bloom/state-counter/v1",
                     w.initial_state.state_counter);
  add_to_bloom<Hash>(filter, "zk-cookies/bloom/avg-geohash/v1",
                     w.initial_state.avg_geohash);
  return randomize_bloom<Hash>(filter, w.initial_state.users_prf_seed,
                                w.new_rappor_nonce,
                                w.initial_state.state_counter,
                                config.rappor_p, config.rappor_q);
}
struct StreamingOutputs : UpdateOutputs {
  GeohashSum new_geohash_sum{};
  uint64_t new_state_counter = 0;
  uint64_t new_avg_geohash = 0;
  Fingerprint new_last_fingerprint{};
};
template <class Hash = hashes::Default>
StreamingOutputs outputs(const StreamingWitness<Value> &w,
                          const StreamingConfig &config = {}) {
  StreamingOutputs out;
  out.old_state_nullifier = state_digest<Hash>(w.initial_state);
  const auto response = response_digest<Hash>(w.new_geohash, w.new_rappor_nonce);
  out.server_response_nullifier =
      response_nullifier<Hash>(w.initial_state.users_prf_seed, response);
  const auto next = updated_state(w);
  out.new_state_commitment = state_commitment<Hash>(
      w.new_state_commitment_randomness, state_digest<Hash>(next));
  out.rappor_response = rappor_response<Hash>(w, config);
  out.new_geohash_sum = next.geohash_sum;
  out.new_state_counter = next.state_counter;
  out.new_avg_geohash = next.avg_geohash;
  out.new_last_fingerprint = next.last_fingerprint;
  return out;
}
template <class Hash = hashes::Default>
std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
signature_messages(const StreamingWitness<Value> &w) {
  const auto old = state_commitment<Hash>(
      w.initial_commitment_randomness, state_digest<Hash>(w.initial_state));
  const auto response = response_digest<Hash>(w.new_geohash, w.new_rappor_nonce);
  return {{old.begin(), old.end()}, {response.begin(), response.end()}};
}
} // namespace host

inline StreamingStatement<Value> streaming_statement(
    const std::vector<uint8_t> &pk, const host::StreamingOutputs &out) {
  auto st = update_statement<StreamingStatement<Value>>(pk, out);
  st.new_geohash_sum = out.new_geohash_sum;
  st.new_state_counter = out.new_state_counter;
  st.new_avg_geohash = out.new_avg_geohash;
  st.new_last_fingerprint = out.new_last_fingerprint;
  return st;
}
} // namespace proofs::gordiehowe::examples::zk_cookies
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STREAMING_BUILDERS_H_
