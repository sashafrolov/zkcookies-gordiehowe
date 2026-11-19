// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Deterministic fixtures for tests and benchmark runners; not production keys.
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_TESTING_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_TESTING_H_

#include "gordiehowe/examples/mldsa/mldsa_native_testing.h"
#include "gordiehowe/examples/mldsa/mldsa_openssl_testing.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_credential_history_builders.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_single_attribution_builders.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_multi_attribution_builders.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_streaming_builders.h"

namespace proofs::gordiehowe::examples::zk_cookies::testing {
inline Fingerprint fingerprint(size_t flipped) {
  Fingerprint out{};
  for (size_t bit = 0; bit < flipped; ++bit) {
    const size_t local = bit % kFingerprintBitsPerBlock;
    out[bit / kFingerprintBitsPerBlock][local / 8] |= uint8_t(1) << (local % 8);
  }
  return out;
}
template <class Witness> void initialize(Witness &w) {
  w.initial_state.year_of_birth = {'0', '0'};
  for (size_t i = 0; i < 32; ++i) {
    w.initial_state.users_prf_seed[i] = uint8_t(3 * i + 1);
    w.initial_commitment_randomness[i] = uint8_t(5 * i + 2);
    w.new_rappor_nonce[i] = uint8_t(7 * i + 3);
    w.new_state_commitment_randomness[i] = uint8_t(11 * i + 4);
  }
  w.new_geohash = 3856082809388864ull;
  w.new_fingerprint = fingerprint(99);
}
inline CredentialHistoryWitness<Value> credential_history_witness(size_t n) {
  auto w = credential_history_witness_shape(n);
  initialize(w);
  w.new_ip = 3232235526u;
  return w;
}
inline AttributionWitness<Value> attribution_witness(
    size_t n, size_t ips, AttributionMode mode) {
  auto w = attribution_witness_shape(n, ips);
  initialize(w);
  w.new_ip = 3232235526u;
  for (size_t i = 0; i < n; ++i)
    for (size_t j = 0; j < kAttributionBytes; ++j)
      w.initial_state.attribution_history[i][j] = uint8_t(17 * i + 3 * j + 1);
  const AttributionConfig config;
  w.initial_state.attribution_history[0] =
      mode == AttributionMode::kSingle ? config.search_value
                                        : config.search_chain[0];
  w.new_attribution_value.fill(0xa5);
  return w;
}
inline StreamingWitness<Value> streaming_witness(uint64_t count = 100) {
  StreamingWitness<Value> w{};
  initialize(w);
  w.initial_state.state_counter = count;
  w.initial_state.avg_geohash = w.new_geohash;
  w.initial_state.geohash_sum =
      host::geohash_sum(host::UInt128(count) * w.new_geohash);
  w.new_geohash += 17;
  w.next_avg_geohash = host::streaming_average(
      host::geohash_sum(host::to_uint128(w.initial_state.geohash_sum) +
                        w.new_geohash), count + 1);
  return w;
}
inline mldsa::Signature decoded_signature(const std::vector<uint8_t> &pk,
                                          const std::vector<uint8_t> &message,
                                          const std::vector<uint8_t> &sig) {
  ml_dsa::MlDsa44SignatureExample ex;
  ex.pkey = pk;
  ex.msg = message;
  ex.sig = sig;
  const mldsa::support::Existing<MLDSA> existing(ex);
  if (!existing.ok) throw std::runtime_error("fixture ML-DSA signature rejected");
  return existing.signature();
}
template <class Hash = hashes::Default, class Witness>
std::vector<uint8_t> sign(Witness &w) {
  std::array<uint8_t, 32> seed{};
  for (size_t i = 0; i < seed.size(); ++i) seed[i] = uint8_t(i);
  const auto key = mldsa::support::mldsa_key<MLDSA>(seed);
  const auto pk = mldsa::support::mldsa_public<MLDSA>(key);
  const auto [old, response] = host::signature_messages<Hash>(w);
  set_signature(w.initial_state_signature, decoded_signature(
      pk, old, mldsa::support::mldsa_sign<MLDSA>(key, old, {})));
  set_signature(w.server_response_signature, decoded_signature(
      pk, response, mldsa::support::mldsa_sign<MLDSA>(key, response, {})));
  return pk;
}
} // namespace proofs::gordiehowe::examples::zk_cookies::testing
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_TESTING_H_
