// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// GordieHowe port of zk_cred_logic/state.circom. The relation validates a
// signed credential state and a signed server response, enforces the
// geohash, fingerprint and age policies, emits a RAPPOR response, and
// commits to the updated state.
//
// Two GordieHowe domains form the system. H is the binary domain: the
// selected application hash, the state transition, policy checks, RAPPOR
// and ML-DSA's required SHAKE computations. A is ML-DSA's native F_q
// extension: both signatures' algebra. GordieHowe MAC crossings bind the
// signature challenges and w1 values between them.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_CREDENTIAL_HISTORY_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_CREDENTIAL_HISTORY_H_

#include "gordiehowe/examples/zk-cookies/zk_cookies_common.h"

namespace proofs::gordiehowe::examples::zk_cookies {

template <template <class> class F> struct CredentialHistoryState {
  F<std::vector<uint32_t>> ips;
  F<std::vector<uint64_t>> geohashes;
  F<Fingerprint> last_fingerprint;
  F<std::array<uint8_t, 2>> year_of_birth;
  F<std::array<uint8_t, 32>> users_prf_seed;
  F<uint64_t> state_counter;
};

template <template <class> class F> struct CredentialHistoryWitness {
  CredentialHistoryState<F> initial_state;
  F<std::array<uint8_t, 32>> initial_commitment_randomness;
  SignatureWitness<F> initial_state_signature;

  F<uint32_t> new_ip;
  F<uint64_t> new_geohash;
  F<std::array<uint8_t, 32>> new_rappor_nonce;
  SignatureWitness<F> server_response_signature;

  F<std::array<uint8_t, 32>> new_state_commitment_randomness;
  F<Fingerprint> new_fingerprint;
};

inline CredentialHistoryWitness<Value>
credential_history_witness_shape(size_t history_length) {
  CredentialHistoryWitness<Value> w{};
  w.initial_state.ips.resize(history_length);
  w.initial_state.geohashes.resize(history_length);
  return w;
}

namespace credential_history_internal {

using namespace common_internal;

template <class F>
Expr<F, Bit>
state_payload(Domain<F> &H, size_t history_length, const Expr<F, Bit> &ips,
              const Expr<F, Bit> &geohashes, const Expr<F, Bit> &fingerprint,
              const Expr<F, Bit> &year_of_birth, const Expr<F, Bit> &seed,
              const Expr<F, Bit> &counter) {
  return lib::keccak::sponge_input(
      lib::keccak::constant_bytes(little_endian(history_length, 4)), ips.flat(),
      geohashes.flat(), fingerprint.flat(), year_of_birth.flat(), seed.flat(),
      counter.flat());
}

template <class Hash, class F>
Expr<F, Bit>
state_digest(const Scope &s, Domain<F> &H, size_t history_length,
             const Expr<F, Bit> &ips, const Expr<F, Bit> &geohashes,
             const Expr<F, Bit> &fingerprint, const Expr<F, Bit> &year_of_birth,
             const Expr<F, Bit> &seed, const Expr<F, Bit> &counter) {
  return tagged_hash<Hash>(s, H, "digest", "zk-cookies/state/v1",
                           state_payload(H, history_length, ips, geohashes,
                                         fingerprint, year_of_birth, seed,
                                         counter));
}

template <class Hash, class F>
Expr<F, Bit>
response_digest(const Scope &s, Domain<F> &H, const Expr<F, Bit> &ip,
                const Expr<F, Bit> &geohash, const Expr<F, Bit> &nonce) {
  return tagged_hash<Hash>(
      s, H, "digest", "zk-cookies/server-response/v1",
      ip.flat().concat(geohash.flat()).concat(nonce.flat()));
}

} // namespace credential_history_internal

// The complete state-update relation. HISTORY_LENGTH changes the compiled
// statement/witness shape and is therefore fixed per compiled relation.
template <class P, class Hash = hashes::Default>
void credential_history_relation(typename mldsa::Env<P>::Sys &cs,
                                 const mldsa::Env<P> &env,
                                 CredentialHistoryStatement<In> st,
                                 CredentialHistoryWitness<In> w,
                                 size_t history_length,
                                 const CredentialHistoryConfig &config = {}) {
  using HF = typename mldsa::Env<P>::HF;
  static_assert(Hash::template supports<HF>,
                "the selected zk-cookies hash does not support this profile");
  namespace si = credential_history_internal;
  if (history_length == 0)
    fail("state: an empty history");
  if (w.initial_state.ips.dims().at(0) != history_length ||
      w.initial_state.geohashes.dims().at(0) != history_length)
    fail("state: history shape mismatch");
  if (config.geohash_shared_bits == 0 || config.geohash_shared_bits > 60)
    fail("state: geohash_shared_bits must lie in [1, 60]");
  if (config.fingerprint_threshold >= kFingerprintBits)
    fail("state: fingerprint threshold must be below 500");

  auto &A = cs.domain(domain_profile<P>(env.af, env.rsa), "A");
  auto &H = cs.domain(domain_profile<P>(env.hf, env.rsh), "H");

  // Commit private inputs in H using fixed-width little-endian bits.
  const auto ips = H.priv(Bit{}, w.initial_state.ips);
  const auto geohashes = H.priv(Bit{}, w.initial_state.geohashes);
  const auto fingerprint = H.priv(w.initial_state.last_fingerprint);
  const auto yob = H.priv(w.initial_state.year_of_birth);
  const auto seed = H.priv(w.initial_state.users_prf_seed);
  const auto counter = H.priv(Bit{}, w.initial_state.state_counter);
  const auto initial_randomness = H.priv(w.initial_commitment_randomness);
  const auto new_ip = H.priv(Bit{}, w.new_ip);
  const auto new_geohash = H.priv(Bit{}, w.new_geohash);
  const auto rappor_nonce = H.priv(w.new_rappor_nonce);
  const auto new_randomness = H.priv(w.new_state_commitment_randomness);
  const auto new_fingerprint = H.priv(w.new_fingerprint);
  const auto counter_word = Expr<HF, Bit>(counter).flat();
  const auto new_ip_word = Expr<HF, Bit>(new_ip).flat();
  const auto new_geohash_word = Expr<HF, Bit>(new_geohash).flat();

  const Scope encoding = cs.scope("encoding");
  si::fingerprint_encoding(encoding.scope("old"), Expr<HF, Bit>(fingerprint));
  si::fingerprint_encoding(encoding.scope("new"),
                           Expr<HF, Bit>(new_fingerprint));

  // Old state, its commitment, and the signed server response.
  const auto old_digest =
      si::state_digest<Hash>(cs.scope("old_state"), H, history_length, ips,
                             geohashes, fingerprint, yob, seed, counter);
  const auto old_commitment = si::state_commitment<Hash>(
      cs.scope("old_state_commitment"), H, initial_randomness, old_digest);
  assert_equal(old_digest, st.old_state_nullifier.bits(H).flat(),
               "old_state_nullifier");

  const auto response = si::response_digest<Hash>(
      cs.scope("server_response"), H, new_ip, new_geohash, rappor_nonce);
  const auto response_nullifier = si::response_nullifier<Hash>(
      cs.scope("server_response_nullifier"), H, seed, response);
  assert_equal(response_nullifier, st.server_response_nullifier.bits(H).flat(),
               "server_response_nullifier");

  si::verify_signatures(cs, A, H, st, w, old_commitment, response);

  const auto [updated_ips, updated_geohashes, updated_counter] =
      si::history_transition<Hash>(
          cs.scope("policy"), H, config,
          si::HistoryInputs<HF>{ips, geohashes, fingerprint, yob, seed,
                                counter_word, new_ip_word, new_geohash_word,
                                rappor_nonce, new_fingerprint},
          st.rappor_response.bits(H).flat());
  const auto new_digest = si::state_digest<Hash>(
      cs.scope("updated_state"), H, history_length, updated_ips,
      updated_geohashes, new_fingerprint, yob, seed, updated_counter);
  const auto new_commitment = si::state_commitment<Hash>(
      cs.scope("new_state_commitment"), H, new_randomness, new_digest);
  assert_equal(new_commitment, st.new_state_commitment.bits(H).flat(),
               "new_state_commitment");
}

template <class P, class Hash = hashes::Default>
Relation<CredentialHistoryStatement<Value>, CredentialHistoryWitness<Value>>
zk_cookies_credential_history(const mldsa::Env<P> &env, size_t history_length,
                             const CredentialHistoryConfig &config = {},
                             const BuildOptions &build = {}) {
  return compile<CredentialHistoryStatement, CredentialHistoryWitness>(
      build.profile(mldsa::compile_profile<P, MLDSA>()),
      [&env, history_length, config](typename mldsa::Env<P>::Sys &cs,
                                    CredentialHistoryStatement<In> st,
                                    CredentialHistoryWitness<In> w) {
        credential_history_relation<P, Hash>(cs, env, st, w, history_length,
                                             config);
      },
      std::string("zk-cookies-credential-history-") + Hash::kId,
      CredentialHistoryStatement<Value>{},
      credential_history_witness_shape(history_length), build.compile);
}

} // namespace proofs::gordiehowe::examples::zk_cookies

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_CREDENTIAL_HISTORY_H_
