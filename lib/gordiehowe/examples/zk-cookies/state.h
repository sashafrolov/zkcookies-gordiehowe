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

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STATE_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STATE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gordiehowe/examples/mldsa/mldsa_builders.h"
#include "gordiehowe/examples/mldsa/mldsa_native.h"
#include "gordiehowe/examples/shared/setup.h"
#include "gordiehowe/examples/zk-cookies/state_hash.h"
#include "gordiehowe/expr.h"
#include "gordiehowe/lib/arith.h"
#include "gordiehowe/lib/keccak.h"
#include "gordiehowe/predicates.h"
#include "gordiehowe/relation.h"
#include "gordiehowe/system.h"

namespace proofs::gordiehowe::examples::zk_cookies {

using MLDSA = mldsa::MLDSA44;
using Digest = hashes::Digest;
using Fingerprint = std::array<std::array<uint8_t, 32>, 2>;
inline constexpr size_t kFingerprintBitsPerBlock = 250;
inline constexpr size_t kFingerprintBits = 2 * kFingerprintBitsPerBlock;

// Policy values from state.circom. A relation's history length is a separate
// construction argument because it changes the compiled shape.
struct StateConfig {
  size_t geohash_shared_bits = 20;
  size_t fingerprint_threshold = 400; // similarity must be strictly above
  uint8_t rappor_p = 127;
  uint8_t rappor_q = 191;
};

template <template <class> class F> struct CredentialState {
  F<std::vector<uint32_t>> ips;
  F<std::vector<uint64_t>> geohashes;
  F<Fingerprint> last_fingerprint;
  F<std::array<uint8_t, 2>> year_of_birth;
  F<std::array<uint8_t, 32>> users_prf_seed;
  F<uint64_t> state_counter;
};

template <template <class> class F> struct SignatureWitness {
  F<std::array<std::array<int32_t, mldsa::kN>, MLDSA::kL>> z;
  F<std::array<std::array<bool, mldsa::kN>, MLDSA::kK>> h;
  F<std::array<uint8_t, MLDSA::kCTildeBytes>> c_tilde;
};

template <template <class> class F> struct StateStatement {
  F<std::array<uint8_t, MLDSA::kPkBytes>> server_public_key;
  F<Digest> old_state_nullifier;
  F<Digest> server_response_nullifier;
  F<Digest> new_state_commitment;
  F<uint16_t> rappor_response;
};

template <template <class> class F> struct StateWitness {
  CredentialState<F> initial_state;
  F<std::array<uint8_t, 32>> initial_commitment_randomness;
  SignatureWitness<F> initial_state_signature;

  F<uint32_t> new_ip;
  F<uint64_t> new_geohash;
  F<std::array<uint8_t, 32>> new_rappor_nonce;
  SignatureWitness<F> server_response_signature;

  F<std::array<uint8_t, 32>> new_state_commitment_randomness;
  F<Fingerprint> new_fingerprint;
};

inline StateWitness<Value> state_witness_shape(size_t history_length) {
  StateWitness<Value> w{};
  w.initial_state.ips.resize(history_length);
  w.initial_state.geohashes.resize(history_length);
  return w;
}

namespace state_internal {

inline std::vector<uint8_t> little_endian(uint64_t x, size_t bytes) {
  std::vector<uint8_t> out(bytes);
  for (size_t i = 0; i < bytes; ++i)
    out[i] = uint8_t(x >> (8 * i));
  return out;
}

// Every application-hash call hashes a self-delimiting domain header followed
// by a fixed-width payload: u16le(tag length) || tag || u64le(payload length).
inline std::vector<uint8_t> domain_header(const std::string &tag,
                                          size_t payload_bytes) {
  if (tag.size() > 0xffff)
    fail("state: a hash tag is too long");
  std::vector<uint8_t> out = little_endian(tag.size(), 2);
  out.insert(out.end(), tag.begin(), tag.end());
  const auto n = little_endian(payload_bytes, 8);
  out.insert(out.end(), n.begin(), n.end());
  return out;
}

// Join scalar/vector views in a balanced tree, avoiding a linear-depth
// concatenation expression and its successively larger index maps.
template <class F>
Expr<F, Bit> balanced_concat(std::vector<Expr<F, Bit>> parts) {
  if (parts.empty()) fail("state: concatenate no parts");
  while (parts.size() > 1) {
    std::vector<Expr<F, Bit>> next;
    next.reserve((parts.size() + 1) / 2);
    for (size_t i = 0; i < parts.size(); i += 2)
      next.push_back(i + 1 == parts.size() ? parts[i]
                                          : parts[i].concat(parts[i + 1]));
    parts = std::move(next);
  }
  return parts.front();
}

// Keep an existing IP; otherwise fill the first zero slot, or shift a full
// history. Prefixes of nonzero slots replace the sequential zero_before OR
// chain. All prefixes have logarithmic depth (Sklansky's parallel scan).
template <class F>
std::pair<Expr<F, Bit>, Expr<F, Bit>>
updated_history(const Expr<F, Bit> &ips,
                const Expr<F, Bit> &geohashes, const Expr<F, Bit> &new_ip,
                const Expr<F, Bit> &new_geohash,
                const Expr<F, Bit> &old_ip_zero) {
  const size_t n = ips.dims().at(0);
  std::vector<Expr<F, Bit>> nonzero;
  nonzero.reserve(n);
  for (size_t i = 0; i < n; ++i) nonzero.push_back(!old_ip_zero.at(i));
  const auto prefix = lib::arith::prefix_and(std::move(nonzero));
  std::vector<Expr<F, Bit>> insert;
  insert.reserve(n);
  for (size_t i = 0; i < n; ++i)
    insert.push_back((i == 0 ? old_ip_zero.at(i)
                            : old_ip_zero.at(i) & prefix[i - 1]).reshape({1}));
  const auto first_zero = balanced_concat(std::move(insert)).reshape({n, 1});
  const auto exists = (!(ips ^ new_ip)).all(1).any(0);
  const auto has_zero = old_ip_zero.any(0);

  // Tensor-wide muxes need no per-slot concatenation chain. A shift is one
  // slice followed by the new entry, including when the history has length 1.
  const auto update = [&](const Expr<F, Bit> &old, const Expr<F, Bit> &value) {
    const size_t width = old.dims().at(1);
    const auto shifted = old.slice(1, n, 0).concat(value.reshape({1, width}), 0);
    return exists.mux(old, has_zero.mux(first_zero.mux(value, old), shifted));
  };
  return {update(ips, new_ip), update(geohashes, new_geohash)};
}

template <class Hash, class F>
Expr<F, Bit> tagged_hash(const Scope &s, Domain<F> &H, const std::string &name,
                         const std::string &tag, const Expr<F, Bit> &payload) {
  if (payload.size() % 8 != 0)
    fail("state: a byte-aligned hash payload");
  const auto head = domain_header(tag, payload.size() / 8);
  const auto msg = lib::keccak::sponge_input(lib::keccak::constant_bytes(head),
                                             payload.flat());
  return Hash::circuit(s, H, name, msg);
}

template <class F>
Expr<F, Bit> extend_word(Domain<F> &H, const Expr<F, Bit> &x, size_t width) {
  const size_t n = x.size();
  if (n > width)
    fail("state: cannot narrow a word");
  if (n == width)
    return x;
  return x.concat(H.constant(Bit{}, std::vector<uint64_t>(width - n, 0)));
}

// The binary population count, returned as a WIDTH-bit little-endian word.
// Pairwise committed additions keep every predicate quadratic.
template <class F>
Expr<F, Bit> popcount(const Scope &s, Domain<F> &H, const std::string &name,
                      const Expr<F, Bit> &bits, size_t width) {
  if (bits.size() == 0)
    fail("state: popcount of no bits");
  const Scope sc = s.scope(name, computes("popcount", {bits.size(), width}));
  std::vector<Expr<F, Bit>> words;
  words.reserve(bits.size());
  for (size_t i = 0; i < bits.size(); ++i)
    words.push_back(extend_word(H, bits.at(i), width));
  size_t level = 0;
  while (words.size() > 1) {
    std::vector<Expr<F, Bit>> next;
    for (size_t i = 0; i < words.size(); i += 2) {
      if (i + 1 == words.size()) {
        next.push_back(words[i]);
      } else {
        next.push_back(
            lib::arith::add(words[i], words[i + 1],
                            sc.name("level" + std::to_string(level) + ".sum" +
                                    std::to_string(i / 2))));
      }
    }
    words = std::move(next);
    ++level;
  }
  return words.front();
}

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
Expr<F, Bit> state_commitment(const Scope &s, Domain<F> &H,
                              const Expr<F, Bit> &randomness,
                              const Expr<F, Bit> &digest) {
  return tagged_hash<Hash>(s, H, "digest", "zk-cookies/state-commitment/v1",
                           randomness.flat().concat(digest.flat()));
}

template <class Hash, class F>
Expr<F, Bit>
response_digest(const Scope &s, Domain<F> &H, const Expr<F, Bit> &ip,
                const Expr<F, Bit> &geohash, const Expr<F, Bit> &nonce) {
  return tagged_hash<Hash>(
      s, H, "digest", "zk-cookies/server-response/v1",
      ip.flat().concat(geohash.flat()).concat(nonce.flat()));
}

template <class Hash, class F>
Expr<F, Bit> response_nullifier(const Scope &s, Domain<F> &H,
                                const Expr<F, Bit> &seed,
                                const Expr<F, Bit> &response) {
  return tagged_hash<Hash>(s, H, "digest", "zk-cookies/response-nullifier/v1",
                           seed.flat().concat(response.flat()));
}

template <class F>
void fingerprint_encoding(const Scope &s, const Expr<F, Bit> &fingerprint) {
  const auto blocks = fingerprint.reshape({2, 256});
  assert_zero(blocks.slice(kFingerprintBitsPerBlock, 256, 1),
              s.name("fingerprint_padding"));
}

template <class F>
Expr<F, Bit> fingerprint_bits(const Expr<F, Bit> &fingerprint) {
  const auto blocks = fingerprint.reshape({2, 256});
  return blocks.slice(0, kFingerprintBitsPerBlock, 1).flat();
}

template <class F>
void age_check(const Scope &s, Domain<F> &H,
               const Expr<F, Bit> &year_of_birth) {
  const auto y = year_of_birth.reshape({2, 8});
  const auto tens = y.at(0, 0).slice(0, 4);
  const auto ones = y.at(0, 1).slice(0, 4);
  const auto ascii_high = H.constant(Bit{}, std::vector<uint64_t>{1, 1, 0, 0});
  assert_equal(y.slice(4, 8, 1),
               ascii_high.reshape({1, 4}).concat(ascii_high.reshape({1, 4}), 0),
               s.name("ascii_digits"));
  assert_true((tens.from_bits() <= 9) & (ones.from_bits() <= 9),
              s.name("decimal_digits"));
  const auto in_2000s = (tens.from_bits() == 0) & (ones.from_bits() <= 6);
  const auto in_1900s = (!(tens.from_bits() <= 2)) |
                        ((tens.from_bits() == 2) & !(ones.from_bits() < 6));
  assert_true(in_2000s | in_1900s, s.name("over_18"));
}

template <class Hash, class F>
Expr<F, Bit> add_to_bloom(const Scope &s, Domain<F> &H, const std::string &name,
                          const std::string &tag, const Expr<F, Bit> &filter,
                          const Expr<F, Bit> &value) {
  const Scope sc = s.scope(name);
  const auto digest = tagged_hash<Hash>(sc, H, "hash", tag, value);
  const auto i0 = digest.slice(0, 4).from_bits();
  const auto i1 = digest.slice(4, 8).from_bits();
  Expr<F, Bit> out = filter.at(0);
  for (size_t i = 0; i < 16; ++i) {
    const auto set = (i0 == i) | (i1 == i);
    const auto bit = filter.at(i) | set;
    out = i == 0 ? bit : out.concat(bit);
  }
  return out;
}

template <class Hash, class F>
Expr<F, Bit> rappor(const Scope &s, Domain<F> &H, const StateConfig &config,
                    const Expr<F, Bit> &seed, const Expr<F, Bit> &nonce,
                    const Expr<F, Bit> &counter,
                    const Expr<F, Bit> &distinct_ips,
                    const Expr<F, Bit> &similarity) {
  const Scope sc = s.scope("rappor");
  const auto p = tagged_hash<Hash>(
      sc, H, "p", "zk-cookies/rappor-p/v1",
      seed.flat().concat(nonce.flat()).concat(counter.flat()));
  const auto q = tagged_hash<Hash>(sc, H, "q", "zk-cookies/rappor-q/v1",
                                   seed.flat().concat(p.flat()));

  auto filter = H.constant(Bit{}, std::vector<uint64_t>(16, 0));
  filter = add_to_bloom<Hash>(sc, H, "distinct_ips",
                              "zk-cookies/bloom/distinct-ips/v1", filter,
                              distinct_ips);
  filter = add_to_bloom<Hash>(sc, H, "fingerprint_similarity",
                              "zk-cookies/bloom/fingerprint-similarity/v1",
                              filter, similarity);
  // The geohash precision is a compile-time policy constant, so its two
  // Bloom positions are constants too (no circuit hash call is needed).
  const std::string geo_tag = "zk-cookies/bloom/geohash-shared-bits/v1";
  const auto geo_payload = little_endian(config.geohash_shared_bits, 8);
  std::vector<uint8_t> geo_message = domain_header(geo_tag, geo_payload.size());
  geo_message.insert(geo_message.end(), geo_payload.begin(), geo_payload.end());
  const auto geo_digest = Hash::host(geo_message);
  std::vector<uint64_t> geo_bits(16, 0);
  geo_bits[geo_digest[0] & 0x0f] = 1;
  geo_bits[geo_digest[0] >> 4] = 1;
  filter = filter | H.constant(Bit{}, geo_bits);

  const auto pb = p.reshape({32, 8});
  const auto qb = q.reshape({32, 8});
  Expr<F, Bit> irr;
  for (size_t i = 0; i < 16; ++i) {
    const auto pbit = pb.at(0, i).from_bits() < config.rappor_p;
    const auto qbit = qb.at(0, i).from_bits() < config.rappor_q;
    const auto bit = filter.at(i).mux(qbit, pbit);
    irr = i == 0 ? bit : irr.concat(bit);
  }
  return irr;
}

} // namespace state_internal

// The complete state-update relation. HISTORY_LENGTH changes the compiled
// statement/witness shape and is therefore fixed per compiled relation.
template <class P, class Hash = hashes::Default>
void state_relation(typename mldsa::Env<P>::Sys &cs, const mldsa::Env<P> &env,
                    StateStatement<In> st, StateWitness<In> w,
                    size_t history_length, const StateConfig &config = {}) {
  using HF = typename mldsa::Env<P>::HF;
  static_assert(Hash::template supports<HF>,
                "the selected zk-cookies hash does not support this profile");
  namespace si = state_internal;
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

  // Both signatures' algebra is isolated in A under disjoint scopes.
  const Scope initial_sig_scope = cs.scope("initial_state_signature");
  const auto initial_sig = mldsa::mldsa_native_signature<MLDSA, HF>(
      initial_sig_scope, cs, A, st.server_public_key,
      w.initial_state_signature);
  const Scope response_sig_scope = cs.scope("server_response_signature");
  const auto response_sig = mldsa::mldsa_native_signature<MLDSA, HF>(
      response_sig_scope, cs, A, st.server_public_key,
      w.server_response_signature);

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

  // ML-DSA signs the two 32-byte application-hash digests under the empty
  // context. Its own standards-mandated SHAKE computations are unchanged.
  const lib::keccak::SpongeInput<HF> empty_context;
  const auto initial_hash = mldsa::mldsa_hash_domain<MLDSA>(
      initial_sig_scope, cs, H, st.server_public_key, initial_sig.w1,
      empty_context, old_commitment);
  mldsa::crossing(initial_sig_scope.scope("crossing"), initial_hash,
                  initial_sig.c);
  const auto response_hash = mldsa::mldsa_hash_domain<MLDSA>(
      response_sig_scope, cs, H, st.server_public_key, response_sig.w1,
      empty_context, response);
  mldsa::crossing(response_sig_scope.scope("crossing"), response_hash,
                  response_sig.c);

  const Scope policy = cs.scope("policy");
  // A first request bypasses the geohash-prefix check. Otherwise at least
  // one stored geohash shares the configured bits 60-B .. 59.
  // Generators reuse this history-wide predicate instead of recomputing
  // every slot's zero test for each population-count leaf and update.
  const Expr<HF, Bit> old_ip_zero = H.bit_from_unchecked(
      policy.scoped("old_ip_zero"), (!Expr<HF, Bit>(ips)).all(1));
  const auto empty_history = old_ip_zero.all(0);
  const size_t lo = 60 - config.geohash_shared_bits;
  const auto old_prefix = Expr<HF, Bit>(geohashes).slice(lo, 60, 1);
  const auto new_prefix = new_geohash_word.slice(lo, 60);
  const auto prefix_match = (!(old_prefix ^ new_prefix)).all(1).any(0);
  assert_true(prefix_match | empty_history, policy.name("geohash_prefix"));

  const auto old_fp = si::fingerprint_bits(Expr<HF, Bit>(fingerprint));
  const auto new_fp = si::fingerprint_bits(Expr<HF, Bit>(new_fingerprint));
  const auto similarity =
      si::popcount(policy, H, "fingerprint_similarity", !(old_fp ^ new_fp), 16);
  assert_true(!(similarity.from_bits() <= config.fingerprint_threshold),
              policy.name("fingerprint_threshold"));
  si::age_check(policy.scope("age"), H, yob);

  const auto distinct_ips =
      si::popcount(policy, H, "distinct_ips", !old_ip_zero, 64);
  const auto similarity64 = si::extend_word(H, similarity, 64);
  const auto irr = si::rappor<Hash>(policy, H, config, seed, rappor_nonce,
                                    counter, distinct_ips, similarity64);
  assert_equal(irr, st.rappor_response.bits(H).flat(), "rappor_response");

  // Preserve state.circom's update semantics: keep an existing IP, else
  // fill the first zero slot, else drop the oldest entry and append.
  const auto [updated_ips, updated_geohashes] = si::updated_history(
      Expr<HF, Bit>(ips), Expr<HF, Bit>(geohashes), new_ip_word,
      new_geohash_word, old_ip_zero);
  const auto one = lib::arith::constant_word(H, 1, 64);
  const auto updated_counter =
      lib::arith::add(counter_word, one, "updated_state.counter");
  const auto new_digest = si::state_digest<Hash>(
      cs.scope("updated_state"), H, history_length, updated_ips,
      updated_geohashes, new_fingerprint, yob, seed, updated_counter);
  const auto new_commitment = si::state_commitment<Hash>(
      cs.scope("new_state_commitment"), H, new_randomness, new_digest);
  assert_equal(new_commitment, st.new_state_commitment.bits(H).flat(),
               "new_state_commitment");
}

template <class P, class Hash = hashes::Default>
Relation<StateStatement<Value>, StateWitness<Value>>
state(const mldsa::Env<P> &env, size_t history_length,
      const StateConfig &config = {}, const BuildOptions &build = {}) {
  return compile<StateStatement, StateWitness>(
      build.profile(mldsa::compile_profile<P, MLDSA>()),
      [&env, history_length, config](typename mldsa::Env<P>::Sys &cs,
                                     StateStatement<In> st,
                                     StateWitness<In> w) {
        state_relation<P, Hash>(cs, env, st, w, history_length, config);
      },
      std::string("zk-cookies-state-") + Hash::kId, StateStatement<Value>{},
      state_witness_shape(history_length), build.compile);
}

} // namespace proofs::gordiehowe::examples::zk_cookies

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_STATE_H_
