// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// Shared encodings, ML-DSA inputs, and bounded-depth history policies.
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_COMMON_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_COMMON_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gordiehowe/examples/mldsa/mldsa_builders.h"
#include "gordiehowe/examples/mldsa/mldsa_native.h"
#include "gordiehowe/examples/shared/setup.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_hash.h"
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
struct CredentialHistoryConfig {
  size_t geohash_shared_bits = 20;
  size_t fingerprint_threshold = 400; // similarity must be strictly above
  uint8_t rappor_p = 127;
  uint8_t rappor_q = 191;
};

template <template <class> class F> struct SignatureWitness {
  F<std::array<std::array<int32_t, mldsa::kN>, MLDSA::kL>> z;
  F<std::array<std::array<bool, mldsa::kN>, MLDSA::kK>> h;
  F<std::array<uint8_t, MLDSA::kCTildeBytes>> c_tilde;
};

template <template <class> class F> struct CredentialHistoryStatement {
  F<std::array<uint8_t, MLDSA::kPkBytes>> server_public_key;
  F<Digest> old_state_nullifier;
  F<Digest> server_response_nullifier;
  F<Digest> new_state_commitment;
  F<uint16_t> rappor_response;
};

namespace common_internal {


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

template <class Hash, class F>
Expr<F, Bit> state_commitment(const Scope &s, Domain<F> &H,
                              const Expr<F, Bit> &randomness,
                              const Expr<F, Bit> &digest) {
  return tagged_hash<Hash>(s, H, "digest", "zk-cookies/state-commitment/v1",
                           randomness.flat().concat(digest.flat()));
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
Expr<F, Bit> randomize_bloom(
    const Scope &sc, Domain<F> &H, uint8_t rappor_p, uint8_t rappor_q,
    const Expr<F, Bit> &seed, const Expr<F, Bit> &nonce,
    const Expr<F, Bit> &counter, const Expr<F, Bit> &filter) {
  const auto p = tagged_hash<Hash>(
      sc, H, "p", "zk-cookies/rappor-p/v1",
      seed.flat().concat(nonce.flat()).concat(counter.flat()));
  const auto q = tagged_hash<Hash>(sc, H, "q", "zk-cookies/rappor-q/v1",
                                   seed.flat().concat(p.flat()));

  const auto pb = p.reshape({32, 8});
  const auto qb = q.reshape({32, 8});
  Expr<F, Bit> irr;
  for (size_t i = 0; i < 16; ++i) {
    const auto pbit = pb.at(0, i).from_bits() < rappor_p;
    const auto qbit = qb.at(0, i).from_bits() < rappor_q;
    const auto bit = filter.at(i).mux(qbit, pbit);
    irr = i == 0 ? bit : irr.concat(bit);
  }
  return irr;
}

template <class Hash, class F>
Expr<F, Bit> rappor(const Scope &s, Domain<F> &H, const CredentialHistoryConfig &config,
                    const Expr<F, Bit> &seed, const Expr<F, Bit> &nonce,
                    const Expr<F, Bit> &counter,
                    const Expr<F, Bit> &distinct_ips,
                    const Expr<F, Bit> &similarity) {
  const Scope sc = s.scope("rappor");
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

  return randomize_bloom<Hash>(sc, H, config.rappor_p, config.rappor_q,
                                seed, nonce, counter, filter);
}

// The two signatures share a public key, with independent algebra and MAC
// crossings. ML-DSA's FIPS-mandated SHAKE remains in H for every hash policy.
template <class Sys, class AF, class HF, class St, class W>
void verify_signatures(Sys &cs, Domain<AF> &A, Domain<HF> &H, const St &st,
                       const W &w, const Expr<HF, Bit> &old_commitment,
                       const Expr<HF, Bit> &response) {
  // Both signatures' algebra is isolated in A under disjoint scopes.
  const Scope initial_sig_scope = cs.scope("initial_state_signature");
  const auto initial_sig = mldsa::mldsa_native_signature<MLDSA, HF>(
      initial_sig_scope, cs, A, st.server_public_key,
      w.initial_state_signature);
  const Scope response_sig_scope = cs.scope("server_response_signature");
  const auto response_sig = mldsa::mldsa_native_signature<MLDSA, HF>(
      response_sig_scope, cs, A, st.server_public_key,
      w.server_response_signature);

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

}

template <class F> struct HistoryInputs {
  Expr<F, Bit> ips, geohashes, fingerprint, yob, seed, counter;
  Expr<F, Bit> new_ip, new_geohash, nonce, new_fingerprint;
};
template <class F> struct HistoryTransition {
  Expr<F, Bit> ips, geohashes, counter;
};

// Shared by credential history and both attribution variants. No selector,
// reduction, or concatenation chain grows linearly in the history length.
template <class Hash, class F>
HistoryTransition<F> history_transition(
    const Scope &policy, Domain<F> &H, const CredentialHistoryConfig &config,
    const HistoryInputs<F> &in, const Expr<F, Bit> &expected_rappor) {
  const auto &[ips, geohashes, fingerprint, yob, seed, counter,
               new_ip_word, new_geohash_word, rappor_nonce, new_fingerprint] = in;
  const auto counter_word = counter.flat();
  // A first request bypasses the geohash-prefix check. Otherwise at least
  // one stored geohash shares the configured bits 60-B .. 59.
  // Generators reuse this history-wide predicate instead of recomputing
  // every slot's zero test for each population-count leaf and update.
  const Expr<F, Bit> old_ip_zero = H.bit_from_unchecked(
      policy.scoped("old_ip_zero"), (!Expr<F, Bit>(ips)).all(1));
  const auto empty_history = old_ip_zero.all(0);
  const size_t lo = 60 - config.geohash_shared_bits;
  const auto old_prefix = Expr<F, Bit>(geohashes).slice(lo, 60, 1);
  const auto new_prefix = new_geohash_word.slice(lo, 60);
  const auto prefix_match = (!(old_prefix ^ new_prefix)).all(1).any(0);
  assert_true(prefix_match | empty_history, policy.name("geohash_prefix"));

  const auto old_fp = fingerprint_bits(Expr<F, Bit>(fingerprint));
  const auto new_fp = fingerprint_bits(Expr<F, Bit>(new_fingerprint));
  const auto similarity =
      popcount(policy, H, "fingerprint_similarity", !(old_fp ^ new_fp), 16);
  assert_true(!(similarity.from_bits() <= config.fingerprint_threshold),
              policy.name("fingerprint_threshold"));
  age_check(policy.scope("age"), H, yob);

  const auto distinct_ips =
      popcount(policy, H, "distinct_ips", !old_ip_zero, 64);
  const auto similarity64 = extend_word(H, similarity, 64);
  const auto irr = rappor<Hash>(policy, H, config, seed, rappor_nonce,
                                    counter, distinct_ips, similarity64);
  assert_equal(irr, expected_rappor, "rappor_response");

  // Preserve state.circom's update semantics: keep an existing IP, else
  // fill the first zero slot, else drop the oldest entry and append.
  const auto [updated_ips, updated_geohashes] = updated_history(
      Expr<F, Bit>(ips), Expr<F, Bit>(geohashes), new_ip_word,
      new_geohash_word, old_ip_zero);
  const auto one = lib::arith::constant_word(H, 1, 64);
  const auto updated_counter =
      lib::arith::add(counter_word, one, policy.name("updated_counter"));
  return {updated_ips, updated_geohashes, updated_counter};
}

} // namespace common_internal

} // namespace proofs::gordiehowe::examples::zk_cookies

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_COMMON_H_
