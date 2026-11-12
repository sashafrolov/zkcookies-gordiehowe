// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// GordieHowe: unkeyed BLAKE2s-256 over a fixed-length byte string.
//
//   blake2s_256(s, H, name, msg)  -> digest, Bit [256]
//
// MSG is a byte string in the binary domain H: bit 8 i + j is bit j of
// byte i. Its length is public and fixed by the compiled relation. One
// native uint32_t computation generates each call's packed trace. Every
// addition is checked by arith::assert_sum over those committed values,
// vectorized across blocks. Binary-field addition expresses XOR; rotations
// are views. The trace also commits and checks each block's chaining value.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_BLAKE2S_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_BLAKE2S_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gordiehowe/ct.h"
#include "gordiehowe/domain.h"
#include "gordiehowe/expr.h"
#include "gordiehowe/lib/arith.h"
#include "gordiehowe/predicates.h"
#include "gordiehowe/system.h"

namespace proofs::gordiehowe::lib::blake2s {

inline constexpr size_t kBlockBytes = 64;
inline constexpr size_t kDigestBytes = 32;
using Digest = std::array<uint8_t, kDigestBytes>;

namespace internal {

inline constexpr uint32_t kIV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline constexpr uint8_t kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline constexpr size_t kGIndices[8][4] = {
    {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
    {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};

// Six committed addition results per G, including the partial sums of its
// two three-operand additions; then eight chaining words per block.
inline constexpr size_t kSumsPerG = 6;
inline constexpr size_t kSumWords = 10 * 8 * kSumsPerG;
inline constexpr size_t kTraceWords = kSumWords + 8;

inline uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

inline void g(uint32_t *v, size_t a, size_t b, size_t c, size_t d,
              uint32_t x, uint32_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = rotr(v[d] ^ v[a], 16);
  v[c] += v[d];
  v[b] = rotr(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr(v[d] ^ v[a], 8);
  v[c] += v[d];
  v[b] = rotr(v[b] ^ v[c], 7);
}

inline uint32_t load32(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
         (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

inline void store32(uint8_t *p, uint32_t x) {
  for (size_t i = 0; i < 4; ++i) p[i] = uint8_t(x >> (8 * i));
}

inline void compress(uint32_t *h, const uint8_t *block, uint64_t count,
                     bool last) {
  uint32_t m[16], v[16];
  for (size_t i = 0; i < 16; ++i) m[i] = load32(block + 4 * i);
  for (size_t i = 0; i < 8; ++i) {
    v[i] = h[i];
    v[i + 8] = kIV[i];
  }
  v[12] ^= uint32_t(count);
  v[13] ^= uint32_t(count >> 32);
  if (last) v[14] = ~v[14];
  for (size_t r = 0; r < 10; ++r) {
    const auto &s = kSigma[r];
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (size_t i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

template <class F>
Expr<F, Bit> word(const Domain<F> &H, uint32_t x) {
  return arith::constant_word(H, x, 32);
}

// The honest prover's G trace, using native wrapping uint32_t arithmetic.
// The standalone host compression remains an independent computation.
inline void trace_g(uint32_t *v, const size_t *at, uint32_t x, uint32_t y,
                     uint32_t *out) {
  const size_t a = at[0], b = at[1], c = at[2], d = at[3];
  out[0] = v[a] + v[b];
  out[1] = v[a] = out[0] + x;
  v[d] = rotr(v[d] ^ v[a], 16);
  out[2] = v[c] = v[c] + v[d];
  v[b] = rotr(v[b] ^ v[c], 12);
  out[3] = v[a] + v[b];
  out[4] = v[a] = out[3] + y;
  v[d] = rotr(v[d] ^ v[a], 8);
  out[5] = v[c] = v[c] + v[d];
  v[b] = rotr(v[b] ^ v[c], 7);
}

// The entire trace, block-major [blocks, 488] native words. PADDED has one
// or more zero-padded 64-byte blocks; BYTES is the unpadded message length.
inline std::vector<uint32_t> host_trace(const std::vector<uint8_t> &padded,
                                       size_t bytes) {
  const size_t nb = padded.size() / kBlockBytes;
  std::vector<uint32_t> trace(nb * kTraceWords);
  uint32_t h[8];
  std::copy(std::begin(kIV), std::end(kIV), h);
  h[0] ^= 0x01010020u;
  for (size_t block = 0; block < nb; ++block) {
    uint32_t m[16], v[16];
    for (size_t i = 0; i < 16; ++i)
      m[i] = load32(&padded[kBlockBytes * block + 4 * i]);
    for (size_t i = 0; i < 8; ++i) {
      v[i] = h[i];
      v[i + 8] = kIV[i];
    }
    const uint64_t count = std::min<uint64_t>(bytes, kBlockBytes * (block + 1));
    v[12] ^= uint32_t(count);
    v[13] ^= uint32_t(count >> 32);
    if (block + 1 == nb) v[14] = ~v[14];
    uint32_t *const out = trace.data() + block * kTraceWords;
    for (size_t r = 0; r < 10; ++r)
      for (size_t j = 0; j < 8; ++j)
        trace_g(v, kGIndices[j], m[kSigma[r][2 * j]],
                m[kSigma[r][2 * j + 1]], out + (8 * r + j) * kSumsPerG);
    for (size_t i = 0; i < 8; ++i)
      out[kSumWords + i] = h[i] = h[i] ^ v[i] ^ v[i + 8];
  }
  return trace;
}

template <class F>
struct TraceValues {
  Expr<F, Bit> sums, h;
};

// One native trace per call and witness run, returned by packed generators
// for the sums, intermediate chaining values and final digest. Keeping the
// digest in its own small value lets subsequent hashes read just its words.
// The thread-local memo is keyed by a call's lifetime token and witness run;
// it never shares data between concurrent proofs or different calls.
template <class F>
TraceValues<F> committed_trace(const Scope &s, Domain<F> &H,
                                const Expr<F, Bit> &padded, size_t bytes) {
  using Elt = typename F::Elt;
  const F *pf = &H.field();
  const size_t nb = padded.size() / (8 * kBlockBytes);
  const auto token = std::make_shared<char>();
  auto family = [&](const std::string &name, size_t first, size_t blocks,
                    size_t offset, size_t per, const Shape &shape) {
    return H.priv(
        Bit{}, s.scoped(name), shape, depends_on(padded),
        [pf, bytes, token, first, blocks, offset, per](
            const std::vector<Elt> &bits) {
          struct Memo {
            uint64_t run = 0;
            const void *call = nullptr;
            std::vector<uint32_t> words;
          };
          static thread_local Memo memo;
          if (witness_run == 0 || memo.run != witness_run ||
              memo.call != token.get()) {
            std::vector<uint8_t> message(bits.size() / 8, 0);
            for (size_t i = 0; i < bits.size(); ++i)
              message[i / 8] |= uint8_t(ct::bit_of(*pf, bits[i])) << (i % 8);
            memo.words = host_trace(message, bytes);
            memo.run = witness_run;
            memo.call = token.get();
          }
          const size_t n = blocks * per;
          PackedBits out{std::vector<uint64_t>((n + 1) / 2, 0)};
          for (size_t i = 0; i < n; ++i) {
            const size_t source =
                (first + i / per) * kTraceWords + offset + i % per;
            out.w[i / 2] |= uint64_t(memo.words[source]) << (32 * (i % 2));
          }
          return out;
        });
  };
  TraceValues<F> out;
  out.sums = family("sums", 0, nb, 0, kSumWords, Shape{nb, kSumWords, 32});
  const Expr<F, Bit> last =
      family("h_last", nb - 1, 1, kSumWords, 8, Shape{8, 32});
  out.h = nb == 1
              ? last.reshape({1, 8, 32})
              : family("h", 0, nb - 1, kSumWords, 8, Shape{nb - 1, 8, 32})
                    .concat(last.reshape({1, 8, 32}));
  return out;
}

// A constant word repeated in all blocks, [nb, 32].
template <class F>
Expr<F, Bit> every_block(const Domain<F> &H, uint32_t x, size_t nb) {
  std::vector<size_t> index(32 * nb);
  for (size_t i = 0; i < index.size(); ++i) index[i] = i % 32;
  return word(H, x).reindex(index).reshape({nb, 32});
}

// G on every block at once. SUMS has shape [nb, 6, 32]; all six advice
// words are constrained, including both three-operand partial sums.
template <class F>
void g(const Scope &s, std::array<Expr<F, Bit>, 16> &v, const size_t *at,
       const Expr<F, Bit> &x, const Expr<F, Bit> &y,
       const Expr<F, Bit> &sums) {
  const size_t a = at[0], b = at[1], c = at[2], d = at[3];
  const auto a0 = sums.at(1, 1), c0 = sums.at(1, 2);
  const auto a1 = sums.at(1, 4), c1 = sums.at(1, 5);
  const size_t nb = x.dims().at(0);
  arith::assert_sum(a0, {v[a], v[b], x},
                    sums.at(1, 0).reshape({1, nb, 32}), s.name("a0"));
  v[a] = a0;
  v[d] = (v[d] + v[a]).rotate(-16, 1);
  arith::assert_sum(c0, {v[c], v[d]}, s.name("c0"));
  v[c] = c0;
  v[b] = (v[b] + v[c]).rotate(-12, 1);
  arith::assert_sum(a1, {v[a], v[b], y},
                    sums.at(1, 3).reshape({1, nb, 32}), s.name("a1"));
  v[a] = a1;
  v[d] = (v[d] + v[a]).rotate(-8, 1);
  arith::assert_sum(c1, {v[c], v[d]}, s.name("c1"));
  v[c] = c1;
  v[b] = (v[b] + v[c]).rotate(-7, 1);
}

}  // namespace internal

namespace host {

// RFC 7693's unkeyed BLAKE2s with a 32-byte digest.
inline Digest blake2s_256(const std::vector<uint8_t> &message) {
  uint32_t h[8];
  std::copy(std::begin(internal::kIV), std::end(internal::kIV), h);
  h[0] ^= 0x01010020u;  // fanout 1, depth 1, key length 0, digest length 32

  const size_t blocks = std::max<size_t>(1, (message.size() + 63) / 64);
  std::array<uint8_t, 64> block{};
  for (size_t b = 0; b < blocks; ++b) {
    block.fill(0);
    const size_t at = 64 * b;
    const size_t n = at < message.size()
                         ? std::min<size_t>(64, message.size() - at)
                         : 0;
    if (n != 0)
      std::copy(message.begin() + long(at), message.begin() + long(at + n),
                block.begin());
    internal::compress(h, block.data(), uint64_t(at + n), b + 1 == blocks);
  }
  Digest out{};
  for (size_t i = 0; i < 8; ++i) internal::store32(&out[4 * i], h[i]);
  return out;
}

}  // namespace host

// BLAKE2s-256 of the fixed, byte-aligned message MSG in H.
template <class F>
Expr<F, Bit> blake2s_256(const Scope &s, Domain<F> &H,
                         const std::string &name, Expr<F, Bit> msg) {
  static_assert(F::kCharacteristicTwo,
                "BLAKE2s is implemented in a characteristic-two domain");
  msg = msg.flat();
  if (msg.size() % 8 != 0) fail("BLAKE2s: a message of whole bytes");
  const size_t bytes = msg.size() / 8;
  const size_t blocks = std::max<size_t>(1, (bytes + 63) / 64);
  const size_t padded_bits = 8 * 64 * blocks;
  if (msg.size() < padded_bits) {
    const auto zeros = H.constant(
        Bit{}, std::vector<uint64_t>(padded_bits - msg.size(), 0));
    msg = msg.concat(zeros);
  }
  const auto words = msg.reshape({blocks, 16, 32});
  const Scope call = s.scope(name, computes("BLAKE2s-256", {bytes}));
  const auto trace = internal::committed_trace(call, H, msg, bytes);
  const auto &sums = trace.sums;
  const auto &h = trace.h;
  std::vector<uint64_t> iv;
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t w = internal::kIV[i] ^ (i == 0 ? 0x01010020u : 0);
    for (size_t bit = 0; bit < 32; ++bit) iv.push_back((w >> bit) & 1);
  }
  const auto first = H.constant(Bit{}, iv, Shape{1, 8, 32});
  const Expr<F, Bit> hin =
      blocks == 1 ? first : first.concat(h.slice(0, blocks - 1), 0);
  std::array<Expr<F, Bit>, 16> v;
  for (size_t i = 0; i < 8; ++i) {
    v[i] = hin.at(1, i);
    v[i + 8] = internal::every_block(H, internal::kIV[i], blocks);
  }
  std::vector<uint64_t> count_low, count_high, last;
  for (size_t block = 0; block < blocks; ++block) {
    const uint64_t count =
        std::min<uint64_t>(uint64_t(bytes), uint64_t(64 * (block + 1)));
    for (size_t bit = 0; bit < 32; ++bit) {
      count_low.push_back((count >> bit) & 1);
      count_high.push_back((count >> (32 + bit)) & 1);
      last.push_back(block + 1 == blocks);
    }
  }
  v[12] = v[12] + H.constant(Bit{}, count_low, Shape{blocks, 32});
  v[13] = v[13] + H.constant(Bit{}, count_high, Shape{blocks, 32});
  v[14] = v[14] + H.constant(Bit{}, last, Shape{blocks, 32});
  for (size_t r = 0; r < 10; ++r) {
    const Scope rs = call.scope("round" + std::to_string(r));
    const auto &p = internal::kSigma[r];
    for (size_t j = 0; j < 8; ++j) {
      const size_t begin = (8 * r + j) * internal::kSumsPerG;
      internal::g(rs.scope("g" + std::to_string(j)), v, internal::kGIndices[j],
                  words.at(1, p[2 * j]), words.at(1, p[2 * j + 1]),
                  sums.slice(begin, begin + internal::kSumsPerG, 1));
    }
  }
  Expr<F, Bit> final = (v[0] + v[8]).reshape({blocks, 1, 32});
  for (size_t i = 1; i < 8; ++i)
    final = final.concat((v[i] + v[i + 8]).reshape({blocks, 1, 32}), 1);
  assert_equal(h, hin + final, call.name("chain"));
  return h.at(0, blocks - 1).flat().named(call.scoped("digest"));
}

}  // namespace proofs::gordiehowe::lib::blake2s

#endif  // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_BLAKE2S_H_
