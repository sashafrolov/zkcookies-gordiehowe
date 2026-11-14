// Copyright 2026
// Parameter tables Copyright 2024-2025 Irreducible Inc.
// SPDX-License-Identifier: Apache-2.0

// Poseidon2b over GordieHowe's polynomial-basis GF(2^128), using the
// n=128, t=6, x^7, (R_F, R_P)=(8,58) instance.  The parameter tables are
// copied from Poseidon-Hash/Poseidon2b commit
// 7072a9438cf48f1b38ad0092cda5452626914068, file
// poseidon2b_x7_128_768.rs.  Their integer coefficients are interpreted in
// GordieHowe's polynomial basis, so this is not byte-for-byte compatible
// with Binius's tower-field serialization.
//
// The byte hash uses the paper's sponge-pi construction with capacity 2,
// rate 4 and a two-element (256-bit) digest.  Bytes are injected into field
// elements as little-endian polynomial coefficients after appending a 0x01
// delimiter and zero-padding to 16 bytes.  Sponge-pi then applies its own
// field-element 10* padding and final mu bit.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_POSEIDON2B_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_POSEIDON2B_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include "gf2k/gf2_128.h"
#include "gordiehowe/ct.h"
#include "gordiehowe/domain.h"
#include "gordiehowe/expr.h"
#include "gordiehowe/predicates.h"
#include "gordiehowe/system.h"

namespace proofs::gordiehowe::lib::poseidon2b {

inline constexpr size_t kStateSize = 6;
inline constexpr size_t kCapacity = 2;
inline constexpr size_t kRate = kStateSize - kCapacity;
inline constexpr size_t kDigestElements = 2;
inline constexpr size_t kFieldBytes = 16;
inline constexpr size_t kDigestBytes = kDigestElements * kFieldBytes;
inline constexpr size_t kFullRounds = 8;
inline constexpr size_t kPartialRounds = 58;
inline constexpr size_t kRounds = kFullRounds + kPartialRounds;
inline constexpr size_t kSboxesPerPermutation =
    kFullRounds * kStateSize + kPartialRounds;
using Digest = std::array<uint8_t, kDigestBytes>;

namespace internal {

// Binius stores constants by state lane and then by round.
inline constexpr std::array<std::array<uint16_t, kRounds>, kStateSize>
    kRoundConstants{{
        {{0xd,  0xa,  0x17, 0xa,  0xe,  0x0,  0xe,  0x15, 0x9,  0x4,  0x1e,
          0x1d, 0x1f, 0x9,  0x17, 0x5,  0x5,  0x1d, 0x1b, 0x10, 0x13, 0x6,
          0x14, 0xf,  0xf,  0x13, 0x15, 0x10, 0x13, 0x2,  0xf,  0xa,  0x16,
          0x13, 0x15, 0x15, 0x18, 0xd,  0x1d, 0x11, 0x1b, 0x10, 0x3,  0x1d,
          0x7,  0x10, 0x12, 0x1a, 0x4,  0x11, 0x16, 0xb,  0x3,  0x6,  0x17,
          0x7,  0x14, 0x6,  0x1a, 0x16, 0x19, 0x1c, 0x4,  0x7,  0x19, 0x18}},
        {{0x6,  0xf,  0x16, 0x15, 0x8,  0x11, 0xf,  0x18, 0x1d, 0x15, 0x8,
          0x8,  0x7,  0xf,  0x14, 0x11, 0x8,  0x9,  0x8,  0x6,  0xa,  0x0,
          0x1c, 0x15, 0x13, 0xb,  0x3,  0xa,  0x10, 0x1,  0x16, 0x1f, 0x4,
          0x0,  0x1d, 0x12, 0x5,  0x5,  0x14, 0x9,  0x1d, 0x10, 0x19, 0x1b,
          0x5,  0x1,  0x17, 0xd,  0x9,  0x19, 0x13, 0x1a, 0x9,  0xe,  0x2,
          0x4,  0x9,  0x18, 0x1a, 0x6,  0xc,  0x11, 0x2,  0x1b, 0xb,  0x1f}},
        {{0xd,  0x1f, 0x14, 0x17, 0x0,  0x3,  0x15, 0xe,  0x10, 0x0,  0x14,
          0x1b, 0xb,  0xc,  0x6,  0x8,  0x1d, 0x1a, 0x13, 0x10, 0xb,  0x1d,
          0x1d, 0x13, 0x7,  0x14, 0xc,  0x10, 0x1a, 0x17, 0x17, 0x1a, 0x1b,
          0x12, 0x1a, 0xe,  0x1,  0x14, 0x14, 0xc,  0x14, 0x7,  0x17, 0x13,
          0x1f, 0x9,  0x14, 0x9,  0x12, 0x1a, 0x10, 0xd,  0x19, 0xc,  0x15,
          0x16, 0xf,  0xf,  0x4,  0xd,  0x16, 0x19, 0xa,  0xa,  0x5,  0x3}},
        {{0x6,  0x14, 0x11, 0x1d, 0x10, 0x2,  0x1f, 0x5,  0x1,  0xa,  0x12,
          0x1d, 0x15, 0x6,  0x6,  0x1c, 0x1,  0x9,  0x14, 0x6,  0x5,  0x5,
          0x1d, 0x19, 0x1f, 0x9,  0x19, 0x15, 0x1c, 0x19, 0x10, 0x1a, 0x17,
          0xe,  0x0,  0x6,  0x1e, 0x2,  0x6,  0xb,  0x14, 0x0,  0x7,  0x12,
          0x1c, 0x15, 0x1c, 0x11, 0x16, 0x14, 0x1a, 0x14, 0xc,  0x7,  0x0,
          0x2,  0x11, 0x1c, 0xa,  0x16, 0x1a, 0x0,  0x1a, 0x1f, 0x18, 0x1b}},
        {{0x16, 0x1e, 0x1e, 0x1d, 0xa,  0xc,  0xb,  0x1d, 0x9,  0x1e, 0xd,
          0x12, 0x17, 0x12, 0x14, 0x16, 0xd,  0x2,  0x1d, 0x1a, 0x7,  0x1b,
          0x1d, 0x19, 0xf,  0x5,  0x1d, 0xe,  0x18, 0xa,  0x3,  0x1c, 0x1f,
          0x0,  0x1d, 0x1e, 0x0,  0x9,  0x1f, 0xd,  0x1c, 0x1c, 0x1,  0x1,
          0x13, 0x9,  0x11, 0x14, 0x1a, 0x17, 0xe,  0x3,  0x1d, 0x1a, 0xb,
          0xa,  0x12, 0x1c, 0x14, 0x1c, 0x1,  0x6,  0x2,  0x17, 0x1f, 0x1b}},
        {{0xe,  0x4,  0x15, 0x1e, 0x2,  0x17, 0xd,  0x2,  0x15, 0xe,  0x1f,
          0x4,  0x9,  0x1d, 0x1,  0x6,  0x1e, 0xa,  0x15, 0x3,  0x12, 0x10,
          0x1b, 0x13, 0xa,  0xf,  0x7,  0x1b, 0x1d, 0x16, 0xd,  0x15, 0x1a,
          0x4,  0x1d, 0xa,  0x8,  0x1c, 0x1,  0x2,  0x1a, 0x19, 0x1f, 0x8,
          0x1d, 0x16, 0x1a, 0x15, 0xe,  0xd,  0x1c, 0x8,  0xd,  0x1c, 0x4,
          0x13, 0x1e, 0x1,  0x10, 0x14, 0x13, 0x10, 0x5,  0x15, 0x16, 0x1d}},
    }};

inline constexpr uint16_t kExternal[kStateSize][kStateSize] = {
    {0x200, 0x1, 0x2, 0x2, 0x800, 0x1}, {0x1, 0x200, 0x1, 0x2, 0x2, 0x800},
    {0x800, 0x1, 0x200, 0x1, 0x2, 0x2}, {0x2, 0x800, 0x1, 0x200, 0x1, 0x2},
    {0x2, 0x2, 0x800, 0x1, 0x200, 0x1}, {0x1, 0x2, 0x2, 0x800, 0x1, 0x200},
};

inline constexpr uint16_t kInternalDiagonal[kStateSize] = {
    0x100, 0x400, 0x8, 0x4, 0x800, 0x4000};

template <class F> typename F::Elt coefficient(const F &f, uint16_t x) {
  return f.of_scalar_field(x);
}

template <class F>
typename F::Elt power7(const F &f, const typename F::Elt &x) {
  const auto x2 = f.mulf(x, x);
  const auto x4 = f.mulf(x2, x2);
  const auto x6 = f.mulf(x2, x4);
  return f.mulf(x6, x);
}

template <class F>
std::array<typename F::Elt, kStateSize>
external_layer(const F &f, const std::array<typename F::Elt, kStateSize> &x) {
  std::array<typename F::Elt, kStateSize> y{};
  for (size_t i = 0; i < kStateSize; ++i)
    for (size_t j = 0; j < kStateSize; ++j)
      f.add(y[i], f.mulf(coefficient(f, kExternal[i][j]), x[j]));
  return y;
}

template <class F>
std::array<typename F::Elt, kStateSize>
internal_layer(const F &f, const std::array<typename F::Elt, kStateSize> &x) {
  auto sum = f.zero();
  for (const auto &v : x)
    f.add(sum, v);
  std::array<typename F::Elt, kStateSize> y{};
  for (size_t i = 0; i < kStateSize; ++i) {
    // sum contains x_i once.  Adding (mu_i + 1)x_i changes that
    // coefficient to mu_i in characteristic two.
    const auto mu_plus_one =
        f.addf(coefficient(f, kInternalDiagonal[i]), f.one());
    y[i] = f.addf(sum, f.mulf(mu_plus_one, x[i]));
  }
  return y;
}

template <class F>
std::array<Expr<F, Field>, kStateSize>
external_layer(const F &f, const std::array<Expr<F, Field>, kStateSize> &x) {
  std::array<Expr<F, Field>, kStateSize> y;
  for (size_t i = 0; i < kStateSize; ++i) {
    y[i] = coefficient(f, kExternal[i][0]) * x[0];
    for (size_t j = 1; j < kStateSize; ++j)
      y[i] = y[i] + coefficient(f, kExternal[i][j]) * x[j];
  }
  return y;
}

template <class F>
std::array<Expr<F, Field>, kStateSize>
internal_layer(const F &f, const std::array<Expr<F, Field>, kStateSize> &x) {
  Expr<F, Field> sum = x[0];
  for (size_t i = 1; i < kStateSize; ++i)
    sum = sum + x[i];
  std::array<Expr<F, Field>, kStateSize> y;
  for (size_t i = 0; i < kStateSize; ++i) {
    const auto mu_plus_one =
        f.addf(coefficient(f, kInternalDiagonal[i]), f.one());
    y[i] = sum + mu_plus_one * x[i];
  }
  return y;
}

template <class F>
Expr<F, Field> power7(const Scope &s, Domain<F> &H, const std::string &name,
                      const Expr<F, Field> &x,
                      const Expr<F, Field> *witness = nullptr) {
  using Elt = typename F::Elt;
  const F *pf = &H.field();

  // Only the nonlinear output is committed. The four products of the x^7
  // addition chain are GKR wires; its affine input reads earlier committed
  // S-box outputs. This cuts the circuit at every S-box, so its depth does
  // not grow with the number of rounds or sponge blocks.
  const Expr<F, Field> out = witness ? *witness : H.priv(
      Field{}, s.scoped(name + ".x7"), Shape{1}, depends_on(x),
      [pf](const Elt &value) { return power7(*pf, value); });
  const auto x2 = x * x;
  const auto x4 = x2 * x2;
  const auto x6 = x2 * x4;
  assert_zero(x6 * x - out, s.name(name + ".x7_power"))
      .pin(Placement::kCircuit);
  return out;
}

// Six affine forms in a shared basis of expressions. Update the coefficients
// with native field arithmetic, rather than nesting symbolic linear layers:
// the latter expands exponentially when the compiler flattens partial rounds.
// Full rounds reset the basis to six committed S-box outputs; partial rounds
// append one output. No linear-layer checkpoint needs to be committed.
template <class F>
class AffineState {
  using Elt = typename F::Elt;

 public:
  AffineState(const F &f,
              const std::array<Expr<F, Field>, kStateSize> &state)
      : f_(f) {
    reset(state);
  }

  void reset(const std::array<Expr<F, Field>, kStateSize> &state) {
    basis_.assign(state.begin(), state.end());
    for (size_t i = 0; i < kStateSize; ++i) {
      coefficients_[i].assign(kStateSize, f_.zero());
      coefficients_[i][i] = f_.one();
    }
  }

  Expr<F, Field> lane(size_t i) const {
    Expr<F, Field> out = constant(f_, std::vector<Elt>{f_.zero()});
    for (size_t j = 0; j < basis_.size(); ++j)
      if (coefficients_[i][j] != f_.zero())
        out = out + coefficients_[i][j] * basis_[j];
    return out;
  }

  void replace_first(const Expr<F, Field> &out) {
    basis_.push_back(out);
    for (auto &row : coefficients_)
      row.push_back(f_.zero());
    coefficients_[0].assign(basis_.size(), f_.zero());
    coefficients_[0].back() = f_.one();
  }

  void mix(bool full) {
    for (size_t j = 0; j < basis_.size(); ++j) {
      std::array<Elt, kStateSize> column;
      for (size_t i = 0; i < kStateSize; ++i)
        column[i] = coefficients_[i][j];
      column = full ? external_layer(f_, column) : internal_layer(f_, column);
      for (size_t i = 0; i < kStateSize; ++i)
        coefficients_[i][j] = column[i];
    }
  }

 private:
  const F &f_;
  std::vector<Expr<F, Field>> basis_;
  std::array<std::vector<Elt>, kStateSize> coefficients_;
};

inline std::vector<uint8_t> encode_bytes(const std::vector<uint8_t> &msg) {
  std::vector<uint8_t> out = msg;
  out.push_back(1);
  while (out.size() % kFieldBytes != 0)
    out.push_back(0);
  return out;
}

} // namespace internal

template <class F>
std::array<typename F::Elt, kStateSize>
permutation(const F &f, std::array<typename F::Elt, kStateSize> state,
            std::vector<typename F::Elt> *trace = nullptr) {
  static_assert(std::is_same_v<F, GF2_128<>>,
                "Poseidon2b is implemented only for GF2_128<>");
  state = internal::external_layer(f, state);
  for (size_t r = 0; r < kRounds; ++r) {
    const bool full =
        r < kFullRounds / 2 || r >= kFullRounds / 2 + kPartialRounds;
    if (full) {
      for (size_t i = 0; i < kStateSize; ++i) {
        f.add(state[i],
              internal::coefficient(f, internal::kRoundConstants[i][r]));
        state[i] = internal::power7(f, state[i]);
        if (trace) trace->push_back(state[i]);
      }
      state = internal::external_layer(f, state);
    } else {
      f.add(state[0],
            internal::coefficient(f, internal::kRoundConstants[0][r]));
      state[0] = internal::power7(f, state[0]);
      if (trace) trace->push_back(state[0]);
      state = internal::internal_layer(f, state);
    }
  }
  return state;
}

template <class F>
std::array<Expr<F, Field>, kStateSize>
permutation(const Scope &s, Domain<F> &H, const std::string &name,
            std::array<Expr<F, Field>, kStateSize> state,
            const Expr<F, Field> *trace = nullptr) {
  static_assert(std::is_same_v<F, GF2_128<>>,
                "Poseidon2b is implemented only for GF2_128<>");
  const F &f = H.field();
  size_t at = 0;
  const auto sbox = [&](const std::string &label, const Expr<F, Field> &x) {
    if (!trace) return internal::power7(s, H, label, x);
    const auto out = trace->at(at++).reshape({1});
    return internal::power7(s, H, label, x, &out);
  };
  internal::AffineState<F> affine(f, state);
  affine.mix(/*full=*/true);
  for (size_t r = 0; r < kRounds; ++r) {
    const bool full =
        r < kFullRounds / 2 || r >= kFullRounds / 2 + kPartialRounds;
    if (full) {
      for (size_t i = 0; i < kStateSize; ++i) {
        state[i] = affine.lane(i) +
                   internal::coefficient(f, internal::kRoundConstants[i][r]);
        state[i] = sbox(name + ".round" + std::to_string(r) +
                            ".lane" + std::to_string(i), state[i]);
      }
      affine.reset(state);
    } else {
      state[0] =
          affine.lane(0) +
          internal::coefficient(f, internal::kRoundConstants[0][r]);
      state[0] = sbox(
          name + ".round" + std::to_string(r) + ".lane0", state[0]);
      affine.replace_first(state[0]);
    }
    affine.mix(full);
  }
  for (size_t i = 0; i < kStateSize; ++i)
    state[i] = affine.lane(i);
  return state;
}

namespace host {

// Sponge state from byte-delimited input, optionally recording every S-box
// output in block/round/lane order for the circuit's committed trace.
template <class F>
std::array<typename F::Elt, kStateSize>
sponge(const F &f, const std::vector<uint8_t> &encoded,
        std::vector<typename F::Elt> *trace = nullptr) {
  using Elt = typename F::Elt;
  std::vector<Elt> words;
  words.reserve(encoded.size() / kFieldBytes + kRate);
  for (size_t i = 0; i < encoded.size(); i += kFieldBytes)
    words.push_back(f.of_bytes_field(encoded.data() + i).value());

  const bool mu = words.size() % kRate == 0;
  if (!mu) {
    words.push_back(f.one());
    while (words.size() % kRate != 0)
      words.push_back(f.zero());
  }

  std::array<Elt, kStateSize> state{};
  state[kStateSize - 1] = f.of_scalar_field(kDigestElements);
  const size_t blocks = words.size() / kRate;
  for (size_t b = 0; b < blocks; ++b) {
    for (size_t i = 0; i < kRate; ++i)
      f.add(state[i], words[b * kRate + i]);
    if (b + 1 == blocks && mu)
      f.add(state[kStateSize - 1], f.one());
    state = permutation(f, state, trace);
  }
  return state;
}

inline Digest hash(const std::vector<uint8_t> &message) {
  GF2_128<> f;
  const auto state = sponge(f, internal::encode_bytes(message));
  Digest out{};
  for (size_t i = 0; i < kDigestElements; ++i)
    f.to_bytes_field(out.data() + i * kFieldBytes, state[i]);
  return out;
}

} // namespace host

// The 256-bit Poseidon2b sponge hash of a fixed, byte-aligned Bit string.
template <class F>
Expr<F, Bit> hash(const Scope &s, Domain<F> &H, const std::string &name,
                  Expr<F, Bit> message) {
  static_assert(std::is_same_v<F, GF2_128<>>,
                "Poseidon2b is implemented only for GF2_128<>");
  message = message.flat();
  if (message.size() % 8 != 0)
    fail("Poseidon2b: a message of whole bytes");
  const F &f = H.field();
  using Elt = typename F::Elt;

  // The byte-to-field delimiter followed by zero padding.
  const size_t bytes = message.size() / 8;
  const size_t encoded_bytes = ((bytes + 1 + 15) / 16) * 16;
  std::vector<uint64_t> suffix(8 * (encoded_bytes - bytes), 0);
  suffix[0] = 1; // byte 0x01, in little-endian bit order
  Expr<F, Bit> encoded =
      message.size() == 0
          ? Expr<F, Bit>(H.constant(Bit{}, suffix))
          : Expr<F, Bit>(message.concat(H.constant(Bit{}, suffix)));
  const size_t word_count = encoded_bytes / kFieldBytes;
  // Evaluate the encoded message once per proof. This derived Bit view adds
  // no committed coordinates and checks still expand the original input.
  const auto input =
      H.bit_from_unchecked(s.scoped(name + ".message"), encoded);
  Expr<F, Field> words =
      Expr<F, Bit>(input).reshape({word_count, 128}).from_digits(f.x());

  const bool mu = word_count % kRate == 0;
  size_t padded_words = word_count;
  if (!mu)
    padded_words = ((word_count + 1 + kRate - 1) / kRate) * kRate;
  if (padded_words != word_count) {
    std::vector<Elt> padding(padded_words - word_count, f.zero());
    padding[0] = f.one();
    words = words.concat(constant(f, padding));
  }

  // One native trace generator packs the message once and computes the whole
  // sponge. This replaces per-S-box expression evaluation without adding any
  // witnesses: only the same 106 nonlinear outputs per permutation are stored.
  // The symbolic computation below independently constrains every output.
  const size_t blocks = padded_words / kRate;
  const F *pf = &f;
  const auto trace = H.priv(
      Field{}, s.scoped(name + ".sboxes"),
      Shape{blocks, kSboxesPerPermutation}, depends_on(input),
      [pf, blocks](const std::vector<Elt> &bits) {
        std::vector<uint8_t> encoded_bytes(bits.size() / 8, 0);
        for (size_t i = 0; i < bits.size(); ++i)
          encoded_bytes[i / 8] |= uint8_t(ct::bit_of(*pf, bits[i])) << (i % 8);
        std::vector<Elt> out;
        out.reserve(blocks * kSboxesPerPermutation);
        host::sponge(*pf, encoded_bytes, &out);
        return out;
      });
  // Share the table's expression node across blocks, so emitting a block
  // view does not repeatedly expand the entire committed array.
  const Expr<F, Field> trace_values(trace);

  std::array<Expr<F, Field>, kStateSize> state;
  const Expr<F, Field> zero = constant(f, std::vector<Elt>{f.zero()});
  for (size_t i = 0; i + 1 < kStateSize; ++i)
    state[i] = zero;
  state[kStateSize - 1] =
      constant(f, std::vector<Elt>{f.of_scalar_field(kDigestElements)});

  for (size_t b = 0; b < blocks; ++b) {
    for (size_t i = 0; i < kRate; ++i)
      state[i] = state[i] + words.at(b * kRate + i).reshape({1});
    if (b + 1 == blocks && mu)
      state[kStateSize - 1] = state[kStateSize - 1] + f.one();
    const auto block_trace = trace_values.at(b);
    state = permutation(s, H, name + ".block" + std::to_string(b), state,
                        &block_trace);
  }

  // Keep the common hash-policy API byte-oriented.  The committed bits are
  // constrained to be the polynomial-basis coefficients of the two output
  // field elements.
  const auto digest =
      H.priv(Bit{}, s.scoped(name + ".digest"), Shape{256},
             depends_on(state[0], state[1]),
             [pf](const Tensor<Elt> &av, const Tensor<Elt> &bv) {
               const Elt &a = av[0];
               const Elt &b = bv[0];
               std::vector<Elt> bits(256, pf->zero());
               std::array<uint8_t, 16> bytes{};
               for (size_t lane = 0; lane < 2; ++lane) {
                 pf->to_bytes_field(bytes.data(), lane == 0 ? a : b);
                 for (size_t i = 0; i < 128; ++i)
                   bits[128 * lane + i] =
                       ct::bit_elt(*pf, (bytes[i / 8] >> (i % 8)) & 1);
               }
               return bits;
             });
  const auto packed =
      Expr<F, Bit>(digest).reshape({kDigestElements, 128}).from_digits(f.x());
  const auto output = state[0].concat(state[1]);
  assert_equal(packed, output, s.name(name + ".digest_packing"));
  return Expr<F, Bit>(digest);
}

} // namespace proofs::gordiehowe::lib::poseidon2b

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_POSEIDON2B_H_
