// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// GordieHowe: standard unkeyed BLAKE3-256 over a fixed-length byte string.
//
//   blake3_256(s, H, name, msg)  -> digest, Bit [256]
//
// MSG is a byte string in the binary domain H: bit 8 i + j is bit j of
// byte i. Its length is public and fixed by the compiled relation. The
// implementation includes BLAKE3's 1024-byte chunks and binary hash tree,
// so it is suitable for messages of arbitrary fixed size.
//
// A native uint32_t computation generates packed advice for every compression
// operation. All wrapping additions are checked by arith::assert_sum, while
// XOR and rotations are native binary-field operations and views. Compression
// operations are vectorized together, including chunk blocks and parent nodes.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_BLAKE3_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_BLAKE3_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "gordiehowe/ct.h"
#include "gordiehowe/domain.h"
#include "gordiehowe/expr.h"
#include "gordiehowe/lib/arith.h"
#include "gordiehowe/predicates.h"
#include "gordiehowe/system.h"

namespace proofs::gordiehowe::lib::blake3 {

inline constexpr size_t kBlockBytes = 64;
inline constexpr size_t kChunkBytes = 1024;
inline constexpr size_t kDigestBytes = 32;
using Digest = std::array<uint8_t, kDigestBytes>;

namespace internal {

inline constexpr uint32_t kIV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

inline constexpr uint32_t kChunkStart = 1u << 0;
inline constexpr uint32_t kChunkEnd = 1u << 1;
inline constexpr uint32_t kParent = 1u << 2;
inline constexpr uint32_t kRoot = 1u << 3;

// The BLAKE3 message permutation, applied zero through six times.
inline constexpr uint8_t kSchedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

inline constexpr size_t kGIndices[8][4] = {
    {0, 4, 8, 12},  {1, 5, 9, 13},  {2, 6, 10, 14}, {3, 7, 11, 15},
    {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13},  {3, 4, 9, 14}};

// Six committed addition results per G, including the partial sums of its
// two three-operand additions, followed by eight chaining/output words.
inline constexpr size_t kSumsPerG = 6;
inline constexpr size_t kSumWords = 7 * 8 * kSumsPerG;
inline constexpr size_t kTraceWords = kSumWords + 8;
inline constexpr size_t kNoSource = std::numeric_limits<size_t>::max();

inline uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

inline uint32_t load32(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
         (uint32_t(p[3]) << 24);
}

inline void store32(uint8_t *p, uint32_t x) {
  for (size_t i = 0; i < 4; ++i)
    p[i] = uint8_t(x >> (8 * i));
}

// One compression in the fixed execution plan. Message operations source a
// 64-byte block from the padded input and optionally a previous block's CV.
// Parent operations source both halves of their block from child CVs.
struct Operation {
  enum class Kind { kMessage, kParent };
  Kind kind = Kind::kMessage;
  size_t block = 0;
  size_t cv_source = kNoSource;
  size_t left_source = kNoSource;
  size_t right_source = kNoSource;
  uint64_t counter = 0;
  uint32_t block_len = 0;
  uint32_t flags = 0;
};

struct Plan {
  size_t message_blocks = 0;
  std::vector<Operation> operations;
  size_t root = 0;
};

// Build the standard BLAKE3 tree for a fixed byte length. The root operation
// gets ROOT directly: there is no redundant non-root compression of the same
// final chunk block or parent node.
inline Plan make_plan(size_t bytes) {
  Plan plan;
  plan.message_blocks = std::max<size_t>(1, (bytes + 63) / 64);
  const size_t chunks = std::max<size_t>(1, (bytes + 1023) / 1024);
  std::vector<size_t> chunk_sources;
  chunk_sources.reserve(chunks);

  for (size_t chunk = 0; chunk < chunks; ++chunk) {
    const size_t chunk_at = chunk * kChunkBytes;
    const size_t chunk_bytes =
        chunk_at < bytes ? std::min(kChunkBytes, bytes - chunk_at) : 0;
    const size_t blocks = std::max<size_t>(1, (chunk_bytes + 63) / 64);
    size_t previous = kNoSource;
    for (size_t block = 0; block < blocks; ++block) {
      const size_t block_at = block * kBlockBytes;
      const size_t block_len =
          block + 1 == blocks ? chunk_bytes - block_at : kBlockBytes;
      uint32_t flags = 0;
      if (block == 0)
        flags |= kChunkStart;
      if (block + 1 == blocks)
        flags |= kChunkEnd;
      if (chunks == 1 && block + 1 == blocks)
        flags |= kRoot;
      plan.operations.push_back({Operation::Kind::kMessage, chunk * 16 + block,
                                 previous, kNoSource, kNoSource,
                                 uint64_t(chunk), uint32_t(block_len), flags});
      previous = plan.operations.size() - 1;
    }
    chunk_sources.push_back(previous);
  }

  if (chunks == 1) {
    plan.root = chunk_sources[0];
    return plan;
  }

  struct Node {
    bool leaf;
    size_t value;
    size_t left;
    size_t right;
  };
  std::vector<Node> nodes;
  std::vector<size_t> stack;
  for (size_t chunk = 0; chunk < chunks; ++chunk) {
    size_t node = nodes.size();
    nodes.push_back({true, chunk_sources[chunk], kNoSource, kNoSource});
    size_t total = chunk + 1;
    while ((total & 1) == 0) {
      const size_t left = stack.back();
      stack.pop_back();
      const size_t right = node;
      node = nodes.size();
      nodes.push_back({false, kNoSource, left, right});
      total >>= 1;
    }
    stack.push_back(node);
  }

  size_t tree_root = stack.back();
  stack.pop_back();
  while (!stack.empty()) {
    const size_t left = stack.back();
    stack.pop_back();
    const size_t right = tree_root;
    tree_root = nodes.size();
    nodes.push_back({false, kNoSource, left, right});
  }

  std::function<size_t(size_t, bool)> emit = [&](size_t node,
                                                 bool root) -> size_t {
    if (nodes[node].leaf)
      return nodes[node].value;
    const size_t left = emit(nodes[node].left, false);
    const size_t right = emit(nodes[node].right, false);
    plan.operations.push_back({Operation::Kind::kParent, 0, kNoSource, left,
                               right, 0, 64, kParent | (root ? kRoot : 0)});
    return plan.operations.size() - 1;
  };
  plan.root = emit(tree_root, true);
  return plan;
}

// The honest prover's G trace, using native wrapping uint32_t arithmetic.
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

inline std::array<uint32_t, 8>
trace_compress(const std::array<uint32_t, 8> &cv,
               const std::array<uint32_t, 16> &block, uint64_t counter,
               uint32_t block_len, uint32_t flags, uint32_t *trace) {
  uint32_t v[16];
  for (size_t i = 0; i < 8; ++i)
    v[i] = cv[i];
  for (size_t i = 0; i < 4; ++i)
    v[8 + i] = kIV[i];
  v[12] = uint32_t(counter);
  v[13] = uint32_t(counter >> 32);
  v[14] = block_len;
  v[15] = flags;
  for (size_t round = 0; round < 7; ++round) {
    for (size_t j = 0; j < 8; ++j)
      trace_g(v, kGIndices[j], block[kSchedule[round][2 * j]],
              block[kSchedule[round][2 * j + 1]],
              trace + (8 * round + j) * kSumsPerG);
  }
  std::array<uint32_t, 8> out{};
  for (size_t i = 0; i < 8; ++i)
    trace[kSumWords + i] = out[i] = v[i] ^ v[i + 8];
  return out;
}

// The entire trace, operation-major [operations, 344] native words.
inline std::vector<uint32_t> host_trace(const std::vector<uint8_t> &padded,
                                        const Plan &plan) {
  std::vector<uint32_t> trace(plan.operations.size() * kTraceWords);
  std::vector<std::array<uint32_t, 8>> cvs(plan.operations.size());
  const std::array<uint32_t, 8> iv = {kIV[0], kIV[1], kIV[2], kIV[3],
                                      kIV[4], kIV[5], kIV[6], kIV[7]};
  for (size_t i = 0; i < plan.operations.size(); ++i) {
    const Operation &op = plan.operations[i];
    const std::array<uint32_t, 8> &cv =
        op.cv_source == kNoSource ? iv : cvs[op.cv_source];
    std::array<uint32_t, 16> block{};
    if (op.kind == Operation::Kind::kMessage) {
      for (size_t word = 0; word < 16; ++word)
        block[word] = load32(&padded[kBlockBytes * op.block + 4 * word]);
    } else {
      for (size_t word = 0; word < 8; ++word) {
        block[word] = cvs[op.left_source][word];
        block[8 + word] = cvs[op.right_source][word];
      }
    }
    cvs[i] = trace_compress(cv, block, op.counter, op.block_len, op.flags,
                            trace.data() + i * kTraceWords);
  }
  return trace;
}

template <class F> struct TraceValues {
  Expr<F, Bit> sums, cv;
};

// One native trace per call and witness run, shared by the packed generators
// for addition results and chaining values.
template <class F>
TraceValues<F> committed_trace(const Scope &s, Domain<F> &H,
                               const Expr<F, Bit> &padded,
                               std::shared_ptr<const Plan> plan) {
  using Elt = typename F::Elt;
  const F *pf = &H.field();
  const size_t operations = plan->operations.size();
  const auto token = std::make_shared<char>();
  auto family = [&](const std::string &name, size_t offset, size_t per,
                    const Shape &shape) {
    return H.priv(
        Bit{}, s.scoped(name), shape, depends_on(padded),
        [pf, plan, token, offset, per](const std::vector<Elt> &bits) {
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
            memo.words = host_trace(message, *plan);
            memo.run = witness_run;
            memo.call = token.get();
          }
          const size_t n = plan->operations.size() * per;
          PackedBits out{std::vector<uint64_t>((n + 1) / 2, 0)};
          for (size_t i = 0; i < n; ++i) {
            const size_t source = (i / per) * kTraceWords + offset + i % per;
            out.w[i / 2] |= uint64_t(memo.words[source]) << (32 * (i % 2));
          }
          return out;
        });
  };
  return {family("sums", 0, kSumWords, Shape{operations, kSumWords, 32}),
          family("cv", kSumWords, 8, Shape{operations, 8, 32})};
}

template <class F> Expr<F, Bit> word(const Domain<F> &H, uint32_t x) {
  return arith::constant_word(H, x, 32);
}

// A constant word repeated in every compression operation, [n, 32].
template <class F>
Expr<F, Bit> every_operation(const Domain<F> &H, uint32_t x, size_t n) {
  std::vector<size_t> index(32 * n);
  for (size_t i = 0; i < index.size(); ++i)
    index[i] = i % 32;
  return word(H, x).reindex(index).reshape({n, 32});
}

template <class F>
Expr<F, Bit> constant_rows(const Domain<F> &H,
                           const std::vector<uint32_t> &words) {
  std::vector<uint64_t> bits;
  bits.reserve(32 * words.size());
  for (uint32_t word : words)
    for (size_t bit = 0; bit < 32; ++bit)
      bits.push_back((word >> bit) & 1);
  return H.constant(Bit{}, bits, Shape{words.size(), 32});
}

// G on every compression operation at once. SUMS has shape [n, 6, 32].
template <class F>
void g(const Scope &s, std::array<Expr<F, Bit>, 16> &v, const size_t *at,
       const Expr<F, Bit> &x, const Expr<F, Bit> &y, const Expr<F, Bit> &sums) {
  const size_t a = at[0], b = at[1], c = at[2], d = at[3];
  const auto a0 = sums.at(1, 1), c0 = sums.at(1, 2);
  const auto a1 = sums.at(1, 4), c1 = sums.at(1, 5);
  const size_t n = x.dims().at(0);
  arith::assert_sum(a0, {v[a], v[b], x}, sums.at(1, 0).reshape({1, n, 32}),
                    s.name("a0"));
  v[a] = a0;
  v[d] = (v[d] + v[a]).rotate(-16, 1);
  arith::assert_sum(c0, {v[c], v[d]}, s.name("c0"));
  v[c] = c0;
  v[b] = (v[b] + v[c]).rotate(-12, 1);
  arith::assert_sum(a1, {v[a], v[b], y}, sums.at(1, 3).reshape({1, n, 32}),
                    s.name("a1"));
  v[a] = a1;
  v[d] = (v[d] + v[a]).rotate(-8, 1);
  arith::assert_sum(c1, {v[c], v[d]}, s.name("c1"));
  v[c] = c1;
  v[b] = (v[b] + v[c]).rotate(-7, 1);
}

} // namespace internal

namespace host {

// Standard unkeyed BLAKE3 with a 32-byte output.
inline Digest blake3_256(const std::vector<uint8_t> &message) {
  const internal::Plan plan = internal::make_plan(message.size());
  std::vector<uint8_t> padded(64 * plan.message_blocks, 0);
  std::copy(message.begin(), message.end(), padded.begin());
  const std::vector<uint32_t> trace = internal::host_trace(padded, plan);
  Digest out{};
  const size_t at = plan.root * internal::kTraceWords + internal::kSumWords;
  for (size_t i = 0; i < 8; ++i)
    internal::store32(&out[4 * i], trace[at + i]);
  return out;
}

} // namespace host

// BLAKE3-256 of the fixed, byte-aligned message MSG in H.
template <class F>
Expr<F, Bit> blake3_256(const Scope &s, Domain<F> &H, const std::string &name,
                        Expr<F, Bit> msg) {
  static_assert(F::kCharacteristicTwo,
                "BLAKE3 is implemented in a characteristic-two domain");
  msg = msg.flat();
  if (msg.size() % 8 != 0)
    fail("BLAKE3: a message of whole bytes");
  const size_t bytes = msg.size() / 8;
  const auto plan =
      std::make_shared<const internal::Plan>(internal::make_plan(bytes));
  const size_t message_blocks = plan->message_blocks;
  const size_t operations = plan->operations.size();
  const size_t padded_bits = 8 * 64 * message_blocks;
  if (msg.size() < padded_bits) {
    const auto zeros =
        H.constant(Bit{}, std::vector<uint64_t>(padded_bits - msg.size(), 0));
    msg = msg.concat(zeros);
  }
  const auto words = msg.reshape({message_blocks, 16, 32});
  const Scope call = s.scope(name, computes("BLAKE3-256", {bytes}));
  const auto trace = internal::committed_trace(call, H, msg, plan);

  std::vector<uint64_t> iv_bits;
  for (size_t i = 0; i < 8; ++i)
    for (size_t bit = 0; bit < 32; ++bit)
      iv_bits.push_back((internal::kIV[i] >> bit) & 1);
  const auto iv = H.constant(Bit{}, iv_bits, Shape{1, 8, 32});

  Expr<F, Bit> input_cvs;
  Expr<F, Bit> blocks;
  for (size_t i = 0; i < operations; ++i) {
    const internal::Operation &op = plan->operations[i];
    const Expr<F, Bit> input_cv =
        (op.cv_source == internal::kNoSource
             ? Expr<F, Bit>(iv)
             : trace.cv.at(0, op.cv_source).reshape({1, 8, 32}));
    Expr<F, Bit> block =
        op.kind == internal::Operation::Kind::kMessage
            ? words.at(0, op.block).reshape({1, 16, 32})
            : trace.cv.at(0, op.left_source)
                  .reshape({1, 8, 32})
                  .concat(trace.cv.at(0, op.right_source).reshape({1, 8, 32}),
                          1);
    if (i == 0) {
      input_cvs = input_cv;
      blocks = block;
    } else {
      input_cvs = input_cvs.concat(input_cv, 0);
      blocks = blocks.concat(block, 0);
    }
  }

  std::array<Expr<F, Bit>, 16> v;
  for (size_t i = 0; i < 8; ++i)
    v[i] = input_cvs.at(1, i);
  for (size_t i = 0; i < 4; ++i)
    v[8 + i] = internal::every_operation(H, internal::kIV[i], operations);
  std::vector<uint32_t> counter_low, counter_high, block_len, flags;
  counter_low.reserve(operations);
  counter_high.reserve(operations);
  block_len.reserve(operations);
  flags.reserve(operations);
  for (const auto &op : plan->operations) {
    counter_low.push_back(uint32_t(op.counter));
    counter_high.push_back(uint32_t(op.counter >> 32));
    block_len.push_back(op.block_len);
    flags.push_back(op.flags);
  }
  v[12] = internal::constant_rows(H, counter_low);
  v[13] = internal::constant_rows(H, counter_high);
  v[14] = internal::constant_rows(H, block_len);
  v[15] = internal::constant_rows(H, flags);

  for (size_t round = 0; round < 7; ++round) {
    const Scope rs = call.scope("round" + std::to_string(round));
    const auto &schedule = internal::kSchedule[round];
    for (size_t j = 0; j < 8; ++j) {
      const size_t begin = (8 * round + j) * internal::kSumsPerG;
      internal::g(rs.scope("g" + std::to_string(j)), v, internal::kGIndices[j],
                  blocks.at(1, schedule[2 * j]),
                  blocks.at(1, schedule[2 * j + 1]),
                  trace.sums.slice(begin, begin + internal::kSumsPerG, 1));
    }
  }

  Expr<F, Bit> final = (v[0] + v[8]).reshape({operations, 1, 32});
  for (size_t i = 1; i < 8; ++i)
    final = final.concat((v[i] + v[i + 8]).reshape({operations, 1, 32}), 1);
  assert_equal(trace.cv, final, call.name("output"));
  return trace.cv.at(0, plan->root).flat().named(call.scoped("digest"));
}

} // namespace proofs::gordiehowe::lib::blake3

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_LIB_BLAKE3_H_
