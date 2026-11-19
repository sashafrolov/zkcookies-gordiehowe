// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

// The application-hash policy boundary for zk-cookies.  A policy supplies
// the same 32-byte hash on the circuit and host sides.  State logic is
// otherwise independent of the selected hash.

#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_HASH_H_

#include <array>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include "gf2k/gf2_128.h"
#include "gordiehowe/expr.h"
#include "gordiehowe/lib/blake2s.h"
#include "gordiehowe/lib/blake3.h"
#include "gordiehowe/lib/keccak.h"
#include "gordiehowe/lib/poseidon2b.h"
#include "gordiehowe/lib/sha256.h"
#include "gordiehowe/system.h"
#include "util/crypto.h"

namespace proofs::gordiehowe::examples::zk_cookies::hashes {

using Digest = std::array<uint8_t, 32>;

struct Poseidon2b {
  static constexpr char kId[] = "poseidon2b";
  template <class F>
  static constexpr bool supports = std::is_same_v<F, GF2_128<>>;

  template <class F>
  static Expr<F, Bit> circuit(const Scope &s, Domain<F> &H,
                              const std::string &name,
                              const Expr<F, Bit> &message) {
    static_assert(supports<F>,
                  "zk-cookies Poseidon2b requires the narrow GF2_128 profile");
    return lib::poseidon2b::hash(s, H, name, message);
  }

  static Digest host(const std::vector<uint8_t> &message) {
    return lib::poseidon2b::host::hash(message);
  }
};

struct Blake2s {
  static constexpr char kId[] = "blake2s";
  template <class F> static constexpr bool supports = F::kCharacteristicTwo;

  template <class F>
  static Expr<F, Bit> circuit(const Scope &s, Domain<F> &H,
                              const std::string &name,
                              const Expr<F, Bit> &message) {
    return lib::blake2s::blake2s_256(s, H, name, message);
  }

  static Digest host(const std::vector<uint8_t> &message) {
    return lib::blake2s::host::blake2s_256(message);
  }
};

struct Blake3 {
  static constexpr char kId[] = "blake3";
  template <class F> static constexpr bool supports = F::kCharacteristicTwo;

  template <class F>
  static Expr<F, Bit> circuit(const Scope &s, Domain<F> &H,
                              const std::string &name,
                              const Expr<F, Bit> &message) {
    return lib::blake3::blake3_256(s, H, name, message);
  }

  static Digest host(const std::vector<uint8_t> &message) {
    return lib::blake3::host::blake3_256(message);
  }
};

struct Sha256 {
  static constexpr char kId[] = "sha256";
  template <class F> static constexpr bool supports = F::kCharacteristicTwo;

  template <class F>
  static Expr<F, Bit> circuit(const Scope &s, Domain<F> &H,
                              const std::string &name,
                              const Expr<F, Bit> &message) {
    return Expr<F, Bit>(
        lib::sha256::sha256(s, H, name, lib::keccak::sponge_input(message)));
  }

  static Digest host(const std::vector<uint8_t> &message) {
    ::proofs::SHA256 sha;
    sha.Update(message.data(), message.size());
    Digest out{};
    sha.DigestData(out.data());
    return out;
  }
};

using Default = Poseidon2b;

} // namespace proofs::gordiehowe::examples::zk_cookies::hashes

#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_HASH_H_
