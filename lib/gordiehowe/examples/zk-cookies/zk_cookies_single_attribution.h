// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_SINGLE_ATTRIBUTION_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_SINGLE_ATTRIBUTION_H_

#include "gordiehowe/examples/zk-cookies/zk_cookies_attribution.h"

namespace proofs::gordiehowe::examples::zk_cookies {
template <template <class> class F>
using SingleAttributionStatement = AttributionStatement<F>;
template <template <class> class F>
using SingleAttributionWitness = AttributionWitness<F>;
using SingleAttributionConfig = AttributionConfig;

// HISTORY_LENGTH counts attribution values; IP history defaults to five.
template <class P, class Hash = hashes::Default>
auto zk_cookies_single_attribution(
    const mldsa::Env<P> &env, size_t history_length,
    size_t ip_history_length = 5, const AttributionConfig &config = {},
    const BuildOptions &build = {}) {
  return attribution<P, Hash>(env, AttributionMode::kSingle, history_length,
                              ip_history_length, config, build);
}
} // namespace proofs::gordiehowe::examples::zk_cookies
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_SINGLE_ATTRIBUTION_H_
