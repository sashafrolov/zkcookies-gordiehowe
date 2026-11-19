// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#ifndef PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_MULTI_ATTRIBUTION_BUILDERS_H_
#define PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_MULTI_ATTRIBUTION_BUILDERS_H_
#include "gordiehowe/examples/zk-cookies/zk_cookies_multi_attribution.h"
#include "gordiehowe/examples/zk-cookies/zk_cookies_attribution_builders.h"

namespace proofs::gordiehowe::examples::zk_cookies {
inline AttributionStatement<Value> multi_attribution_statement(
    const std::vector<uint8_t> &pk, const host::AttributionOutputs &outputs) {
  return update_statement<AttributionStatement<Value>>(pk, outputs);
}
} // namespace proofs::gordiehowe::examples::zk_cookies
#endif // PRIVACY_PROOFS_ZK_LIB_GORDIEHOWE_EXAMPLES_ZK_COOKIES_MULTI_ATTRIBUTION_BUILDERS_H_
