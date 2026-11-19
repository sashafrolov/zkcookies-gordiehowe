// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#include "gordiehowe/examples/zk-cookies/zk_cookies_attribution_testing.h"

namespace proofs::gordiehowe::examples::zk_cookies {
TEST(ZkCookiesSingleAttribution, ProofAndServerBinding) {
  testing::attribution_proof(AttributionMode::kSingle);
}
TEST(ZkCookiesSingleAttribution, OriginalSearchSemantics) {
  testing::attribution_search(AttributionMode::kSingle);
}
TEST(ZkCookiesSingleAttribution, LogarithmicSearchDepthAndFlatShift) {
  testing::attribution_depth(AttributionMode::kSingle);
}
TEST(ZkCookiesSingleAttribution, Full128BitUuidEncodingAndLengthOneUpdate) {
  testing::attribution_host_encoding();
}
} // namespace proofs::gordiehowe::examples::zk_cookies
