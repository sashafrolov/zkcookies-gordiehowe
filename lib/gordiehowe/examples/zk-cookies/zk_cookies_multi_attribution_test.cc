// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
#include "gordiehowe/examples/zk-cookies/zk_cookies_attribution_testing.h"

namespace proofs::gordiehowe::examples::zk_cookies {
TEST(ZkCookiesMultiAttribution, ProofAndServerBinding) {
  testing::attribution_proof(AttributionMode::kMulti);
}
TEST(ZkCookiesMultiAttribution, OriginalSearchSemantics) {
  testing::attribution_search(AttributionMode::kMulti);
}
TEST(ZkCookiesMultiAttribution, LogarithmicSearchDepthAndFlatShift) {
  testing::attribution_depth(AttributionMode::kMulti);
}
TEST(ZkCookiesMultiAttribution, Full128BitUuidEncodingAndLengthOneUpdate) {
  testing::attribution_host_encoding();
}
} // namespace proofs::gordiehowe::examples::zk_cookies
