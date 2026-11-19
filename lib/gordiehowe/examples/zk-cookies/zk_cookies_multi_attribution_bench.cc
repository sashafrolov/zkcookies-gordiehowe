// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#include "gordiehowe/examples/zk-cookies/zk_cookies_bench.h"

int main(int argc, char **argv) {
  namespace app = proofs::gordiehowe::examples::zk_cookies::benchmark;
  return app::main<app::Kind::kMultiAttribution>(argc, argv);
}
