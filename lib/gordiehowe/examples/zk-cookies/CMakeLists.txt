
# The zk-cookies credential-state relation: BLAKE2s state logic in H and two
# ML-DSA-44 signature checks split between H and the native ML-DSA domain A.
gordiehowe_add_test(zk_cookies_state_test zk_cookies_blake2s_test.cc
                    SETS rom_ml_dsa qrom_ml_dsa)
target_link_libraries(zk_cookies_state_test ml_dsa sha3 OpenSSL::Crypto)

# The bench executable (bench/cli.h), in the build tree's bench/. The
# compiled relation's state-history shape is selected by --history-length.
gordiehowe_add_bench(zk_cookies_state_bench
                     SETS rom_ml_dsa qrom_ml_dsa)
target_link_libraries(zk_cookies_state_bench ml_dsa sha3 OpenSSL::Crypto)
