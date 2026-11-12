# Copyright 2026 Chad Sharp and Paul Grubbs
# SPDX-License-Identifier: Apache-2.0
proofs_add_tests(ligero_test)

add_executable(ligero_phase_bench ligero_phase_bench.cc)
target_link_libraries(ligero_phase_bench util pthread)
set_target_properties(ligero_phase_bench PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bench)
