cmake_minimum_required(VERSION 3.16)
project(ascon128_impl C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(ascon
    src/ascon_permutation.c
    src/ascon_aead128.c
    src/ascon_bytes.c
    src/ascon_api.c
)

target_include_directories(ascon PUBLIC include)

target_compile_options(ascon PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()

add_executable(test_permutation tests/test_permutation.c)
target_link_libraries(test_permutation PRIVATE ascon)
add_test(NAME permutation COMMAND test_permutation)

add_executable(test_aead128 tests/test_aead128.c)
target_link_libraries(test_aead128 PRIVATE ascon)
add_test(NAME aead128 COMMAND test_aead128)

add_executable(test_bytes_api tests/test_bytes_api.c)
target_link_libraries(test_bytes_api PRIVATE ascon)
add_test(NAME bytes_api COMMAND test_bytes_api)

add_executable(test_vectors tests/test_vectors.c)
target_link_libraries(test_vectors PRIVATE ascon)
add_test(NAME vectors COMMAND test_vectors)

add_executable(test_fuzz_harness tests/test_fuzz_harness.c)
target_link_libraries(test_fuzz_harness PRIVATE ascon)
add_test(NAME fuzz_harness COMMAND test_fuzz_harness)

add_executable(demo_aead128 examples/demo_aead128.c)
target_link_libraries(demo_aead128 PRIVATE ascon)
