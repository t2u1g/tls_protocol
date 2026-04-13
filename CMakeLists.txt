cmake_minimum_required(VERSION 3.16)
project(tls_protocol LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(MAIN_FILES
src/algorithm/tls_hash.cpp
src/algorithm/tls_crypto_aes.cpp
src/win32/win32_sockets.cpp
src/tls_record.cpp
)

add_executable(tls_main)
target_sources(tls_main PUBLIC ${MAIN_FILES} src/main.cpp)

add_executable(tls_sha_test)
target_sources(tls_sha_test PUBLIC ${MAIN_FILES} test/sha_test.cpp)