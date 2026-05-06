cmake_minimum_required(VERSION 3.16)
project(tls_protocol LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(MAIN_FILES
src/tools/long_number.cpp
src/tools/memory_pool.cpp
src/algorithm/tls_hash.cpp
src/algorithm/tls_crypto_aes.cpp
src/algorithm/tls_crypto_rsa.cpp
src/algorithm/tls_cert.cpp
src/win32/win32_sockets.cpp
src/tls_record.cpp
src/tls_handshake.cpp
src/tls_common.cpp
)

include_directories("C:/App/OpenSSL/OpenSSL-Win64/include")
link_directories("C:/App/OpenSSL/OpenSSL-Win64/lib/VC/x64/MDd")
set(OPENSSL_TEST_FILES
test/openssl_test/openssl_main.cpp
)

add_executable(tls_main)
target_sources(tls_main PUBLIC ${MAIN_FILES} src/main.cpp)

add_executable(tls_algorithm_test)
target_sources(tls_algorithm_test PUBLIC ${MAIN_FILES} test/algorithm_test.cpp)

add_executable(openssl_test)
target_sources(openssl_test PUBLIC ${OPENSSL_TEST_FILES} ${MAIN_FILES})