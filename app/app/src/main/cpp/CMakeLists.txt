cmake_minimum_required(VERSION 3.18.1)
project(nekosu_native)

set(OPENSSL_DIR ${CMAKE_SOURCE_DIR}/third_party/openssl)

add_library(nksu SHARED sigcheck.cpp su.cpp libnksu.cpp)

target_include_directories(nksu PRIVATE ${OPENSSL_DIR}/include)


target_link_libraries(nksu
    log
    ${OPENSSL_DIR}/${ANDROID_ABI}/libssl.a
    ${OPENSSL_DIR}/${ANDROID_ABI}/libcrypto.a
)
