cmake_minimum_required(VERSION 3.18.1)
project(nekosu_native)

add_library(nksu SHARED su.cpp libnksu.cpp)

target_link_libraries(nksu log)
