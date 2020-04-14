cmake_minimum_required (VERSION 2.6)
project (jjson_test C)

if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -pedantic -Wall -g")
endif()

add_library(jjson jjson.c)
add_executable(jjson_test test.c)
target_link_libraries(jjson_test jjson)
