cmake_minimum_required(VERSION 3.5)
project(userproc_lib C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(userproc SHARED
    src/userproc.c
)

set_target_properties(userproc PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(userproc
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/inc ${CMAKE_CURRENT_SOURCE_DIR}/../driver
)

find_package(Threads REQUIRED)
