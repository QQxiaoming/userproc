cmake_minimum_required(VERSION 3.5)
project(uproc_project C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build the library in lib (will now be SHARED)
add_subdirectory(lib)

find_package(Threads REQUIRED)

# Custom target to build the kernel module in driver using its Makefile
add_custom_target(driver_module
    COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/driver
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/driver
    COMMENT "Building kernel module in driver/ via its Makefile"
)

# Build test executable from test/test.c
add_executable(test_exec test/test.c)
target_include_directories(test_exec PRIVATE ${CMAKE_SOURCE_DIR}/lib/inc ${CMAKE_SOURCE_DIR}/driver)
target_link_libraries(test_exec PRIVATE userproc ${CMAKE_THREAD_LIBS_INIT})

# Make sure the test and driver are built as part of the default build
add_dependencies(test_exec driver_module)
add_custom_target(all_targets DEPENDS userproc test_exec driver_module)
