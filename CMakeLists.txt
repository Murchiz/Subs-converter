cmake_minimum_required(VERSION 3.10)
project(SubBridge VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(include)

# Windows specific libraries
link_libraries(ws2_32 winhttp advapi32)

set(SOURCES
    src/globals.cpp
    src/utils.cpp
    src/parser.cpp
    src/generator.cpp
    src/server.cpp
    src/main.cpp
)

add_executable(sub_bridge ${SOURCES})

# Testing
enable_testing()

set(TEST_SOURCES
    tests/test_parser.cpp
    src/globals.cpp
    src/utils.cpp
    src/parser.cpp
    src/generator.cpp
)

add_executable(test_parser ${TEST_SOURCES})
add_test(NAME ParserTest COMMAND test_parser)
