cmake_minimum_required(VERSION 3.10)
project(SubBridge VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable secure CRT template overloads (must be before any standard header includes)
add_compile_definitions(_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1)

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

# Parser test
set(TEST_SOURCES_PARSER
    tests/test_parser.cpp
    src/globals.cpp
    src/utils.cpp
    src/parser.cpp
    src/generator.cpp
)
add_executable(test_parser ${TEST_SOURCES_PARSER})
add_test(NAME ParserTest COMMAND test_parser)

# YAML test
set(TEST_SOURCES_YAML
    tests/test_yaml.cpp
    src/globals.cpp
    src/utils.cpp
    src/parser.cpp
    src/generator.cpp
)
add_executable(test_yaml ${TEST_SOURCES_YAML})
add_test(NAME YamlTest COMMAND test_yaml)

# Python YAML test (run via custom test command using python)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME PythonYamlTest COMMAND Python3::Interpreter ${CMAKE_SOURCE_DIR}/tests/test_yaml.py)
    set_tests_properties(PythonYamlTest PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

# Copy test fixtures from private references (done externally); 
# fixtures should exist in: example.json fetched_sub.json references/original.json reference/meta.yaml
