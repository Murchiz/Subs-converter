cmake_minimum_required(VERSION 3.10)
if(DEFINED PROJECT_VERSION)
    set(SUB_BRIDGE_VER ${PROJECT_VERSION})
else()
    set(SUB_BRIDGE_VER "1.0.0")
endif()

project(SubBridge
    VERSION ${SUB_BRIDGE_VER}
    DESCRIPTION "SubBridge - Local Proxy Subscription Converter & Aggregator"
    LANGUAGES CXX
)

if(WIN32)
    enable_language(RC)
endif()

# Project Metadata
set(PROJECT_COMPANY_NAME "Murchiz" CACHE STRING "Company/Author Name")
set(PROJECT_COPYRIGHT "Copyright (c) 2026 Murchiz. Licensed under MIT." CACHE STRING "Copyright notice")
set(PROJECT_DESCRIPTION "${PROJECT_DESCRIPTION}" CACHE STRING "Application description")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable secure CRT template overloads (must be before any standard header includes)
add_compile_definitions(_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1)
add_compile_definitions(SUB_BRIDGE_VERSION="${SUB_BRIDGE_VER}")

include_directories(include)

if(WIN32)
    # Windows specific libraries
    link_libraries(ws2_32 winhttp advapi32)
    if(MSVC)
        add_compile_options("$<$<CONFIG:Release>:/O2;/Ob2;/Oi;/Ot;/Oy;/GL;/GF;/Gy;/Gw;/fp:fast>")
        add_link_options("$<$<CONFIG:Release>:/LTCG;/OPT:REF;/OPT:ICF;/INCREMENTAL:NO>")
        add_compile_options("$<$<CONFIG:Debug>:/Zi;/Od;/RTC1;/MDd>")
    endif()
else()
    find_package(CURL REQUIRED)
    link_libraries(CURL::libcurl)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options("$<$<CONFIG:Release>:-O3;-flto;-fPIE>")
        add_link_options("$<$<CONFIG:Release>:-flto;-pie>")
        add_compile_options("$<$<CONFIG:Debug>:-g;-O0>")
    endif()
endif()

set(SOURCES
    src/globals.cpp
    src/utils.cpp
    src/parser.cpp
    src/generator.cpp
    src/server.cpp
    src/main.cpp
)

if(WIN32)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/res/version.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/version.rc
        @ONLY
    )
    list(APPEND SOURCES ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
endif()

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
