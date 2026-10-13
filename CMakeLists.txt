cmake_minimum_required(VERSION 3.20)
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
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Require the actual standard library facilities we use, rather than adding
# non-standard replacements in namespace std on incomplete implementations.
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
    #include <format>
    #include <print>
    #include <string_view>
    int main() {
        static_assert(std::string_view{\"C++23\"}.contains(\"23\"));
        std::println(\"{}\", std::format(\"{}\", 23));
    }
" SUB_BRIDGE_HAS_CXX23_LIBRARY)
if(NOT SUB_BRIDGE_HAS_CXX23_LIBRARY)
    message(FATAL_ERROR "A C++23 standard library with <format>, <print>, and string_view::contains is required.")
endif()

if(MSVC)
    add_compile_options(/permissive- /Zc:__cplusplus)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-pedantic-errors)
endif()

# Enable secure CRT template overloads (must be before any standard header includes)
add_compile_definitions(_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1)
add_compile_definitions(SUB_BRIDGE_VERSION="${SUB_BRIDGE_VER}")
# SOURCE_DATE_EPOCH is honored when supplied by reproducible build environments.
string(TIMESTAMP SUB_BRIDGE_BUILD_TIME "%Y-%m-%d %H:%M:%S UTC" UTC)
add_compile_definitions(SUB_BRIDGE_BUILD_TIME="${SUB_BRIDGE_BUILD_TIME}")

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
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            add_compile_options("$<$<CONFIG:Release>:-O3;-flto=auto;-fPIE>")
            add_link_options("$<$<CONFIG:Release>:-flto=auto;-pie>")
        else()
            add_compile_options("$<$<CONFIG:Release>:-O3;-flto;-fPIE>")
            add_link_options("$<$<CONFIG:Release>:-flto;-pie>")
        endif()
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
set_tests_properties(ParserTest PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Xray generation and transport regression tests
add_executable(test_xray
    tests/test_xray.cpp
    src/globals.cpp
    src/utils.cpp
    src/parser.cpp
    src/generator.cpp
)
add_test(NAME XrayTest COMMAND test_xray)
set_tests_properties(XrayTest PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

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
set_tests_properties(YamlTest PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

if(UNIX)
    add_executable(test_http_targets
        tests/test_http_targets.cpp
        src/globals.cpp
        src/utils.cpp
        src/parser.cpp
        src/generator.cpp
        src/server.cpp
    )
    add_test(NAME HttpTargetTest COMMAND test_http_targets)
    set_tests_properties(HttpTargetTest PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

# Assertions must run in Release/CI builds too, not just Debug.
foreach(test_target IN ITEMS test_parser test_xray test_yaml test_http_targets)
    if(NOT TARGET ${test_target})
        continue()
    endif()
    if(MSVC)
        target_compile_options(${test_target} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${test_target} PRIVATE -UNDEBUG)
    endif()
endforeach()

# Python YAML test (run via custom test command using python)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME PythonYamlTest COMMAND Python3::Interpreter ${CMAKE_SOURCE_DIR}/tests/test_yaml.py)
    set_tests_properties(PythonYamlTest PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME XrayFidelityTest COMMAND Python3::Interpreter
        ${CMAKE_SOURCE_DIR}/tests/test_xray_fidelity.py $<TARGET_FILE:sub_bridge>)
endif()

# Ensure test fixtures are copied to build directory for direct binary execution
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/example.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/fetched_sub.json DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/references DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/tests/reference DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
