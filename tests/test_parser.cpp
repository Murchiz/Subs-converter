#include "parser.h"
#include "utils.h"
#include <iostream>
#include <cassert>
#include <string.h>

void test_base64() {
    std::string encoded = "SGVsbG8gV29ybGQ="; // "Hello World"
    std::string decoded = base64_decode(encoded);
    assert(decoded == "Hello World");
    std::cout << "test_base64 passed.\n";
}

void test_parse_uri() {
    std::string uri = "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiMTA4MCIsImlkIjoiOTRhYzRjZGEtMTIzNC01Njc4LTlhYmMtZGVmMDExMjIzMzQ0In0=";
    Proxy p = parse_uri(uri);
    assert(strcmp(p.protocol, "vmess") == 0);
    assert(strcmp(p.server, "127.0.0.1") == 0);
    assert(p.port == 1080);
    assert(strcmp(p.uuid, "94ac4cda-1234-5678-9abc-def011223344") == 0);
    std::cout << "test_parse_uri passed.\n";
}

int main() {
    std::cout << "Running tests...\n";
    test_base64();
    test_parse_uri();
    std::cout << "All tests passed successfully.\n";
    return 0;
}
