#include "parser.h"
#include "generator.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
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
    
    // Test Hysteria 1 URI
    std::string hy_uri = "hysteria://mytoken@12.34.56.78:12345?peer=my-sni.com&upmbps=50&downmbps=100&alpn=h3&obfs=obfs-type#HysteriaNode";
    Proxy p_hy = parse_uri(hy_uri);
    assert(strcmp(p_hy.protocol, "hysteria") == 0);
    assert(strcmp(p_hy.server, "12.34.56.78") == 0);
    assert(p_hy.port == 12345);
    assert(strcmp(p_hy.uuid, "mytoken") == 0);
    assert(strcmp(p_hy.sni, "my-sni.com") == 0);
    assert(strcmp(p_hy.up, "50") == 0);
    assert(strcmp(p_hy.down, "100") == 0);
    assert(strcmp(p_hy.alpn, "h3") == 0);
    assert(strcmp(p_hy.obfs, "obfs-type") == 0);
    assert(strcmp(p_hy.name, "HysteriaNode") == 0);

    // Test generator output for Hysteria 1
    std::vector<Proxy> list = { p_hy };
    std::string base64_v2ray = gen_v2ray(list);
    std::string raw_v2ray = base64_decode(base64_v2ray);
    assert(raw_v2ray.find("hysteria://mytoken@12.34.56.78:12345?peer=my-sni.com&obfs=obfs-type&upmbps=50&downmbps=100&alpn=h3#HysteriaNode") != std::string::npos);

    std::cout << "test_parse_uri passed.\n";
}

void test_parse_json() {
    // 1. Test example.json
    {
        std::ifstream file("example.json");
        assert(file.is_open());
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::vector<Proxy> proxies = parse_proxies(buffer.str());
        assert(proxies.size() == 1);
        const auto& p = proxies[0];
        assert(strcmp(p.protocol, "hysteria2") == 0);
        assert(strcmp(p.server, "example.com") == 0);
        assert(p.port == 47006);
        assert(strcmp(p.uuid, "example-uuid-0000-0000-0000-00000000") == 0);
        assert(strcmp(p.sni, "example.net") == 0);
        assert(strcmp(p.alpn, "h3") == 0);
    }

    // 2. Test fetched_sub.json
    {
        std::ifstream file("fetched_sub.json");
        assert(file.is_open());
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::vector<Proxy> proxies = parse_proxies(buffer.str());
        assert(proxies.size() == 28);
        int hysteria_cnt = 0;
        int vless_cnt = 0;
        for (const auto& p : proxies) {
            if (strcmp(p.protocol, "hysteria2") == 0 || strcmp(p.protocol, "hysteria") == 0) {
                hysteria_cnt++;
            } else if (strcmp(p.protocol, "vless") == 0) {
                vless_cnt++;
            }
        }
        assert(hysteria_cnt == 14);
        assert(vless_cnt == 14);
    }
    
    std::cout << "test_parse_json passed.\n";
}

int main() {
    std::cout << "Running tests...\n";
    test_base64();
    test_parse_uri();
    test_parse_json();
    std::cout << "All tests passed successfully.\n";
    return 0;
}


