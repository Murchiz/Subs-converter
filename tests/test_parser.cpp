#include "parser.h"
#include "generator.h"
#include "utils.h"
#include <fstream>
#include <sstream>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <print>
#include <string_view>

namespace fs = std::filesystem;

void test_base64() {
    std::string encoded = "SGVsbG8gV29ybGQ="; // "Hello World"
    std::string decoded = base64_decode(encoded);
    assert(decoded == "Hello World");
    std::println("test_base64 passed.");
}

void test_parse_uri() {
    std::string uri = "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiMTA4MCIsImlkIjoiOTRhYzRjZGEtMTIzNC01Njc4LTlhYmMtZGVmMDExMjIzMzQ0In0=";
    Proxy p = parse_uri(uri);
    assert(std::string_view(p.protocol) == "vmess");
    assert(std::string_view(p.server) == "127.0.0.1");
    assert(p.port == 1080);
    assert(std::string_view(p.uuid) == "94ac4cda-1234-5678-9abc-def011223344");
    
    // Test Hysteria 1 URI
    std::string hy_uri = "hysteria://mytoken@12.34.56.78:12345?peer=my-sni.com&upmbps=50&downmbps=100&alpn=h3&obfs=obfs-type#HysteriaNode";
    Proxy p_hy = parse_uri(hy_uri);
    assert(std::string_view(p_hy.protocol) == "hysteria");
    assert(std::string_view(p_hy.server) == "12.34.56.78");
    assert(p_hy.port == 12345);
    assert(std::string_view(p_hy.uuid) == "mytoken");
    assert(std::string_view(p_hy.sni) == "my-sni.com");
    assert(std::string_view(p_hy.up) == "50");
    assert(std::string_view(p_hy.down) == "100");
    assert(std::string_view(p_hy.alpn) == "h3");
    assert(std::string_view(p_hy.obfs) == "obfs-type");
    assert(std::string_view(p_hy.name) == "HysteriaNode");

    // Test generator output for Hysteria 1
    std::vector<Proxy> list = { p_hy };
    std::string base64_v2ray = gen_v2ray(list);
    std::string raw_v2ray = base64_decode(base64_v2ray);
    assert(raw_v2ray.contains("hysteria://mytoken@12.34.56.78:12345?peer=my-sni.com&obfs=obfs-type&upmbps=50&downmbps=100&alpn=h3#HysteriaNode"));

    std::println("test_parse_uri passed.");
}

void test_parse_json() {
    // 1. Test example.json
    if (fs::exists("example.json")) {
        std::ifstream file("example.json");
        assert(file.is_open());
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::vector<Proxy> proxies = parse_proxies(buffer.str());
        assert(proxies.size() == 1);
        const auto& p = proxies[0];
        assert(std::string_view(p.protocol) == "hysteria2");
        assert(std::string_view(p.server) == "example.com");
        assert(p.port == 47006);
        assert(std::string_view(p.uuid) == "example-uuid-0000-0000-0000-00000000");
        assert(std::string_view(p.sni) == "example.net");
        assert(std::string_view(p.alpn) == "h3");

    }

    // 2. Test fetched_sub.json
    if (fs::exists("fetched_sub.json")) {
        std::ifstream file("fetched_sub.json");
        assert(file.is_open());
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::vector<Proxy> proxies = parse_proxies(buffer.str());
        assert(proxies.size() == 28);
        int hysteria_cnt = 0;
        int vless_cnt = 0;
        for (const auto& p : proxies) {
            std::string_view proto = p.protocol;
            if (proto == "hysteria2" || proto == "hysteria") {
                hysteria_cnt++;
            } else if (proto == "vless") {
                vless_cnt++;
            }
        }
        assert(hysteria_cnt == 14);
        assert(vless_cnt == 14);
    }
    
    std::println("test_parse_json passed.");
}

void test_rules() {
    std::string filename = fs::exists("references/original.json") ? "references/original.json" :
                          (fs::exists("../references/original.json") ? "../references/original.json" : "");
    if (filename.empty()) return;

    std::ifstream file(filename);
    if (!file.is_open()) return;
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    std::vector<Proxy> proxies = parse_proxies(content);
    std::vector<Rule> rules = parse_xray_rules(content);
    
    std::println("Parsed {} rules from original.json:", rules.size());
    for (size_t i = 0; i < rules.size(); i++) {
        std::println(" Rule #{}: outbound={}, domains={}, ips={}, protocols={}, port={}",
                     i, rules[i].outbound, rules[i].domains.size(),
                     rules[i].ips.size(), rules[i].protocols.size(), rules[i].port);
    }
    
    std::string clash = gen_clash(proxies, rules);
    std::string singbox = gen_singbox(proxies, "android", rules);
    
    std::println("Clash rule generation contains DOMAIN-SUFFIX: {}", 
                 clash.contains("DOMAIN-SUFFIX,img.avito.st,DIRECT") ? "YES" : "NO");
    std::println("Clash rule generation contains 255.255.255.255/32: {}", 
                 clash.contains("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve") ? "YES" : "NO");
    std::println("Singbox rule generation contains domain_suffix: {}", 
                 singbox.contains("img.avito.st") ? "YES" : "NO");
    std::println("Singbox rule has no 'type: field': {}", 
                 !singbox.contains("\"type\":\"field\"") ? "YES" : "NO");
    
    assert(clash.contains("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve"));
    assert(!singbox.contains("\"type\":\"field\""));
    std::println("test_rules passed.");
}

void test_clash_to_singbox_and_xray() {
    std::string_view clash_yaml = 
        "mixed-port: 7890\n"
        "proxies:\n"
        "  - name: \"Germany Reality\"\n"
        "    type: vless\n"
        "    server: example.org\n"
        "    port: 47005\n"
        "    uuid: example-uuid-0000-0000-0000-00000000\n"
        "    udp: true\n"
        "    flow: xtls-rprx-vision\n"
        "    tls: true\n"
        "    servername: example.com\n"
        "    client-fingerprint: firefox\n"
        "    reality-opts:\n"
        "      public-key: example-public-key\n"
        "      short-id: 16ee3a5f0387c553\n"
        "  - name: \"US HTTPS Proxy\"\n"
        "    type: https\n"
        "    server: 1.1.1.1\n"
        "    port: 8443\n"
        "    password: mysecret\n"
        "    sni: myproxy.com\n"
        "  - name: \"SS Node\"\n"
        "    type: ss\n"
        "    server: 2.2.2.2\n"
        "    port: 8388\n"
        "    cipher: aes-256-gcm\n"
        "    password: sspass\n"
        "rules:\n"
        "  - DOMAIN-SUFFIX,img.avito.st,REJECT\n"
        "  - IP-CIDR,255.255.255.255/32,DIRECT,no-resolve\n"
        "  - MATCH,Proxy\n";

    std::vector<Proxy> proxies = parse_proxies(clash_yaml);
    assert(proxies.size() == 3);
    assert(std::string_view(proxies[0].protocol) == "vless");
    assert(std::string_view(proxies[0].security) == "reality");
    assert(std::string_view(proxies[0].server) == "example.org");
    assert(proxies[0].port == 47005);
    assert(std::string_view(proxies[0].pbk) == "example-public-key");


    assert(std::string_view(proxies[1].protocol) == "https");
    assert(proxies[1].port == 8443);

    assert(std::string_view(proxies[2].protocol) == "shadowsocks");
    assert(std::string_view(proxies[2].cipher) == "aes-256-gcm");

    std::vector<Rule> rules = parse_xray_rules(clash_yaml);
    assert(rules.size() >= 2);

    // Singbox generation
    std::string sb = gen_singbox(proxies, "android", rules);
    assert(!sb.contains("\"type\": \"https\"")); // NO "type": "https"
    assert(sb.contains("\"type\": \"http\""));   // Translated to "http" with TLS
    assert(sb.contains("\"type\": \"shadowsocks\""));
    assert(sb.contains("\"method\": \"aes-256-gcm\""));
    assert(sb.contains("\"public_key\": \"example-public-key\""));


    // Xray generation
    std::string xray = gen_xray(proxies, "My Profile", rules);
    assert(xray.contains("\"routing\""));
    assert(xray.contains("\"inbounds\""));
    assert(xray.contains("\"outbounds\""));
    assert(xray.contains("\"protocol\": \"vless\""));
    assert(xray.contains("\"security\": \"reality\""));
    assert(xray.contains("\"remarks\": \"My Profile\""));

    std::println("test_clash_to_singbox_and_xray passed.");
}

void test_xray_grpc_roundtrip() {
    std::string filename;
    for (const auto& path : {"reference/original.json", "../reference/original.json", "../../reference/original.json"}) {
        if (fs::exists(path)) {
            filename = path;
            break;
        }
    }
    if (!filename.empty()) {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();

            std::vector<Proxy> proxies = parse_proxies(content);
            assert(proxies.size() == 1);
            assert(std::string_view(proxies[0].protocol) == "vless");
            assert(std::string_view(proxies[0].type) == "grpc");
            assert(std::string_view(proxies[0].path) == "qwen-services-8443");
            assert(std::string_view(proxies[0].sni) == "chat.qwen.ai");
            assert(std::string_view(proxies[0].pbk) == "sm4JzfsMkmDUreMh_2BQQu8IZIrWYja9qgF2mxFvIUo");
            assert(std::string_view(proxies[0].sid) == "BDD9BC8C2A0F70D0");

            std::vector<Rule> rules = parse_xray_rules(content);
            std::string clash_yaml = gen_clash(proxies, rules);
            assert(clash_yaml.contains("grpc-service-name: qwen-services-8443"));

            std::vector<Proxy> re_proxies = parse_proxies(clash_yaml);
            assert(re_proxies.size() == 1);
            assert(std::string_view(re_proxies[0].path) == "qwen-services-8443");
            assert(std::string_view(re_proxies[0].type) == "grpc");

            std::string re_xray = gen_xray(re_proxies, "🇪🇪Эстония 2 test", rules);
            assert(re_xray.contains("\"serviceName\": \"qwen-services-8443\""));

            std::string re_sb = gen_singbox(re_proxies, "android", rules);
            assert(re_sb.contains("\"service_name\": \"qwen-services-8443\""));

            std::println("test_xray_grpc_roundtrip passed.");
        }
    }
}

void test_multi_xray_json_subscription() {
    std::string_view multi_json = 
        "[\n"
        "  {\n"
        "    \"remarks\": \"Server-US\",\n"
        "    \"outbounds\": [\n"
        "      {\n"
        "        \"protocol\": \"vless\",\n"
        "        \"settings\": { \"address\": \"1.1.1.1\", \"port\": 443, \"id\": \"uuid-1\" },\n"
        "        \"streamSettings\": { \"network\": \"ws\", \"security\": \"tls\", \"serverName\": \"us.example.com\" }\n"
        "      },\n"
        "      { \"protocol\": \"freedom\", \"tag\": \"direct\" }\n"
        "    ]\n"
        "  },\n"
        "  {\n"
        "    \"remarks\": \"Server-DE\",\n"
        "    \"outbounds\": [\n"
        "      {\n"
        "        \"protocol\": \"trojan\",\n"
        "        \"settings\": { \"address\": \"2.2.2.2\", \"port\": 8443, \"password\": \"trojan-pass\" },\n"
        "        \"streamSettings\": { \"network\": \"grpc\", \"security\": \"reality\", \"grpcSettings\": { \"serviceName\": \"de-grpc\" }, \"realitySettings\": { \"publicKey\": \"pbk-de\", \"shortId\": \"sid-de\", \"serverName\": \"de.example.com\" } }\n"
        "      }\n"
        "    ]\n"
        "  }\n"
        "]\n";

    std::vector<Proxy> proxies = parse_proxies(multi_json);
    assert(proxies.size() == 2);
    assert(std::string_view(proxies[0].name) == "Server-US");
    assert(std::string_view(proxies[0].protocol) == "vless");
    assert(std::string_view(proxies[0].server) == "1.1.1.1");
    assert(proxies[0].port == 443);

    assert(std::string_view(proxies[1].name) == "Server-DE");
    assert(std::string_view(proxies[1].protocol) == "trojan");
    assert(std::string_view(proxies[1].server) == "2.2.2.2");
    assert(std::string_view(proxies[1].path) == "de-grpc");

    std::string xray_links = gen_v2ray(proxies);
    assert(!xray_links.empty());
    std::string decoded_links = base64_decode(xray_links);
    assert(decoded_links.contains("vless://"));
    assert(decoded_links.contains("trojan://"));
    assert(decoded_links.contains("serviceName=de-grpc"));

    std::println("test_multi_xray_json_subscription passed.");
}

int main() {
    std::println("Running tests...");
    test_base64();
    test_parse_uri();
    test_rules();
    test_clash_to_singbox_and_xray();
    test_xray_grpc_roundtrip();
    test_multi_xray_json_subscription();
    std::println("All tests passed successfully.");
    return 0;
}





