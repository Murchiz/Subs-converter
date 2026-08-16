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

void test_rules() {
    std::ifstream file("references/original.json");
    if (!file.is_open()) return;
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    std::vector<Proxy> proxies = parse_proxies(content);
    std::vector<Rule> rules = parse_xray_rules(content);
    
    std::cout << "Parsed " << rules.size() << " rules from original.json:\n";
    for (size_t i = 0; i < rules.size(); i++) {
        std::cout << " Rule #" << i << ": outbound=" << rules[i].outbound
                  << ", domains=" << rules[i].domains.size()
                  << ", ips=" << rules[i].ips.size()
                  << ", protocols=" << rules[i].protocols.size()
                  << ", port=" << rules[i].port << "\n";
    }
    
    std::string clash = gen_clash(proxies, rules);
    std::string singbox = gen_singbox(proxies, "android", rules);
    
    std::cout << "Clash rule generation contains DOMAIN-SUFFIX: " 
              << (clash.find("DOMAIN-SUFFIX,img.avito.st,DIRECT") != std::string::npos ? "YES" : "NO") << "\n";
    std::cout << "Clash rule generation contains 255.255.255.255/32: " 
              << (clash.find("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve") != std::string::npos ? "YES" : "NO") << "\n";
    std::cout << "Singbox rule generation contains domain_suffix: "
              << (singbox.find("img.avito.st") != std::string::npos ? "YES" : "NO") << "\n";
    std::cout << "Singbox rule has no 'type: field': "
              << (singbox.find("\"type\":\"field\"") == std::string::npos ? "YES" : "NO") << "\n";
    
    assert(clash.find("IP-CIDR,255.255.255.255/32,DIRECT,no-resolve") != std::string::npos);
    assert(singbox.find("\"type\":\"field\"") == std::string::npos);
    std::cout << "test_rules passed.\n";
}

void test_clash_to_singbox_and_xray() {
    std::string clash_yaml = 
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
    assert(strcmp(proxies[0].protocol, "vless") == 0);
    assert(strcmp(proxies[0].security, "reality") == 0);
    assert(strcmp(proxies[0].server, "example.org") == 0);
    assert(proxies[0].port == 47005);
    assert(strcmp(proxies[0].pbk, "example-public-key") == 0);

    assert(strcmp(proxies[1].protocol, "https") == 0);
    assert(proxies[1].port == 8443);

    assert(strcmp(proxies[2].protocol, "shadowsocks") == 0);
    assert(strcmp(proxies[2].cipher, "aes-256-gcm") == 0);

    std::vector<Rule> rules = parse_xray_rules(clash_yaml);
    assert(rules.size() >= 2);

    // Singbox generation
    std::string sb = gen_singbox(proxies, "android", rules);
    assert(sb.find("\"type\": \"https\"") == std::string::npos); // NO "type": "https"
    assert(sb.find("\"type\": \"http\"") != std::string::npos);   // Translated to "http" with TLS
    assert(sb.find("\"type\": \"shadowsocks\"") != std::string::npos);
    assert(sb.find("\"method\": \"aes-256-gcm\"") != std::string::npos);
    assert(sb.find("\"public_key\": \"example-public-key\"") != std::string::npos);

    // Xray generation
    std::string xray = gen_xray(proxies, "My Profile", rules);
    assert(xray.find("\"routing\"") != std::string::npos);
    assert(xray.find("\"inbounds\"") != std::string::npos);
    assert(xray.find("\"outbounds\"") != std::string::npos);
    assert(xray.find("\"protocol\": \"vless\"") != std::string::npos);
    assert(xray.find("\"security\": \"reality\"") != std::string::npos);
    assert(xray.find("\"remarks\": \"My Profile\"") != std::string::npos);

    std::cout << "test_clash_to_singbox_and_xray passed.\n";
}

void test_xray_grpc_roundtrip() {
    std::ifstream file("reference/original.json");
    if (!file.is_open()) file.open("../reference/original.json");
    if (!file.is_open()) file.open("../../reference/original.json");
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();

        std::vector<Proxy> proxies = parse_proxies(content);
        assert(proxies.size() == 1);
        assert(strcmp(proxies[0].protocol, "vless") == 0);
        assert(strcmp(proxies[0].type, "grpc") == 0);
        assert(strcmp(proxies[0].path, "qwen-services-8443") == 0);
        assert(strcmp(proxies[0].sni, "chat.qwen.ai") == 0);
        assert(strcmp(proxies[0].pbk, "sm4JzfsMkmDUreMh_2BQQu8IZIrWYja9qgF2mxFvIUo") == 0);
        assert(strcmp(proxies[0].sid, "BDD9BC8C2A0F70D0") == 0);

        std::vector<Rule> rules = parse_xray_rules(content);
        std::string clash_yaml = gen_clash(proxies, rules);
        assert(clash_yaml.find("grpc-service-name: qwen-services-8443") != std::string::npos);

        std::vector<Proxy> re_proxies = parse_proxies(clash_yaml);
        assert(re_proxies.size() == 1);
        assert(strcmp(re_proxies[0].path, "qwen-services-8443") == 0);
        assert(strcmp(re_proxies[0].type, "grpc") == 0);

        std::string re_xray = gen_xray(re_proxies, "🇪🇪Эстония 2 test", rules);
        assert(re_xray.find("\"serviceName\": \"qwen-services-8443\"") != std::string::npos);

        std::string re_sb = gen_singbox(re_proxies, "android", rules);
        assert(re_sb.find("\"service_name\": \"qwen-services-8443\"") != std::string::npos);

        std::cout << "test_xray_grpc_roundtrip passed.\n";
    }
}

void test_multi_xray_json_subscription() {
    std::string multi_json = 
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
    assert(strcmp(proxies[0].name, "Server-US") == 0);
    assert(strcmp(proxies[0].protocol, "vless") == 0);
    assert(strcmp(proxies[0].server, "1.1.1.1") == 0);
    assert(proxies[0].port == 443);

    assert(strcmp(proxies[1].name, "Server-DE") == 0);
    assert(strcmp(proxies[1].protocol, "trojan") == 0);
    assert(strcmp(proxies[1].server, "2.2.2.2") == 0);
    assert(strcmp(proxies[1].path, "de-grpc") == 0);

    std::string xray_links = gen_v2ray(proxies);
    assert(!xray_links.empty());
    std::string decoded_links = base64_decode(xray_links);
    assert(decoded_links.find("vless://") != std::string::npos);
    assert(decoded_links.find("trojan://") != std::string::npos);
    assert(decoded_links.find("serviceName=de-grpc") != std::string::npos);

    std::cout << "test_multi_xray_json_subscription passed.\n";
}

int main() {
    std::cout << "Running tests...\n";
    test_base64();
    test_parse_uri();
    test_rules();
    test_clash_to_singbox_and_xray();
    test_xray_grpc_roundtrip();
    test_multi_xray_json_subscription();
    std::cout << "All tests passed successfully.\n";
    return 0;
}



