#include "generator.h"
#include "parser.h"
#include "utils.h"
#include <cassert>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <cstring>
#include <string_view>

static_assert(is_supported_target("xray"));
static_assert(is_supported_target("xray-jsons"));
static_assert(is_supported_target("v2ray-json"));
static_assert(!is_supported_target(""));
static_assert(!is_supported_target("unsupported-target"));

void test_share_links() {
    assert(gen_v2ray({}).empty());
    assert(gen_v2ray({Proxy{}}).empty());

    const std::vector<std::string> protocols = {
        "vless", "trojan", "vmess", "ss", "shadowsocks", "hysteria", "hysteria2", "hy2"
    };
    std::vector<Proxy> proxies;
    for (const auto& protocol : protocols) {
        Proxy p{};
        strcpy(p.protocol, protocol.c_str());
        strcpy(p.name, "Test node");
        strcpy(p.server, "192.0.2.10");
        strcpy(p.uuid, "00000000-0000-0000-0000-000000000001");
        p.port = 443;
        proxies.push_back(p);
        std::string scheme = protocol;
        if (scheme == "shadowsocks") scheme = "ss";
        if (scheme == "hy2") scheme = "hysteria2";
        std::string links = base64_decode(gen_v2ray({p}));
        assert(links.starts_with(scheme + "://"));
        assert(links.ends_with("\n"));
        assert(links.find('\0') == std::string::npos);
    }
    // Decoding the subscription yields a link list without embedded JSON or NULs.
    std::string links = base64_decode(gen_v2ray(proxies));
    assert(links.find('\0') == std::string::npos);
    assert(links.find('{') == std::string::npos);
    std::println("test_share_links passed.");
}

void test_xhttp_share_links() {
    // This combination reproduces the reported Xray validation error if mode
    // is lost: header placement is only valid in packet-up mode.
    const std::string_view config = R"json({
      "remarks": "XHTTP packet up",
      "outbounds": [{
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": "192.0.2.10", "port": 443,
          "users": [{"id": "00000000-0000-0000-0000-000000000001"}]}]},
        "streamSettings": {
          "network": "xhttp", "security": "tls",
          "tlsSettings": {"serverName": "example.com"},
          "xhttpSettings": {
            "host": "example.com", "path": "/upload?a=1&b=2",
            "mode": "packet-up",
            "extra": {"uplinkDataPlacement":"header","uplinkDataKey":"X-Data"}
          }
        }
      }]
    })json";
    Proxy p = parse_xray_json(config);
    assert(std::string_view(p.type) == "xhttp");
    assert(std::string_view(p.mode) == "packet-up");
    assert(std::string_view(p.extra).contains("\"uplinkDataPlacement\":\"header\""));

    for (const char* protocol : {"vless", "trojan"}) {
        strcpy(p.protocol, protocol);
        for (const char* mode : {"packet-up", "stream-up", "stream-one", "auto"}) {
            strcpy(p.mode, mode);
            std::string link = base64_decode(gen_v2ray({p}));
            assert(link.contains("type=xhttp&"));
            assert(link.contains(std::string("mode=") + mode + "&"));
            assert(link.contains("path=%2Fupload%3Fa%3D1%26b%3D2&"));
            assert(link.contains("extra=" + url_encode(p.extra)));
            link.pop_back(); // Strip the subscription line separator.
            Proxy roundtrip = parse_uri(link);
            assert(std::string_view(roundtrip.mode) == mode);
            assert(std::string_view(roundtrip.extra) == p.extra);
            assert(std::string_view(roundtrip.path) == p.path);
            assert(std::string_view(roundtrip.host) == p.host);
            assert(std::string_view(roundtrip.sni) == p.sni);
            if (std::string_view(mode) == "packet-up") {
                std::string json = gen_xray({roundtrip});
                assert(json.contains("\"mode\": \"packet-up\""));
                assert(json.contains("\"uplinkDataPlacement\":\"header\""));
            }
        }
    }

    // Mode must not depend on whether the optional path was supplied.
    p.path[0] = '\0';
    strcpy(p.mode, "packet-up");
    assert(base64_decode(gen_v2ray({p})).contains("mode=packet-up&"));
    // Do not invent a mode for nodes that leave it unspecified.
    p.mode[0] = '\0';
    assert(!base64_decode(gen_v2ray({p})).contains("mode="));

    // Leave the existing gRPC mode/serviceName handling intact.
    strcpy(p.type, "grpc");
    strcpy(p.path, "grpc-service");
    p.extra[0] = '\0';
    assert(base64_decode(gen_v2ray({p})).contains("serviceName=grpc-service&mode=gun"));
    strcpy(p.mode, "multi");
    assert(base64_decode(gen_v2ray({p})).contains("serviceName=grpc-service&mode=multi"));
    std::println("test_xhttp_share_links passed.");
}

static std::string read_fixture(const char* name) {
    std::ifstream input(std::string("tests/reference/") + name);
    assert(input.is_open());
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    const auto last = text.find_last_not_of(" \t\r\n");
    assert(last != std::string::npos);
    text.resize(last + 1);
    return text;
}

void test_upstream_balancer_fidelity() {
    const std::string source = read_fixture("leastload_balancer.json");
    std::vector<Proxy> members;
    std::vector<Balancer> balancers;
    std::vector<Rule> rules;
    parse_subscription(source, members, balancers, rules);
    assert(members.size() == 4);
    assert(balancers.size() == 1);

    // Balancers from a different provider must not depend on the standalone
    // node list, or be rebuilt as leastPing with their original settings lost.
    const Proxy standalone = parse_uri(read_fixture("grpc_reality_uri.txt"));
    assert(std::string_view(standalone.type) == "grpc");
    assert(std::string_view(standalone.path) == "synthetic-grpc");
    assert(std::string_view(standalone.mode) == "gun");
    assert(std::string_view(standalone.security) == "reality");
    assert(std::string_view(standalone.sni) == "example.net");
    assert(gen_xray_jsons({}, balancers) == "[\n" + source + "\n]\n");
    const std::string links = base64_decode(gen_v2ray({standalone}));
    assert(links.starts_with("vless://"));
    assert(links.contains("serviceName=synthetic-grpc&mode=gun"));

    // Neither aggregation with other nodes nor unrelated rules may overwrite
    // an upstream balancer's routing, selectors, strategy or observatory.
    members.push_back(standalone);
    Rule unrelated{};
    strcpy(unrelated.outbound, "block");
    unrelated.domains = {"unrelated.example"};
    rules.push_back(unrelated);
    assert(gen_xray_jsons(members, balancers, rules).starts_with("[\n" + source + ",\n"));
    balancers.push_back(balancers[0]);
    assert(gen_xray_jsons({}, balancers) == "[\n" + source + ",\n" + source + "\n]\n");
    std::println("test_upstream_balancer_fidelity passed.");
}

void test_hysteria2_xray_output() {
    Proxy p = parse_xray_json(read_fixture("hysteria2_xray.json"));
    assert(std::string_view(p.protocol) == "hysteria2");
    assert(std::string_view(p.uuid) == "dummy-auth");
    assert(p.xray_stream_settings.contains("\"enableSessionResumption\": false"));
    assert(p.xray_stream_settings.contains("\"congestion\": \"bbr\""));
    const std::string config = gen_xray({p});
    assert(config.contains("\"protocol\": \"hysteria\""));
    assert(config.contains(p.xray_stream_settings));
    assert(!config.contains("\"vnext\""));
    assert(!config.contains("\"protocol\": \"vless\""));

    Balancer group{};
    strcpy(group.name, "Synthetic group");
    group.proxies = {p.name};
    assert(gen_xray_jsons({p}, {group}).contains(p.xray_stream_settings));

    // URI and non-Xray inputs do not have a preserved stream. Synthesize the
    // native Xray schema rather than writing a VLESS outbound or TCP transport.
    for (const char* alias : {"hysteria2", "hy2"}) {
        p = parse_uri("hysteria2://dummy-auth@192.0.2.91:443?sni=example.com#Synthetic");
        strcpy(p.protocol, alias);
        assert(p.xray_stream_settings.empty());
        const auto generated = gen_xray({p});
        assert(generated.contains("\"protocol\": \"hysteria\""));
        assert(generated.contains("\"network\": \"hysteria\""));
        assert(generated.contains("\"version\": 2"));
        assert(generated.contains("\"auth\": \"dummy-auth\""));
        assert(generated.contains("\"security\": \"tls\""));
        assert(generated.contains("\"alpn\": [\"h3\"]"));
    }
    strcpy(p.protocol, "hysteria");
    bool rejected = false;
    try { (void)gen_xray({p}); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected); // Xray supports Hysteria 2, not Hysteria 1.
    assert(base64_decode(gen_v2ray({p})).starts_with("hysteria://"));
    std::println("test_hysteria2_xray_output passed.");
}

void test_json_object_extraction() {
    // Nested same-name members and braces/escaped quotes inside strings must
    // not affect locating and preserving a top-level streamSettings object.
    const std::string_view object = R"({"auth":"escaped \" } { \\ end","nested":{"value":2}})";
    const std::string json = "{\"other\":{\"streamSettings\":{}},\"streamSettings\":" +
                             std::string(object) + ",\"tail\":true}";
    assert(json_extract_object(json, "streamSettings") == object);
    assert(json_extract_object(json, "absent").empty());
    assert(json_extract_object("{\"streamSettings\":null}", "streamSettings").empty());
    assert(json_extract_object("{\"streamSettings\":{", "streamSettings").empty());
    std::println("test_json_object_extraction passed.");
}

void test_vless_encryption() {
    const std::string pq_encryption = "mlkem768x25519plus.native.0rtt.dummy-key-for-test";
    const std::string config = std::format(R"json({{
      "remarks": "PQ-VLESS",
      "outbounds": [{{
        "tag": "proxy",
        "protocol": "vless",
        "settings": {{
          "vnext": [{{
            "address": "example.com",
            "port": 443,
            "users": [{{
              "id": "40688376-ebc9-4782-8f72-1db90fbfe66d",
              "encryption": "{}",
              "flow": "xtls-rprx-vision"
            }}]
          }}]
        }},
        "streamSettings": {{
          "network": "tcp",
          "security": "reality",
          "realitySettings": {{
            "serverName": "example.com",
            "publicKey": "dummy-pbk",
            "fingerprint": "firefox"
          }}
        }}
      }}]
    }})json", pq_encryption);

    Proxy p = parse_xray_json(config);
    assert(std::string_view(p.protocol) == "vless");
    assert(std::string_view(p.cipher) == pq_encryption);

    // Test gen_share_links / gen_v2ray
    std::string b64 = gen_v2ray({p});
    std::string link = base64_decode(b64);
    assert(link.contains("encryption=" + pq_encryption + "&"));

    // Roundtrip via parse_uri
    if (link.back() == '\n') link.pop_back();
    Proxy p_from_link = parse_uri(link);
    assert(std::string_view(p_from_link.cipher) == pq_encryption);

    // Test gen_xray output preserves encryption
    std::string json_out = gen_xray({p});
    assert(json_out.contains("\"encryption\": \"" + pq_encryption + "\""));

    // Test gen_clash preserves encryption
    std::string clash_out = gen_clash({p}, {});
    assert(clash_out.contains("encryption: \"" + pq_encryption + "\""));

    // Roundtrip via parse_clash_yaml
    std::vector<Proxy> p_from_clash = parse_proxies(clash_out);
    assert(!p_from_clash.empty());
    assert(std::string_view(p_from_clash[0].cipher) == pq_encryption);

    // Test default "none" encryption when empty or "none"
    Proxy p_none{};
    strcpy(p_none.protocol, "vless");
    strcpy(p_none.server, "example.com");
    strcpy(p_none.uuid, "40688376-ebc9-4782-8f72-1db90fbfe66d");
    p_none.port = 443;
    std::string none_link = base64_decode(gen_v2ray({p_none}));
    assert(none_link.contains("encryption=none&"));
    std::string none_json = gen_xray({p_none});
    assert(none_json.contains("\"encryption\": \"none\""));

    std::println("test_vless_encryption passed.");
}

int main() {
    test_vless_encryption();
    test_share_links();
    test_xhttp_share_links();
    test_upstream_balancer_fidelity();
    test_hysteria2_xray_output();
    test_json_object_extraction();
}
