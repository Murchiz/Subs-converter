#include "parser.h"
#include "utils.h"
#include <cstring>

Proxy parse_uri(const std::string& uri) {
    Proxy p = {0};
    size_t scheme_pos = uri.find("://");
    if (scheme_pos == std::string::npos) return p;
    std::string scheme = uri.substr(0, scheme_pos);
    strncpy_s(p.protocol, sizeof(p.protocol), scheme.c_str(), sizeof(p.protocol) - 1);

    if (scheme == "vless" || scheme == "trojan" || scheme == "hysteria2" || scheme == "hy2" || scheme == "hysteria") {
        if (scheme == "hy2") {
            strncpy_s(p.protocol, sizeof(p.protocol), "hysteria2", sizeof(p.protocol) - 1);
        }
        size_t at_pos = uri.find('@', scheme_pos + 3);
        size_t hostport_start = scheme_pos + 3;
        if (at_pos != std::string::npos) {
            strncpy_s(p.uuid, sizeof(p.uuid), uri.substr(scheme_pos + 3, at_pos - (scheme_pos + 3)).c_str(), sizeof(p.uuid) - 1);
            hostport_start = at_pos + 1;
        }

        size_t q_pos = uri.find('?', hostport_start);
        size_t hash_pos = uri.find('#', hostport_start);
        if (hash_pos == std::string::npos) hash_pos = uri.length();
        size_t hostport_end = (q_pos != std::string::npos && q_pos < hash_pos) ? q_pos : hash_pos;

        std::string hostport = uri.substr(hostport_start, hostport_end - hostport_start);
        size_t colon_pos = hostport.find(':');
        if (colon_pos != std::string::npos) {
            strncpy_s(p.server, sizeof(p.server), hostport.substr(0, colon_pos).c_str(), sizeof(p.server) - 1);
            p.port = std::stoi(hostport.substr(colon_pos + 1));
        }

        if (hash_pos < uri.length()) {
            std::string name_decoded = url_decode(uri.substr(hash_pos + 1));
            strncpy_s(p.name, sizeof(p.name), name_decoded.c_str(), sizeof(p.name) - 1);
        }

        if (q_pos != std::string::npos && q_pos < hash_pos) {
            std::string qs = uri.substr(q_pos + 1, hash_pos - (q_pos + 1));
            size_t start = 0;
            while (start < qs.length()) {
                size_t amp = qs.find('&', start);
                if (amp == std::string::npos) amp = qs.length();
                std::string kv = qs.substr(start, amp - start);
                size_t eq = kv.find('=');
                if (eq != std::string::npos) {
                    std::string k = kv.substr(0, eq);
                    std::string v = url_decode(kv.substr(eq + 1));
                    while (!v.empty() && (v.back() == '\r' || v.back() == '\n' || v.back() == ' ')) v.pop_back();

                    if (k == "type") { strncpy_s(p.type, sizeof(p.type), v.c_str(), sizeof(p.type) - 1); }
                    else if (k == "security") { strncpy_s(p.security, sizeof(p.security), v.c_str(), sizeof(p.security) - 1); }
                    else if (k == "sni" || k == "peer") { strncpy_s(p.sni, sizeof(p.sni), v.c_str(), sizeof(p.sni) - 1); }
                    else if (k == "fp") { strncpy_s(p.fp, sizeof(p.fp), v.c_str(), sizeof(p.fp) - 1); }
                    else if (k == "pbk") { strncpy_s(p.pbk, sizeof(p.pbk), v.c_str(), sizeof(p.pbk) - 1); }
                    else if (k == "sid") { strncpy_s(p.sid, sizeof(p.sid), v.c_str(), sizeof(p.sid) - 1); }
                    else if (k == "flow") { strncpy_s(p.flow, sizeof(p.flow), v.c_str(), sizeof(p.flow) - 1); }
                    else if (k == "path") { strncpy_s(p.path, sizeof(p.path), v.c_str(), sizeof(p.path) - 1); }
                    else if (k == "host") { strncpy_s(p.host, sizeof(p.host), v.c_str(), sizeof(p.host) - 1); }
                    else if (k == "alpn") { strncpy_s(p.alpn, sizeof(p.alpn), v.c_str(), sizeof(p.alpn) - 1); }
                    else if (k == "serviceName") { strncpy_s(p.path, sizeof(p.path), v.c_str(), sizeof(p.path) - 1); }
                    else if (k == "mode") { strncpy_s(p.mode, sizeof(p.mode), v.c_str(), sizeof(p.mode) - 1); }
                    else if (k == "encryption") { strncpy_s(p.cipher, sizeof(p.cipher), v.c_str(), sizeof(p.cipher) - 1); }
                    else if (k == "headerType") { strncpy_s(p.type, sizeof(p.type), v.c_str(), sizeof(p.type) - 1); }
                    else if (k == "obfs") { strncpy_s(p.obfs, sizeof(p.obfs), v.c_str(), sizeof(p.obfs) - 1); }
                    else if (k == "obfs-password" || k == "obfs-param" || k == "obfsParam" || k == "obfsparam") { strncpy_s(p.obfs_pass, sizeof(p.obfs_pass), v.c_str(), sizeof(p.obfs_pass) - 1); }
                    else if (k == "up" || k == "upmbps") { strncpy_s(p.up, sizeof(p.up), v.c_str(), sizeof(p.up) - 1); }
                    else if (k == "down" || k == "downmbps") { strncpy_s(p.down, sizeof(p.down), v.c_str(), sizeof(p.down) - 1); }
                    else if (k == "auth") { strncpy_s(p.uuid, sizeof(p.uuid), v.c_str(), sizeof(p.uuid) - 1); }
                    else if (k == "extra") {
                        strncpy_s(p.extra, sizeof(p.extra), v.c_str(), sizeof(p.extra) - 1);
                    }
                    else if (k != "type" && k != "security" && k != "sni" && k != "peer" && k != "fp" && k != "pbk" && k != "sid" && k != "host" && k != "path" && k != "alpn" && k != "serviceName" && k != "mode" && k != "flow" && k != "uuid" && k != "port" && k != "name" && k != "encryption" && k != "headerType" && k != "obfs" && k != "obfs-password" && k != "obfs-param" && k != "obfsParam" && k != "obfsparam" && k != "up" && k != "upmbps" && k != "down" && k != "downmbps" && k != "auth") {
                        std::string kebab;
                        for (char c : k) {
                            if (isupper(c)) { kebab += '-'; kebab += tolower(c); }
                            else kebab += c;
                        }
                        std::string v_json;
                        if (v == "true" || v == "false" || (v.length() > 0 && v.find_first_not_of("0123456789-") == std::string::npos)) {
                            v_json = v;
                        } else {
                            v_json = "\"" + sanitize_json(v) + "\"";
                        }
                        
                        if (p.extra[0] == '\0') {
                            strncpy_s(p.extra, sizeof(p.extra), "{", sizeof(p.extra) - 1);
                        } else {
                            p.extra[strlen(p.extra) - 1] = ',';
                        }
                        std::string kv_json = "\"" + kebab + "\":" + v_json + "}";
                        strncat_s(p.extra, sizeof(p.extra), kv_json.c_str(), sizeof(p.extra) - strlen(p.extra) - 1);
                    }
                }
                start = amp + 1;
            }
        }
    } else if (scheme == "vmess") {
        std::string b64 = uri.substr(scheme_pos + 3);
        std::string jstr = base64_decode(b64);
        auto get_json_str = [&](const std::string& key) {
            size_t kp = jstr.find("\"" + key + "\":");
            if (kp == std::string::npos) return std::string("");
            size_t q1 = jstr.find("\"", kp + key.length() + 2);
            if (q1 == std::string::npos) return std::string("");
            size_t q2 = jstr.find("\"", q1 + 1);
            if (q2 == std::string::npos) return std::string("");
            return decode_json_string(jstr.substr(q1 + 1, q2 - q1 - 1));
        };
        auto get_json_int = [&](const std::string& key) {
            size_t kp = jstr.find("\"" + key + "\":");
            if (kp == std::string::npos) return 0;
            size_t st = kp + key.length() + 2;
            while (st < jstr.length() && (jstr[st] == ' ' || jstr[st] == ':')) st++;
            int v = 0;
            while (st < jstr.length() && isdigit(jstr[st])) {
                v = v * 10 + (jstr[st] - '0');
                st++;
            }
            return v;
        };
        std::string ps_decoded = get_json_str("ps");
        strncpy_s(p.name, sizeof(p.name), ps_decoded.c_str(), sizeof(p.name) - 1);
        std::string server_decoded = get_json_str("add");
        strncpy_s(p.server, sizeof(p.server), server_decoded.c_str(), sizeof(p.server) - 1);
        p.port = get_json_int("port");
        if (p.port == 0) {
            std::string ps = get_json_str("port");
            if (!ps.empty()) p.port = std::stoi(ps);
        }
        std::string uuid_decoded = get_json_str("id");
        strncpy_s(p.uuid, sizeof(p.uuid), uuid_decoded.c_str(), sizeof(p.uuid) - 1);
        std::string type_decoded = get_json_str("net");
        strncpy_s(p.type, sizeof(p.type), type_decoded.c_str(), sizeof(p.type) - 1);
        std::string security_decoded = get_json_str("tls");
        strncpy_s(p.security, sizeof(p.security), security_decoded.c_str(), sizeof(p.security) - 1);
        std::string path_decoded = get_json_str("path");
        strncpy_s(p.path, sizeof(p.path), path_decoded.c_str(), sizeof(p.path) - 1);
        std::string host_decoded = get_json_str("host");
        strncpy_s(p.host, sizeof(p.host), host_decoded.c_str(), sizeof(p.host) - 1);
        std::string sni_decoded = get_json_str("sni");
        strncpy_s(p.sni, sizeof(p.sni), sni_decoded.c_str(), sizeof(p.sni) - 1);
        if (p.security[0] == 0) {
            std::string tls_str = get_json_str("tls");
            if (tls_str == "tls") {
                strncpy_s(p.security, sizeof(p.security), "tls", sizeof(p.security) - 1);
            }
        }
    }
    return p;
}

Proxy parse_xray_json(const std::string& obj) {
    Proxy p = {0};
    if (obj.find("\"outbounds\"") == std::string::npos) return p;
    
    std::string remarks = json_extract_string(obj, "remarks");
    std::string remarks_decoded = url_decode(remarks);
    strncpy_s(p.name, sizeof(p.name), remarks_decoded.c_str(), sizeof(p.name) - 1);
    
    size_t proxy_pos = obj.find("\"tag\": \"proxy\"");
    if (proxy_pos == std::string::npos) proxy_pos = obj.find("\"tag\":\"proxy\"");
    if (proxy_pos == std::string::npos) return p;
    
    size_t start = obj.rfind("{", proxy_pos);
    if (start == std::string::npos) return p;
    int depth = 0;
    size_t end = start;
    for (size_t i = start; i < obj.length(); i++) {
        if (obj[i] == '{') depth++;
        else if (obj[i] == '}') {
            depth--;
            if (depth == 0) { end = i; break; }
        }
    }
    std::string outbound = obj.substr(start, end - start + 1);
    
    std::string proto = json_extract_string(outbound, "protocol");
    if (proto == "hysteria" && obj.find("\"version\": 2") != std::string::npos) proto = "hysteria2";
    else if (proto == "hysteria" && json_extract_int(outbound, "version") == 2) proto = "hysteria2";
    std::string proto_decoded = proto;
    strncpy_s(p.protocol, sizeof(p.protocol), proto_decoded.c_str(), sizeof(p.protocol) - 1);
    
    std::string server_decoded = json_extract_string(outbound, "address");
    strncpy_s(p.server, sizeof(p.server), server_decoded.c_str(), sizeof(p.server) - 1);
    p.port = json_extract_int(outbound, "port");
    
    std::string id = json_extract_string(outbound, "id");
    if (id.empty()) id = json_extract_string(outbound, "auth");
    if (id.empty()) id = json_extract_string(outbound, "password");
    if (id.empty()) id = json_extract_string(outbound, "uuid");
    std::string id_decoded = id;
    strncpy_s(p.uuid, sizeof(p.uuid), id_decoded.c_str(), sizeof(p.uuid) - 1);
    
    std::string flow_decoded = json_extract_string(outbound, "flow");
    strncpy_s(p.flow, sizeof(p.flow), flow_decoded.c_str(), sizeof(p.flow) - 1);

    std::string net = json_extract_string(outbound, "network");
    if (net.empty()) net = json_extract_string(outbound, "type");
    if (net.empty()) net = json_extract_string(outbound, "net");
    std::string net_decoded = net;
    strncpy_s(p.type, sizeof(p.type), net_decoded.c_str(), sizeof(p.type) - 1);

    std::string sec = json_extract_string(outbound, "security");
    if (sec.empty()) sec = json_extract_string(outbound, "tls");
    std::string sec_decoded = sec;
    strncpy_s(p.security, sizeof(p.security), sec_decoded.c_str(), sizeof(p.security) - 1);

    std::string sni = json_extract_string(outbound, "serverName");
    if (sni.empty()) sni = json_extract_string(outbound, "servername");
    if (sni.empty()) sni = json_extract_string(outbound, "sni");
    if (sni.empty()) sni = json_extract_string(outbound, "peer");
    std::string sni_decoded = sni;
    strncpy_s(p.sni, sizeof(p.sni), sni_decoded.c_str(), sizeof(p.sni) - 1);

    std::string fp = json_extract_string(outbound, "fingerprint");
    if (fp.empty()) fp = json_extract_string(outbound, "fp");
    std::string fp_decoded = fp;
    strncpy_s(p.fp, sizeof(p.fp), fp_decoded.c_str(), sizeof(p.fp) - 1);

    std::string pbk = json_extract_string(outbound, "publicKey");
    if (pbk.empty()) pbk = json_extract_string(outbound, "public_key");
    if (pbk.empty()) pbk = json_extract_string(outbound, "pbk");
    std::string pbk_decoded = pbk;
    strncpy_s(p.pbk, sizeof(p.pbk), pbk_decoded.c_str(), sizeof(p.pbk) - 1);

    std::string sid = json_extract_string(outbound, "shortId");
    if (sid.empty()) sid = json_extract_string(outbound, "short_id");
    if (sid.empty()) sid = json_extract_string(outbound, "sid");
    std::string sid_decoded = sid;
    strncpy_s(p.sid, sizeof(p.sid), sid_decoded.c_str(), sizeof(p.sid) - 1);

    std::string path = json_extract_string(outbound, "path");
    if (path.empty()) path = json_extract_string(outbound, "serviceName");
    if (path.empty()) path = json_extract_string(outbound, "service_name");
    std::string path_decoded = path;
    strncpy_s(p.path, sizeof(p.path), path_decoded.c_str(), sizeof(p.path) - 1);
    p.path[sizeof(p.path) - 1] = '\0';

    std::string host = json_extract_string(outbound, "host");
    if (host.empty()) host = json_extract_string(outbound, "Host");
    std::string host_decoded = host;
    strncpy_s(p.host, sizeof(p.host), host_decoded.c_str(), sizeof(p.host) - 1);
    
    size_t alpn_pos = outbound.find("\"alpn\"");
    if (alpn_pos != std::string::npos) {
        size_t b_start = outbound.find("[", alpn_pos);
        size_t b_end = outbound.find("]", b_start);
        if (b_start != std::string::npos && b_end != std::string::npos) {
            std::string alpn_arr = outbound.substr(b_start, b_end - b_start);
            size_t q1 = alpn_arr.find("\"");
            if (q1 != std::string::npos) {
                size_t q2 = alpn_arr.find("\"", q1 + 1);
                if (q2 != std::string::npos) {
                    std::string alpn_decoded = alpn_arr.substr(q1 + 1, q2 - q1 - 1);
                    strncpy_s(p.alpn, sizeof(p.alpn), alpn_decoded.c_str(), sizeof(p.alpn) - 1);
                }
            }
        }
    }
    
    size_t extra_pos = outbound.find("\"extra\"");
    if (extra_pos != std::string::npos) {
        size_t b_start = outbound.find("{", extra_pos);
        if (b_start != std::string::npos) {
            int d = 0;
            size_t b_end = b_start;
            for (size_t i = b_start; i < outbound.length(); i++) {
                if (outbound[i] == '{') d++;
                else if (outbound[i] == '}') {
                    d--;
                    if (d == 0) { b_end = i; break; }
                }
            }
            if (b_end > b_start) {
                std::string extra_obj = outbound.substr(b_start, b_end - b_start + 1);
                std::string extra_obj_decoded = outbound.substr(b_start, b_end - b_start + 1);
                strncpy_s(p.extra, sizeof(p.extra), extra_obj_decoded.c_str(), sizeof(p.extra) - 1);
            }
        }
    }
    
    return p;
}

std::vector<Proxy> parse_proxies(const std::string& decoded) {
    std::vector<Proxy> proxies;
    
    size_t first_char = decoded.find_first_not_of(" \t\r\n");
    if (first_char != std::string::npos && (decoded[first_char] == '[' || decoded[first_char] == '{')) {
        size_t start = first_char;
        while ((start = decoded.find("{", start)) != std::string::npos) {
            int depth = 0;
            size_t end = start;
            for (size_t i = start; i < decoded.length(); i++) {
                if (decoded[i] == '{') depth++;
                else if (decoded[i] == '}') {
                    depth--;
                    if (depth == 0) { end = i; break; }
                }
            }
            if (depth == 0 && end > start) {
                std::string obj = decoded.substr(start, end - start + 1);
                Proxy p = parse_xray_json(obj);
                if (p.protocol[0] != '\0') {
                    proxies.push_back(p);
                }
                start = end + 1;
            } else {
                break;
            }
        }
        if (!proxies.empty()) return proxies;
    }

    size_t start = 0;
    while (start < decoded.length()) {
        size_t nl = decoded.find('\n', start);
        if (nl == std::string::npos) nl = decoded.length();
        std::string line = decoded.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (!line.empty()) {
            Proxy p = parse_uri(line);
            if (p.protocol[0]) proxies.push_back(p);
        }
        start = nl + 1;
    }
    return proxies;
}

std::vector<Rule> parse_xray_rules(const std::string& json) {
    std::vector<Rule> rules;
    size_t r_pos = json.find("\"routing\"");
    if (r_pos == std::string::npos) r_pos = json.find("\"rules\"");
    if (r_pos == std::string::npos) return rules;

    size_t array_start = json.find("[", r_pos);
    if (array_start == std::string::npos) return rules;

    int depth = 0;
    size_t array_end = array_start;
    for (size_t i = array_start; i < json.length(); i++) {
        if (json[i] == '[') depth++;
        else if (json[i] == ']') {
            depth--;
            if (depth == 0) { array_end = i; break; }
        }
    }

    std::string rules_block = json.substr(array_start + 1, array_end - array_start - 1);
    
    size_t start = 0;
    while ((start = rules_block.find("{", start)) != std::string::npos) {
        int obj_depth = 0;
        size_t end = start;
        for (size_t i = start; i < rules_block.length(); i++) {
            if (rules_block[i] == '{') obj_depth++;
            else if (rules_block[i] == '}') {
                obj_depth--;
                if (obj_depth == 0) { end = i; break; }
            }
        }
        if (obj_depth == 0 && end > start) {
            std::string rule_obj = rules_block.substr(start, end - start + 1);
            Rule r = {0};
            std::string tag = json_extract_string(rule_obj, "outboundTag");
            if (tag.empty()) tag = json_extract_string(rule_obj, "outbound");
            strncpy_s(r.outbound, sizeof(r.outbound), tag.c_str(), sizeof(r.outbound) - 1);

            r.domains = json_extract_string_array(rule_obj, "domain");
            r.ips = json_extract_string_array(rule_obj, "ip");
            r.protocols = json_extract_string_array(rule_obj, "protocol");
            r.port = json_extract_string(rule_obj, "port");
            if (r.port.empty()) {
                int p = json_extract_int(rule_obj, "port");
                if (p > 0) r.port = std::to_string(p);
            }
            r.network = json_extract_string(rule_obj, "network");

            if (r.outbound[0] || !r.domains.empty() || !r.ips.empty() || !r.protocols.empty() || !r.port.empty()) {
                rules.push_back(r);
            }
            start = end + 1;
        } else {
            break;
        }
    }
    return rules;
}

