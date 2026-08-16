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

static Proxy parse_xray_outbound_obj(const std::string& outbound, const std::string& default_name) {
    Proxy p = {0};
    
    std::string proto = json_extract_string(outbound, "protocol");
    if (proto.empty()) proto = json_extract_string(outbound, "type");
    
    // Skip non-proxy outbounds
    if (proto.empty() || proto == "freedom" || proto == "blackhole" || proto == "dns" || 
        proto == "direct" || proto == "block" || proto == "reject" || proto == "selector" || 
        proto == "urltest" || proto == "mixed" || proto == "tun") {
        return p;
    }
    
    if (proto == "hysteria" && (outbound.find("\"version\": 2") != std::string::npos || json_extract_int(outbound, "version") == 2)) {
        proto = "hysteria2";
    }
    strncpy_s(p.protocol, sizeof(p.protocol), proto.c_str(), sizeof(p.protocol) - 1);
    
    std::string tag = json_extract_string(outbound, "tag");
    if (!tag.empty() && tag != "proxy") {
        strncpy_s(p.name, sizeof(p.name), tag.c_str(), sizeof(p.name) - 1);
    } else if (!default_name.empty()) {
        strncpy_s(p.name, sizeof(p.name), default_name.c_str(), sizeof(p.name) - 1);
    } else if (!tag.empty()) {
        strncpy_s(p.name, sizeof(p.name), tag.c_str(), sizeof(p.name) - 1);
    }

    // Server
    std::string server = json_extract_string(outbound, "address");
    if (server.empty()) server = json_extract_string(outbound, "server");
    strncpy_s(p.server, sizeof(p.server), server.c_str(), sizeof(p.server) - 1);

    // Port
    p.port = json_extract_int(outbound, "port");
    if (p.port == 0) p.port = json_extract_int(outbound, "server_port");

    // UUID / Password / Auth
    std::string id = json_extract_string(outbound, "id");
    if (id.empty()) id = json_extract_string(outbound, "uuid");
    if (id.empty()) id = json_extract_string(outbound, "password");
    if (id.empty()) id = json_extract_string(outbound, "auth");
    if (id.empty()) id = json_extract_string(outbound, "auth_str");
    strncpy_s(p.uuid, sizeof(p.uuid), id.c_str(), sizeof(p.uuid) - 1);

    // Flow
    std::string flow = json_extract_string(outbound, "flow");
    strncpy_s(p.flow, sizeof(p.flow), flow.c_str(), sizeof(p.flow) - 1);

    // Cipher / Security
    std::string cipher = json_extract_string(outbound, "encryption");
    if (cipher.empty()) cipher = json_extract_string(outbound, "method");
    if (cipher.empty()) cipher = json_extract_string(outbound, "cipher");
    strncpy_s(p.cipher, sizeof(p.cipher), cipher.c_str(), sizeof(p.cipher) - 1);

    // Network / Type
    std::string net = json_extract_string(outbound, "network");
    if (net.empty()) {
        size_t stream_pos = outbound.find("\"streamSettings\"");
        if (stream_pos != std::string::npos) {
            net = json_extract_string(outbound.substr(stream_pos), "network");
        }
    }
    if (net.empty()) {
        size_t trans_pos = outbound.find("\"transport\"");
        if (trans_pos != std::string::npos) {
            net = json_extract_string(outbound.substr(trans_pos), "type");
        }
    }
    if (net.empty()) {
        if (outbound.find("grpcSettings") != std::string::npos) net = "grpc";
        else if (outbound.find("wsSettings") != std::string::npos) net = "ws";
        else if (outbound.find("xhttpSettings") != std::string::npos) net = "xhttp";
        else net = "tcp";
    }
    strncpy_s(p.type, sizeof(p.type), net.c_str(), sizeof(p.type) - 1);

    // Security / TLS / Reality
    std::string sec = json_extract_string(outbound, "security");
    if (sec.empty()) sec = json_extract_string(outbound, "tls");
    if (sec.empty() && outbound.find("\"realitySettings\"") != std::string::npos) sec = "reality";
    if (sec.empty() && (outbound.find("\"tlsSettings\"") != std::string::npos || outbound.find("\"tls\"") != std::string::npos)) sec = "tls";
    strncpy_s(p.security, sizeof(p.security), sec.c_str(), sizeof(p.security) - 1);

    // SNI / ServerName
    std::string sni = json_extract_string(outbound, "serverName");
    if (sni.empty()) sni = json_extract_string(outbound, "servername");
    if (sni.empty()) sni = json_extract_string(outbound, "server_name");
    if (sni.empty()) sni = json_extract_string(outbound, "sni");
    if (sni.empty()) sni = json_extract_string(outbound, "peer");
    strncpy_s(p.sni, sizeof(p.sni), sni.c_str(), sizeof(p.sni) - 1);

    // Fingerprint
    std::string fp = json_extract_string(outbound, "fingerprint");
    if (fp.empty()) fp = json_extract_string(outbound, "fp");
    strncpy_s(p.fp, sizeof(p.fp), fp.c_str(), sizeof(p.fp) - 1);

    // Reality public key & short ID
    std::string pbk = json_extract_string(outbound, "publicKey");
    if (pbk.empty()) pbk = json_extract_string(outbound, "public_key");
    if (pbk.empty()) pbk = json_extract_string(outbound, "pbk");
    strncpy_s(p.pbk, sizeof(p.pbk), pbk.c_str(), sizeof(p.pbk) - 1);

    std::string sid = json_extract_string(outbound, "shortId");
    if (sid.empty()) sid = json_extract_string(outbound, "short_id");
    if (sid.empty()) sid = json_extract_string(outbound, "sid");
    strncpy_s(p.sid, sizeof(p.sid), sid.c_str(), sizeof(p.sid) - 1);

    if (!pbk.empty()) {
        strncpy_s(p.security, sizeof(p.security), "reality", sizeof(p.security) - 1);
    }

    // Path / ServiceName
    std::string path = json_extract_string(outbound, "serviceName");
    if (path.empty()) path = json_extract_string(outbound, "service_name");
    if (path.empty()) path = json_extract_string(outbound, "service-name");
    if (path.empty()) path = json_extract_string(outbound, "grpc-service-name");
    if (path.empty()) path = json_extract_string(outbound, "path");
    if (path.empty()) path = json_extract_string(outbound, "ws-path");
    strncpy_s(p.path, sizeof(p.path), path.c_str(), sizeof(p.path) - 1);

    // Host
    std::string host = json_extract_string(outbound, "host");
    if (host.empty()) host = json_extract_string(outbound, "Host");
    strncpy_s(p.host, sizeof(p.host), host.c_str(), sizeof(p.host) - 1);

    // ALPN
    size_t alpn_pos = outbound.find("\"alpn\"");
    if (alpn_pos != std::string::npos) {
        size_t b_start = outbound.find("[", alpn_pos);
        size_t b_end = outbound.find("]", b_start);
        if (b_start != std::string::npos && b_end != std::string::npos) {
            std::string alpn_arr = outbound.substr(b_start, b_end - b_start);
            std::string alpn_result;
            size_t cur = 0;
            while (cur < alpn_arr.length()) {
                size_t q1 = alpn_arr.find("\"", cur);
                if (q1 == std::string::npos) break;
                size_t q2 = alpn_arr.find("\"", q1 + 1);
                if (q2 == std::string::npos) break;
                std::string item = alpn_arr.substr(q1 + 1, q2 - q1 - 1);
                if (!alpn_result.empty()) alpn_result += ",";
                alpn_result += item;
                cur = q2 + 1;
            }
            if (!alpn_result.empty()) {
                strncpy_s(p.alpn, sizeof(p.alpn), alpn_result.c_str(), sizeof(p.alpn) - 1);
            }
        }
    }

    // Extra / mode (xhttp)
    std::string mode = json_extract_string(outbound, "mode");
    strncpy_s(p.mode, sizeof(p.mode), mode.c_str(), sizeof(p.mode) - 1);

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
                strncpy_s(p.extra, sizeof(p.extra), extra_obj.c_str(), sizeof(p.extra) - 1);
            }
        }
    }

    return p;
}

Proxy parse_xray_json(const std::string& obj) {
    std::string remarks = json_extract_string(obj, "remarks");
    if (remarks.empty()) remarks = json_extract_string(obj, "ps");

    size_t outbounds_pos = obj.find("\"outbounds\"");
    if (outbounds_pos != std::string::npos) {
        size_t arr_start = obj.find("[", outbounds_pos);
        if (arr_start != std::string::npos) {
            int depth = 0;
            size_t arr_end = arr_start;
            for (size_t i = arr_start; i < obj.length(); i++) {
                if (obj[i] == '[') depth++;
                else if (obj[i] == ']') {
                    depth--;
                    if (depth == 0) { arr_end = i; break; }
                }
            }
            std::string block = obj.substr(arr_start + 1, arr_end - arr_start - 1);
            size_t start = 0;
            while ((start = block.find("{", start)) != std::string::npos) {
                int d = 0;
                size_t end = start;
                for (size_t i = start; i < block.length(); i++) {
                    if (block[i] == '{') d++;
                    else if (block[i] == '}') {
                        d--;
                        if (d == 0) { end = i; break; }
                    }
                }
                if (d == 0 && end > start) {
                    std::string out_item = block.substr(start, end - start + 1);
                    Proxy p = parse_xray_outbound_obj(out_item, remarks);
                    if (p.protocol[0] != '\0') return p;
                    start = end + 1;
                } else break;
            }
        }
    }
    return parse_xray_outbound_obj(obj, remarks);
}

static std::string yaml_get_val(const std::string& block, const std::string& key) {
    size_t pos = 0;
    while ((pos = block.find(key, pos)) != std::string::npos) {
        if (pos > 0) {
            char prev = block[pos - 1];
            if (isalnum((unsigned char)prev) || prev == '-' || prev == '_' || prev == '.') {
                pos += key.length();
                continue;
            }
        }
        size_t colon = block.find(':', pos + key.length());
        if (colon == std::string::npos) break;
        bool ok = true;
        for (size_t i = pos + key.length(); i < colon; i++) {
            if (block[i] != ' ' && block[i] != '\t' && block[i] != '"' && block[i] != '\'') {
                ok = false; break;
            }
        }
        if (!ok) { pos = colon + 1; continue; }

        size_t v_start = block.find_first_not_of(" \t", colon + 1);
        if (v_start == std::string::npos) return "";
        if (block[v_start] == '\r' || block[v_start] == '\n') return "";

        size_t v_end = block.find_first_of("\r\n,}", v_start);
        if (v_end == std::string::npos) v_end = block.length();

        std::string val = block.substr(v_start, v_end - v_start);
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) val.pop_back();
        if (val.length() >= 2 && ((val.front() == '"' && val.back() == '"') || (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.length() - 2);
        }
        return val;
    }
    return "";
}

static Proxy parse_clash_node(const std::string& node_str) {
    Proxy p = {0};
    std::string name = yaml_get_val(node_str, "name");
    std::string type = yaml_get_val(node_str, "type");
    if (type.empty()) type = yaml_get_val(node_str, "protocol");
    std::string server = yaml_get_val(node_str, "server");
    if (server.empty()) server = yaml_get_val(node_str, "address");
    std::string port_str = yaml_get_val(node_str, "port");

    if (name.empty() || type.empty() || server.empty() || port_str.empty()) return p;

    strncpy_s(p.name, sizeof(p.name), name.c_str(), sizeof(p.name) - 1);
    strncpy_s(p.server, sizeof(p.server), server.c_str(), sizeof(p.server) - 1);
    p.port = atoi(port_str.c_str());

    std::string proto = type;
    if (proto == "ss") proto = "shadowsocks";
    else if (proto == "hy2") proto = "hysteria2";
    strncpy_s(p.protocol, sizeof(p.protocol), proto.c_str(), sizeof(p.protocol) - 1);

    std::string uuid = yaml_get_val(node_str, "uuid");
    if (uuid.empty()) uuid = yaml_get_val(node_str, "password");
    if (uuid.empty()) uuid = yaml_get_val(node_str, "auth-str");
    if (uuid.empty()) uuid = yaml_get_val(node_str, "auth_str");
    if (uuid.empty()) uuid = yaml_get_val(node_str, "auth");
    if (uuid.empty()) uuid = yaml_get_val(node_str, "token");
    if (uuid.empty()) uuid = yaml_get_val(node_str, "secret");
    strncpy_s(p.uuid, sizeof(p.uuid), uuid.c_str(), sizeof(p.uuid) - 1);

    std::string cipher = yaml_get_val(node_str, "cipher");
    if (cipher.empty()) cipher = yaml_get_val(node_str, "method");
    strncpy_s(p.cipher, sizeof(p.cipher), cipher.c_str(), sizeof(p.cipher) - 1);

    std::string net = yaml_get_val(node_str, "network");
    if (net.empty()) net = yaml_get_val(node_str, "net");
    if (net.empty()) {
        if (node_str.find("grpc-opts") != std::string::npos || node_str.find("grpc-service-name") != std::string::npos || node_str.find("service-name") != std::string::npos) {
            net = "grpc";
        } else if (node_str.find("ws-opts") != std::string::npos || node_str.find("ws-path") != std::string::npos) {
            net = "ws";
        } else if (node_str.find("xhttp-opts") != std::string::npos) {
            net = "xhttp";
        } else if (node_str.find("h2-opts") != std::string::npos) {
            net = "h2";
        } else if (node_str.find("http-opts") != std::string::npos) {
            net = "http";
        } else {
            net = "tcp";
        }
    }
    strncpy_s(p.type, sizeof(p.type), net.c_str(), sizeof(p.type) - 1);

    std::string flow = yaml_get_val(node_str, "flow");
    strncpy_s(p.flow, sizeof(p.flow), flow.c_str(), sizeof(p.flow) - 1);

    std::string sni = yaml_get_val(node_str, "servername");
    if (sni.empty()) sni = yaml_get_val(node_str, "server-name");
    if (sni.empty()) sni = yaml_get_val(node_str, "server_name");
    if (sni.empty()) sni = yaml_get_val(node_str, "sni");
    if (sni.empty()) sni = yaml_get_val(node_str, "peer");
    strncpy_s(p.sni, sizeof(p.sni), sni.c_str(), sizeof(p.sni) - 1);

    std::string fp = yaml_get_val(node_str, "client-fingerprint");
    if (fp.empty()) fp = yaml_get_val(node_str, "client_fingerprint");
    if (fp.empty()) fp = yaml_get_val(node_str, "fingerprint");
    if (fp.empty()) fp = yaml_get_val(node_str, "fp");
    strncpy_s(p.fp, sizeof(p.fp), fp.c_str(), sizeof(p.fp) - 1);

    std::string pbk = yaml_get_val(node_str, "public-key");
    if (pbk.empty()) pbk = yaml_get_val(node_str, "publicKey");
    if (pbk.empty()) pbk = yaml_get_val(node_str, "public_key");
    if (pbk.empty()) pbk = yaml_get_val(node_str, "pbk");
    strncpy_s(p.pbk, sizeof(p.pbk), pbk.c_str(), sizeof(p.pbk) - 1);

    std::string sid = yaml_get_val(node_str, "short-id");
    if (sid.empty()) sid = yaml_get_val(node_str, "shortId");
    if (sid.empty()) sid = yaml_get_val(node_str, "short_id");
    if (sid.empty()) sid = yaml_get_val(node_str, "sid");
    strncpy_s(p.sid, sizeof(p.sid), sid.c_str(), sizeof(p.sid) - 1);

    std::string path = yaml_get_val(node_str, "grpc-service-name");
    if (path.empty()) path = yaml_get_val(node_str, "grpc_service_name");
    if (path.empty()) path = yaml_get_val(node_str, "service-name");
    if (path.empty()) path = yaml_get_val(node_str, "service_name");
    if (path.empty()) path = yaml_get_val(node_str, "serviceName");
    if (path.empty()) path = yaml_get_val(node_str, "service");
    if (path.empty()) path = yaml_get_val(node_str, "path");
    if (path.empty()) path = yaml_get_val(node_str, "ws-path");
    strncpy_s(p.path, sizeof(p.path), path.c_str(), sizeof(p.path) - 1);

    std::string host = yaml_get_val(node_str, "Host");
    if (host.empty()) host = yaml_get_val(node_str, "host");
    strncpy_s(p.host, sizeof(p.host), host.c_str(), sizeof(p.host) - 1);

    std::string tls = yaml_get_val(node_str, "tls");
    std::string sec = yaml_get_val(node_str, "security");
    if (tls == "true" || tls == "1" || sec == "tls" || sec == "reality" || proto == "trojan" || proto == "hysteria" || proto == "hysteria2" || proto == "https" || !pbk.empty()) {
        if (!pbk.empty() || sec == "reality") strncpy_s(p.security, sizeof(p.security), "reality", sizeof(p.security) - 1);
        else strncpy_s(p.security, sizeof(p.security), "tls", sizeof(p.security) - 1);
    }

    std::string obfs = yaml_get_val(node_str, "obfs");
    if (obfs.empty()) obfs = yaml_get_val(node_str, "plugin");
    strncpy_s(p.obfs, sizeof(p.obfs), obfs.c_str(), sizeof(p.obfs) - 1);

    std::string obfs_pass = yaml_get_val(node_str, "obfs-password");
    if (obfs_pass.empty()) obfs_pass = yaml_get_val(node_str, "obfs_password");
    if (obfs_pass.empty()) obfs_pass = yaml_get_val(node_str, "obfs-parameter");
    if (obfs_pass.empty()) obfs_pass = yaml_get_val(node_str, "obfsParam");
    if (obfs_pass.empty()) obfs_pass = yaml_get_val(node_str, "plugin-opts");
    strncpy_s(p.obfs_pass, sizeof(p.obfs_pass), obfs_pass.c_str(), sizeof(p.obfs_pass) - 1);

    std::string up = yaml_get_val(node_str, "up");
    if (up.empty()) up = yaml_get_val(node_str, "up_mbps");
    if (up.empty()) up = yaml_get_val(node_str, "up-mbps");
    if (up.empty()) up = yaml_get_val(node_str, "upmbps");
    strncpy_s(p.up, sizeof(p.up), up.c_str(), sizeof(p.up) - 1);

    std::string down = yaml_get_val(node_str, "down");
    if (down.empty()) down = yaml_get_val(node_str, "down_mbps");
    if (down.empty()) down = yaml_get_val(node_str, "down-mbps");
    if (down.empty()) down = yaml_get_val(node_str, "downmbps");
    strncpy_s(p.down, sizeof(p.down), down.c_str(), sizeof(p.down) - 1);

    size_t alpn_pos = node_str.find("alpn:");
    if (alpn_pos != std::string::npos) {
        size_t b_start = node_str.find_first_not_of(" \t", alpn_pos + 5);
        if (b_start != std::string::npos) {
            if (node_str[b_start] == '[') {
                size_t b_end = node_str.find(']', b_start);
                if (b_end != std::string::npos) {
                    std::string arr = node_str.substr(b_start + 1, b_end - b_start - 1);
                    std::string cleaned;
                    for (char ch : arr) {
                        if (ch != '"' && ch != '\'' && ch != ' ' && ch != '\t') cleaned += ch;
                    }
                    strncpy_s(p.alpn, sizeof(p.alpn), cleaned.c_str(), sizeof(p.alpn) - 1);
                }
            } else if (node_str[b_start] == '\r' || node_str[b_start] == '\n') {
                std::string alpns;
                size_t l_start = b_start;
                while (l_start < node_str.length()) {
                    size_t item = node_str.find("- ", l_start);
                    if (item == std::string::npos || item > l_start + 20) break;
                    size_t item_end = node_str.find_first_of("\r\n", item);
                    if (item_end == std::string::npos) item_end = node_str.length();
                    std::string entry = node_str.substr(item + 2, item_end - (item + 2));
                    while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.pop_back();
                    if (entry.length() >= 2 && ((entry.front() == '"' && entry.back() == '"') || (entry.front() == '\'' && entry.back() == '\''))) {
                        entry = entry.substr(1, entry.length() - 2);
                    }
                    if (!entry.empty()) {
                        if (!alpns.empty()) alpns += ",";
                        alpns += entry;
                    }
                    l_start = item_end + 1;
                }
                if (!alpns.empty()) {
                    strncpy_s(p.alpn, sizeof(p.alpn), alpns.c_str(), sizeof(p.alpn) - 1);
                }
            }
        }
    }

    return p;
}

std::vector<Proxy> parse_clash_yaml(const std::string& yaml) {
    std::vector<Proxy> proxies;
    size_t p_start = yaml.find("proxies:");
    if (p_start == std::string::npos) return proxies;

    p_start += 8;
    if (p_start < yaml.length() && yaml[p_start] == '\r') p_start++;
    if (p_start < yaml.length() && yaml[p_start] == '\n') p_start++;

    size_t next_section = std::string::npos;
    size_t search_pos = p_start;
    while ((search_pos = yaml.find('\n', search_pos)) != std::string::npos) {
        search_pos++;
        if (search_pos < yaml.length() && isalpha((unsigned char)yaml[search_pos])) {
            next_section = search_pos;
            break;
        }
    }
    size_t p_end = (next_section != std::string::npos) ? next_section : yaml.length();
    std::string block = yaml.substr(p_start, p_end - p_start);

    size_t search_start = 0;
    while (true) {
        size_t name_pos = block.find("- name:", search_start);
        if (name_pos == std::string::npos) {
            name_pos = block.find("- {", search_start);
            if (name_pos == std::string::npos) break;
        }

        size_t node_start = name_pos;
        while (node_start > 0 && (block[node_start - 1] == ' ' || block[node_start - 1] == '\t')) {
            node_start--;
        }

        size_t next_name_pos1 = block.find("- name:", name_pos + 4);
        size_t next_name_pos2 = block.find("- {", name_pos + 4);
        size_t next_name_pos = std::string::npos;
        if (next_name_pos1 != std::string::npos && next_name_pos2 != std::string::npos) {
            next_name_pos = (next_name_pos1 < next_name_pos2) ? next_name_pos1 : next_name_pos2;
        } else if (next_name_pos1 != std::string::npos) {
            next_name_pos = next_name_pos1;
        } else {
            next_name_pos = next_name_pos2;
        }

        size_t next_node_start = block.length();
        if (next_name_pos != std::string::npos) {
            next_node_start = next_name_pos;
            while (next_node_start > node_start && (block[next_node_start - 1] == ' ' || block[next_node_start - 1] == '\t')) {
                next_node_start--;
            }
        }

        std::string node_str = block.substr(node_start, next_node_start - node_start);
        Proxy p = parse_clash_node(node_str);
        if (p.protocol[0]) {
            proxies.push_back(p);
        }

        if (next_name_pos == std::string::npos) break;
        search_start = next_name_pos;
    }
    return proxies;
}

std::vector<Rule> parse_clash_rules(const std::string& yaml) {
    std::vector<Rule> rules;
    size_t r_pos = yaml.find("rules:");
    if (r_pos == std::string::npos) return rules;

    r_pos += 6;
    size_t search_pos = r_pos;
    while (search_pos < yaml.length()) {
        size_t nl = yaml.find('\n', search_pos);
        if (nl == std::string::npos) nl = yaml.length();
        std::string line = yaml.substr(search_pos, nl - search_pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        size_t dash = line.find("- ");
        if (dash != std::string::npos) {
            std::string r_str = line.substr(dash + 2);
            while (!r_str.empty() && (r_str.front() == ' ' || r_str.front() == '\t')) r_str.erase(0, 1);
            while (!r_str.empty() && (r_str.back() == ' ' || r_str.back() == '\t')) r_str.pop_back();

            std::vector<std::string> parts;
            size_t s = 0;
            while (s < r_str.length()) {
                size_t c = r_str.find(',', s);
                if (c == std::string::npos) c = r_str.length();
                std::string part = r_str.substr(s, c - s);
                while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) part.erase(0, 1);
                while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) part.pop_back();
                if (!part.empty()) parts.push_back(part);
                s = c + 1;
            }

            if (parts.size() >= 2) {
                std::string type = parts[0];
                std::string target = (parts.size() >= 3) ? parts[2] : parts[1];
                std::string val = parts[1];

                Rule r = {0};
                if (_stricmp(target.c_str(), "DIRECT") == 0) strcpy_s(r.outbound, "direct");
                else if (_stricmp(target.c_str(), "REJECT") == 0 || _stricmp(target.c_str(), "BLOCK") == 0) strcpy_s(r.outbound, "block");
                else strcpy_s(r.outbound, "proxy");

                if (type == "DOMAIN") {
                    r.domains.push_back("full:" + val);
                    rules.push_back(r);
                } else if (type == "DOMAIN-SUFFIX") {
                    r.domains.push_back("domain:" + val);
                    rules.push_back(r);
                } else if (type == "DOMAIN-KEYWORD") {
                    r.domains.push_back(val);
                    rules.push_back(r);
                } else if (type == "IP-CIDR" || type == "IP-CIDR6") {
                    r.ips.push_back(val);
                    rules.push_back(r);
                } else if (type == "GEOIP") {
                    r.ips.push_back("geoip:" + val);
                    rules.push_back(r);
                } else if (type == "DST-PORT") {
                    r.port = val;
                    rules.push_back(r);
                }
            }
        } else if (!line.empty() && isalpha((unsigned char)line[0])) {
            break;
        }
        search_pos = nl + 1;
    }
    return rules;
}

std::vector<Proxy> parse_proxies(const std::string& decoded) {
    if (decoded.find("proxies:") != std::string::npos) {
        auto clash_proxies = parse_clash_yaml(decoded);
        if (!clash_proxies.empty()) return clash_proxies;
    }

    std::vector<Proxy> proxies;

    size_t outbounds_pos = decoded.find("\"outbounds\"");
    if (outbounds_pos != std::string::npos) {
        std::string remarks = json_extract_string(decoded, "remarks");
        if (remarks.empty()) remarks = json_extract_string(decoded, "ps");

        size_t arr_start = decoded.find("[", outbounds_pos);
        if (arr_start != std::string::npos) {
            int depth = 0;
            size_t arr_end = arr_start;
            for (size_t i = arr_start; i < decoded.length(); i++) {
                if (decoded[i] == '[') depth++;
                else if (decoded[i] == ']') {
                    depth--;
                    if (depth == 0) { arr_end = i; break; }
                }
            }
            std::string block = decoded.substr(arr_start + 1, arr_end - arr_start - 1);
            size_t start = 0;
            while ((start = block.find("{", start)) != std::string::npos) {
                int d = 0;
                size_t end = start;
                for (size_t i = start; i < block.length(); i++) {
                    if (block[i] == '{') d++;
                    else if (block[i] == '}') {
                        d--;
                        if (d == 0) { end = i; break; }
                    }
                }
                if (d == 0 && end > start) {
                    std::string out_item = block.substr(start, end - start + 1);
                    Proxy p = parse_xray_outbound_obj(out_item, remarks);
                    if (p.protocol[0] != '\0') {
                        proxies.push_back(p);
                    }
                    start = end + 1;
                } else break;
            }
            if (!proxies.empty()) return proxies;
        }
    }

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
                Proxy p = parse_xray_outbound_obj(obj, "");
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
    if (json.find("rules:") != std::string::npos && json.find("\"routing\"") == std::string::npos && json.find("\"rules\"") == std::string::npos) {
        return parse_clash_rules(json);
    }

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

