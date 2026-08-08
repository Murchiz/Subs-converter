#include "types.h"
#include "server.h"
#include "parser.h"
#include "generator.h"
#include "utils.h"
#include <stdio.h>
int reg_sz(HKEY root, const char *sub, const char *name, char *buf, DWORD cap) {
    HKEY hk;
    DWORD type = 0, sz = cap;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk)) return 0;
    int ok = !RegQueryValueExA(hk, name, NULL, &type, (BYTE *)buf, &sz) && type == REG_SZ;
    RegCloseKey(hk);
    return ok;
}
void dev_gather() {
    memset(&g_Dev, 0, sizeof(g_Dev));
    strcpy(g_Dev.os, "Windows");

    if (!reg_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", g_Dev.hwid, sizeof(g_Dev.hwid)))
        strcpy(g_Dev.hwid, "unknown");

    typedef LONG(WINAPI *RGV)(OSVERSIONINFOW *);
    OSVERSIONINFOW v;
    memset(&v, 0, sizeof(v));
    v.dwOSVersionInfoSize = sizeof(v);
    RGV fn = (RGV)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (fn && fn(&v) == 0)
        snprintf(g_Dev.ver, sizeof(g_Dev.ver), "%lu.%lu.%lu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
    else
        strcpy(g_Dev.ver, "10.0");

    char mfr[128] = { 0 }, prod[128] = { 0 };
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemManufacturer", mfr, sizeof(mfr));
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", prod, sizeof(prod));

    if (mfr[0] && prod[0]) snprintf(g_Dev.model, sizeof(g_Dev.model), "%s %s", mfr, prod);
    else if (prod[0]) strcpy(g_Dev.model, prod);
    else strcpy(g_Dev.model, "Windows PC");
}
void load_config() {
    char cfg_path[MAX_PATH];
    snprintf(cfg_path, sizeof(cfg_path), "%s\\config.ini", g_ExeDir);

    Route *subc = &g_Routes[g_RouteCount++];
    subc->local_port = 25500;
    subc->is_subconverter = 1;
    subc->is_convert = 0;

    FILE *f = fopen(cfg_path, "r");
    if (!f) {
        logm("Warning: Cannot open %s\n", cfg_path);
        return;
    }

    char line[1024];
    int in_sub = 0, in_dev = 0;
    char links[8][2048] = { 0 };
    char uas[8][128] = { 0 };
    char sub_name[128] = { 0 };
    int link_count = 0;
    int port = 0, hwid = 0;
    char converts[1024] = { 0 };

    auto commit_sub = [&]() {
        if (in_sub && port > 0 && link_count > 0) {
            if (g_RouteCount >= 64) return;
            Route *r = &g_Routes[g_RouteCount++];
            r->local_port = port;
            r->is_convert = 0;
            r->is_subconverter = 0;
            r->url_count = link_count;
            strcpy(r->name, sub_name);
            for (int i = 0; i < link_count; i++) {
                strcpy(r->urls[i], links[i]);
                strcpy(r->user_agents[i], uas[i]);
            }
            r->use_hwid = hwid;

            if (converts[0]) {
                int c_idx = 1;
                char *tok = strtok(converts, ", \t");
                while (tok) {
                    if (g_RouteCount >= 64) break;
                    Route *rc = &g_Routes[g_RouteCount++];
                    rc->local_port = port + c_idx;
                    rc->is_convert = 1;
                    rc->is_subconverter = 0;
                    rc->base_port = port;
                    rc->url_count = 1;
                    strcpy(rc->target, tok);
                    strcpy(rc->name, r->name);
                    // Conversion routes do not need user agents, they fetch from local 25500
                    rc->use_hwid = 0;
                    c_idx++;
                    tok = strtok(NULL, ", \t");
                }
            }
        }
        for(int i=0; i<8; i++) { links[i][0] = 0; uas[i][0] = 0; }
        sub_name[0] = 0;
        link_count = 0; port = 0; hwid = 0; converts[0] = 0;
    };

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *end = p + strlen(p) - 1;
        while (end >= p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';
        if (!*p || *p == ';' || *p == '#') continue;

        if (*p == '[') {
            commit_sub();
            if (_strnicmp(p, "[Sub_", 5) == 0) { in_sub = 1; in_dev = 0; }
            else if (_stricmp(p, "[Device]") == 0) { in_sub = 0; in_dev = 1; }
            else { in_sub = 0; in_dev = 0; }
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = p; char *v = eq + 1;
        char *kend = k + strlen(k) - 1;
        while (kend >= k && (*kend == ' ' || *kend == '\t')) *kend-- = '\0';
        while (*v == ' ' || *v == '\t') v++;

        if (in_sub) {
            if (_strnicmp(k, "link", 4) == 0 && link_count < 8) {
                int idx = (strlen(k) > 4) ? atoi(k + 4) - 1 : link_count;
                if (idx >= 0 && idx < 8) { strcpy(links[idx], v); if (idx >= link_count) link_count = idx + 1; }
            }
            else if (_strnicmp(k, "user_agent", 10) == 0) {
                int idx = (strlen(k) > 10) ? atoi(k + 10) - 1 : 0;
                if (idx >= 0 && idx < 8) strcpy(uas[idx], v);
            }
            else if (_stricmp(k, "name") == 0) strcpy(sub_name, v);
            else if (_stricmp(k, "port") == 0) port = atoi(v);
            else if (_stricmp(k, "hwid") == 0) hwid = (_stricmp(v, "true") == 0 || _stricmp(v, "1") == 0);
            else if (_stricmp(k, "converts") == 0) strcpy(converts, v);
        } else if (in_dev) {
            if (_stricmp(k, "hwid") == 0) strcpy(g_Dev.hwid, v);
            else if (_stricmp(k, "os") == 0) strcpy(g_Dev.os, v);
            else if (_stricmp(k, "ver") == 0) strcpy(g_Dev.ver, v);
            else if (_stricmp(k, "model") == 0) strcpy(g_Dev.model, v);
        }
    }
    commit_sub();
    fclose(f);
}
void svc_report(DWORD st, DWORD err, DWORD hint) {
    static DWORD ck = 1;
    g_Svc.dwCurrentState = st;
    g_Svc.dwWin32ExitCode = err;
    g_Svc.dwWaitHint = hint;
    g_Svc.dwCheckPoint = (st == SERVICE_RUNNING || st == SERVICE_STOPPED) ? 0 : ck++;
    SetServiceStatus(g_SvcH, &g_Svc);
}

VOID WINAPI svc_ctrl(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        svc_report(SERVICE_STOP_PENDING, 0, 5000);
        SetEvent(g_Stop);
    }
}

VOID WINAPI svc_main(DWORD argc, LPSTR *argv) {
    (void)argc; (void)argv;
    g_SvcH = RegisterServiceCtrlHandlerA(SVC_NAME, svc_ctrl);
    if (!g_SvcH) return;

    g_Svc.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Svc.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    g_Stop = CreateEvent(NULL, TRUE, FALSE, NULL);
    svc_report(SERVICE_RUNNING, 0, 0);
    server_loop();
    svc_report(SERVICE_STOPPED, 0, 0);
}
void do_install(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { puts("ERROR: run as Administrator."); return; }

    SC_HANDLE s = CreateServiceA(scm, SVC_NAME, SVC_DISPLAY, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        path, NULL, NULL, NULL, NULL, NULL);

    if (s) {
        SERVICE_DESCRIPTIONA desc = { (char *)"Local Subscription Bridge & Subconverter" };
        ChangeServiceConfig2A(s, SERVICE_CONFIG_DESCRIPTION, &desc);
        printf("Installed. Starting... ");
        if (StartServiceA(s, 0, NULL)) puts("OK.");
        else printf("err %lu (start manually: sc start %s)\n", GetLastError(), SVC_NAME);
        CloseServiceHandle(s);
    } else {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) puts("Already installed.");
        else printf("CreateService error %lu\n", e);
    }
    CloseServiceHandle(scm);
}

void do_uninstall(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { puts("ERROR: run as Administrator."); return; }

    SC_HANDLE s = OpenServiceA(scm, SVC_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS ss;
        ControlService(s, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 30; i++) {
            if (!QueryServiceStatus(s, &ss) || ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(200);
        }
        puts(DeleteService(s) ? "Uninstalled." : "Delete failed.");
        CloseServiceHandle(s);
    } else {
        puts("Service not found.");
    }
    CloseServiceHandle(scm);
}
BOOL WINAPI con_ctrl(DWORD c) {
    if (c == CTRL_C_EVENT || c == CTRL_BREAK_EVENT) {
        SetEvent(g_Stop);
        return TRUE;
    }
    return FALSE;
}

void run_console(void) {
    g_IsCon = 1;
    g_Stop = CreateEvent(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(con_ctrl, TRUE);

    printf("\n  SubBridge & Subconverter - console mode\n");
    printf("  HWID:   %s\n", g_Dev.hwid);
    printf("  OS:     %s %s\n", g_Dev.os, g_Dev.ver);
    printf("  Model:  %s\n\n", g_Dev.model);

    server_loop();
    puts("\nStopped.");
}
void run_convert(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: sub_bridge -convert <target> <url> [output_file]\n");
        printf("Targets: clash, singbox, singbox-pc\n");
        return;
    }
    std::string target = argv[2];
    std::string url = argv[3];
    std::string outfile = (argc >= 5) ? argv[4] : "output.txt";

    Route temp_rt = { 0 };
    strcpy(temp_rt.urls[0], url.c_str());
    temp_rt.url_count = 1;

    char *body = (char *)HeapAlloc(GetProcessHeap(), 0, BODY_CAP);

    std::string out_payload;
    std::string raw_clash_proxies;
    std::string raw_clash_names;
    std::vector<Proxy> all_proxies;
    std::vector<Rule> all_rules;
    int success_count = 0;

    for (int i = 0; i < temp_rt.url_count; i++) {
        int blen = fetch_url(&temp_rt, body, BODY_CAP, NULL, i);
        if (blen >= 0) {
            success_count++;
            std::string payload(body, blen);
            if (target == "clash" && payload.find("proxies:") != std::string::npos) {
                // Extract Native Clash YAML proxies
                size_t p_start = payload.find("proxies:");
                if (p_start != std::string::npos) {
                    p_start += 8; // skip 'proxies:'
                    if (p_start < payload.length() && payload[p_start] == '\r') p_start++;
                    if (p_start < payload.length() && payload[p_start] == '\n') p_start++;
                    
                    size_t next_section = std::string::npos;
                    size_t search_pos = p_start;
                    while ((search_pos = payload.find('\n', search_pos)) != std::string::npos) {
                        search_pos++;
                        if (search_pos < payload.length() && isalpha((unsigned char)payload[search_pos])) {
                            next_section = search_pos;
                            break;
                        }
                    }
                    size_t p_end = (next_section != std::string::npos) ? next_section : payload.length();
                    
                    std::string block = payload.substr(p_start, p_end - p_start);
                    
                    std::string filtered_block;
                    size_t search_start = 0;
                    while (true) {
                        size_t name_pos = block.find("- name:", search_start);
                        if (name_pos == std::string::npos) break;
                        
                        size_t node_start = name_pos;
                        while (node_start > 0 && (block[node_start - 1] == ' ' || block[node_start - 1] == '\t')) {
                            node_start--;
                        }
                        
                        size_t next_name_pos = block.find("- name:", name_pos + 7);
                        size_t next_node_start = block.length();
                        if (next_name_pos != std::string::npos) {
                            next_node_start = next_name_pos;
                            while (next_node_start > node_start && (block[next_node_start - 1] == ' ' || block[next_node_start - 1] == '\t')) {
                                next_node_start--;
                            }
                        }
                        
                        std::string node_str = block.substr(node_start, next_node_start - node_start);
                        
                        filtered_block += node_str;
                        
                        size_t n_pos = node_str.find("- name:");
                        size_t end_line = node_str.find('\n', n_pos);
                        if (end_line == std::string::npos) end_line = node_str.length();
                        size_t val_start = node_str.find_first_not_of(" \t", n_pos + 7);
                        if (val_start != std::string::npos && val_start < end_line) {
                            size_t val_end = end_line - 1;
                            while (val_end >= val_start && (node_str[val_end] == ' ' || node_str[val_end] == '\t' || node_str[val_end] == '\r' || node_str[val_end] == '\n')) {
                                val_end--;
                            }
                            if (val_start <= val_end) {
                                std::string raw_name = node_str.substr(val_start, val_end - val_start + 1);
                                if (raw_name.length() >= 2 && ((raw_name.front() == '"' && raw_name.back() == '"') ||
                                    (raw_name.front() == '\'' && raw_name.back() == '\''))) {
                                    raw_name = raw_name.substr(1, raw_name.length() - 2);
                                }
                                raw_clash_names += "      - \"" + raw_name + "\"\n";
                            }
                        }
                        
                        search_start = next_name_pos;
                    }
                    raw_clash_proxies += filtered_block;
                }
            } else {
                std::string decoded;
                size_t first_char = payload.find_first_not_of(" \t\r\n");
                if (first_char != std::string::npos && (payload[first_char] == '[' || payload[first_char] == '{')) {
                    decoded = payload;
                } else {
                    decoded = (payload.find("://") != std::string::npos) ? payload : base64_decode(payload);
                }
                auto p = parse_proxies(decoded);
                all_proxies.insert(all_proxies.end(), p.begin(), p.end());
                auto r = parse_xray_rules(decoded);
                all_rules.insert(all_rules.end(), r.begin(), r.end());
            }
        }
    }

    if (success_count > 0) {
        if (target == "clash") {
            out_payload = gen_clash(all_proxies, all_rules);
            if (!raw_clash_proxies.empty()) {
                while (!raw_clash_proxies.empty() && isspace((unsigned char)raw_clash_proxies.back())) {
                    raw_clash_proxies.pop_back();
                }
                raw_clash_proxies += "\n";
                
                size_t pg = out_payload.find("proxy-groups:");
                if (pg != std::string::npos) {
                    out_payload.insert(pg, raw_clash_proxies);
                    
                    size_t auto_grp = out_payload.find("  - name: Auto\n    type: url-test");
                    if (auto_grp != std::string::npos) {
                        out_payload.insert(auto_grp, raw_clash_names);
                    }
                    
                    size_t rules = out_payload.find("rules:");
                    if (rules != std::string::npos) {
                        out_payload.insert(rules, raw_clash_names);
                    }
                }
            }
        } else if (target == "singbox" || target == "sing-box") {
            out_payload = gen_singbox(all_proxies, "android", all_rules);
        } else if (target == "singbox-pc" || target == "sing-box-pc") {
            out_payload = gen_singbox(all_proxies, "pc", all_rules);
        } else {
            out_payload = gen_v2ray(all_proxies);
        }
        
        FILE *f = fopen(outfile.c_str(), "wb");
        if (f) {
            fwrite(out_payload.c_str(), 1, out_payload.length(), f);
            fclose(f);
            printf("Successfully converted to %s\n", outfile.c_str());
        } else {
            printf("Error writing to %s\n", outfile.c_str());
        }
    } else {
        printf("Error fetching URL\n");
    }
    HeapFree(GetProcessHeap(), 0, body);
}
int main(int argc, char **argv) {
    GetModuleFileNameA(NULL, g_ExeDir, MAX_PATH);
    char *last_slash = strrchr(g_ExeDir, '\\');
    if (last_slash) *last_slash = '\0';

    dev_gather();
    load_config();

    if (argc > 1) {
        const char *a = argv[1];
        if (!_stricmp(a, "-install") || !_stricmp(a, "/install")) { do_install(); return 0; }
        if (!_stricmp(a, "-uninstall") || !_stricmp(a, "/uninstall") || !_stricmp(a, "-remove")) { do_uninstall(); return 0; }
        if (!_stricmp(a, "-console") || !_stricmp(a, "/console") || !_stricmp(a, "-c")) { run_console(); return 0; }
        if (!_stricmp(a, "-convert")) { run_convert(argc, argv); return 0; }

        printf("Subscription Bridge & Embedded Subconverter\n\n"
            "  %s -install                    install + start service\n"
            "  %s -uninstall                  stop + remove service\n"
            "  %s -console                    run in foreground\n"
            "  %s -convert <target> <url> [f] static file convert\n", argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    SERVICE_TABLE_ENTRYA tbl[] = { { (char *)SVC_NAME, svc_main }, { NULL, NULL } };
    if (!StartServiceCtrlDispatcherA(tbl)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            puts("Not launched by SCM.");
            puts("  Use  -console   to run interactively");
            puts("  Use  -install   to install as a service");
        }
    }
    return 0;
}
