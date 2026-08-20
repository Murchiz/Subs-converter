#include "types.h"
#include "server.h"
#include "parser.h"
#include "generator.h"
#include "utils.h"
#include "safe_crt.h"
#include <cstdio>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <format>
#include <string_view>
#include <algorithm>

namespace fs = std::filesystem;

namespace {

inline std::string_view trim_sv(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
        s.remove_suffix(1);
    }
    return s;
}

inline bool iequals(std::string_view a, std::string_view b) noexcept {
    return std::ranges::equal(a, b, [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

inline bool istarts_with(std::string_view str, std::string_view prefix) noexcept {
    if (str.length() < prefix.length()) return false;
    return iequals(str.substr(0, prefix.length()), prefix);
}

} // namespace

#ifndef SUB_BRIDGE_VERSION
#define SUB_BRIDGE_VERSION "1.0.0"
#endif

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#endif

void print_version() {
    std::println("SubBridge Version: {}", SUB_BRIDGE_VERSION);
    std::println("Build Time: {} {}", __DATE__, __TIME__);
    std::println("Repository: https://github.com/Murchiz/Subs-converter");
}

#ifdef _WIN32
int reg_sz(HKEY root, const char *sub, const char *name, char *buf, DWORD cap) {
    HKEY hk = nullptr;
    DWORD type = 0, sz = cap;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return 0;
    int ok = (!RegQueryValueExA(hk, name, nullptr, &type, reinterpret_cast<BYTE *>(buf), &sz) && type == REG_SZ) ? 1 : 0;
    RegCloseKey(hk);
    return ok;
}

void dev_gather() {
    memset(&g_Dev, 0, sizeof(g_Dev));
    safe_strncpy(g_Dev.os, "Windows");

    if (!reg_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", g_Dev.hwid, sizeof(g_Dev.hwid)))
        safe_strncpy(g_Dev.hwid, "unknown");

    typedef LONG(WINAPI *RGV)(OSVERSIONINFOW *);
    OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    auto fn = reinterpret_cast<RGV>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (fn && fn(&v) == 0) {
        std::string ver = std::format("{}.{}.{}", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
        safe_strncpy(g_Dev.ver, ver.c_str());
    } else {
        safe_strncpy(g_Dev.ver, "10.0");
    }

    char mfr[128]{}, prod[128]{};
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemManufacturer", mfr, sizeof(mfr));
    reg_sz(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", prod, sizeof(prod));

    if (mfr[0] && prod[0]) {
        std::string model = std::format("{} {}", mfr, prod);
        safe_strncpy(g_Dev.model, model.c_str());
    } else if (prod[0]) {
        safe_strncpy(g_Dev.model, prod);
    } else {
        safe_strncpy(g_Dev.model, "Windows PC");
    }
}
#else
void dev_gather() {
    std::memset(&g_Dev, 0, sizeof(g_Dev));
    safe_strncpy(g_Dev.os, "Linux");

    // Read machine-id for HWID
    std::ifstream mid_file("/etc/machine-id");
    if (!mid_file.is_open()) mid_file.open("/var/lib/dbus/machine-id");
    if (mid_file.is_open()) {
        std::string mid;
        if (std::getline(mid_file, mid)) {
            mid = std::string(trim_sv(mid));
            safe_strncpy(g_Dev.hwid, mid.c_str());
        }
    }
    if (!g_Dev.hwid[0]) safe_strncpy(g_Dev.hwid, "unknown");

    // Read OS info from /etc/os-release
    std::ifstream os_file("/etc/os-release");
    std::string os_name = "Linux";
    std::string os_ver = "unknown";
    if (os_file.is_open()) {
        std::string line;
        while (std::getline(os_file, line)) {
            std::string_view sv = trim_sv(line);
            if (sv.starts_with("PRETTY_NAME=")) {
                std::string_view val = sv.substr(12);
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"') val = val.substr(1, val.size() - 2);
                os_name = std::string(val);
            } else if (sv.starts_with("VERSION_ID=")) {
                std::string_view val = sv.substr(11);
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"') val = val.substr(1, val.size() - 2);
                os_ver = std::string(val);
            }
        }
    }
    safe_strncpy(g_Dev.os, os_name.c_str());
    safe_strncpy(g_Dev.ver, os_ver.c_str());

    // Read Model from /sys/devices/virtual/dmi/id/product_name
    std::ifstream dmi_file("/sys/devices/virtual/dmi/id/product_name");
    if (dmi_file.is_open()) {
        std::string prod;
        if (std::getline(dmi_file, prod)) {
            prod = std::string(trim_sv(prod));
            safe_strncpy(g_Dev.model, prod.c_str());
        }
    }
    if (!g_Dev.model[0]) safe_strncpy(g_Dev.model, "Linux Device");
}
#endif

void load_config() {
    fs::path cfg_path = fs::path(g_ExeDir) / "config.ini";

    Route *subc = &g_Routes[g_RouteCount++];
    subc->local_port = 25500;
    subc->is_subconverter = 1;
    subc->is_convert = 0;

    std::ifstream f(cfg_path);
    if (!f.is_open()) {
        logm("Warning: Cannot open %s\n", cfg_path.string().c_str());
        return;
    }

    std::string raw_line;
    int in_sub = 0, in_dev = 0;
    char links[8][2048]{};
    char uas[8][128]{};
    char sub_name[128]{};
    int link_count = 0;
    int port = 0, hwid = 0;
    char converts[1024]{};

    auto commit_sub = [&]() {
        if (in_sub && port > 0 && link_count > 0) {
            if (g_RouteCount >= 64) return;
            Route *r = &g_Routes[g_RouteCount++];
            r->local_port = port;
            r->is_convert = 0;
            r->is_subconverter = 0;
            r->url_count = link_count;
            safe_strncpy(r->name, sub_name);
            for (int i = 0; i < link_count; i++) {
                safe_strncpy(r->urls[i], links[i]);
                safe_strncpy(r->user_agents[i], uas[i]);
            }
            r->use_hwid = hwid;

            if (converts[0]) {
                int c_idx = 1;
                char *context = nullptr;
                char *tok = safe_crt::strtok_s_wrapper(converts, ", \t", &context);
                while (tok) {
                    if (g_RouteCount >= 64) break;
                    Route *rc = &g_Routes[g_RouteCount++];
                    rc->local_port = port + c_idx;
                    rc->is_convert = 1;
                    rc->is_subconverter = 0;
                    rc->base_port = port;
                    rc->url_count = 1;
                    safe_strncpy(rc->target, tok);
                    safe_strncpy(rc->name, r->name);
                    rc->use_hwid = 0;
                    c_idx++;
                    tok = safe_crt::strtok_s_wrapper(nullptr, ", \t", &context);
                }
            }
        }
        for (int i = 0; i < 8; i++) { links[i][0] = 0; uas[i][0] = 0; }
        sub_name[0] = 0;
        link_count = 0; port = 0; hwid = 0; converts[0] = 0;
    };

    while (std::getline(f, raw_line)) {
        std::string_view line = trim_sv(raw_line);
        if (line.empty() || line.front() == ';' || line.front() == '#') continue;

        if (line.front() == '[') {
            commit_sub();
            if (istarts_with(line, "[Sub_")) { in_sub = 1; in_dev = 0; }
            else if (iequals(line, "[Device]")) { in_sub = 0; in_dev = 1; }
            else { in_sub = 0; in_dev = 0; }
            continue;
        }

        size_t eq_pos = line.find('=');
        if (eq_pos == std::string_view::npos) continue;
        std::string_view k = trim_sv(line.substr(0, eq_pos));
        std::string_view v = trim_sv(line.substr(eq_pos + 1));
        std::string v_str(v);

        if (in_sub) {
            if (istarts_with(k, "link") && link_count < 8) {
                int idx = (k.length() > 4) ? atoi(std::string(k.substr(4)).c_str()) - 1 : link_count;
                if (idx >= 0 && idx < 8) {
                    safe_strncpy(links[idx], v_str.c_str());
                    if (idx >= link_count) link_count = idx + 1;
                }
            }
            else if (istarts_with(k, "user_agent")) {
                int idx = (k.length() > 10) ? atoi(std::string(k.substr(10)).c_str()) - 1 : 0;
                if (idx >= 0 && idx < 8) safe_strncpy(uas[idx], v_str.c_str());
            }
            else if (iequals(k, "name")) safe_strncpy(sub_name, v_str.c_str());
            else if (iequals(k, "port")) port = atoi(v_str.c_str());
            else if (iequals(k, "hwid")) hwid = (iequals(v, "true") || iequals(v, "1"));
            else if (iequals(k, "converts")) safe_strncpy(converts, v_str.c_str());
        } else if (in_dev) {
            if (iequals(k, "hwid")) safe_strncpy(g_Dev.hwid, v_str.c_str());
            else if (iequals(k, "os")) safe_strncpy(g_Dev.os, v_str.c_str());
            else if (iequals(k, "ver")) safe_strncpy(g_Dev.ver, v_str.c_str());
            else if (iequals(k, "model")) safe_strncpy(g_Dev.model, v_str.c_str());
        }
    }
    commit_sub();
}

#ifdef _WIN32
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

    g_Stop = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    svc_report(SERVICE_RUNNING, 0, 0);
    server_loop();
    svc_report(SERVICE_STOPPED, 0, 0);
}

void do_install() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { std::println("ERROR: run as Administrator."); return; }

    SC_HANDLE s = CreateServiceA(scm, SVC_NAME, SVC_DISPLAY, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        path, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (s) {
        SERVICE_DESCRIPTIONA desc = { const_cast<char *>("Local Subscription Bridge & Subconverter") };
        ChangeServiceConfig2A(s, SERVICE_CONFIG_DESCRIPTION, &desc);
        std::print("Installed. Starting... ");
        if (StartServiceA(s, 0, nullptr)) {
            std::println("OK.");
        } else {
            std::println("err {} (start manually: sc start {})", GetLastError(), SVC_NAME);
        }
        CloseServiceHandle(s);
    } else {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) std::println("Already installed.");
        else std::println("CreateService error {}", e);
    }
    CloseServiceHandle(scm);
}

void do_uninstall() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { std::println("ERROR: run as Administrator."); return; }

    SC_HANDLE s = OpenServiceA(scm, SVC_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS ss{};
        ControlService(s, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 30; i++) {
            if (!QueryServiceStatus(s, &ss) || ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(200);
        }
        std::println("{}", DeleteService(s) ? "Uninstalled." : "Delete failed.");
        CloseServiceHandle(s);
    } else {
        std::println("Service not found.");
    }
    CloseServiceHandle(scm);
}

void do_restart() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { std::println("ERROR: run as Administrator."); return; }

    SC_HANDLE s = OpenServiceA(scm, SVC_NAME, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS ss{};
        std::print("Stopping service... ");
        if (ControlService(s, SERVICE_CONTROL_STOP, &ss)) {
            for (int i = 0; i < 30; i++) {
                if (!QueryServiceStatus(s, &ss) || ss.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(200);
            }
        }
        std::println("OK.");
        std::print("Starting service... ");
        if (StartServiceA(s, 0, nullptr)) {
            std::println("OK.");
        } else {
            std::println("err {} (start manually: sc start {})", GetLastError(), SVC_NAME);
        }
        CloseServiceHandle(s);
    } else {
        std::println("Service not found.");
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

void run_console() {
    g_IsCon = 1;
    g_Stop = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(con_ctrl, TRUE);

    std::println("\n  SubBridge & Subconverter - console mode");
    std::println("  HWID:   {}", g_Dev.hwid);
    std::println("  OS:     {} {}", g_Dev.os, g_Dev.ver);
    std::println("  Model:  {}\n", g_Dev.model);

    server_loop();
    std::println("\nStopped.");
}
#else
bool has_systemd() {
    struct stat st{};
    return (stat("/run/systemd/system", &st) == 0);
}

std::string get_self_exe_path() {
    char buf[PATH_MAX]{};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        return std::string(buf);
    }
    return "";
}

std::string get_pid_file_path() {
    return "/tmp/subbridge.pid";
}

void do_install() {
    if (has_systemd()) {
        std::string exe_path = get_self_exe_path();
        if (exe_path.empty()) {
            std::println("ERROR: Cannot determine executable path.");
            return;
        }
        fs::path exe_p(exe_path);
        std::string working_dir = exe_p.parent_path().string();

        std::string service_content = std::format(
            "[Unit]\n"
            "Description=Subscription Converter Bridge\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "WorkingDirectory={}\n"
            "ExecStart={} --console\n"
            "Restart=always\n"
            "RestartSec=3\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n",
            working_dir, exe_path
        );

        std::ofstream unit_file("/etc/systemd/system/subbridge.service");
        if (!unit_file.is_open()) {
            std::println("ERROR: Cannot write /etc/systemd/system/subbridge.service (run with sudo).");
            return;
        }
        unit_file << service_content;
        unit_file.close();

        std::print("Enabling and starting systemd service... ");
        int r = system("systemctl daemon-reload && systemctl enable subbridge && systemctl start subbridge");
        if (r == 0) {
            std::println("OK.");
        } else {
            std::println("Failed. Run manually: sudo systemctl start subbridge");
        }
    } else {
        std::string pid_file = get_pid_file_path();
        std::ifstream pf(pid_file);
        if (pf.is_open()) {
            pid_t old_pid = 0;
            if (pf >> old_pid && old_pid > 0 && kill(old_pid, 0) == 0) {
                std::println("Service is already running (PID {}).", old_pid);
                return;
            }
        }

        pid_t pid = fork();
        if (pid < 0) {
            std::println("ERROR: Fork failed.");
            return;
        }
        if (pid > 0) {
            std::ofstream out_pf(pid_file);
            if (out_pf.is_open()) {
                out_pf << pid << "\n";
            }
            std::println("Started SubBridge daemon (PID {}).", pid);
            return;
        }

        setsid();
        umask(0);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        g_IsCon = 0;
        server_loop();
        unlink(pid_file.c_str());
        exit(0);
    }
}

void do_uninstall() {
    if (has_systemd()) {
        std::print("Stopping and removing systemd service... ");
        [[maybe_unused]] int r1 = system("systemctl stop subbridge >/dev/null 2>&1");
        [[maybe_unused]] int r2 = system("systemctl disable subbridge >/dev/null 2>&1");
        unlink("/etc/systemd/system/subbridge.service");
        [[maybe_unused]] int r3 = system("systemctl daemon-reload >/dev/null 2>&1");
        std::println("OK.");
    } else {
        std::string pid_file = get_pid_file_path();
        std::ifstream pf(pid_file);
        if (!pf.is_open()) {
            std::println("Service PID file not found.");
            return;
        }
        pid_t pid = 0;
        if (pf >> pid && pid > 0) {
            kill(pid, SIGTERM);
            for (int i = 0; i < 30; i++) {
                if (kill(pid, 0) != 0) break;
                usleep(100000);
            }
            unlink(pid_file.c_str());
            std::println("Stopped SubBridge daemon (PID {}).", pid);
        } else {
            std::println("Invalid PID file.");
            unlink(pid_file.c_str());
        }
    }
}

void do_restart() {
    if (has_systemd()) {
        std::print("Restarting systemd service... ");
        int r = system("systemctl restart subbridge");
        if (r == 0) {
            std::println("OK.");
        } else {
            std::println("Failed. Run manually: sudo systemctl restart subbridge");
        }
    } else {
        do_uninstall();
        usleep(300000);
        do_install();
    }
}

void sig_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_Stop = 1;
    }
}

void run_console() {
    g_IsCon = 1;
    g_Stop = 0;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    std::println("\n  SubBridge & Subconverter - console mode");
    std::println("  HWID:   {}", g_Dev.hwid);
    std::println("  OS:     {} {}", g_Dev.os, g_Dev.ver);
    std::println("  Model:  {}\n", g_Dev.model);

    server_loop();
    std::println("\nStopped.");
}
#endif

void run_convert(int argc, char **argv) {
    if (argc < 4) {
        std::println("Usage: sub_bridge --convert <target> <url> [output_file]");
        std::println("Targets: clash, singbox, singbox-pc, xray, xray-one");
        return;
    }
    std::string target = argv[2];
    std::string url = argv[3];
    std::string outfile = (argc >= 5) ? argv[4] : "output.txt";

    Route temp_rt{};
    copy_limited(temp_rt.urls[0], sizeof(temp_rt.urls[0]), url.c_str());
    temp_rt.url_count = 1;

    char *body = static_cast<char *>(mem_alloc(BODY_CAP));

    std::string out_payload;
    std::string raw_clash_proxies;
    std::string raw_clash_names;
    std::vector<Proxy> all_proxies;
    std::vector<Rule> all_rules;
    int success_count = 0;

    for (int i = 0; i < temp_rt.url_count; i++) {
        int blen = fetch_url(&temp_rt, body, static_cast<int>(BODY_CAP), nullptr, i);
        if (blen >= 0) {
            success_count++;
            std::string_view payload(body, blen);
            if (target == "clash" && payload.contains("proxies:")) {
                // Extract Native Clash YAML proxies
                size_t p_start = payload.find("proxies:");
                if (p_start != std::string_view::npos) {
                    p_start += 8; // skip 'proxies:'
                    if (p_start < payload.length() && payload[p_start] == '\r') p_start++;
                    if (p_start < payload.length() && payload[p_start] == '\n') p_start++;
                    
                    size_t next_section = std::string_view::npos;
                    size_t search_pos = p_start;
                    while ((search_pos = payload.find('\n', search_pos)) != std::string_view::npos) {
                        search_pos++;
                        if (search_pos < payload.length() && isalpha(static_cast<unsigned char>(payload[search_pos]))) {
                            next_section = search_pos;
                            break;
                        }
                    }
                    size_t p_end = (next_section != std::string_view::npos) ? next_section : payload.length();
                    
                    std::string_view block = payload.substr(p_start, p_end - p_start);
                    
                    std::string filtered_block;
                    size_t search_start = 0;
                    while (true) {
                        size_t name_pos = block.find("- name:", search_start);
                        if (name_pos == std::string_view::npos) break;
                        
                        size_t node_start = name_pos;
                        while (node_start > 0 && (block[node_start - 1] == ' ' || block[node_start - 1] == '\t')) {
                            node_start--;
                        }
                        
                        size_t next_name_pos = block.find("- name:", name_pos + 7);
                        size_t next_node_start = block.length();
                        if (next_name_pos != std::string_view::npos) {
                            next_node_start = next_name_pos;
                            while (next_node_start > node_start && (block[next_node_start - 1] == ' ' || block[next_node_start - 1] == '\t')) {
                                next_node_start--;
                            }
                        }
                        
                        std::string_view node_str = block.substr(node_start, next_node_start - node_start);
                        filtered_block.append(node_str);
                        
                        size_t n_pos = node_str.find("- name:");
                        size_t end_line = node_str.find('\n', n_pos);
                        if (end_line == std::string_view::npos) end_line = node_str.length();
                        size_t val_start = node_str.find_first_not_of(" \t", n_pos + 7);
                        if (val_start != std::string_view::npos && val_start < end_line) {
                            size_t val_end = end_line - 1;
                            while (val_end >= val_start && (node_str[val_end] == ' ' || node_str[val_end] == '\t' || node_str[val_end] == '\r' || node_str[val_end] == '\n')) {
                                val_end--;
                            }
                            if (val_start <= val_end) {
                                std::string_view raw_name = node_str.substr(val_start, val_end - val_start + 1);
                                if (raw_name.length() >= 2 && ((raw_name.front() == '"' && raw_name.back() == '"') ||
                                    (raw_name.front() == '\'' && raw_name.back() == '\''))) {
                                    raw_name = raw_name.substr(1, raw_name.length() - 2);
                                }
                                raw_clash_names += std::format("      - \"{}\"\n", raw_name);
                            }
                        }
                        
                        search_start = next_name_pos;
                    }
                    raw_clash_proxies += filtered_block;
                }
            } else {
                std::string_view decoded;
                size_t first_char = payload.find_first_not_of(" \t\r\n");
                std::string decoded_buf;
                if (first_char != std::string_view::npos && (payload[first_char] == '[' || payload[first_char] == '{')) {
                    decoded = payload;
                } else if (payload.contains("proxies:")) {
                    decoded = payload;
                } else {
                    if (payload.contains("://")) {
                        decoded = payload;
                    } else {
                        decoded_buf = base64_decode(payload);
                        decoded = decoded_buf;
                    }
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
                while (!raw_clash_proxies.empty() && isspace(static_cast<unsigned char>(raw_clash_proxies.back()))) {
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
        } else if (target == "xray-one" || target == "xray-json" || target == "v2ray-json") {
            out_payload = gen_xray(all_proxies, "", all_rules);
        } else {
            out_payload = gen_v2ray(all_proxies);
        }
        
        std::ofstream out_file(outfile, std::ios::binary);
        if (out_file.is_open()) {
            out_file.write(out_payload.data(), out_payload.length());
            std::println("Successfully converted to {}", outfile);
        } else {
            std::println("Error writing to {}", outfile);
        }
    } else {
        std::println("Error fetching URL");
    }
    mem_free(body);
}

int main(int argc, char **argv) {
#ifdef _WIN32
    GetModuleFileNameA(nullptr, g_ExeDir, MAX_PATH);
    char *last_slash = strrchr(g_ExeDir, '\\');
    if (last_slash) *last_slash = '\0';
#else
    std::string exe_path = get_self_exe_path();
    if (!exe_path.empty()) {
        safe_strncpy(g_ExeDir, fs::path(exe_path).parent_path().string().c_str());
    } else {
        safe_strncpy(g_ExeDir, ".");
    }
#endif

    dev_gather();
    load_config();

    if (argc > 1) {
        std::string_view a = argv[1];
        if (iequals(a, "--version") || iequals(a, "-version") || iequals(a, "-v") || iequals(a, "/version")) {
            print_version();
            return 0;
        }
        if (iequals(a, "--install") || iequals(a, "-install") || iequals(a, "/install")) {
            do_install();
            return 0;
        }
        if (iequals(a, "--uninstall") || iequals(a, "-uninstall") || iequals(a, "/uninstall") ||
            iequals(a, "--remove") || iequals(a, "-remove")) {
            do_uninstall();
            return 0;
        }
        if (iequals(a, "--restart") || iequals(a, "-restart") || iequals(a, "/restart")) {
            do_restart();
            return 0;
        }
        if (iequals(a, "--console") || iequals(a, "-console") || iequals(a, "/console") || iequals(a, "-c")) {
            run_console();
            return 0;
        }
        if (iequals(a, "--convert") || iequals(a, "-convert") || iequals(a, "/convert")) {
            run_convert(argc, argv);
            return 0;
        }

        fs::path prog_path(argv[0]);
        std::string prog_name = prog_path.filename().string();
        if (prog_name.empty()) prog_name = "sub_bridge";
#ifndef _WIN32
        std::string prog_cmd = "./" + prog_name;
#else
        std::string prog_cmd = ".\\" + prog_name;
#endif

        std::println("Subscription Bridge & Embedded Subconverter\n");
        std::println("  {} --install                      install + start service", prog_cmd);
        std::println("  {} --uninstall                    stop + remove service", prog_cmd);
        std::println("  {} --restart                      restart service", prog_cmd);
        std::println("  {} --console                      run in foreground", prog_cmd);
        std::println("  {} --convert <target> <url> [file] static file convert", prog_cmd);
        std::println("  {} --version                      show version information", prog_cmd);
        return 1;
    }

#ifdef _WIN32
    SERVICE_TABLE_ENTRYA tbl[] = { { const_cast<char *>(SVC_NAME), svc_main }, { nullptr, nullptr } };
    if (!StartServiceCtrlDispatcherA(tbl)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::println("Not launched by SCM.");
            std::println("  Use  --console   to run interactively");
            std::println("  Use  --install   to install as a service");
            std::println("  Use  --restart   to restart the service");
        }
    }
#else
    std::println("SubBridge - Local Subscription Bridge & Subconverter\n");
    std::println("  Use  --console   to run interactively");
    std::println("  Use  --install   to install as a background service");
    std::println("  Use  --restart   to restart the service");
    std::println("  Use  --version   to show version");
#endif
    return 0;
}

