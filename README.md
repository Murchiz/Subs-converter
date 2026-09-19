# SubBridge

[![Build and Release](https://github.com/Murchiz/Subs-converter/actions/workflows/build.yml/badge.svg)](https://github.com/Murchiz/Subs-converter/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/Language-C%2B%2B23-00599C.svg)](https://en.cppreference.com/w/cpp/23)

**SubBridge** is a high-performance, lightweight local proxy subscription converter, aggregator, and bridge written in C++ for Windows and Linux.

It parses and normalizes diverse proxy subscription formats and protocols (VLESS, VMess, Trojan, Shadowsocks, Hysteria 1/2, TUIC, Clash YAML, Sing-box JSON, V2Ray Base64) with zero external heavy dependencies, low memory footprint, and sub-millisecond conversion latency.

---

## ✨ Features

- **Multi-Protocol & Multi-Format Parsing**:
  - Protocols: `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria://`, `hysteria2://`, `tuic://`, `wireguard://`
  - Targets:
    - `clash`: Clash / Mihomo YAML
    - `singbox-android`: Sing-box JSON (Mobile / Android)
    - `singbox-pc`: Sing-box JSON (Desktop / PC with SOCKS & Mixed inbounds)
    - `xray`: Base64-encoded V2Ray / Xray link list
    - `xray-one`: Single consolidated Xray JSON configuration
    - `xray-jsons`: Array of standalone Xray JSON configurations (`[...]`) containing balancers with `burstObservatory` and individual node configs
    - `v2ray`: Base64-encoded V2Ray link list
  - Full routing rule extraction and conversion between Xray/Sing-box rules and Clash rule sets.
- **Smart Balancer Handling & Deduplication**:
  - Automatically identifies and preserves upstream subscription balancers (e.g. leastPing urltest groups).
  - Eliminates duplicate node tags (e.g. `proxy-2`) by mapping balancer members to their respective proxy nodes.
  - Intelligently omits redundant auto-balancer groups if upstream balancers already cover all nodes.
  - Optional `force_balancer` flag to force SubBridge's generic `Auto` group alongside upstream balancers.
- **Subscription Merging**: Aggregate up to 8 upstream subscription links per route into a single unified endpoint.
- **Auto-Spawned Conversion Ports**: Specify `converts = clash, singbox-android, singbox-pc, xray-jsons` in `config.ini` to automatically spin up dedicated converted endpoints on consecutive local ports.
- **Subconverter Compatible API**: Built-in HTTP endpoint on port `25500` compatible with standard subconverter clients (`http://127.0.0.1:25500/sub?target=clash&url=...`).
- **Device Fingerprinting & Spoofing**: Automatic hardware ID (`MachineGuid` / `machine-id`) and OS telemetry gathering with optional per-route spoofing and custom `User-Agent` headers.
- **Flexible Execution Modes**:
  - Run interactively in terminal (`--console`)
  - Run in the background as a Windows Service or Linux systemd daemon (`--install`, `--uninstall`, `--restart`)
  - Static one-shot file converter via CLI (`--convert`)
  - Built-in help and version flags (`--help`, `-h`, `--version`, `-v`)

---

## 🛠️ Building from Source

### Prerequisites
- **CMake** (3.20 or newer)
- **Ninja** (recommended)
- **C++23 Compiler**:
  - **Windows**: Visual Studio 2022 / MSVC
  - **Linux**: GCC 14+ or Clang 18+
- **Linux Build Dependencies**:
  - `libcurl` development package (e.g. `sudo apt install -y libcurl4-openssl-dev ninja-build`)
- **Python 3** (optional, for YAML tests)

### Build with CMake Presets (Recommended)

Configure, compile with full optimizations, and run tests:

```bash
# 1. Configure optimized release preset
cmake --preset release

# 2. Build binaries
cmake --build --preset release

# 3. Run test suite
ctest --preset release
```

The optimized executable will be located in `build/release/sub_bridge.exe` (Windows) or `build/release/sub_bridge` (Linux).

---

## ⚙️ Configuration

SubBridge looks for `config.ini` in the same directory as the executable. Copy [`config.ini.example`](config.ini.example) to get started:

```bash
# Windows
Copy-Item config.ini.example config.ini

# Linux
cp config.ini.example config.ini
```

### Configuration Structure

```ini
# [Device] (Optional hardware telemetry override)
[Device]
# hwid = 00000000-0000-0000-0000-000000000000
# os = Windows
# ver = 10.0.22631
# model = Custom PC

# [Sub_<Name>] (Subscription group)
[Sub_Main]
name = MyProxyBundle
port = 25501
hwid = false

# Upstream subscription links (link1 .. link8)
link1 = https://example.com/api/v1/client/subscribe?token=xxx
user_agent1 = Happ/3.23.0

# Force SubBridge generic Auto balancer group even if upstream already provides auto-balancers (default: false)
force_balancer = false

# Automatically expose converted outputs on consecutive ports
# Port 25501 -> Raw / Merged V2Ray Base64
# Port 25502 -> Clash / Mihomo YAML
# Port 25503 -> Sing-Box Android JSON
# Port 25504 -> Sing-Box PC JSON
# Port 25505 -> Xray / V2Ray Share Links (Base64)
# Port 25506 -> Xray Standalone Config JSON
# Port 25507 -> Xray Configs Array JSON ([...])
converts = clash, singbox-android, singbox-pc, xray, xray-one, xray-jsons
```

---

## 🚀 Usage

### 1. Interactive / Console Mode
Run in the foreground with live logging:
```bash
./sub_bridge --console
```

### 2. Service Management Mode
Install, start, restart, or remove SubBridge as a background service:
```bash
# Windows (run as Administrator)
.\sub_bridge.exe --install
.\sub_bridge.exe --restart
.\sub_bridge.exe --uninstall

# Linux (run with sudo)
sudo ./sub_bridge --install
sudo ./sub_bridge --restart
sudo ./sub_bridge --uninstall
```
*Note: On Linux, SubBridge automatically registers a `systemd` service unit if `systemd` is present, or falls back to native daemonization otherwise.*

### 3. One-Shot File Converter
Convert any subscription URL or local file directly into a target configuration:
```bash
# Syntax: ./sub_bridge --convert <target> <url_or_file> [output_file] [--force-balancer]
# Targets: clash, singbox-android, singbox-pc, xray, xray-one, xray-jsons, v2ray

# Convert to Clash YAML
./sub_bridge --convert clash "https://example.com/sub" clash_config.yaml

# Convert to Sing-box JSON (Mobile/Android)
./sub_bridge --convert singbox-android "https://example.com/sub" singbox_android.json

# Convert to Sing-box JSON for Desktop / PC
./sub_bridge --convert singbox-pc "https://example.com/sub" singbox_pc.json

# Convert to native Xray JSONs Array ([...])
./sub_bridge --convert xray-jsons "https://example.com/sub" xray_configs.json

# Force generation of SubBridge Auto balancer group
./sub_bridge --convert clash "https://example.com/sub" clash_config.yaml --force-balancer
```

### 4. Help & Version
```bash
./sub_bridge --help
./sub_bridge --version
```

### 5. Subconverter HTTP Endpoint
When SubBridge is running, connect your proxy client directly to the built-in subconverter port (`25500`):
```text
http://127.0.0.1:25500/sub?target=clash&url=http://127.0.0.1:25501
http://127.0.0.1:25500/sub?target=xray-jsons&url=https://example.com/sub
http://127.0.0.1:25500/sub?target=clash&force_balancer=true&url=https://example.com/sub
```

---

## 🧪 Testing

Run all unit and integration tests:

```bash
ctest --preset release --output-on-failure
```

Tests include:
- `ParserTest`: URI parsing, Base64 decoding, Xray JSON & gRPC node validation, balancer deduplication, Sing-box 1.14+ syntax, and `xray-jsons` generation
- `YamlTest`: Native Clash YAML node extraction, sanitization, and rule conversion
- `PythonYamlTest`: Reference YAML test verification

All tests use synthetic, sanitized dummy data without external dependencies.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
