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
  - Targets: Clash / Mihomo YAML, Sing-Box (Android & PC) JSON, V2Ray Base64, Raw URIs
  - Full routing rule extraction and conversion between Xray/Sing-box rules and Clash rule sets.
- **Subscription Merging**: Aggregate up to 8 upstream subscription links per route into a single unified endpoint.
- **Auto-Spawned Conversion Ports**: Specify `converts = clash, singbox, singbox-pc` to automatically spin up dedicated converted endpoints on consecutive local ports.
- **Subconverter Compatible API**: Built-in HTTP endpoint on port `25500` compatible with standard subconverter clients (`http://127.0.0.1:25500/sub?target=clash&url=...`).
- **Device Fingerprinting & Spoofing**: Automatic hardware ID (`MachineGuid` / `machine-id`) and OS telemetry gathering with optional per-route spoofing and custom `User-Agent` headers.
- **Flexible Execution Modes**:
  - Run interactively in terminal (`--console`)
  - Run in the background as a Windows Service or Linux systemd daemon (`--install`, `--uninstall`, `--restart`)
  - Static one-shot file converter via CLI (`--convert`)
  - Version & build inspection (`--version`)

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
user_agent1 = v2rayng

# Automatically expose converted outputs on consecutive ports
# Port 25501 -> Raw / Merged V2Ray Base64
# Port 25502 -> Clash / Mihomo YAML
# Port 25503 -> Sing-Box Android JSON
# Port 25504 -> Sing-Box PC JSON
# Port 25505 -> Xray / V2Ray Share Links (Base64)
# Port 25506 -> Xray Standalone Config JSON
converts = clash, singbox, singbox-pc, xray, xray-one
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
Convert any subscription URL or file directly into a configuration file:
```bash
# Syntax: ./sub_bridge --convert <target> <url_or_file> [output_file]
# Targets: clash, singbox, singbox-pc, xray, xray-one, v2ray

./sub_bridge --convert clash "https://example.com/sub" clash_config.yaml
./sub_bridge --convert singbox "https://example.com/sub" singbox_config.json
./sub_bridge --convert xray "https://example.com/sub" xray_links.txt
./sub_bridge --convert xray-one "https://example.com/sub" xray_config.json
```

### 4. Check Version
Display version metadata, build time, and repository info:
```bash
./sub_bridge --version
```

### 5. Subconverter HTTP Endpoint
When SubBridge is running, connect your proxy client directly to the built-in subconverter port (`25500`):
```text
http://127.0.0.1:25500/sub?target=clash&url=http://127.0.0.1:25501
```

---

## 🧪 Testing

Run all unit and integration tests:

```bash
ctest --preset release --output-on-failure
```

Tests include:
- `ParserTest`: URI parsing, Base64 decoding, Xray JSON & node parser validation
- `YamlTest`: Native Clash YAML node extraction, sanitization, and rule conversion
- `PythonYamlTest`: Reference YAML test verification

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

