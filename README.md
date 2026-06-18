# Subscription Bridge

Subscription Bridge is a lightweight proxy subscription converter and server bridge. It parses various proxy subscription links (like vmess, vless, trojan, hysteria2, clash, sing-box) and allows merging them or bridging them dynamically.

## Building

This project uses CMake for its build system.

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Running

```bash
# Run in console mode
./sub_bridge.exe -console

# Install as Windows Service
./sub_bridge.exe -install

# Convert a static URL
./sub_bridge.exe -convert clash "http://example.com/sub" output.yaml
```

## Configuration
Configure the bridge using `config.ini`. Look at the provided examples to understand routing and conversion.
