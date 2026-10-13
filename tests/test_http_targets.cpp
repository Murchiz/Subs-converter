#include "generator.h"
#include "server.h"
#include "utils.h"
#include <cassert>
#include <string>
#include <string_view>

// POSIX socket pairs exercise the HTTP handler without a listening server or
// external network access. All successful conversions use synthetic fixtures.
static std::string request(std::string_view target, std::string_view source) {
    int sockets[2]{};
    const int status = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    assert(status == 0);
    const std::string req = "GET /sub?target=" + url_encode(target) + "&url=" +
                            url_encode(source) + " HTTP/1.1\r\n\r\n";
    handle_subconverter(sockets[0], req);
    shutdown(sockets[0], SHUT_WR);
    std::string response;
    char buffer[4096]{};
    for (;;) {
        const auto length = recv(sockets[1], buffer, sizeof(buffer), 0);
        assert(length >= 0);
        if (length == 0) break;
        response.append(buffer, static_cast<std::size_t>(length));
    }
    close(sockets[0]);
    close(sockets[1]);
    return response;
}

int main() {
    const auto rejected = request("unsupported-target", "missing-file.txt");
    assert(rejected.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert(rejected.ends_with("Unsupported conversion target\n"));

    constexpr std::string_view fixture = "tests/reference/grpc_reality_uri.txt";
    for (const auto target : supported_targets) {
        const auto response = request(target, fixture);
        assert(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(response.find('\0') == std::string::npos);
    }
    const auto raw = request("", fixture);
    assert(raw.starts_with("HTTP/1.1 200 OK\r\n"));
    assert(raw.contains("vless://"));
    std::println("HTTP target validation passed.");
}
