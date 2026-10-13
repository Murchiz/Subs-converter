"""Offline CLI fidelity checks, not an end-to-end client import test."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit


def main():
    executable = str(Path(sys.argv[1]).resolve())
    fixtures = Path(__file__).resolve().parent / "reference"
    source = json.loads((fixtures / "leastload_balancer.json").read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "output.txt"

        def convert(target, fixture):
            subprocess.run(
                [executable, "--convert", target, str(fixtures / fixture), str(output)],
                check=True,
                capture_output=True,
            )
            return output.read_text(encoding="utf-8")

        configs = json.loads(convert("xray-jsons", "leastload_balancer.json"))
        assert configs[0] == source, "Upstream balancer changed during conversion"
        assert len(configs) == 5  # Balancer plus the four expanded member nodes.

        # Check only the generated components. This deliberately does not claim
        # that concatenated JSON + links form a client-compatible subscription.
        mixed = convert("xray-mixed", "leastload_balancer.json").lstrip()
        balancer, end = json.JSONDecoder().raw_decode(mixed)
        assert balancer == source
        links = mixed[end:].strip().splitlines()
        assert len(links) == 4
        for link in links:
            query = parse_qs(urlsplit(link).query)
            assert query["security"] == ["reality"]
            assert query["type"] == ["tcp"]
            assert query["flow"] == ["xtls-rprx-vision"]

        hysteria = json.loads((fixtures / "hysteria2_xray.json").read_text())
        expected = hysteria["outbounds"][0]
        for target in ("xray-jsons", "xray-one", "xray-json", "v2ray-json"):
            result = json.loads(convert(target, "hysteria2_xray.json"))
            if isinstance(result, list):
                assert len(result) == 1
                result = result[0]
            assert result["outbounds"][0] == expected, "Hysteria 2 outbound was changed"

        uri_file = Path(temporary) / "hysteria.txt"
        for scheme in ("hysteria2", "hy2"):
            uri_file.write_text(
                f"{scheme}://dummy-auth@192.0.2.91:443?sni=example.com"
                "&obfs=salamander&obfs-password=dummy-mask#Synthetic\n"
            )
            result = json.loads(convert("xray-one", uri_file))["outbounds"][0]
            assert result["protocol"] == "hysteria"
            assert result["settings"] == {"address": "192.0.2.91", "port": 443, "version": 2}
            stream = result["streamSettings"]
            assert stream["network"] == "hysteria"
            assert stream["hysteriaSettings"] == {"version": 2, "auth": "dummy-auth"}
            assert stream["security"] == "tls"
            assert stream["tlsSettings"]["alpn"] == ["h3"]
            assert stream["finalmask"]["udp"] == [
                {"type": "salamander", "settings": {"password": "dummy-mask"}}
            ]

        # Unsupported Hysteria 1 must not silently turn into VLESS, crash, or
        # overwrite an existing output file with a broken configuration.
        uri_file.write_text("hysteria://dummy-auth@192.0.2.91:443#Synthetic\n")
        output.write_text("keep-existing-output")
        failed = subprocess.run(
            [executable, "--convert", "xray-jsons", str(uri_file), str(output)],
            capture_output=True, text=True,
        )
        assert failed.returncode == 1
        assert "Hysteria 1 is not supported" in failed.stderr
        assert output.read_text() == "keep-existing-output"
        assert base64.b64decode(convert("xray", uri_file)).decode().startswith("hysteria://")

        link = convert("xray-mixed", "grpc_reality_uri.txt")
        encoded = convert("xray", "grpc_reality_uri.txt")
        assert base64.b64decode(encoded, validate=True).decode("utf-8") == link
        query = parse_qs(urlsplit(link.strip()).query)
        assert query["type"] == ["grpc"]
        assert query["serviceName"] == ["synthetic-grpc"]
        assert query["mode"] == ["gun"]
        assert query["security"] == ["reality"]
        assert query["sni"] == ["example.net"]
        assert query["pbk"] == ["dummy-public-key"]

    print("Xray balancer, Hysteria 2 and gRPC/Reality CLI fidelity checks passed.")


if __name__ == "__main__":
    main()
