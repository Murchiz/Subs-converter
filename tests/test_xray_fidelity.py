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

    print("Xray balancer and gRPC/Reality CLI fidelity checks passed.")


if __name__ == "__main__":
    main()
