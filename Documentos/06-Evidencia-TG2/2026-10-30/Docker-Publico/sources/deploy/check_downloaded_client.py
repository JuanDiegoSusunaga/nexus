"""Cliente aislado: descarga solo artefactos públicos y verifica cuatro validadores."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(args.expected)
    if not args.url.startswith("https://"):
        raise ValueError("Se requiere un origen HTTPS")
    with tempfile.TemporaryDirectory() as directory:
        folder = Path(directory)
        paths = {"genesis.json": "/genesis.json", "home_connect.py": "/client/home_connect.py",
                 "home_transport.py": "/client/home_transport.py", "nexus-linux-amd64": "/client/nexus-linux-amd64"}
        for name, path in paths.items():
            with urllib.request.urlopen(args.url + path, timeout=25) as response:
                content = response.read(8 * 1024 * 1024 + 1)
            if len(content) > 8 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != expected[name]:
                raise ValueError(f"La huella de {name} no coincide con la fijada por el operador")
            (folder / name).write_bytes(content)
        binary = folder / "nexus-linux-amd64"
        binary.chmod(0o500)
        sys.path.insert(0, str(folder))
        specification = importlib.util.spec_from_file_location("downloaded_adapter", folder / "home_connect.py")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        servers, threads = [], []
        try:
            for index in range(4):
                servers.append(module.Adapter(("127.0.0.1", 0), args.url, index))
            for server in servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            observations = []
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                statuses = []
                for server in servers:
                    port = server.server_address[1]
                    result = subprocess.run([str(binary), "testnet", "status", "--genesis", str(folder / "genesis.json"),
                        "--node", f"127.0.0.1:{port}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    if result.returncode:
                        raise RuntimeError(result.stderr.decode(errors="replace"))
                    statuses.append(json.loads(result.stdout))
                if {value["attested_by_validator"] for value in statuses} != {0, 1, 2, 3}:
                    raise ValueError("No se verificaron cuatro identidades")
                observations.append(statuses)
                if len({value["height"] for value in statuses}) == 1 and len({value["state_root"] for value in statuses}) == 1:
                    break
            else:
                raise TimeoutError("No se observó raíz certificada común")
            report = {"success": True, "origin": "isolated Docker client on same host", "url": args.url,
                      "private_key_mounts": False, "artifact_sha256": expected,
                      "common_height": statuses[0]["height"], "state_root": statuses[0]["state_root"],
                      "observations": observations}
            with args.out.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
            print(json.dumps({"success": True, "common_height": report["common_height"], "private_keys": False}), flush=True)
        finally:
            for server in servers[:len(threads)]:
                server.shutdown()
            for server in servers:
                server.server_close()


if __name__ == "__main__":
    main()
