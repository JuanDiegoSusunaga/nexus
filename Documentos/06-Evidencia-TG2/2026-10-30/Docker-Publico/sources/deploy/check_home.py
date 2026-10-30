"""Verifica firmas y una transferencia real usando el adaptador HTTP/HTTPS."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from home_connect import Adapter
from verify_public import verify

WORKSPACE = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=WORKSPACE / "target/home-testnet")
    parser.add_argument("--binary", type=Path, default=WORKSPACE / "target/debug" / ("nexus.exe" if os.name == "nt" else "nexus"))
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("La evidencia ya existe; elegir otro archivo")
    root, binary = args.root.resolve(), args.binary.resolve()
    servers, threads = [], []
    try:
        for index in range(4):
            servers.append(Adapter(("127.0.0.1", 0), args.url, index, args.url.startswith("http://127.0.0.1:")))
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        peers = [f"127.0.0.1:{server.server_address[1]}" for server in servers]
        witness = verify(binary, root / "genesis.json", peers, True)
        recipient = os.urandom(32).hex()

        def cli(index, operation, *extra):
            command = [str(binary), "testnet", operation, "--genesis", str(root / "genesis.json"),
                       "--node", peers[index], *map(str, extra)]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                raise RuntimeError(result.stderr.decode("utf-8", errors="replace")[-2000:])
            return json.loads(result.stdout)

        accepted = cli(0, "transfer", "--key", root / "keys/faucet.key", "--to", recipient, "--amount", "1.25")
        if accepted.get("state") != "pending":
            raise ValueError("La operación no fue admitida")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            accounts = [cli(index, "account", "--address", recipient) for index in range(4)]
            if all(value["balance_raw"] == "1250000000000000000" for value in accounts):
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("La transferencia no se incluyó en los cuatro nodos")
        report = {"success": True, "url": args.url, "verification_origin": "same host",
                  "genesis": json.loads((root / "home.json").read_text(encoding="utf-8"))["genesis"],
                  "witness": witness, "transaction": accepted["hash"], "recipient": recipient,
                  "amount_raw": "1250000000000000000", "accounts": accounts}
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"success": True, "common_height": witness["common_height"],
                          "transaction": accepted["hash"], "out": str(args.out)}), flush=True)
    finally:
        for server in servers[:len(threads)]:
            server.shutdown()
        for server in servers:
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
