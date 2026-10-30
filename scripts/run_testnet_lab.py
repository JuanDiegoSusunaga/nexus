"""Ejecuta cuatro nodos de laboratorio sin abrir consolas adicionales de Windows."""
import argparse
from pathlib import Path
import os
import socket
import subprocess
import time


def main():
    workspace = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=workspace / "target/debug" / ("nexus.exe" if os.name == "nt" else "nexus"))
    parser.add_argument("--root", type=Path, default=workspace / "target/testnet-journal-lab")
    parser.add_argument("--base-port", type=int, default=19001)
    parser.add_argument("--seconds", type=int, default=30, help="0 keeps running until Ctrl+C")
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = args.root.resolve()
    if not binary.is_file():
        parser.error("Build nexus-cli first or provide --binary")
    if not 1024 <= args.base_port <= 65532 or args.seconds < 0:
        parser.error("Invalid port range or duration")
    ports = list(range(args.base_port, args.base_port + 4))
    # Evita escuchas duplicadas y no detiene procesos ajenos.
    reserved = []
    try:
        for port in ports:
            listener = socket.socket()
            listener.bind(("127.0.0.1", port))
            reserved.append(listener)
    except OSError as error:
        parser.error(f"A requested port is in use; reuse that instance or choose --base-port: {error}")
    finally:
        for listener in reserved:
            listener.close()
    hidden = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    genesis = root / "genesis-data/genesis.json"
    root.mkdir(parents=True, exist_ok=True)
    if not genesis.exists():
        subprocess.run([str(binary), "testnet", "init", "--out", str(genesis.parent)],
                       check=True, creationflags=hidden)
    for index in range(4):
        if not (genesis.parent / f"validator-{index}.key").is_file():
            parser.error("Missing validator key; no replacement keys are generated for an existing genesis")
    workers = []
    logs = []
    try:
        for index, port in enumerate(ports):
            command = [str(binary), "testnet", "run", "--genesis", str(genesis),
                       "--data-dir", str(root / f"node-{index}"), "--key", str(genesis.parent / f"validator-{index}.key"),
                       "--listen", f"127.0.0.1:{port}", "--poll-ms", "200"]
            for peer in ports:
                if peer != port:
                    command.extend(["--peer", f"127.0.0.1:{peer}"])
            log = (root / f"node-{index}.log").open("ab")
            logs.append(log)
            workers.append(subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                             stderr=subprocess.STDOUT, creationflags=hidden))
        print(f"Four local TEST nodes: {ports}. Logs and state: {root}", flush=True)
        print("Ctrl+C stops only these child processes. Test keys are unencrypted; publish only genesis.json.", flush=True)
        deadline = None if args.seconds == 0 else time.monotonic() + args.seconds
        while deadline is None or time.monotonic() < deadline:
            if any(worker.poll() is not None for worker in workers):
                raise RuntimeError(f"A node exited; inspect the logs in {root}")
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.terminate()
        for worker in workers:
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
