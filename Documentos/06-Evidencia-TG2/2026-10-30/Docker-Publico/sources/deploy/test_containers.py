"""Ensayo acotado de cuatro contenedores Linux con cliente nativo y diarios persistentes."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from prepare import prepare, service
from verify_public import verify

WORKSPACE = Path(__file__).resolve().parents[1]
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run(command, check=True, timeout=45):
    result = subprocess.run([str(value) for value in command], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        creationflags=HIDDEN, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Fallo de comando ({result.returncode}): {result.stdout[-2000:]} {result.stderr[-4000:]}")
    return result


def wait_for(function, description, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = function()
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError(f"Se agotó el plazo: {description}")


def choose_subnet():
    identifiers = run(["docker", "network", "ls", "-q"]).stdout.split()
    networks = json.loads(run(["docker", "network", "inspect", *identifiers]).stdout) if identifiers else []
    used = [ipaddress.ip_network(config["Subnet"]) for network in networks
            for config in ((network.get("IPAM") or {}).get("Config") or []) if config.get("Subnet")]
    for index in range(256):
        candidate = ipaddress.ip_network(f"10.240.{index}.0/24")
        if not any(item.version == 4 and candidate.overlaps(item) for item in used):
            return candidate
    raise RuntimeError("No hay una subred de ensayo libre; no se modifican las redes existentes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=WORKSPACE / "target/debug" / ("nexus.exe" if os.name == "nt" else "nexus"))
    parser.add_argument("--image", default="nexus-testnet:protocol4-journal2")
    parser.add_argument("--memory-limit", choices=["512m", "1g"], default="1g")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error("Falta el cliente nativo compilado")
    image = run(["docker", "image", "inspect", args.image, "--format", "{{.Id}} {{.Os}} {{.Architecture}}"]).stdout.strip().split()
    image_id, operating_system, architecture = image
    assert operating_system == "linux" and architecture == "amd64", image
    root = WORKSPACE / "target/container-process-tests" / f"{os.getpid()}-{time.time_ns()}"
    root.mkdir(parents=True)
    public = json.loads(run([binary, "testnet", "init", "--out", root / "lab"]).stdout)
    genesis = root / "lab/genesis.json"
    subnet = choose_subnet()
    addresses = [str(subnet.network_address + 10 + index) for index in range(4)]
    peers = [f"{address}:19001" for address in addresses]
    # La plantilla resultante es revisable y no contiene archivos privados.
    prepare(genesis, root / "bundle", [f"198.51.100.{10 + n}:19001" for n in range(4)], image_id, True, args.memory_limit)
    reservations = []
    try:
        for _ in range(4):
            connection = socket.socket()
            connection.bind(("127.0.0.1", 0))
            reservations.append(connection)
        ports = [connection.getsockname()[1] for connection in reservations]
    finally:
        for connection in reservations:
            connection.close()
    services = {}
    for index in range(4):
        node = service(image_id, genesis.as_posix(), (root / f"lab/validator-{index}.key").as_posix(),
                       peers[:index] + peers[index + 1:], ports[index], "127.0.0.1", args.memory_limit)
        node["volumes"][-1]["source"] = f"data-{index}"
        node["networks"] = {"testnet": {"ipv4_address": addresses[index]}}
        services[f"node-{index}"] = node
    compose = {"services": services, "volumes": {f"data-{i}": {} for i in range(4)},
               "networks": {"testnet": {"ipam": {"config": [{"subnet": str(subnet)}]}}}}
    compose_path = root / "compose.json"
    compose_path.write_text(json.dumps(compose, indent=2) + "\n", encoding="utf-8")
    project = f"nexus-linux-{os.getpid()}-{time.time_ns()}"
    base = ["docker", "compose", "-p", project, "-f", compose_path]

    def cli(index, operation, *extra):
        result = run([binary, "testnet", operation, "--genesis", genesis, "--node", f"127.0.0.1:{ports[index]}", *extra], False, 15)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def heights(indices, minimum):
        statuses = [cli(index, "status") for index in indices]
        return statuses if all(status and status["height"] >= minimum for status in statuses) else None

    recipient = os.urandom(32).hex()

    def balance(indices, expected):
        accounts = [cli(index, "account", "--address", recipient) for index in indices]
        return accounts if all(account and int(account["balance_raw"]) == expected for account in accounts) else None

    def transfer(text):
        accepted = cli(0, "transfer", "--key", root / "lab/faucet.key", "--to", recipient, "--amount", text)
        assert accepted and accepted["state"] == "pending", accepted
        return accepted["hash"]

    report = {"scope": "Docker Desktop, cuatro contenedores Linux amd64 y cliente Windows; no Internet",
              "image_id": image_id, "protocol": 4, "journal": 2, "ports": ports,
              "subnet": str(subnet),
              "memory_limit": args.memory_limit,
              "genesis": public["genesis"], "network_domain": public["network_domain"], "success": False}
    print(f"Inicia ensayo Linux: {root}", flush=True)
    try:
        run([*base, "config", "--quiet"])
        run([*base, "up", "-d"], timeout=90)
        statuses = wait_for(lambda: heights(range(4), 2), "arranque y quórum inicial")
        assert {status["attested_by_validator"] for status in statuses} == {0, 1, 2, 3}
        ids = run([*base, "ps", "-q"]).stdout.split()
        inspected = json.loads(run(["docker", "inspect", *ids]).stdout)
        for item in inspected:
            assert item["Image"] == image_id
            assert item["Config"]["User"] == "10001:10001"
            assert item["HostConfig"]["ReadonlyRootfs"]
            assert item["HostConfig"]["Memory"] == (512 * 1024 * 1024 if args.memory_limit == "512m" else 1024 ** 3)
            assert "ALL" in item["HostConfig"]["CapDrop"]
            assert any(value in {"no-new-privileges", "no-new-privileges:true"} for value in item["HostConfig"]["SecurityOpt"])
            key_mounts = [mount for mount in item["Mounts"] if mount["Destination"] == "/run/secrets/validator.key"]
            assert len(key_mounts) == 1 and not key_mounts[0]["RW"]
        report["isolated_validators"] = len(inspected)
        run([*base, "exec", "-T", "node-0", "sh", "-c", "test ! -e /src && test ! -e /usr/local/cargo && test $(id -u) = 10001"])
        report["runtime_excludes_build_sources_and_cargo"] = True
        witness = verify(binary, genesis, [f"127.0.0.1:{port}" for port in ports], True)
        (root / "verified-queries.json").write_text(json.dumps(witness, indent=2) + "\n", encoding="utf-8")
        report["common_certified_height"] = witness["common_height"]
        report["initial_heights"] = [status["height"] for status in statuses]
        hashes = [transfer("1.25")]
        wait_for(lambda: balance(range(4), 1_250_000_000_000_000_000), "primera transferencia")
        previous = cli(0, "status")["height"]
        run([*base, "kill", "-s", "SIGKILL", "node-3"])
        progressed = wait_for(lambda: heights(range(3), previous + 2), "avance con tres contenedores")
        report["three_node_heights"] = [status["height"] for status in progressed]
        run([*base, "kill", "-s", "SIGKILL", "node-2"])
        time.sleep(1)
        hashes.append(transfer("0.75"))
        before = cli(0, "status")["height"]
        time.sleep(4)
        assert cli(0, "status")["height"] == before
        assert balance(range(2), 1_250_000_000_000_000_000)
        report["two_node_transfer_stayed_pending"] = True
        run([*base, "start", "node-2"])
        wait_for(lambda: balance(range(3), 2_000_000_000_000_000_000), "recuperación del tercer contenedor")
        run([*base, "start", "node-3"])
        wait_for(lambda: balance(range(4), 2_000_000_000_000_000_000), "sincronización del cuarto contenedor")
        final = wait_for(lambda: heights(range(4), before + 1), "altura final")
        report["final_heights"] = [status["height"] for status in final]
        report["burned_raw"] = final[0]["burned_raw"]
        assert int(report["burned_raw"]) > 0
        run([*base, "down"], timeout=90)
        run([*base, "up", "-d"], timeout=90)
        reopened = wait_for(lambda: heights(range(4), min(report["final_heights"])), "reapertura de volúmenes persistentes")
        wait_for(lambda: balance(range(4), 2_000_000_000_000_000_000), "saldo después de recrear contenedores")
        report["reopened_heights"] = [status["height"] for status in reopened]
        report["recipient_balance_raw"] = "2000000000000000000"
        report["transfer_hashes"] = hashes
        live_ids = run([*base, "ps", "-q"]).stdout.split()
        statistics = run(["docker", "stats", "--no-stream", "--format", "{{json .}}", *live_ids]).stdout
        report["resource_snapshot"] = [json.loads(line) for line in statistics.splitlines() if line.strip()]
        archive = root / "nexus-testnet-linux.tar"
        run(["docker", "image", "save", "--output", archive, args.image], timeout=120)
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        report["image_archive"] = {"path": archive.name, "bytes": archive.stat().st_size, "sha256": digest.hexdigest()}
        report["success"] = True
    finally:
        logs = run([*base, "logs", "--no-color"], False).stdout
        (root / "containers.log").write_text(logs, encoding="utf-8")
        cleanup = run([*base, "down"], False, 90)
        report["cleanup_exit_code"] = cleanup.returncode
        report["remaining_own_containers"] = run([*base, "ps", "-aq"], False).stdout.split()
        report["volumes_preserved"] = True
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    assert report["cleanup_exit_code"] == 0 and not report["remaining_own_containers"]
    print(json.dumps({"result": str(root / "result.json"), "success": report["success"]}), flush=True)


if __name__ == "__main__":
    main()
