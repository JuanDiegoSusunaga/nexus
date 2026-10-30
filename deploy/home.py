"""Prepara y controla NEXUS en Docker local con publicación temporal opcional."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import time
import urllib.request
from prepare import service
from test_containers import choose_subnet, run

WORKSPACE = Path(__file__).resolve().parents[1]
CLOUDFLARED = "cloudflare/cloudflared:2026.10.6@sha256:004d843fa5fdc3103983fd580ee19fab4a8fa98add31f87249c1659e848c98e0"


def prepare_home(root, binary, base_port, gateway_port):
    if root.exists():
        raise ValueError("El directorio ya existe: conserva su génesis/diarios y usa start/status/stop")
    nexus_image = run(["docker", "inspect", "nexus-testnet:protocol4-journal2", "--format", "{{.Id}}"]).stdout.strip()
    gateway_image = run(["docker", "inspect", "nexus-home-gateway:1", "--format", "{{.Id}}"]).stdout.strip()
    reservations = []
    try:
        for port in [*range(base_port, base_port + 4), gateway_port]:
            listener = socket.socket()
            listener.bind(("127.0.0.1", port))
            reservations.append(listener)
    finally:
        for listener in reservations:
            listener.close()
    subnet = choose_subnet()
    root.mkdir(mode=0o700, parents=True)
    initial = json.loads(run([binary, "testnet", "init", "--out", root / "keys", "--block-time-ms", "5000"]).stdout)
    genesis = root / "genesis.json"
    genesis.write_bytes((root / "keys/genesis.json").read_bytes())
    project = "nexus-home-" + initial["genesis"][:16]
    peers = [f"{subnet.network_address + 10 + index}:19001" for index in range(4)]
    services = {}
    for index in range(4):
        node = service(nexus_image, genesis.as_posix(), (root / f"keys/validator-{index}.key").as_posix(),
                       peers[:index] + peers[index + 1:], base_port + index, "127.0.0.1", "512m")
        node["volumes"][-1]["source"] = f"data-{index}"
        node["networks"] = {"testnet": {"ipv4_address": str(subnet.network_address + 10 + index)}}
        services[f"node-{index}"] = node
    command = ["--genesis", "/etc/nexus/genesis.json"]
    for peer in peers:
        command.extend(["--backend", peer])
    services["gateway"] = {
        "image": gateway_image, "pull_policy": "never", "user": "10001:10001", "init": True,
        "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "mem_limit": "256m", "pids_limit": 64, "cpus": 1.0, "restart": "unless-stopped",
        "command": command, "networks": ["testnet"],
        "ports": [{"host_ip": "127.0.0.1", "published": str(gateway_port), "target": 8080}],
        "volumes": [{"type": "bind", "source": genesis.as_posix(), "target": "/etc/nexus/genesis.json",
                     "read_only": True, "bind": {"create_host_path": False}}],
        "tmpfs": ["/tmp:size=16m,nosuid,nodev,noexec"],
        "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
    }
    services["tunnel"] = {
        "image": CLOUDFLARED, "profiles": ["internet"], "user": "65532:65532", "read_only": True,
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "mem_limit": "256m", "pids_limit": 64,
        "restart": "unless-stopped", "networks": ["testnet"],
        "command": ["tunnel", "--no-autoupdate", "--protocol", "http2", "--edge-ip-version", "4",
                    "--url", "http://gateway:8080", "--metrics", "127.0.0.1:2000"],
        "tmpfs": ["/tmp:size=16m,nosuid,nodev,noexec"],
        "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
    }
    compose = {"name": project, "services": services,
               "volumes": {f"data-{index}": {} for index in range(4)},
               "networks": {"testnet": {"ipam": {"config": [{"subnet": str(subnet)}]}}}}
    (root / "compose.json").write_text(json.dumps(compose, indent=2) + "\n", encoding="utf-8")
    info = {"schema": 1, "project": project, "protocol": 4, "journal": 2, "scope": "Docker en una máquina",
            "genesis": initial["genesis"], "network_domain": initial["network_domain"],
            "faucet_address": initial["faucet"], "nexus_image": nexus_image, "gateway_image": gateway_image,
            "genesis_file_sha256": hashlib.sha256(genesis.read_bytes()).hexdigest(),
            "base_port": base_port, "gateway_port": gateway_port, "subnet": str(subnet)}
    (root / "home.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "start", "publish", "status", "stop", "refresh-gateway"])
    parser.add_argument("--root", type=Path, default=WORKSPACE / "target/home-testnet")
    parser.add_argument("--binary", type=Path, default=WORKSPACE / "target/debug" / ("nexus.exe" if os.name == "nt" else "nexus"))
    parser.add_argument("--base-port", type=int, default=19001)
    parser.add_argument("--gateway-port", type=int, default=18080)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == "prepare":
        if not 1024 <= args.base_port <= 65532 or not 1024 <= args.gateway_port <= 65535:
            parser.error("Puertos inválidos")
        value = prepare_home(root, args.binary.resolve(), args.base_port, args.gateway_port)
        run(["docker", "compose", "-f", root / "compose.json", "config", "--quiet"])
        print(json.dumps(value), flush=True)
        return
    info = json.loads((root / "home.json").read_text(encoding="utf-8"))
    if hashlib.sha256((root / "genesis.json").read_bytes()).hexdigest() != info["genesis_file_sha256"]:
        raise ValueError("El génesis local cambió; no se arranca otra cadena")
    command = ["docker", "compose", "-f", root / "compose.json"]
    if args.command == "refresh-gateway":
        native = run(["docker", "inspect", "nexus-testnet:protocol4-journal2", "--format", "{{.Id}}"]).stdout.strip()
        if native != info["nexus_image"]:
            raise ValueError("Cambió la imagen de NEXUS: no se actualiza la pasarela automáticamente")
        gateway = run(["docker", "inspect", "nexus-home-gateway:1", "--format", "{{.Id}}"]).stdout.strip()
        configuration = json.loads((root / "compose.json").read_text(encoding="utf-8"))
        configuration["services"]["gateway"]["image"] = gateway
        (root / "compose.json").write_text(json.dumps(configuration, indent=2) + "\n", encoding="utf-8")
        run([*command, "up", "-d", "--no-deps", "gateway"], timeout=90)
        info["gateway_image"] = gateway
        (root / "home.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    elif args.command in {"start", "publish"}:
        if args.command == "publish":
            command.extend(["--profile", "internet"])
        run([*command, "up", "-d"], timeout=90)
    elif args.command == "stop":
        run([*command, "--profile", "internet", "down"], timeout=90)
        print(json.dumps({"stopped": True, "volumes_preserved": True}))
        return
    elif args.command == "status":
        run([*command, "ps"])
    result = {"project": info["project"], "gateway": f"http://127.0.0.1:{info['gateway_port']}",
              "genesis": info["genesis"], "public_url": None}
    if args.command in {"publish", "status", "refresh-gateway"}:
        for _ in range(45 if args.command == "publish" else 1):
            logs = run([*command, "logs", "--no-color", "--tail", "80", "tunnel"], check=False).stdout
            urls = re.findall(r"https://[a-z0-9-]+\.trycloudflare\.com", logs)
            urls = [value for value in urls if value.split("//")[1].split(".")[0] != "api"]
            if urls:
                result["public_url"] = urls[-1]
                break
            time.sleep(1)
        if args.command == "publish" and not result["public_url"]:
            raise RuntimeError("El túnel sigue sin URL: revisar sus logs sin reiniciar la cadena")
        if result["public_url"]:
            (root / "publication.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
