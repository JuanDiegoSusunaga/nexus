"""Genera configuraciones de cuatro nodos sin copiar ninguna clave privada."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re


def endpoint(text, allow_nonpublic=False):
    if text.startswith("["):
        host, separator, port = text[1:].partition("]:")
    else:
        host, separator, port = text.rpartition(":")
    if not separator or not port.isascii() or not port.isdigit() or not 1024 <= int(port) <= 65535:
        raise ValueError("Se requiere una IP literal y un puerto entre 1024 y 65535")
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast or (not allow_nonpublic and not address.is_global):
        raise ValueError("El endpoint público debe ser una IP global; --allow-nonpublic es solo para plantillas/ensayos")
    return f"[{address}]:{int(port)}" if address.version == 6 else f"{address}:{int(port)}"


def service(image, genesis, key, peers, published_port, bind_host="0.0.0.0", memory_limit="1g"):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Se requiere el ID inmutable de la imagen: sha256 y 64 dígitos hexadecimales")
    if memory_limit not in {"512m", "1g"}:
        raise ValueError("Los límites de memoria admitidos son 512m y 1g")
    command = ["testnet", "run", "--genesis", "/etc/nexus/genesis.json", "--data-dir",
               "/var/lib/nexus/chain", "--key", "/run/secrets/validator.key",
               "--listen", "0.0.0.0:19001", "--poll-ms", "300"]
    for peer in peers:
        command.extend(["--peer", peer])
    return {
        "image": image, "pull_policy": "never", "user": "10001:10001", "init": True,
        "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "pids_limit": 128, "mem_limit": memory_limit, "cpus": 1.0,
        "restart": "unless-stopped", "stop_signal": "SIGINT", "stop_grace_period": "30s",
        "command": command,
        "ports": [{"target": 19001, "published": str(published_port), "host_ip": bind_host, "protocol": "tcp"}],
        "volumes": [
            {"type": "bind", "source": str(genesis), "target": "/etc/nexus/genesis.json", "read_only": True,
             "bind": {"create_host_path": False}},
            {"type": "bind", "source": str(key), "target": "/run/secrets/validator.key", "read_only": True,
             "bind": {"create_host_path": False}},
            {"type": "volume", "source": "data", "target": "/var/lib/nexus"},
        ],
        "tmpfs": ["/tmp:size=16m,nosuid,nodev,noexec"],
        "healthcheck": {"test": ["CMD", "/usr/local/bin/nexus", "testnet", "status", "--genesis",
                                 "/etc/nexus/genesis.json", "--node", "127.0.0.1:19001"],
                        "interval": "15s", "timeout": "10s", "retries": 3, "start_period": "30s"},
        "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
    }


def prepare(genesis, out, endpoints, image, allow_nonpublic=False, memory_limit="1g"):
    endpoints = [endpoint(value, allow_nonpublic) for value in endpoints]
    if len(endpoints) != 4 or len(set(endpoints)) != 4:
        raise ValueError("Deben especificarse cuatro endpoints distintos")
    raw = genesis.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("El génesis supera 1 MiB")
    document = json.loads(raw)
    if set(document) != {"protocol_version", "genesis_hash", "network_domain", "committee_context", "config"}:
        raise ValueError("El documento debe contener únicamente los campos del génesis público")
    if set(document["config"]) != {"anchor", "monetary", "validators", "proposal_future_ms"}:
        raise ValueError("La configuración contiene campos desconocidos")
    if document["protocol_version"] != 4 or len(document["config"]["validators"]) != 4:
        raise ValueError("Se requiere un génesis NEXUS de protocolo 4 con cuatro validadores")
    for key in document["config"]["validators"]:
        if set(key) != {"bytes", "scheme"} or key["scheme"] != "Dilithium3" or len(key["bytes"]) != 1952:
            raise ValueError("Se requieren cuatro claves públicas ML-DSA-65 canónicas")
    genesis_hash = document["genesis_hash"]
    if not isinstance(genesis_hash, list) or len(genesis_hash) != 32 or any(type(v) is not int or not 0 <= v < 256 for v in genesis_hash):
        raise ValueError("El hash de génesis debe contener 32 bytes")
    project = "nexus-" + bytes(genesis_hash).hex()[:16]
    # La comprobación criptográfica completa corresponde al cargador nativo de NEXUS.
    for index in range(4):
        service(image, "./genesis.json", "./validator.key", endpoints[:index] + endpoints[index + 1:], 19001,
                memory_limit=memory_limit)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {"schema": 1, "protocol": 4, "bft_journal": 2, "image_id": image,
                "genesis_sha256": hashlib.sha256(raw).hexdigest(), "genesis_hash": document["genesis_hash"],
                "endpoints": endpoints, "public_addresses_required": not allow_nonpublic,
                "contains_private_keys": False, "memory_limit": memory_limit, "nodes": []}
    for index, address in enumerate(endpoints):
        folder = out / f"node-{index}"
        folder.mkdir(mode=0o700)
        (folder / "genesis.json").write_bytes(raw)
        port = int(address.rsplit(":", 1)[1])
        node = service(image, "./genesis.json", "./validator.key",
                       endpoints[:index] + endpoints[index + 1:], port, memory_limit=memory_limit)
        compose = {"name": f"{project}-v{index}", "services": {"node": node}, "volumes": {"data": {}}}
        (folder / "compose.json").write_text(json.dumps(compose, indent=2) + "\n", encoding="utf-8")
        manifest["nodes"].append({"index": index, "endpoint": address,
                                  "validator_public_key": document["config"]["validators"][index],
                                  "separate_secret_source": f"validator-{index}.key",
                                  "secret_destination_on_its_host": "validator.key"})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--endpoint", action="append", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--allow-nonpublic", action="store_true")
    parser.add_argument("--memory-limit", choices=["512m", "1g"], default="1g")
    args = parser.parse_args()
    try:
        manifest = prepare(args.genesis, args.out, args.endpoint, args.image_id, args.allow_nonpublic, args.memory_limit)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"No se pudo preparar el despliegue: {error}\n")
    print(json.dumps({"out": str(args.out), "nodes": len(manifest["nodes"]), "contains_private_keys": False}))


if __name__ == "__main__":
    main()
