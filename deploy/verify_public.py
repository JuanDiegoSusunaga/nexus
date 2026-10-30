"""Consulta los cuatro endpoints con el cliente nativo y registra evidencia pública."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
from prepare import endpoint


def verify(binary, genesis, peers, allow_nonpublic=False, timeout=90):
    peers = [endpoint(value, allow_nonpublic) for value in peers]
    if len(peers) != 4 or len(set(peers)) != 4:
        raise ValueError("Se requieren cuatro endpoints distintos")
    deadline = time.monotonic() + timeout
    observations = []
    while time.monotonic() < deadline:
        statuses = []
        for peer in peers:
            result = subprocess.run([str(binary), "testnet", "status", "--genesis", str(genesis), "--node", peer],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                raise RuntimeError(f"No se pudo verificar {peer}: {result.stderr[-2000:]}")
            statuses.append(json.loads(result.stdout))
        identities = [status["attested_by_validator"] for status in statuses]
        if set(identities) != {0, 1, 2, 3}:
            raise ValueError("Los endpoints no acreditan cuatro identidades distintas del comité")
        observations.append({"utc": datetime.now(timezone.utc).isoformat(), "statuses": statuses})
        heights = {status["height"] for status in statuses}
        if len(heights) == 1 and next(iter(heights)) > 0:
            roots = {status["state_root"] for status in statuses}
            if len(roots) != 1:
                raise ValueError("Los certificados de la misma altura discrepan en raíz")
            return {"schema": 1, "endpoints": peers, "observations": observations,
                    "common_height": next(iter(heights)), "state_root": next(iter(roots)),
                    "scope": "Consultas autenticadas y certificados BFT verificados por CLI; no replay de toda la historia",
                    "independent_external_origin_confirmed": False}
        time.sleep(0.25)
    raise TimeoutError("No se observó una altura certificada común dentro del plazo")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--endpoint", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-nonpublic", action="store_true")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("La salida ya existe; no se reemplaza evidencia previa")
    try:
        result = verify(args.binary.resolve(), args.genesis.resolve(), args.endpoint, args.allow_nonpublic)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except (ValueError, OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Verificación incompleta: {error}\n")
    print(json.dumps({"common_height": result["common_height"], "out": str(args.out)}))


if __name__ == "__main__":
    main()
