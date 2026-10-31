"""Measure the running Docker LAB with certified transactions and resource samples.

Requires the Rust example testnet_load, the existing public genesis and its TEST
faucet key. Publishes no keys. Results are screening measurements on one host,
not an L1/L2 architecture comparison or a production capacity guarantee.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time


def run(command, timeout=30):
    return subprocess.run(list(map(str, command)), check=True, capture_output=True,
                          text=True, timeout=timeout).stdout


def memory_bytes(text):
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3,
             "kB": 1000, "MB": 1000**2, "GB": 1000**3}
    match = re.fullmatch(r"\s*([0-9.]+)\s*([A-Za-z]+)\s*", text)
    if not match:
        raise ValueError("Unrecognized Docker memory unit")
    value, unit = match.groups()
    return float(value)*units[unit]


def sample(nodes):
    started = time.time_ns()//1_000_000
    stats = run(["docker", "stats", "--no-stream", "--format", "{{json .}}",
                 *[node["id"] for node in nodes]])
    by_id = {item["ID"]: item for item in map(json.loads, stats.splitlines())}
    values = []
    for node in nodes:
        stat = next(v for k, v in by_id.items() if node["id"].startswith(k))
        # Metadata only, inside the data volume; no private-key reads.
        allocated = int(run(["docker", "exec", node["id"], "du", "-sk", "/var/lib/nexus/chain"]).split()[0])*1024
        values.append({"service": node["service"], "cpu_percent": float(stat["CPUPerc"].rstrip("%")),
                       "memory_bytes": memory_bytes(stat["MemUsage"].split("/")[0]),
                       "journal_allocated_bytes": allocated})
    return {"started_unix_ms": started, "finished_unix_ms": time.time_ns()//1_000_000,
            "nodes": values}


def percentile(values, q):
    import math
    values = sorted(values)
    return values[max(0, math.ceil(len(values)*q)-1)] if values else None


def summarize(load, samples):
    groups = []
    for concurrency in (1, 8, 32):
        phases = [p for p in load["phases"] if p["concurrency"] == concurrency]
        if not phases:
            continue
        receipts = [r for p in phases for r in p["receipts"]]
        latencies = [r["confirmation_ms"] for r in receipts]
        resources = [s for s in samples if any(
            p["started_unix_ms"] <= s["started_unix_ms"] and
            s["finished_unix_ms"] <= p["finished_unix_ms"] for p in phases)]
        node_samples = [n for s in resources for n in s["nodes"]]
        growth = []
        for phase in phases:
            # Nearest sampled brackets INCLUDE the whole phase; includes empty-block
            # and background history growth. It is not attributable solely to txs.
            before = [s for s in samples if s["finished_unix_ms"] <= phase["started_unix_ms"]]
            after = [s for s in samples if s["started_unix_ms"] >= phase["finished_unix_ms"]]
            if before and after:
                first = {n["service"]: n for n in before[-1]["nodes"]}
                last = {n["service"]: n for n in after[0]["nodes"]}
                growth.append({"repetition": phase["repetition"],
                    "sample_interval_seconds": (after[0]["finished_unix_ms"]-before[-1]["started_unix_ms"])/1000,
                    "allocated_growth_bytes_per_node": {name: last[name]["journal_allocated_bytes"]-
                        first[name]["journal_allocated_bytes"] for name in first}})
        offer = sum(p["offer_seconds"] for p in phases)
        elapsed = sum(p["elapsed_including_drain_seconds"] for p in phases)
        groups.append({"concurrency": concurrency, "repetitions": len(phases), "confirmed": len(receipts),
            "offer_seconds": offer, "elapsed_including_drain_seconds": elapsed,
            "confirmed_tps_offer_window": sum(p["confirmed_in_offer_window"] for p in phases)/offer,
            "confirmed_tps_including_drain": len(receipts)/elapsed,
            "latency_ms_p50": percentile(latencies, .50), "latency_ms_p95": percentile(latencies, .95),
            "latency_ms_p99": percentile(latencies, .99),
            "submission_ack_ms_p95": percentile([r["submit_ack_ms"] for r in receipts], .95),
            "memory_peak_bytes_per_node": max((n["memory_bytes"] for n in node_samples), default=None),
            "cpu_mean_percent_per_node": sum(n["cpu_percent"] for n in node_samples)/len(node_samples) if node_samples else None,
            "cpu_peak_percent_per_node": max((n["cpu_percent"] for n in node_samples), default=None),
            "resource_samples": len(resources), "journal_growth_bracketed": growth,
            "signed_transaction_bytes": sum(r["signed_bytes"] for r in receipts)})
    return {"success": load["success"], "groups": groups,
            "scope": "Existing four-validator Docker LAB; client and sampler share host; monetary L1 transfers only",
            "journal_growth_scope": "du -sk allocated bytes; brackets may extend beyond phase and include background blocks",
            "limits": ["One outstanding transaction per sender; 32 senders maximum",
                       "Empirical nearest-rank quantiles; small sample sizes, especially concurrency 1",
                       "No open-loop overload, distributed operators, independent host or L2 proof generation",
                       "CPU percentages use Docker semantics (100 percent corresponds to one CPU)",
                       "Resource collection and certificate polling also consume host resources",
                       "Signed byte totals exclude TCP framing, consensus retransmission and query traffic"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--load-binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--phase-seconds", type=int, default=30)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    if not 5 <= args.phase_seconds <= 300 or not 1 <= args.repetitions <= 10:
        parser.error("Use 5..300 seconds and 1..10 repetitions")
    info = json.loads((root/"home.json").read_text())
    compose = json.loads((root/"compose.json").read_text())
    rows = [json.loads(line) for line in run(["docker", "compose", "-f", root/"compose.json",
                                            "ps", "--format", "json"]).splitlines() if line.strip()]
    nodes = [{"service": r["Service"], "id": r["ID"], "image": r["Image"]} for r in rows
             if r["Service"] in {f"node-{n}" for n in range(4)} and r["State"] == "running"]
    if len(nodes) != 4:
        parser.error("Four running validators required")
    nodes.sort(key=lambda n: n["service"])
    out.mkdir(parents=True, exist_ok=False)
    meta = {"utc": datetime.now(timezone.utc).isoformat(), "genesis": info["genesis"],
            "platform": platform.platform(), "logical_cpus_reported": os.cpu_count(),
            "nodes": nodes, "phase_seconds": args.phase_seconds, "repetitions": args.repetitions,
            "sample_interval_target_seconds": 5,
            "binary_sha256": hashlib.sha256(args.load_binary.read_bytes()).hexdigest(),
            "container_limits": {n["service"]: {k: compose["services"][n["service"]][k]
                for k in ("cpus", "mem_limit", "pids_limit")} for n in nodes}}
    workspace = Path(__file__).resolve().parents[1]
    meta["base_commit"] = run(["git", "-C", workspace, "rev-parse", "HEAD"]).strip()
    source_paths = ["Cargo.lock", "nexus-core/src/journal.rs", "nexus-node/src/bft.rs",
                    "nexus-zk/src/verifier.rs", "nexus-zk/src/prover.rs",
                    "nexus-cli/examples/testnet_load.rs", "deploy/measure_testnet.py"]
    meta["source_sha256"] = {name: hashlib.sha256((workspace/name).read_bytes()).hexdigest()
                             for name in source_paths}
    for name in ("cpu.max", "memory.max"):
        path = Path("/sys/fs/cgroup")/name
        meta[name] = path.read_text().strip() if path.is_file() else None
    (out/"metadata.json").write_text(json.dumps(meta, indent=2)+"\n")
    samples = []
    proc = None
    with (out/"resources.jsonl").open("x") as resources, (out/"load.log").open("x") as log:
        def collect():
            point = sample(nodes)
            samples.append(point)
            resources.write(json.dumps(point)+"\n")
            resources.flush()
        try:
            collect()
            command = [str(args.load_binary.resolve()), "--genesis", str(root/"genesis.json"),
                "--faucet", str(root/"keys/faucet.key"), "--out", str(out/"load.json"),
                "--phase-seconds", str(args.phase_seconds), "--repetitions", str(args.repetitions),
                "--nodes", *[f"127.0.0.1:{info['base_port']+n}" for n in range(4)]]
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            while proc.poll() is None:
                collect()
                time.sleep(3)  # docker stats itself samples for roughly two seconds.
            collect()
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    load = json.loads((out/"load.json").read_text())
    summary = summarize(load, samples)
    (out/"summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    if proc.returncode or not load["success"]:
        raise SystemExit("Load run failed; partial evidence preserved in output directory")
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
