"""Regresiones del generador: aislamiento, identidad y entradas peligrosas."""
import json
from pathlib import Path
import tempfile
import unittest
from prepare import endpoint, prepare

IMAGE = "sha256:" + "a" * 64
PEERS = [f"8.8.8.{n}:19001" for n in range(1, 5)]


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.genesis = self.root / "genesis.json"
        self.document = {"protocol_version": 4, "genesis_hash": [1] * 32, "network_domain": [2] * 32,
            "committee_context": [3] * 32, "config": {"anchor": {}, "monetary": {}, "proposal_future_ms": 30000,
                "validators": [{"bytes": [n] * 1952, "scheme": "Dilithium3"} for n in range(4)]}}
        self.genesis.write_text(json.dumps(self.document), encoding="utf-8")

    def test_secret_files_are_never_copied_and_each_node_mounts_one_key_read_only(self):
        (self.root / "validator-0.key").write_bytes(b"NO COPIAR ESTE SECRETO")
        out = self.root / "bundle"
        prepare(self.genesis, out, PEERS, IMAGE)
        self.assertFalse(list(out.rglob("*.key")))
        for index in range(4):
            compose = json.loads((out / f"node-{index}/compose.json").read_text(encoding="utf-8"))
            node = compose["services"]["node"]
            self.assertTrue(node["read_only"])
            self.assertEqual(node["user"], "10001:10001")
            keys = [v for v in node["volumes"] if "validator.key" in v["target"]]
            self.assertEqual(len(keys), 1)
            self.assertTrue(keys[0]["read_only"])
            self.assertFalse(keys[0]["bind"]["create_host_path"])
            self.assertEqual(node["command"].count("--peer"), 3)
            self.assertNotIn(PEERS[index], node["command"])

    def test_invalid_or_duplicate_addresses_fail_before_creating_a_bundle(self):
        for value in ["0.0.0.0:19001", "127.0.0.1:19001", "host;shutdown:19001", "8.8.8.8:22", "[::]:19001"]:
            with self.assertRaises(ValueError):
                endpoint(value)
        with self.assertRaises(ValueError):
            prepare(self.genesis, self.root / "duplicate", [PEERS[0]] * 4, IMAGE)
        self.assertFalse((self.root / "duplicate").exists())

    def test_canonical_address_normalization_detects_aliases(self):
        self.assertEqual(endpoint("[2001:4860:4860:0:0:0:0:8888]:19001"), "[2001:4860:4860::8888]:19001")
        self.assertEqual(endpoint("127.0.0.1:019001", True), "127.0.0.1:19001")

    def test_image_must_be_content_pinned(self):
        with self.assertRaises(ValueError):
            prepare(self.genesis, self.root / "mutable", PEERS, "nexus:latest")
        self.assertFalse((self.root / "mutable").exists())

    def test_memory_profile_applies_to_all_four_nodes_and_invalid_limits_fail_before_output(self):
        out = self.root / "limited"
        prepare(self.genesis, out, PEERS, IMAGE, memory_limit="512m")
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["memory_limit"], "512m")
        for index in range(4):
            compose = json.loads((out / f"node-{index}/compose.json").read_text(encoding="utf-8"))
            self.assertEqual(compose["services"]["node"]["mem_limit"], "512m")
        with self.assertRaises(ValueError):
            prepare(self.genesis, self.root / "bad-limit", PEERS, IMAGE, memory_limit="0")
        self.assertFalse((self.root / "bad-limit").exists())

    def test_existing_bundle_is_never_overwritten(self):
        out = self.root / "existing"
        prepare(self.genesis, out, PEERS, IMAGE)
        original = (out / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            prepare(self.genesis, out, PEERS, IMAGE)
        self.assertEqual((out / "manifest.json").read_bytes(), original)

    def test_json_whitespace_cannot_select_a_fresh_volume_for_the_same_genesis(self):
        first, second = self.root / "first", self.root / "second"
        prepare(self.genesis, first, PEERS, IMAGE)
        self.genesis.write_text(json.dumps(self.document, indent=4), encoding="utf-8")
        prepare(self.genesis, second, PEERS, IMAGE)
        a = json.loads((first / "node-0/compose.json").read_text(encoding="utf-8"))
        b = json.loads((second / "node-0/compose.json").read_text(encoding="utf-8"))
        self.assertEqual(a["name"], b["name"])

    def test_unknown_fields_cannot_smuggle_a_private_key_into_the_public_bundle(self):
        self.document["private_key"] = "NO PUBLICAR"
        self.genesis.write_text(json.dumps(self.document), encoding="utf-8")
        with self.assertRaises(ValueError):
            prepare(self.genesis, self.root / "bad", PEERS, IMAGE)
        self.assertFalse((self.root / "bad").exists())


if __name__ == "__main__":
    unittest.main()
