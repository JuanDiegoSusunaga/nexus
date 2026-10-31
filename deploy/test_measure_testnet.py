"""Regression checks for reporting units, confirmation timing and sample scope."""
import unittest
from measure_testnet import memory_bytes, summarize


class MeasurementTests(unittest.TestCase):
    def test_docker_memory_format_does_not_require_space_before_unit(self):
        self.assertEqual(memory_bytes("8.5MiB"), 8.5*1024**2)
        self.assertEqual(memory_bytes(" 512 KiB "), 512*1024)
        with self.assertRaises(ValueError):
            memory_bytes("unavailable")

    def test_rates_use_confirmed_transactions_and_include_drain_separately(self):
        receipts = [{"confirmation_ms": value, "submit_ack_ms": 0.5, "signed_bytes": 100}
                    for value in (100, 200)]
        phase = {"repetition": 0, "concurrency": 1, "started_unix_ms": 2000,
                 "finished_unix_ms": 32000, "offer_seconds": 10,
                 "elapsed_including_drain_seconds": 30,
                 "confirmed_in_offer_window": 1, "receipts": receipts}
        def point(start, end, allocated):
            return {"started_unix_ms": start, "finished_unix_ms": end,
                    "nodes": [{"service": "node-0", "cpu_percent": 2,
                               "memory_bytes": 1000, "journal_allocated_bytes": allocated}]}
        samples = [point(0, 1000, 100), point(3000, 4000, 150),
                   point(31000, 33000, 200), point(34000, 35000, 300)]
        result = summarize({"success": True, "phases": [phase]}, samples)["groups"][0]
        self.assertEqual(result["confirmed"], 2)
        self.assertEqual(result["confirmed_tps_offer_window"], 0.1)
        self.assertAlmostEqual(result["confirmed_tps_including_drain"], 2/30)
        self.assertEqual(result["latency_ms_p95"], 200)
        self.assertEqual(result["resource_samples"], 1)  # Crossing sample is not phase-local.
        growth = result["journal_growth_bracketed"][0]
        self.assertEqual(growth["allocated_growth_bytes_per_node"], {"node-0": 200})
        self.assertEqual(growth["sample_interval_seconds"], 35)


if __name__ == "__main__":
    unittest.main()
