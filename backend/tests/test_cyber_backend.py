import unittest
from backend.src.cyber_platform import (
    analyze_ot_ics_context,
    analyze_topology_context,
    build_threat_intelligence_index,
    build_unified_assessment,
    discover_dataset_files,
    prioritize_vulnerabilities,
    orchestrate_incident_response,
    read_audit_log,
    summarize_data_fabric,
)


class CyberBackendTests(unittest.TestCase):
    def test_discover_dataset_files_finds_expected_inputs(self):
        discovered = discover_dataset_files()
        self.assertIn("training_set", discovered)
        self.assertIn("testing_set", discovered)
        # The application must remain demo-runnable without the large optional datasets.
        # When datasets are mounted, these fields contain the corresponding paths.
        self.assertIsInstance(discovered["training_set"], str)
        self.assertIsInstance(discovered["testing_set"], str)

    def test_threat_intelligence_index_contains_attack_data(self):
        index = build_threat_intelligence_index()
        self.assertGreater(len(index), 0)
        self.assertIn("techniques", index)
        self.assertGreater(len(index["techniques"]), 0)

    def test_prioritize_vulnerabilities_returns_ranked_items(self):
        ranked = prioritize_vulnerabilities(asset_count=4, threat_level="high")
        self.assertGreater(len(ranked), 0)
        self.assertTrue(all("score" in item for item in ranked))
        self.assertTrue(all("priority" in item for item in ranked))

    def test_topology_and_ot_ics_contexts_are_available(self):
        topology = analyze_topology_context()
        ot_ics = analyze_ot_ics_context()
        self.assertIn("available", topology)
        self.assertIn("available", ot_ics)
        self.assertIn(topology["mode"], {"demo_fallback", "repository_data"})
        self.assertIn(ot_ics["mode"], {"demo_fallback", "repository_data"})

    def test_unified_assessment_is_demo_runnable(self):
        result = build_unified_assessment(
            [{"dur": 0.12, "proto": "tcp", "service": "-", "state": "FIN", "spkts": 6, "dpkts": 4, "sbytes": 258, "dbytes": 172}],
            ["credential access", "lateral movement", "ransomware"],
            asset_count=4,
            threat_level="high",
        )
        self.assertIn("context", result)
        self.assertTrue(result["context"]["unsw"]["available"])
        self.assertTrue(result["vulnerabilities"]["summary"]["available"])
        self.assertGreater(len(result["threat_mapping"]["techniques"]), 0)

    def test_data_fabric_summary_includes_all_intelligence_domains(self):
        summary = summarize_data_fabric()
        self.assertTrue(summary["available"])
        self.assertIn("attck", summary["domains"])
        self.assertIn("topology", summary["domains"])
        self.assertIn("ot_ics", summary["domains"])
        self.assertIn("unsw", summary["domains"])
        self.assertIn("vulnerability", summary["domains"])
        self.assertGreater(summary["threat_intelligence"]["technique_count"], 0)

    def test_high_blast_radius_is_gated_and_audited(self):
        response = orchestrate_incident_response(["credential access", "ransomware"], blast_radius="critical")
        self.assertTrue(response["approval_required"])
        self.assertEqual(response["execution_mode"], "simulation_only")
        self.assertTrue(any(event["event_id"] == response["audit_event_id"] for event in read_audit_log()))


if __name__ == "__main__":
    unittest.main()
