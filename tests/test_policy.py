import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import provenance, sigdb, config

class TestVerdictRule(unittest.TestCase):
    def setUp(self):
        self.payload = b"PAYROLL-CONFIDENTIAL;" * 500
        self.ix = sigdb.AnchorIndex(chunk_kb=4, min_contig=512)
        self.ix.index_bytes("s0", r"C:\vault\payroll.xlsx", self.payload)

    def test_taint_alone_never_blocks(self):
        d = provenance.verdict({"hit": False}, provenance.PLANE_PACKET, tainted=["s0"])
        self.assertEqual(d["verdict"], "allow")
        self.assertEqual(d["action"], "none")

    def test_clean_body_from_tainted_process_allows(self):
        ev = self.ix.match(b"benign telemetry " * 200, allowed={"s0"})
        d = provenance.verdict(ev, provenance.PLANE_GX, tainted=["s0"])
        self.assertEqual(d["verdict"], "allow")

    def test_content_evidence_blocks_per_flow(self):
        ev = self.ix.match(self.payload, allowed={"s0"})
        d = provenance.verdict(ev, provenance.PLANE_GX, tainted=["s0"], action="403")
        self.assertEqual(d["verdict"], "block")
        self.assertEqual(d["scope"], "per-flow")
        self.assertEqual(d["action"], "403")

    def test_evidence_binds_to_forbidden_path(self):
        ev = self.ix.match(self.payload, allowed={"s0"})
        self.assertEqual(ev["source_path"], r"C:\vault\payroll.xlsx")

    def test_disarmed_audits_only(self):
        ev = self.ix.match(self.payload, allowed={"s0"})
        d = provenance.verdict(ev, provenance.PLANE_PACKET, armed=False, tainted=["s0"])
        self.assertEqual(d["verdict"], "audit")

    def test_scope_restriction(self):
        self.assertFalse(self.ix.match(self.payload, allowed={"other"})["hit"])

    def test_boundary_key_path(self):
        keys = [sigdb.key(ch).hex() for _, ch in sigdb.cdc(self.payload, 4096, 1024)]
        ev = self.ix.match_keys(keys, allowed={"s0"})
        self.assertTrue(ev["hit"])
        self.assertEqual(ev["kind"], "boundary")

    def test_wrapped_names_corroborate_only(self):
        hits = self.ix.names_hit(["payroll.xlsx"], allowed={"s0"})
        self.assertTrue(hits)
        d = provenance.verdict({"hit": False}, provenance.PLANE_GX, tainted=["s0"])
        d["corroborating"] = hits
        self.assertEqual(d["verdict"], "allow")

    def test_per_flow_only_is_mandatory(self):
        c = config.merged({"enforce": {"per_flow_only": False}, "gx": {"enabled": False}})
        self.assertTrue(any("per_flow_only" in e for e in config.validate(c)))

if __name__ == "__main__":
    unittest.main()
