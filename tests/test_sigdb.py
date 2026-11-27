import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import sigdb

class TestAnchors(unittest.TestCase):
    def setUp(self):
        self.payload = b"CONFIDENTIAL-PAYROLL-ROW-" * 400
        self.ix = sigdb.AnchorIndex(chunk_kb=4, min_contig=512, cap=8192)
        self.ix.index_bytes("s0", r"C:\vault\payroll.xlsx", self.payload)

    def test_exact_copy(self):
        m = self.ix.match(self.payload, allowed={"s0"})
        self.assertTrue(m["hit"])
        self.assertGreaterEqual(m["length"], 512)

    def test_embedded_offset(self):
        body = b"multipart junk\r\n" * 40 + self.payload + b"\r\n--end--"
        self.assertTrue(self.ix.match(body, allowed={"s0"})["hit"])

    def test_clean_allows(self):
        self.assertFalse(self.ix.match(b"heartbeat " * 100, allowed={"s0"})["hit"])

    def test_cap_bounds_memory(self):
        ix = sigdb.AnchorIndex(chunk_kb=2, min_contig=256, cap=32)
        ix.index_bytes("s1", "p", b"x" * 400000)
        self.assertLessEqual(ix.sources["s1"]["anchors"], 32)

    def test_max_inspect_bytes(self):
        m = self.ix.match(self.payload, allowed={"s0"}, max_bytes=1024 * 1024)
        self.assertTrue(m["hit"])

    def test_json_roundtrip(self):
        ix2 = sigdb.AnchorIndex.from_json(self.ix.to_json())
        self.assertTrue(ix2.match(self.payload, allowed={"s0"})["hit"])

    def test_cdc_deterministic_and_lossless(self):
        a = list(sigdb.cdc(self.payload, 4096))
        self.assertEqual(a, list(sigdb.cdc(self.payload, 4096)))
        self.assertEqual(b"".join(c for _, c in a), self.payload)

    def test_magic(self):
        self.assertEqual(sigdb.magic_of(b"%PDF-1.7"), "pdf")
        self.assertEqual(sigdb.magic_of(b"PK\x03\x04"), "zip")

if __name__ == "__main__":
    unittest.main()
