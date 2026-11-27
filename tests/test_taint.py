import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.taint import TaintLedger

class TestLedger(unittest.TestCase):
    def test_touch_and_scope(self):
        L = TaintLedger(ttl_s=100)
        L.touch(10, "s0", now=0, image="opera.exe")
        self.assertEqual(L.sources(10, now=5), {"s0"})

    def test_ttl_expiry(self):
        L = TaintLedger(ttl_s=100)
        L.touch(10, "s0", now=0)
        self.assertEqual(L.sources(10, now=101), set())

    def test_depth_limit(self):
        L = TaintLedger(ttl_s=1000, depth=1)
        L.touch(1, "s0", now=0)
        L.propagate(1, 2, now=1)
        self.assertEqual(L.sources(2, now=2), {"s0"})
        self.assertIsNone(L.propagate(2, 3, now=2))

    def test_pid_cap(self):
        L = TaintLedger(ttl_s=1000, max_pids=8)
        for i in range(50):
            L.touch(i, "s0", now=i)
        self.assertLessEqual(len(L.pids), 64)

    def test_snapshot_roundtrip(self):
        L = TaintLedger()
        L.touch(5, "s1", now=0, image="opera.exe")
        snap = L.snapshot(now=1)
        L2 = TaintLedger.from_snapshot(snap)
        self.assertEqual(L2.sources(5), {"s1"})

if __name__ == "__main__":
    unittest.main()
