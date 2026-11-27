# Provenance ledger: which PID recently read which PROTECTED PATH.
# Taint alone is never a block reason; it only scopes the content search.
import time

class TaintLedger:
    def __init__(self, ttl_s=900, depth=2, max_pids=4096):
        self.ttl = float(ttl_s)
        self.depth = int(depth)
        self.max_pids = int(max_pids)
        self.pids = {}

    def touch(self, pid, sid, now=None, image="", path=""):
        now = time.time() if now is None else now
        r = self.pids.setdefault(int(pid), {"src": {}, "depth": 0, "image": image, "reads": 0})
        r["src"][sid] = now
        r["reads"] += 1
        if image:
            r["image"] = image
        if path:
            r["last_path"] = path
        if len(self.pids) > self.max_pids:
            self._prune(now, force=True)
        return r

    def propagate(self, parent, child, now=None, image=""):
        now = time.time() if now is None else now
        p = self.pids.get(int(parent))
        if not p:
            return None
        live = self.sources(int(parent), now)
        if not live:
            return None
        c = self.pids.setdefault(int(child), {"src": {}, "depth": p["depth"] + 1,
                                              "image": image, "reads": 0})
        if c["depth"] > self.depth:
            return None
        for s in live:
            c["src"][s] = now
        return c

    def sources(self, pid, now=None):
        now = time.time() if now is None else now
        r = self.pids.get(int(pid))
        if not r:
            return set()
        live = {s for s, t in r["src"].items() if now - t <= self.ttl}
        r["src"] = {s: t for s, t in r["src"].items() if s in live}
        return live

    def _prune(self, now, force=False):
        for pid in list(self.pids):
            if not self.sources(pid, now):
                del self.pids[pid]
        if force and len(self.pids) > self.max_pids:
            for pid in sorted(self.pids, key=lambda p: max(self.pids[p]["src"].values() or [0]))[:64]:
                del self.pids[pid]

    def cleanup(self, now=None):
        self._prune(time.time() if now is None else now)

    def snapshot(self, now=None):
        now = time.time() if now is None else now
        self.cleanup(now)
        return {str(pid): {"sources": sorted(self.sources(pid, now)), "depth": r["depth"],
                           "image": r["image"], "reads": r["reads"]}
                for pid, r in self.pids.items()}

    @classmethod
    def from_snapshot(cls, snap, ttl_s=900, depth=2):
        led = cls(ttl_s, depth)
        now = time.time()
        for pid, r in (snap or {}).items():
            led.pids[int(pid)] = {"src": {s: now for s in r.get("sources", [])},
                                  "depth": r.get("depth", 0), "image": r.get("image", ""),
                                  "reads": r.get("reads", 0)}
        return led
