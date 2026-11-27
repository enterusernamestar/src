# Anchor index: content-defined chunks + structural anchors of PROTECTED PATHS.
# Resource-light: 12-byte digest keys, per-source cap, single streaming pass,
# early exit on first evidence. An anchor is always bound to its source path,
# so a hit is proof of "forbidden content from a forbidden path".
import hashlib, os, glob

MAGICS = [
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"PK\x03\x04", "zip"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"%PDF", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
]

def _gear():
    st = 0x9E3779B97F4A7C15
    t = []
    for _ in range(256):
        st ^= (st << 13) & 0xFFFFFFFFFFFFFFFF
        st ^= st >> 7
        st ^= (st << 17) & 0xFFFFFFFFFFFFFFFF
        t.append(st)
    return t

_G = _gear()
_M64 = 0xFFFFFFFFFFFFFFFF
KEYLEN = 12

def key(ch):
    return hashlib.sha256(ch).digest()[:KEYLEN]

def cdc(data, avg=8192, min_size=1024, max_size=65536):
    mask = avg - 1
    n = len(data); start = 0; h = 0; i = 0
    while i < n:
        h = ((h << 1) + _G[data[i]]) & _M64
        size = i - start + 1
        if (size >= min_size and (h & mask) == 0) or size >= max_size:
            yield start, data[start:i + 1]
            start = i + 1; h = 0
        i += 1
    if start < n:
        yield start, data[start:n]

def windows(data, win=8192):
    for off in range(0, len(data), win):
        yield off, data[off:off + win]

def magic_of(d):
    for sig, name in MAGICS:
        if d.startswith(sig):
            return name
    return ""

def expand(entry):
    p = entry["path"]
    kind = entry.get("kind") or ("folder" if os.path.isdir(p) else "file")
    if kind == "folder":
        out = []
        for pat in [x.strip() for x in (entry.get("patterns") or "*.*").split(";") if x.strip()]:
            out.extend(glob.glob(os.path.join(p, "**", pat), recursive=True))
        return [x for x in out if os.path.isfile(x)]
    return [p] if os.path.isfile(p) else []

class AnchorIndex:
    def __init__(self, chunk_kb=8, min_contig=1024, cap=8192):
        self.win = int(chunk_kb) * 1024
        self.min_contig = int(min_contig)
        self.cap = int(cap)
        self.anchors = {}        # 12-byte key -> (source_id, chunk_len)
        self.sources = {}        # source_id -> {path, size, magic, anchors, mtime}
        self.by_name = {}        # basename.lower() -> set(source_id)  (wrapped-name evidence)

    def _add(self, sid, ch):
        self.anchors.setdefault(key(ch), (sid, len(ch)))

    def index_bytes(self, sid, path, data, mtime=0):
        mg = magic_of(data)
        n = 0
        for _, ch in cdc(data, self.win, max(512, self.win // 4)):
            if n >= self.cap:
                break
            self._add(sid, ch); n += 1
        for _, ch in windows(data, self.win):
            if n >= self.cap:
                break
            self._add(sid, ch); n += 1
        self.sources[sid] = {"path": path, "size": len(data), "magic": mg,
                             "anchors": n, "mtime": mtime}
        self.by_name.setdefault(os.path.basename(path).lower(), set()).add(sid)
        return self.sources[sid]

    def index_file(self, sid, path):
        try:
            st = os.stat(path)
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return None
        return self.index_bytes(sid, path, data, st.st_mtime)

    def build(self, protected):
        for i, e in enumerate(protected):
            sid = e.get("id") or ("s%d" % i)
            for p in expand(e):
                self.index_file(sid, p)
        return self

    def stale(self, protected):
        # cheap re-index trigger: mtime/size drift only, never rehash on every flow
        for i, e in enumerate(protected):
            sid = e.get("id") or ("s%d" % i)
            for p in expand(e):
                rec = next((r for r in self.sources.values() if r["path"] == p), None)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if rec is None or rec["mtime"] != st.st_mtime or rec["size"] != st.st_size:
                    return True
        return False

    def match(self, data, allowed=None, modes=("cdc", "sha256", "sig"), max_bytes=None):
        """Return content evidence or {'hit': False}. Taint is NOT consulted here."""
        if not data:
            return {"hit": False}
        if max_bytes and len(data) > max_bytes:
            data = data[:max_bytes]
        modes = set(modes)
        best = None
        streams = []
        if "cdc" in modes:
            streams.append(("cdc", cdc(data, self.win, max(512, self.win // 4))))
        if "sha256" in modes:
            streams.append(("sha256", windows(data, self.win)))
        for kind, gen in streams:
            for off, ch in gen:
                hit = self.anchors.get(key(ch))
                if not hit:
                    continue
                sid, ln = hit
                if allowed is not None and sid not in allowed:
                    continue
                ev = {"hit": True, "source_id": sid, "length": ln, "offset": off, "kind": kind,
                      "source_path": self.sources.get(sid, {}).get("path", "")}
                if ln >= self.min_contig:
                    return ev                      # early exit: proof found
                if best is None:
                    best = ev
        if "sig" in modes and best is None:
            mg = magic_of(data)
            if mg:
                for off, ch in cdc(data, self.win, 256):
                    hit = self.anchors.get(key(ch))
                    if hit and (allowed is None or hit[0] in allowed):
                        if self.sources.get(hit[0], {}).get("magic") == mg:
                            best = {"hit": True, "source_id": hit[0], "length": hit[1],
                                    "offset": off, "kind": "sig",
                                    "source_path": self.sources.get(hit[0], {}).get("path", "")}
                            break
        return best or {"hit": False}

    def match_keys(self, keys, allowed=None):
        """Boundary sensor path: browser already hashed its CDC chunks."""
        best = None
        for k in keys:
            try:
                kb = bytes.fromhex(k)[:KEYLEN]
            except (ValueError, TypeError):
                continue
            hit = self.anchors.get(kb)
            if not hit:
                continue
            sid, ln = hit
            if allowed is not None and sid not in allowed:
                continue
            ev = {"hit": True, "source_id": sid, "length": ln, "offset": 0, "kind": "boundary",
                  "source_path": self.sources.get(sid, {}).get("path", "")}
            if ln >= self.min_contig:
                return ev
            if best is None:
                best = ev
        return best or {"hit": False}

    def names_hit(self, names, allowed=None):
        out = []
        for n in names or []:
            base = os.path.basename(str(n)).lower()
            for sid in self.by_name.get(base, ()):
                if allowed is None or sid in allowed:
                    out.append({"source_id": sid, "name": n,
                                "source_path": self.sources.get(sid, {}).get("path", "")})
        return out

    def to_json(self):
        return {"win": self.win, "min_contig": self.min_contig, "cap": self.cap,
                "sources": self.sources,
                "by_name": {k: sorted(v) for k, v in self.by_name.items()},
                "anchors": {k.hex(): list(v) for k, v in self.anchors.items()}}

    @classmethod
    def from_json(cls, d):
        ix = cls(d["win"] // 1024, d["min_contig"], d["cap"])
        ix.sources = d["sources"]
        ix.by_name = {k: set(v) for k, v in d.get("by_name", {}).items()}
        ix.anchors = {bytes.fromhex(k): tuple(v) for k, v in d["anchors"].items()}
        return ix
