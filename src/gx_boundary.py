# Plane A: Opera GX APPLICATION BOUNDARY sensor (native messaging host).
# The renderer hashes its outbound CDC chunks BEFORE TLS and asks us whether the
# bytes belong to a protected path. We answer with content evidence only.
# Block => the browser cancels that one request. No network-wide action.
import json, os, struct, sys, time
from . import config, sigdb, provenance

STATE = config.state_dir()
HOST_NAME = "com.src.boundary"

def _read(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

class Boundary:
    def __init__(self):
        self.cfg = config.load()
        self.index = None
        self.taint = {}
        self._mt = {}

    def _mtime(self, p):
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0

    def reload(self):
        cp, ip, tp = (os.path.join(STATE, x) for x in ("config.json", "index.json", "taint.json"))
        if self._mtime(cp) != self._mt.get("c"):
            self.cfg = config.load(); self._mt["c"] = self._mtime(cp)
        if self._mtime(ip) != self._mt.get("i"):
            d = _read(ip)
            self.index = sigdb.AnchorIndex.from_json(d) if d else None
            self._mt["i"] = self._mtime(ip)
        if self._mtime(tp) != self._mt.get("t"):
            self.taint = _read(tp) or {}; self._mt["t"] = self._mtime(tp)

    def decide(self, msg):
        self.reload()
        cfg = self.cfg
        m = cfg["match"]
        if self.index is None or not cfg["gx"]["enabled"]:
            return {"block": False, "reason": "boundary idle"}
        pid = msg.get("pid")
        rec = self.taint.get(str(pid), {}) if pid else {}
        tainted = set(rec.get("sources", []))
        # The browser cannot know its own PID reliably; fall back to image-scoped taint.
        if not tainted:
            gximg = os.path.normcase(cfg["gx"].get("image", ""))
            for r in self.taint.values():
                if os.path.normcase(r.get("image", "")) == gximg:
                    tainted |= set(r.get("sources", []))
        if m["scope"] == "taint" and not tainted and not m["sweep_untainted"]:
            return {"block": False, "reason": "no provenance in scope"}
        allowed = provenance.allowed_sources(tainted, m["scope"], self.index.sources.keys())
        if not allowed:
            return {"block": False, "reason": "empty scope"}

        ev = self.index.match_keys(msg.get("keys") or [], allowed=allowed)
        names = []
        if cfg["gx"]["inspect_wrapped_names"]:
            names = self.index.names_hit(msg.get("names") or [], allowed=allowed)
        d = provenance.verdict(ev, provenance.PLANE_GX, armed=cfg.get("armed", True),
                               action=cfg["gx"]["action"], tainted=tainted)
        if names:
            d["corroborating"] = names
        self._audit({"ts": time.time(), "url": msg.get("url", ""), "pid": pid, **d})
        return {"block": d["verdict"] == "block",
                "action": d["action"],
                "reason": d["reason"],
                "source": (ev.get("source_path") if ev.get("hit") else ""),
                "length": ev.get("length", 0),
                "page": cfg["gx"]["block_page"]}

    def _audit(self, rec):
        if not self.cfg.get("audit", True):
            return
        try:
            os.makedirs(STATE, exist_ok=True)
            with open(os.path.join(STATE, "audit.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

def serve_stdio():
    b = Boundary()
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        hdr = stdin.read(4)
        if len(hdr) < 4:
            return
        n = struct.unpack("<I", hdr)[0]
        if n == 0 or n > 8 * 1024 * 1024:
            continue
        try:
            msg = json.loads(stdin.read(n).decode("utf-8"))
        except Exception:
            continue
        try:
            reply = b.decide(msg)
        except Exception as e:
            reply = {"block": False, "reason": "host error: %s" % e}
        data = json.dumps(reply).encode("utf-8")
        stdout.write(struct.pack("<I", len(data)))
        stdout.write(data)
        stdout.flush()

def manifest_path():
    return os.path.join(config.state_dir(), "boundary_host.json")

def install_host(extension_id):
    """Register the native messaging host for Opera GX / Chromium."""
    os.makedirs(config.state_dir(), exist_ok=True)
    launcher = os.path.join(config.state_dir(), "boundary_host.cmd")
    py = sys.executable
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(launcher, "w", encoding="utf-8") as f:
        f.write('@echo off\r\nset PYTHONPATH=%s\r\n"%s" -m src.gx_boundary --stdio\r\n' % (root, py))
    man = {"name": HOST_NAME,
           "description": "SRC Opera GX application-boundary sensor",
           "path": launcher,
           "type": "stdio",
           "allowed_origins": ["chrome-extension://%s/" % extension_id]}
    with open(manifest_path(), "w", encoding="utf-8") as f:
        json.dump(man, f, indent=2)
    if sys.platform == "win32":
        import winreg
        for base in (r"Software\Opera Software\Opera GX\NativeMessagingHosts",
                     r"Software\Google\Chrome\NativeMessagingHosts",
                     r"Software\Chromium\NativeMessagingHosts"):
            try:
                k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + "\\" + HOST_NAME)
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, manifest_path())
                winreg.CloseKey(k)
            except Exception:
                pass
    return manifest_path()

def remove_host():
    if sys.platform == "win32":
        import winreg
        for base in (r"Software\Opera Software\Opera GX\NativeMessagingHosts",
                     r"Software\Google\Chrome\NativeMessagingHosts",
                     r"Software\Chromium\NativeMessagingHosts"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + "\\" + HOST_NAME)
            except Exception:
                pass
    for p in (manifest_path(), os.path.join(config.state_dir(), "boundary_host.cmd")):
        try:
            os.remove(p)
        except OSError:
            pass

if __name__ == "__main__":
    if "--stdio" in sys.argv:
        serve_stdio()
