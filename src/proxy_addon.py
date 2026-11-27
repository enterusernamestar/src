# Plane B (packet decryption) + Plane A backstop for Opera GX.
# A block happens ONLY when the decrypted body carries protected bytes.
# Enforcement is per-request: 403 for this request, or kill this flow. Nothing else.
import json, os, time
from mitmproxy import http
from . import config, sigdb, provenance, winapi, flowkill, blockpage

STATE = config.state_dir()

def _read(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

class SRC:
    def __init__(self):
        self.cfg = config.load()
        self.index = None
        self.taint = {}
        self._mt = {}
        self._reload()

    def _mtime(self, p):
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0

    def _reload(self):
        cp, ip, tp = (os.path.join(STATE, x) for x in ("config.json", "index.json", "taint.json"))
        if self._mtime(cp) != self._mt.get("c"):
            self.cfg = config.load(); self._mt["c"] = self._mtime(cp)
        if self._mtime(ip) != self._mt.get("i"):
            d = _read(ip)
            self.index = sigdb.AnchorIndex.from_json(d) if d else None
            self._mt["i"] = self._mtime(ip)
        if self._mtime(tp) != self._mt.get("t"):
            self.taint = _read(tp) or {}; self._mt["t"] = self._mtime(tp)

    def _audit(self, rec):
        if not self.cfg.get("audit", True):
            return
        try:
            os.makedirs(STATE, exist_ok=True)
            with open(os.path.join(STATE, "audit.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

    def _is_gx(self, image):
        g = self.cfg["gx"]
        if not image or os.path.basename(image).lower() != "opera.exe":
            return False
        if g.get("verified") and g.get("image"):
            return os.path.normcase(image) == os.path.normcase(g["image"])
        return True

    def request(self, flow: http.HTTPFlow):
        self._reload()
        cfg = self.cfg
        req = flow.request
        m = cfg["match"]
        if req.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        body = req.get_content(strict=False) or b""
        if len(body) < int(m["min_body"]) or self.index is None:
            return

        port = flow.client_conn.peername[1] if flow.client_conn.peername else None
        pid = winapi.port_pid(port, cfg["packet"]["port"]) if port else None
        image = winapi.image_path(pid) if pid else ""
        gx = self._is_gx(image)

        if gx and not (cfg["gx"]["enabled"] and cfg["gx"]["proxy_backstop"]):
            return
        if not gx and not (cfg["packet"]["enabled"] and cfg["packet"]["decrypt"]):
            return

        rec = self.taint.get(str(pid), {}) if pid else {}
        tainted = set(rec.get("sources", []))
        if m["scope"] == "taint" and not tainted and not m["sweep_untainted"]:
            return                                   # nothing to search: cheap exit
        allowed = provenance.allowed_sources(tainted, m["scope"], self.index.sources.keys())
        if not allowed:
            return

        ev = self.index.match(body, allowed=allowed, modes=m["modes"],
                              max_bytes=int(m["max_inspect_bytes"]))
        plane = provenance.PLANE_GX_BACKSTOP if gx else provenance.PLANE_PACKET
        action = cfg["gx"]["action"] if gx else "403"
        d = provenance.verdict(ev, plane, armed=cfg.get("armed", True),
                               action=action, tainted=tainted)

        out = {"ts": time.time(), "pid": pid, "image": image, "host": req.host,
               "method": req.method, "bytes": len(body), **d}

        if d["verdict"] == "block":
            if d["action"] == "kill":
                # kill THIS flow only
                if port:
                    flowkill.terminate_client_flow(port, cfg["packet"]["port"])
                try:
                    flow.kill()
                except Exception:
                    flow.response = http.Response.make(403, b"blocked", {})
            else:
                page = blockpage.render(req.host, os.path.basename(ev.get("source_path", "")),
                                        chunk="%s %dB" % (ev.get("kind", ""), ev.get("length", 0)))
                flow.response = http.Response.make(
                    403, page.encode("utf-8"),
                    {"Content-Type": "text/html; charset=utf-8",
                     "X-SRC-Rule": "SRC-GX-01" if gx else "SRC-PKT-01",
                     "X-SRC-Evidence": str(ev.get("length", 0)),
                     "Connection": "close"})
        self._audit(out)

    def responseheaders(self, flow: http.HTTPFlow):
        # keep memory bounded on large uploads/downloads; bodies we inspect are capped
        try:
            flow.response.stream = False
        except Exception:
            pass

addons = [SRC()]
