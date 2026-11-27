# Configuration. Two enforcement planes, one content-confirmed verdict rule.
import json, os, sys, copy

APP = "SRC"

def state_dir():
    if sys.platform == "win32":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), APP)
    return os.path.join(os.path.expanduser("~"), ".src")

DEFAULTS = {
    "armed": True,
    "protected": [],

    # ---- plane A: Opera GX application boundary (pre-TLS, inside the browser) ----
    "gx": {
        "enabled": True,
        "image": "",                 # verified opera.exe image path (asked at setup)
        "package_family": "",
        "verified": False,
        "boundary_sensor": True,     # in-renderer hook via extension + native host
        "proxy_backstop": True,      # mitmproxy local-mode scoped to opera.exe
        "methods": ["POST", "PUT", "PATCH"],
        "action": "403",             # 403 | kill   (per-request / per-flow only)
        "block_page": True,
        "inspect_wrapped_names": True,  # FormData/File names that wrap protected paths
    },

    # ---- plane B: every other process, packet decryption via mitmproxy ----
    "packet": {
        "enabled": True,
        "mode": "proxy",             # proxy (WinINET) | local (WFP redirect)
        "port": 8080,
        "decrypt": True,
    },

    # ---- content proof (the only thing that can produce a block) ----
    "match": {
        "modes": ["cdc", "sha256", "sig"],
        "chunk_kb": 8,
        "min_contig": 1024,          # contiguous protected bytes required as evidence
        "cap_anchors_per_source": 8192,
        "scope": "taint",            # taint = cheap provenance-scoped search
        "sweep_untainted": False,    # optional sampled global sweep (costs CPU)
        "min_body": 512,             # ignore bodies too small to carry evidence
        "max_inspect_bytes": 8 * 1024 * 1024,
    },

    # ---- provenance ledger ----
    "taint": {"ttl_s": 900, "depth": 2, "monitor": "auto", "max_pids": 4096},

    # ---- enforcement is ALWAYS per-request / per-flow ----
    "enforce": {
        "per_flow_only": True,       # never an app-wide network block
        "wfp_redirect": True,        # WFP used to REDIRECT, not to block apps
        "quic_policy_off": True,     # Opera enterprise policy QuicAllowed=false
    },

    "autostart": False,
    "notify": True,
    "audit": True,
}

def merged(user=None):
    out = copy.deepcopy(DEFAULTS)
    for k, v in (user or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out

def validate(cfg):
    e = []
    if cfg["packet"]["mode"] not in ("proxy", "local"):
        e.append("packet.mode must be proxy or local")
    if not (1024 <= int(cfg["packet"]["port"]) <= 65535):
        e.append("packet.port must be 1024..65535")
    if cfg["gx"]["action"] not in ("403", "kill"):
        e.append("gx.action must be 403 or kill (per-flow)")
    if cfg["gx"]["enabled"]:
        if not cfg["gx"].get("image", "").lower().endswith("opera.exe"):
            e.append("gx.image must point at opera.exe (Opera GX application boundary)")
    m = cfg["match"]
    if not (2 <= int(m["chunk_kb"]) <= 128):
        e.append("match.chunk_kb must be 2..128")
    if int(m["min_contig"]) < 256:
        e.append("match.min_contig must be >= 256")
    if not set(m["modes"]) & {"cdc", "sha256", "sig"}:
        e.append("match.modes needs cdc/sha256/sig")
    if m["scope"] not in ("taint", "global"):
        e.append("match.scope must be taint or global")
    if not cfg["enforce"]["per_flow_only"]:
        e.append("enforce.per_flow_only must stay true: SRC blocks flows, not apps")
    for p in cfg.get("protected", []):
        if not p.get("path"):
            e.append("protected entry missing path")
    return e

def load(path=None):
    path = path or os.path.join(state_dir(), "config.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return merged(json.load(f))
    return merged()

def save(cfg, path=None):
    path = path or os.path.join(state_dir(), "config.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return path
