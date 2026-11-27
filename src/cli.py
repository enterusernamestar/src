# setup / start / stop / status / doctor / boundary / uninstall
import argparse, os, sys
from . import config, engine, ca, winapi, uninstall, gx_boundary

GX_CANDIDATES = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Opera GX", "opera.exe"),
    r"C:\Program Files\Opera GX\opera.exe",
    r"C:\Program Files (x86)\Opera GX\opera.exe",
]

def _detect_gx():
    for p in GX_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    if sys.platform == "win32":
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera.exe")
            v = winreg.QueryValueEx(k, "")[0]
            if os.path.isfile(v):
                return v
        except Exception:
            pass
    return ""

def cmd_setup(a):
    cfg = config.load()
    print("SRC setup — content-confirmed exfiltration prevention")
    print("Protected paths (blank line to finish):")
    prot = []
    while True:
        try:
            p = input("  path> ").strip().strip('"')
        except EOFError:
            break
        if not p:
            break
        kind = "folder" if os.path.isdir(p) else "file"
        sens = input("  sensitivity [Critical/High/Medium] (High)> ").strip() or "High"
        prot.append({"path": p, "kind": kind, "sensitivity": sens,
                     "patterns": "*.*" if kind == "folder" else ""})
    if prot:
        cfg["protected"] = prot
    det = _detect_gx()
    print("Opera GX image (detected: %s)" % (det or "none"))
    try:
        img = input("  opera.exe [%s]> " % det).strip().strip('"') or det
    except EOFError:
        img = det
    cfg["gx"]["image"] = img
    cfg["gx"]["verified"] = img.lower().endswith("opera.exe") and os.path.isfile(img)
    errs = config.validate(cfg)
    if errs:
        print("config errors:", errs)
    config.save(cfg)
    print("saved", os.path.join(config.state_dir(), "config.json"))

def cmd_boundary(a):
    if not a.extension_id:
        print("load extension/ unpacked in Opera GX (developer mode), then:")
        print("  python -m src boundary --extension-id <id>")
        return
    p = gx_boundary.install_host(a.extension_id)
    print("boundary host registered:", p)

def cmd_start(a):
    r = engine.start(extension_id=a.extension_id or "")
    if not r.get("ok"):
        print("start failed:", r.get("errors")); sys.exit(1)

def cmd_stop(a):
    engine.stop(); print("stopped")

def cmd_status(a):
    import json
    print(json.dumps(engine.status(), indent=2))

def cmd_doctor(a):
    cfg = config.load()
    checks = {"windows": sys.platform == "win32", "admin": winapi.is_admin(),
              "mitmdump": bool(__import__("shutil").which("mitmdump")),
              "config_valid": not config.validate(cfg),
              "ca_trusted": ca.is_installed(),
              "gx_image_verified": cfg["gx"]["verified"],
              "boundary_host": os.path.exists(gx_boundary.manifest_path()),
              "protected": len(cfg.get("protected", [])),
              "per_flow_only": cfg["enforce"]["per_flow_only"]}
    for k, v in checks.items():
        print("  [%s] %s" % ("ok" if v else "--", k))
    print(ca.CHROMIUM_NOTE)

def cmd_uninstall(a):
    r = uninstall.run(keep_data=a.keep_data)
    uninstall.print_report(r)
    sys.exit(0 if r["clean"] else 2)

def main(argv=None):
    p = argparse.ArgumentParser(prog="src", description="SRC - Source Route Control")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").set_defaults(fn=cmd_setup)
    s = sub.add_parser("start"); s.add_argument("--extension-id"); s.set_defaults(fn=cmd_start)
    sub.add_parser("stop").set_defaults(fn=cmd_stop)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("doctor").set_defaults(fn=cmd_doctor)
    b = sub.add_parser("boundary"); b.add_argument("--extension-id"); b.set_defaults(fn=cmd_boundary)
    u = sub.add_parser("uninstall"); u.add_argument("--keep-data", action="store_true")
    u.set_defaults(fn=cmd_uninstall)
    a = p.parse_args(argv)
    a.fn(a)
