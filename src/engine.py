# Orchestration. Installs both planes; never installs an app-wide network block.
import json, os, shutil, signal, subprocess, sys, time
from . import config, sigdb, ca, winapi, wfp, gx_boundary
from .etw_monitor import Monitor

def _p(n):
    return os.path.join(config.state_dir(), n)

def _read(n):
    try:
        return json.load(open(_p(n)))
    except Exception:
        return None

def build_index(cfg):
    ix = sigdb.AnchorIndex(cfg["match"]["chunk_kb"], cfg["match"]["min_contig"],
                           cfg["match"]["cap_anchors_per_source"])
    ix.build(cfg.get("protected", []))
    os.makedirs(config.state_dir(), exist_ok=True)
    with open(_p("index.json"), "w", encoding="utf-8") as f:
        json.dump(ix.to_json(), f)
    return ix

def _set_proxy(port):
    if sys.platform != "win32":
        return
    import winreg
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                       r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_ALL_ACCESS)
    bak = {}
    for n in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
        try:
            bak[n] = winreg.QueryValueEx(k, n)[0]
        except FileNotFoundError:
            bak[n] = None
    json.dump(bak, open(_p("proxy_backup.json"), "w"))
    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:%d" % port)
    winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
    winreg.CloseKey(k)
    _notify()

def restore_proxy():
    if sys.platform != "win32":
        return False
    import winreg
    bak = _read("proxy_backup.json")
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                       r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_ALL_ACCESS)
    if bak is None:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    else:
        for n, v in bak.items():
            if v is None:
                try:
                    winreg.DeleteValue(k, n)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, n, 0, winreg.REG_DWORD if isinstance(v, int) else winreg.REG_SZ, v)
    winreg.CloseKey(k)
    try:
        os.remove(_p("proxy_backup.json"))
    except OSError:
        pass
    _notify()
    return True

def _notify():
    try:
        import ctypes
        w = ctypes.WinDLL("wininet")
        w.InternetSetOptionW(0, 39, 0, 0)
        w.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass

def set_quic_policy(off=True):
    """Opera enterprise policy: disable QUIC so HTTP/3 cannot skip the TLS plane.
    This is a browser policy, not a network block, and it is reversible."""
    if sys.platform != "win32":
        return False
    import winreg
    path = r"Software\Policies\Opera Software\Opera GX"
    try:
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, path)
        if off:
            winreg.SetValueEx(k, "QuicAllowed", 0, winreg.REG_DWORD, 0)
        else:
            try:
                winreg.DeleteValue(k, "QuicAllowed")
            except FileNotFoundError:
                pass
        winreg.CloseKey(k)
        return True
    except Exception:
        return False

def start(cfg=None, foreground=True, extension_id=""):
    cfg = cfg or config.load()
    errs = config.validate(cfg)
    if errs:
        return {"ok": False, "errors": errs}
    if not winapi.is_admin():
        print("[!] elevated terminal recommended (ETW + CA)")
    ok, msg = ca.install()
    if not ok:
        return {"ok": False, "errors": ["CA install failed: " + msg]}

    ix = build_index(cfg)
    mon = Monitor(cfg, ix)
    mode = mon.start()

    if cfg["gx"]["boundary_sensor"] and extension_id:
        gx_boundary.install_host(extension_id)
    if cfg["enforce"]["quic_policy_off"]:
        set_quic_policy(True)

    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        return {"ok": False, "errors": ["mitmdump not found; pip install mitmproxy"]}
    addon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_addon.py")
    args = [mitmdump, "--listen-host", "127.0.0.1", "-p", str(cfg["packet"]["port"]),
            "-s", addon, "-q", "--set", "stream_large_bodies=2m"]
    if cfg["packet"]["mode"] == "local":
        args += ["--mode", "local:opera.exe"]
    env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    proc = subprocess.Popen(args, env=env)
    if cfg["packet"]["mode"] == "proxy":
        _set_proxy(cfg["packet"]["port"])

    json.dump({"mitm_pid": proc.pid, "port": cfg["packet"]["port"], "monitor": mode,
               "started": time.time()}, open(_p("engine.json"), "w"))
    print("[+] armed · provenance=%s · GX boundary=%s · packet-decrypt=%s"
          % (mode, cfg["gx"]["boundary_sensor"], cfg["packet"]["decrypt"]))
    print("    blocks require protected bytes in the payload; enforcement is per-flow")
    if foreground:
        try:
            proc.wait()
        except KeyboardInterrupt:
            pass
        finally:
            stop()
    return {"ok": True, "mitm_pid": proc.pid, "monitor": mode}

def stop():
    eng = _read("engine.json")
    if eng and eng.get("mitm_pid"):
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(eng["mitm_pid"]), "/T", "/F"], capture_output=True)
            else:
                os.kill(eng["mitm_pid"], signal.SIGTERM)
        except Exception:
            pass
    restore_proxy()
    wfp.remove_all()
    try:
        os.remove(_p("engine.json"))
    except OSError:
        pass
    return True

def status():
    return {"running": bool(_read("engine.json")), "engine": _read("engine.json"),
            "tainted_pids": len(_read("taint.json") or {}),
            "indexed_sources": len((_read("index.json") or {}).get("sources", {})),
            "ca_installed": ca.is_installed()}
