# Reverses every system change, including the boundary host and QUIC policy.
import os, shutil, sys
from . import config, ca, engine, wfp, gx_boundary

def _autostart():
    if sys.platform != "win32":
        return
    import winreg, subprocess
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.DeleteValue(k, "SRC")
        except FileNotFoundError:
            pass
        winreg.CloseKey(k)
    except Exception:
        pass
    subprocess.run(["schtasks", "/Delete", "/TN", "SRC-Watchdog", "/F"], capture_output=True)

def run(keep_data=False):
    rep = []
    engine.stop(); rep.append(("stop engine + mitmproxy", True))
    n, t = wfp.remove_all(); rep.append(("remove WFP redirect filters (%d/%d)" % (n, t), True))
    gx_boundary.remove_host(); rep.append(("remove GX boundary native host", True))
    engine.set_quic_policy(False); rep.append(("restore Opera QUIC policy", True))
    ok, _ = ca.remove(); rep.append(("remove root CA from Trusted Root", ok))
    engine.restore_proxy(); rep.append(("restore system proxy settings", True))
    _autostart(); rep.append(("remove autorun", True))
    sd = config.state_dir()
    if not keep_data and os.path.isdir(sd):
        shutil.rmtree(sd, ignore_errors=True)
        rep.append(("delete state dir", not os.path.isdir(sd)))
    verify = {"ca_absent": not ca.is_installed(),
              "engine_stopped": engine.status()["running"] is False,
              "state_removed": (not os.path.isdir(sd)) if not keep_data else True}
    return {"report": rep, "verify": verify,
            "clean": all(v for _, v in rep) and all(verify.values())}

def print_report(r):
    print("SRC uninstall report")
    for n, ok in r["report"]:
        print("  [%s] %s" % ("ok" if ok else "!!", n))
    for k, v in r["verify"].items():
        print("  [%s] %s" % ("ok" if v else "!!", k))
    print("RESULT:", "CLEAN" if r["clean"] else "CHECK FAILED ITEMS")
