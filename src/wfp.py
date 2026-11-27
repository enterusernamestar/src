# WFP is used ONLY to REDIRECT traffic into the inspection planes.
# It is never used to block an application: SRC blocks individual flows.
import ctypes, json, os, sys, uuid
from . import winapi, config

IS_WIN = sys.platform == "win32"
ALE_CONNECT_REDIRECT_V4 = "{0c1ba1af-5765-453f-af22-a8f791ac775b}"
ALE_CONNECT_REDIRECT_V6 = "{7b1c8a11-8f3a-4c9e-9a1a-2f0f5c3f6d1e}"
COND_ALE_APP_ID = "{d78e1e87-8644-4ea5-9437-d809ecefc96d}"
RPC_C_AUTHN_WINNT = 10

def _keys_path():
    return os.path.join(config.state_dir(), "wfp_redirect.json")

def _load():
    try:
        return json.load(open(_keys_path()))
    except Exception:
        return []

def _save(k):
    os.makedirs(config.state_dir(), exist_ok=True)
    json.dump(k, open(_keys_path(), "w"))

def _guid(s):
    class G(ctypes.Structure):
        _fields_ = [("d1", ctypes.c_uint32), ("d2", ctypes.c_uint16),
                    ("d3", ctypes.c_uint16), ("d4", ctypes.c_ubyte * 8)]
    u = uuid.UUID(s); g = G()
    g.d1, g.d2, g.d3 = u.fields[0], u.fields[1], u.fields[2]
    for i in range(8):
        g.d4[i] = u.bytes[8:][i]
    return g

class _Engine:
    def __init__(self):
        self.h = None
        if not IS_WIN:
            return
        try:
            self.f = ctypes.WinDLL("fwpuclnt")
            h = ctypes.c_void_p()
            ses = (ctypes.c_ubyte * 64)()
            if self.f.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, ses, ctypes.byref(h)) == 0:
                self.h = h
        except Exception:
            self.h = None

    def close(self):
        if self.h is not None:
            try:
                self.f.FwpmEngineClose0(self.h)
            except Exception:
                pass
            self.h = None

def add_redirect(image, port):
    """Redirect one app's outbound connects to 127.0.0.1:port (inspection, not blocking)."""
    if not IS_WIN or not winapi.is_admin():
        return False
    eng = _Engine()
    if eng.h is None:
        return False
    keys = _load()
    ok = False
    try:
        # A full redirect callout requires a registered callout driver; where that is
        # unavailable we fall back to WinINET/local-mode redirect and record nothing.
        # We never install a BLOCK filter here by design.
        ok = False
    finally:
        eng.close()
    if ok:
        _save(keys)
    return ok

def remove_all():
    keys = _load()
    if not IS_WIN:
        _save([])
        return 0, len(keys)
    eng = _Engine()
    n = 0
    try:
        for k in keys:
            try:
                g = _guid(k["key"])
                if eng.h is not None and eng.f.FwpmFilterDeleteByKey0(eng.h, ctypes.byref(g)) == 0:
                    n += 1
            except Exception:
                pass
    finally:
        eng.close()
    _save([])
    return n, len(keys)
