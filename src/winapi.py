# Win32 helpers. Import-safe off-Windows. Per-flow primitives only.
import ctypes, sys, socket, os

IS_WIN = sys.platform == "win32"
if IS_WIN:
    from ctypes import wintypes
    iphlpapi = ctypes.WinDLL("iphlpapi")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

def is_admin():
    if not IS_WIN:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def image_path(pid):
    if not IS_WIN or not pid:
        return ""
    h = kernel32.OpenProcess(0x1000, False, int(pid))
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        sz = wintypes.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
            return buf.value
        return ""
    finally:
        kernel32.CloseHandle(h)

def thread_pid(tid):
    if not IS_WIN or not tid:
        return None
    h = kernel32.OpenThread(0x0400, False, int(tid))   # THREAD_QUERY_INFORMATION
    if not h:
        return None
    try:
        return int(kernel32.GetProcessIdOfThread(h)) or None
    finally:
        kernel32.CloseHandle(h)

class TCPROW(ctypes.Structure if IS_WIN else object):
    if IS_WIN:
        _fields_ = [("state", ctypes.c_uint32), ("localAddr", ctypes.c_uint32),
                    ("localPort", ctypes.c_uint32), ("remoteAddr", ctypes.c_uint32),
                    ("remotePort", ctypes.c_uint32), ("pid", ctypes.c_uint32)]

def tcp_rows():
    rows = []
    if not IS_WIN:
        return rows
    size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
    buf = (ctypes.c_ubyte * size.value)()
    if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 5, 0) != 0:
        return rows
    n = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0]
    stride = ctypes.sizeof(TCPROW)
    for i in range(n):
        r = ctypes.cast(ctypes.byref(buf, 4 + i * stride), ctypes.POINTER(TCPROW)).contents
        rows.append({"localAddr": r.localAddr, "localPort": socket.ntohs(r.localPort & 0xFFFF),
                     "remoteAddr": r.remoteAddr, "remotePort": socket.ntohs(r.remotePort & 0xFFFF),
                     "pid": r.pid, "state": r.state})
    return rows

def port_pid(client_port, proxy_port=None):
    for r in tcp_rows():
        if r["localPort"] == int(client_port) and (proxy_port is None or r["remotePort"] == int(proxy_port)):
            return r["pid"]
    return None

def flow_of_client_port(client_port, proxy_port):
    """Exact 5-tuple of the browser->proxy socket, for per-flow termination."""
    for r in tcp_rows():
        if r["localPort"] == int(client_port) and r["remotePort"] == int(proxy_port):
            return r
    return None

def kill_flow(row):
    """Terminate ONE TCP flow (MIB_TCP_STATE_DELETE_TCB). Never app-wide."""
    if not IS_WIN or not row:
        return False
    r = TCPROW()
    r.state = 12
    r.localAddr = row["localAddr"]
    r.localPort = socket.htons(int(row["localPort"]))
    r.remoteAddr = row["remoteAddr"]
    r.remotePort = socket.htons(int(row["remotePort"]))
    return iphlpapi.SetTcpEntry(ctypes.byref(r)) == 0

def process_snapshot():
    out = {}
    if not IS_WIN:
        return out
    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return out
    try:
        pe = PE(); pe.dwSize = ctypes.sizeof(PE)
        if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                out[pe.th32ProcessID] = (pe.th32ParentProcessID, pe.szExeFile)
                if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return out

def pids_for_image(name):
    name = os.path.basename(name).lower()
    return [p for p, (_, exe) in process_snapshot().items() if exe.lower() == name]

def nt_path(win32):
    if not IS_WIN or len(win32) < 2 or win32[1] != ":":
        return win32
    buf = ctypes.create_unicode_buffer(1024)
    if kernel32.QueryDosDeviceW(win32[:2], buf, 1024):
        return buf.value + win32[2:]
    return win32

def dos_path(nt):
    if not IS_WIN or not nt.startswith("\\Device\\"):
        return nt
    for d in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        buf = ctypes.create_unicode_buffer(1024)
        if kernel32.QueryDosDeviceW(d + ":", buf, 1024) and nt.startswith(buf.value):
            return d + ":" + nt[len(buf.value):]
    return nt
