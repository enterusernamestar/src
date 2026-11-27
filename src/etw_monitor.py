# Provenance acquisition. Primary: ETW Microsoft-Windows-Kernel-File.
# Resolves FileObject -> path once (Create), then Read/Write resolve from cache,
# so steady-state cost is a dict lookup, not a path query per event.
# Fallback: bounded open-handle scan (SystemExtendedHandleInformation + NtQueryObject).
import json, os, threading, time, collections
from . import config, taint, winapi

KERNEL_FILE = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
KW_READ = 0x100
KW_WRITE = 0x200
KW_NAME = 0x80
KW_FILEIO = 0x1000

class Monitor:
    def __init__(self, cfg, index):
        self.cfg = cfg
        self.index = index
        self.ledger = taint.TaintLedger(cfg["taint"]["ttl_s"], cfg["taint"]["depth"],
                                        cfg["taint"]["max_pids"])
        self.stop = threading.Event()
        self.mode = "none"
        self._obj2path = collections.OrderedDict()   # FileObject -> path (bounded LRU)
        self._obj_cap = 8192
        self._prefix = {}
        for i, e in enumerate(cfg.get("protected", [])):
            sid = e.get("id") or ("s%d" % i)
            self._prefix[os.path.normcase(e["path"]).rstrip("\\")] = sid
        self._etw = None
        self._thread = None
        self.events = 0

    # ---------- provenance matching ----------
    def _sid_for(self, path):
        if not path:
            return None
        p = os.path.normcase(path)
        for pre, sid in self._prefix.items():
            if p == pre or p.startswith(pre + "\\"):
                return sid
        return None

    def _remember_obj(self, obj, path):
        if not obj or not path:
            return
        self._obj2path[obj] = path
        if len(self._obj2path) > self._obj_cap:
            self._obj2path.popitem(last=False)

    def _record(self, pid, path, how):
        sid = self._sid_for(path)
        if not sid or not pid:
            return
        self.events += 1
        self.ledger.touch(pid, sid, image=winapi.image_path(pid), path=path)

    # ---------- lifecycle ----------
    def start(self):
        want = self.cfg["taint"]["monitor"]
        if want in ("auto", "etw") and self._start_etw():
            self.mode = "etw"
        elif want in ("auto", "handles") and winapi.IS_WIN:
            self.mode = "handles"
            self._thread = threading.Thread(target=self._handle_loop, daemon=True)
            self._thread.start()
        self._writer = threading.Thread(target=self._write_loop, daemon=True)
        self._writer.start()
        return self.mode

    def _start_etw(self):
        try:
            import etw
        except Exception:
            return False
        mon = self

        class Consumer(etw.ETW):
            def on_event_callback(self_, ev):
                try:
                    hdr = ev.get("EventHeader", {}) or {}
                    pid = hdr.get("ProcessId") or winapi.thread_pid(hdr.get("ThreadId"))
                    props = ev.get("Properties", {}) or {}
                    name = ev.get("EventName") or ev.get("TaskName") or ""
                    obj = props.get("FileObject") or props.get("FileKey")
                    path = props.get("FileName") or props.get("FilePath") or ""
                    if path:
                        mon._remember_obj(obj, path)
                    else:
                        path = mon._obj2path.get(obj, "")
                    if not path:
                        return
                    if isinstance(name, str) and name.lower().startswith(("read", "write", "create", "cleanup")):
                        mon._record(pid, path, name)
                    elif not name:
                        mon._record(pid, path, "fileio")
                except Exception:
                    pass

        try:
            prov = etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(KERNEL_FILE),
                                    any_keyword=(KW_READ | KW_WRITE | KW_NAME | KW_FILEIO))
            self._etw = Consumer(providers=[prov], event_callback=Consumer.on_event_callback)
            self._etw.start()
            return True
        except Exception:
            try:
                prov = etw.ProviderInfo("Microsoft-Windows-Kernel-File", etw.GUID(KERNEL_FILE))
                self._etw = Consumer(providers=[prov], event_callback=Consumer.on_event_callback)
                self._etw.start()
                return True
            except Exception:
                return False

    # ---------- bounded handle-scan fallback ----------
    def _handle_loop(self):
        seen = {}
        while not self.stop.is_set():
            try:
                self._scan_handles(seen)
            except Exception:
                pass
            self.stop.wait(3.0)

    def _scan_handles(self, seen):
        import ctypes
        nt = ctypes.WinDLL("ntdll")
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        SystemExtendedHandleInformation = 64
        sz = ctypes.c_ulong(0x20000)
        buf = (ctypes.c_ubyte * sz.value)()
        while nt.NtQuerySystemInformation(SystemExtendedHandleInformation, buf, sz, ctypes.byref(sz)) == 0xC0000004:
            sz = ctypes.c_ulong(sz.value * 2)
            buf = (ctypes.c_ubyte * sz.value)()

        class ENTRY(ctypes.Structure):
            _fields_ = [("Object", ctypes.c_void_p), ("UniqueProcessId", ctypes.c_size_t),
                        ("HandleValue", ctypes.c_size_t), ("GrantedAccess", ctypes.c_ulong),
                        ("CreatorBackTraceIndex", ctypes.c_ushort), ("ObjectTypeIndex", ctypes.c_ushort),
                        ("HandleAttributes", ctypes.c_ulong), ("Reserved", ctypes.c_ulong)]

        count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_size_t))[0]
        ptr_size = ctypes.sizeof(ctypes.c_size_t)
        base = ptr_size * 2
        stride = ctypes.sizeof(ENTRY)
        cur_pid = os.getpid()
        DUP = 0x0040
        PROTECT = 0x1000
        for i in range(min(count, 200000)):
            if self.stop.is_set():
                return
            e = ctypes.cast(ctypes.byref(buf, base + i * stride), ctypes.POINTER(ENTRY)).contents
            pid = int(e.UniqueProcessId)
            if pid == cur_pid or pid == 0 or pid == 4:
                continue
            ck = (pid, int(e.HandleValue))
            if ck in seen:
                continue
            seen[ck] = True
            if len(seen) > 200000:
                seen.clear()
            hp = k32.OpenProcess(PROTECT | DUP, False, pid)
            if not hp:
                continue
            dup = ctypes.c_void_p()
            ok = k32.DuplicateHandle(hp, ctypes.c_void_p(e.HandleValue),
                                     ctypes.c_void_p(-1), ctypes.byref(dup), 0, False, DUP)
            k32.CloseHandle(hp)
            if not ok:
                continue
            try:
                need = ctypes.c_ulong(0)
                nt.NtQueryObject(dup, 1, None, 0, ctypes.byref(need))
                if need.value == 0 or need.value > 4096:
                    continue
                ob = (ctypes.c_ubyte * need.value)()
                if nt.NtQueryObject(dup, 1, ob, need, ctypes.byref(need)) != 0:
                    continue
                ln = ctypes.cast(ob, ctypes.POINTER(ctypes.c_ushort))[0]
                pstr = ctypes.wstring_at(ctypes.byref(ob, ptr_size * 2), ln // 2)
                dos = winapi.dos_path(pstr)
                self._record(pid, dos, "handle")
            finally:
                k32.CloseHandle(dup)

    # ---------- share ledger with both planes ----------
    def _write_loop(self):
        while not self.stop.is_set():
            self.ledger.cleanup()
            try:
                os.makedirs(config.state_dir(), exist_ok=True)
                tmp = os.path.join(config.state_dir(), "taint.json.tmp")
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.ledger.snapshot(), f)
                os.replace(tmp, os.path.join(config.state_dir(), "taint.json"))
            except Exception:
                pass
            self.stop.wait(1.0)

    def stop_monitor(self):
        self.stop.set()
        try:
            if self._etw:
                self._etw.stop()
        except Exception:
            pass
