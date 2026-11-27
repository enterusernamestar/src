# SRC - Source Route Control

Resource-light, **content-confirmed** exfiltration prevention for Windows 11.

## The rule

```
BLOCK  <=>  the outbound payload actually carries >= min_contig contiguous bytes
            of a file that lives under a protected path.
```

Taint is **provenance**, not a trigger. A process that read a protected file and
then talks to the network is **allowed** unless its payload is proven to contain
that file's bytes. Destination / SNI / reputation are never used.

There is **no app-wide kill switch**. Enforcement is always one request or one
flow: HTTP 403 for that request, or terminate that exact TCP 5-tuple.

## Two planes

| plane | scope | where the body is read | enforcement |
| --- | --- | --- | --- |
| **A — Opera GX application boundary** | `opera.exe` image path / package, verified at setup | inside the renderer, **before TLS** (`extension/boundary.js` hooks `fetch` / `XHR` / `sendBeacon` / `FormData` / `Blob`, CDC-hashes chunks with SubtleCrypto, asks the native host) | cancel that one request |
| **A' — GX proxy backstop** | same image, via mitmproxy `--mode local:opera.exe` | plaintext at the proxy, before upstream TLS | 403 / kill that flow |
| **B — packet decryption** | every other process | mitmproxy MITM with a trusted local root CA | 403 / kill that flow |

Both planes run the **same** verdict function (`src/provenance.py`) against the
**same** anchor index, so they cannot disagree about what "forbidden content from
a forbidden path" means.

The GX boundary hook also inspects *wrapped* payload names (`File.name`, 
`webkitRelativePath`, FormData filenames) that try to smuggle a protected path —
but that is **corroborating** evidence only; it never blocks on its own.

## Resource-light by construction

- ETW `Microsoft-Windows-Kernel-File` with narrowed keywords; `FileObject -> path`
  resolved once on Create and cached (bounded LRU), so steady state is a dict hit.
- Anchors are 12-byte digest keys with a per-source cap; no raw file bytes retained.
- One streaming CDC pass per body, **early exit on first evidence**.
- `min_body` skip, `max_inspect_bytes` ceiling, `stream_large_bodies` on the proxy.
- Taint ledger has TTL + PID cap; scope `taint` searches only the sources that PID
  actually touched (global sweep is opt-in because it costs CPU).
- Index re-hash is triggered by mtime/size drift only, never per flow.

## Install

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src setup                 # protected paths + Opera GX image
python -m src doctor
# load extension/ unpacked in Opera GX (developer mode), copy its ID, then:
python -m src boundary --extension-id <id>
python -m src start --extension-id <id>
```

`start` installs the mitmproxy root CA into **Trusted Root Certification
Authorities** (`LocalMachine\Root`). Chromium's Chrome Root Store honors
locally-added roots on Windows, so Opera GX accepts interception without any
`opera://flags` change; restart Opera GX if you still see
`NET::ERR_CERT_AUTHORITY_INVALID`.

QUIC is turned off through Opera **enterprise policy** (`QuicAllowed=false`) so
HTTP/3 cannot bypass the TLS plane. That is a browser policy, not a network block,
and uninstall restores it.

## Uninstall

```powershell
python -m src uninstall
```

Stops the engine, removes WFP redirect filters, removes the boundary native host
and its registry entries, restores the QUIC policy, **removes the root CA from
Trusted Root**, restores WinINET proxy settings, removes autorun, deletes state,
then prints a verification report.

## Tests

```bash
python -m unittest discover -s tests -v
```

`tests/test_policy.py` pins the rule: taint alone allows, clean body from a tainted
process allows, content evidence blocks per-flow, evidence is bound to the
protected path, and `per_flow_only` cannot be turned off.

## License

MIT.
