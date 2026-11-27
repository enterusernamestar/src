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
