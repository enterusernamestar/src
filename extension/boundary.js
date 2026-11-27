// Opera GX application-boundary hook (MAIN world, document_start).
// Hashes outbound body chunks BEFORE the browser encrypts them into TLS, asks the
// native host whether those bytes come from a protected path, and cancels ONLY
// that request when the answer is yes. Clean bodies from a tainted browser pass.
(() => {
  const AVG = 8192, MIN = 2048, MAX = 65536, CAP = 512;
  const GEAR = (() => {
    let st = 0x9e3779b97f4a7c15n;
    const t = [];
    const M = 0xffffffffffffffffn;
    for (let i = 0; i < 256; i++) {
      st ^= (st << 13n) & M; st ^= st >> 7n; st ^= (st << 17n) & M;
      t.push(st);
    }
    return t;
  })();
  const M64 = 0xffffffffffffffffn;

  function chunks(bytes) {
    const out = [];
    let start = 0, h = 0n, mask = BigInt(AVG - 1);
    for (let i = 0; i < bytes.length && out.length < CAP; i++) {
      h = ((h << 1n) + GEAR[bytes[i]]) & M64;
      const size = i - start + 1;
      if ((size >= MIN && (h & mask) === 0n) || size >= MAX) {
        out.push(bytes.subarray(start, i + 1));
        start = i + 1; h = 0n;
      }
    }
    if (start < bytes.length && out.length < CAP) out.push(bytes.subarray(start));
    return out;
  }

  async function keysOf(bytes) {
    const ks = [];
    for (const c of chunks(bytes)) {
      const d = await crypto.subtle.digest('SHA-256', c);
      ks.push([...new Uint8Array(d)].slice(0, 12).map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    return ks;
  }

  function ask(url, keys, names) {
    return new Promise(res => {
      try {
        chrome.runtime.sendMessage({ type: 'src-ask', url, keys, names }, r => res(r || { block: false }));
      } catch (e) { res({ block: false }); }
    });
  }

  async function bodyBytes(body) {
    if (!body) return null;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
    if (typeof body === 'string') return new TextEncoder().encode(body);
    if (body instanceof URLSearchParams) return new TextEncoder().encode(body.toString());
    if (body instanceof FormData) {
      const parts = [];
      for (const [k, v] of body.entries()) {
        parts.push(new TextEncoder().encode('--src\r\n' + k + '\r\n'));
        if (v instanceof Blob) parts.push(new Uint8Array(await v.arrayBuffer()));
        else parts.push(new TextEncoder().encode(String(v)));
      }
      let n = parts.reduce((a, p) => a + p.length, 0);
      const out = new Uint8Array(n); let o = 0;
      for (const p of parts) { out.set(p, o); o += p.length; }
      return out;
    }
    return null;
  }

  function wrappedNames(body) {
    const names = [];
    if (body instanceof FormData) {
      for (const [, v] of body.entries()) {
        if (v instanceof File) names.push(v.name, v.webkitRelativePath || '');
      }
    } else if (body instanceof File) names.push(body.name);
    return names.filter(Boolean);
  }

  function blocked(reason, source) {
    const e = new Error('SRC: request blocked — payload carries protected content from ' + (source || 'a protected path'));
    e.name = 'SRCBlocked';
    return e;
  }

  const origFetch = window.fetch;
  window.fetch = async function (input, init) {
    try {
      const method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
      if (['POST', 'PUT', 'PATCH'].includes(method)) {
        const body = (init && init.body) || (input instanceof Request ? input.body : null);
        const bytes = await bodyBytes(body);
        if (bytes && bytes.length >= 512) {
          const url = typeof input === 'string' ? input : (input && input.url) || location.href;
          const r = await ask(url, await keysOf(bytes), wrappedNames(body));
          if (r.block) throw blocked(r.reason, r.source);
        }
      }
    } catch (e) {
      if (e && e.name === 'SRCBlocked') throw e;
    }
    return origFetch.apply(this, arguments);
  };

  const OrigXHR = window.XMLHttpRequest;
  const open = OrigXHR.prototype.open, send = OrigXHR.prototype.send;
  OrigXHR.prototype.open = function (m, u) { this.__srcM = (m || 'GET').toUpperCase(); this.__srcU = u; return open.apply(this, arguments); };
  OrigXHR.prototype.send = function (body) {
    const xhr = this;
    if (!['POST', 'PUT', 'PATCH'].includes(xhr.__srcM || '')) return send.apply(this, arguments);
    (async () => {
      let verdict = { block: false };
      try {
        const bytes = await bodyBytes(body);
        if (bytes && bytes.length >= 512) {
          verdict = await ask(xhr.__srcU || location.href, await keysOf(bytes), wrappedNames(body));
        }
      } catch (e) { /* sensor failure must not break the page */ }
      if (verdict.block) {
        try { xhr.abort(); } catch (e) {}
        xhr.dispatchEvent(new ProgressEvent('error'));
        console.warn('[SRC]', verdict.reason);
        return;
      }
      send.call(xhr, body);
    })();
  };

  const beacon = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
  if (beacon) {
    navigator.sendBeacon = function (url, data) {
      // beacons are fire-and-forget: hash synchronously is impossible, so route via fetch gate
      bodyBytes(data).then(async b => {
        if (!b || b.length < 512) return beacon(url, data);
        const r = await ask(String(url), await keysOf(b), wrappedNames(data));
        if (!r.block) beacon(url, data);
        else console.warn('[SRC] beacon blocked:', r.reason);
      });
      return true;
    };
  }
})();
