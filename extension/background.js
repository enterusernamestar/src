// Bridges the in-page boundary hook to the SRC native host.
const HOST = 'com.src.boundary';
let port = null;
let seq = 0;
const pending = new Map();

function connect() {
  try {
    port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener(m => {
      const r = pending.get(m.__id);
      if (r) { pending.delete(m.__id); r(m); }
    });
    port.onDisconnect.addListener(() => { port = null; });
  } catch (e) { port = null; }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'src-ask') {
    if (!port) connect();
    if (!port) { sendResponse({ block: false, reason: 'host unavailable' }); return true; }
    const id = ++seq;
    pending.set(id, reply => sendResponse(reply));
    try {
      port.postMessage({ __id: id, url: msg.url, keys: msg.keys, names: msg.names });
    } catch (e) {
      pending.delete(id);
      sendResponse({ block: false, reason: 'post failed' });
    }
    return true;   // async
  }
});
