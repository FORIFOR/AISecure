/* MAIN-world fetch wrapper. Runs at document_start on the hosts listed in
   manifest.json, ahead of the page's own scripts, so the page sees this fetch.

   What this covers: window.fetch with a readable text body.
   What it does not cover: XMLHttpRequest, sendBeacon, WebSocket, requests made
   from a service worker or a cross-origin iframe, and any page that captures a
   pristine fetch (for example from a fresh iframe) before or after this runs.
   This wrapper shares the MAIN world with the page by necessity, so it is a
   guard against mistakes, not a boundary against someone who wants around it.
   See docs/security/THREAT_MODEL.md §2: A3 and A4 are out of scope. */
(() => {
  'use strict';
  const nativeFetch = window.fetch;
  if (typeof nativeFetch !== 'function') return;
  const CHANNEL = 'aisecure-preflight';
  const pending = new Map();
  let sequence = 0;

  window.addEventListener('message', event => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || data.direction !== 'verdict') return;
    const resolve = pending.get(data.id);
    if (resolve) { pending.delete(data.id); resolve(data.result); }
  });

  function ask(request) {
    return new Promise(resolve => {
      const id = ++sequence;
      pending.set(id, resolve);
      window.postMessage({ channel: CHANNEL, direction: 'inspect', id, request }, window.origin);
      // A missing content script must not hang the page forever, and must not
      // turn into silent approval either.
      setTimeout(() => {
        if (pending.delete(id)) resolve({ action: 'block', reason: 'inspection_unavailable', override: false });
      }, 20000);
    });
  }

  /* Only a body we can read as text is inspectable. A multipart upload or a
     stream is reported as unreadable so it stops for confirmation rather than
     passing as checked. */
  async function readBody(input, init) {
    if (init && 'body' in init) {
      const raw = init.body;
      if (raw === null || raw === undefined) return '';
      if (typeof raw === 'string') return raw;
      if (typeof URLSearchParams === 'function' && raw instanceof URLSearchParams) return raw.toString();
      return null;
    }
    if (typeof Request === 'function' && input instanceof Request) {
      const type = input.headers.get('content-type') || '';
      if (!/json|text|urlencoded/i.test(type)) return null;
      try { return await input.clone().text(); } catch { return null; }
    }
    return '';
  }

  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const method = (init && init.method) || (input && input.method) || 'GET';
    if (!['POST', 'PUT', 'PATCH'].includes(String(method).toUpperCase())) {
      return nativeFetch.apply(this, arguments);
    }
    let verdict;
    try {
      const body = await readBody(input, init);
      verdict = await ask({ url, method, body, unreadable: body === null });
    } catch {
      verdict = { action: 'block', reason: 'inspection_unavailable', override: false };
    }
    if (verdict.action === 'allow') return nativeFetch.apply(this, arguments);
    throw new DOMException('AISecure: 送信前検査で停止しました (' + verdict.reason + ')', 'AbortError');
  };
})();
