/* Isolated-world bridge and interstitial.

   This script carries no decision logic: it relays the request to the service
   worker, which owns enforce.js, and renders the result. The page cannot reach
   chrome.runtime from the MAIN world, so the verdict is produced outside the
   page's reach even though the wrapper that enforces it is not. */
(() => {
  'use strict';
  const CHANNEL = 'aisecure-preflight';

  const REASONS = {
    secret_detected: ['この送信を停止しました', '秘密鍵・認証情報に一致するパターンを検出しました。値は表示しません。取り消して、該当箇所を削除してください。'],
    review_required: ['送信前に確認が必要です', '個人情報・社外秘表記など、確認が必要なパターンを検出しました。検出なしでも安全の証明にはなりません。'],
    uninspectable_body: ['内容を読み取れませんでした', '添付やバイナリ形式のため、この送信の中身を検査できませんでした。検査していない、という意味です。'],
    inspection_unavailable: ['検査サービスに接続できません', '端末内の検査サービスが応答しないため、送信を許可しません。ワークベンチの起動とネイティブホストの登録を確認してください。'],
    unexpected_response: ['検査結果を確認できません', '想定外の応答のため、送信を許可しません。'],
  };

  function interstitial(verdict) {
    return new Promise(resolve => {
      const [title, detail] = REASONS[verdict.reason] || ['送信を停止しました', verdict.reason];
      const host = document.createElement('div');
      host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647';
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `
        <style>
          :host{all:initial}
          .sheet{position:fixed;inset:0;display:grid;place-items:center;background:rgba(4,6,10,.72);
            font:16px/1.7 system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}
          .card{max-width:520px;width:calc(100% - 40px);background:#11141b;color:#eef1f6;border:1px solid #272c38;
            border-radius:16px;padding:28px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
          .tag{font:700 11px/1.4 ui-monospace,monospace;letter-spacing:.12em;color:#54e0b2;margin:0 0 14px}
          h2{font-size:21px;line-height:1.45;margin:0 0 12px}
          p{color:#98a1b2;font-size:14px;margin:0 0 14px}
          ul{margin:0 0 16px;padding-left:20px;color:#98a1b2;font-size:13px}
          code{font-family:ui-monospace,monospace;color:#f5c26b}
          .row{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}
          button{font:inherit;font-size:14px;min-height:44px;padding:11px 18px;border-radius:10px;cursor:pointer;
            border:1px solid #272c38;background:#0c0e13;color:#eef1f6}
          button.go{background:#2a1416;border-color:#5a2a2e;color:#ffb4b4}
          button:focus-visible{outline:3px solid #54e0b2;outline-offset:3px}
          .note{font-size:12px;color:#6f7787;margin:16px 0 0}
        </style>
        <div class="sheet" role="dialog" aria-modal="true" aria-labelledby="t">
          <div class="card">
            <p class="tag">AISECURE / 送信前検査</p>
            <h2 id="t"></h2>
            <p id="d"></p>
            <ul id="r" hidden></ul>
            <div class="row">
              <button id="cancel">取り消して戻る</button>
              <button id="go" class="go" hidden>理解したうえで送信する</button>
            </div>
            <p class="note">この確認はブラウザ内の best effort です。別ブラウザ・別経路・拡張の無効化は防げません。</p>
          </div>
        </div>`;
      root.getElementById('t').textContent = title;
      root.getElementById('d').textContent = detail;
      if (verdict.rules && verdict.rules.length) {
        const list = root.getElementById('r');
        list.hidden = false;
        for (const rule of verdict.rules) {
          const item = document.createElement('li');
          item.textContent = '検出ルール: ' + rule;
          list.appendChild(item);
        }
      }
      const finish = allowed => { host.remove(); resolve(allowed); };
      root.getElementById('cancel').addEventListener('click', () => finish(false));
      const go = root.getElementById('go');
      if (verdict.override) {
        go.hidden = false;
        go.addEventListener('click', () => finish(true));
      }
      (document.body || document.documentElement).appendChild(host);
      root.getElementById('cancel').focus();
    });
  }

  window.addEventListener('message', async event => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || data.direction !== 'inspect') return;
    let verdict;
    try {
      verdict = await chrome.runtime.sendMessage({ action: 'enforce_prompt', request: data.request });
    } catch {
      verdict = { action: 'block', reason: 'inspection_unavailable', override: false };
    }
    if (!verdict || typeof verdict !== 'object') {
      verdict = { action: 'block', reason: 'unexpected_response', override: false };
    }
    if (verdict.action !== 'allow') {
      const allowed = await interstitial(verdict);
      if (allowed && verdict.override) verdict = { action: 'allow', reason: 'user_confirmed', override: false };
    }
    window.postMessage({ channel: CHANNEL, direction: 'verdict', id: data.id, result: verdict }, window.origin);
  });
})();
