import test from 'node:test';
import assert from 'node:assert/strict';
import { candidate, endpointLabel, extractText, decide, evaluateRequest, MIN_TEXT, HOSTS } from './enforce.js';

const prompt = 'x'.repeat(MIN_TEXT + 10);

test('configured hosts with state-changing methods are candidates', () => {
  assert.equal(candidate('https://chatgpt.com/backend-api/conversation', 'POST'), true);
  assert.equal(candidate('https://claude.ai/api/organizations/o1/chat_conversations/c1/completion', 'POST'), true);
  assert.equal(candidate('https://chatgpt.com/backend-api/conversation', 'GET'), false);
});

test('host matching is exact, so a lookalike domain cannot opt in or out', () => {
  assert.equal(candidate('https://chatgpt.com.evil.test/backend-api/conversation', 'POST'), false);
  assert.equal(candidate('https://evil.test/?x=chatgpt.com', 'POST'), false);
  assert.equal(candidate('https://notchatgpt.com/backend-api/conversation', 'POST'), false);
});

test('a renamed vendor endpoint is still inspected, only the label changes', () => {
  const renamed = 'https://chatgpt.com/backend-api/v9/send';
  assert.equal(candidate(renamed, 'POST'), true);
  assert.equal(endpointLabel(renamed), 'other_request');
  assert.equal(endpointLabel('https://chatgpt.com/backend-api/f/conversation'), 'known_prompt_endpoint');
});

test('text is collected from nested JSON', () => {
  const body = JSON.stringify({ messages: [{ content: { parts: ['secret memo', 'second'] } }], n: 3, ok: true });
  const text = extractText(body);
  assert.match(text, /secret memo/);
  assert.match(text, /second/);
});

test('non-string bodies are reported as unreadable, never as clean', () => {
  assert.equal(extractText(new Uint8Array([1, 2, 3])), null);
  assert.equal(extractText({ not: 'a string' }), null);
  assert.equal(extractText(''), '');
});

test('an unreadable body stops the request but can be confirmed through', () => {
  const d = decide({ uninspectable: true });
  assert.equal(d.action, 'confirm');
  assert.equal(d.override, true);
});

test('an unavailable inspector fails closed with no override', () => {
  for (const outcome of [{ error: 'offline' }, {}, null, 'nope']) {
    const d = decide(outcome);
    assert.equal(d.action, 'block');
    assert.equal(d.override, false);
  }
});

test('a detected secret cannot be overridden, a review can', () => {
  assert.deepEqual(decide({ decision: 'block', rules: ['DOC-SECRET'] }),
    { action: 'block', reason: 'secret_detected', override: false, rules: ['DOC-SECRET'] });
  assert.equal(decide({ decision: 'review', rules: ['DOC-PII'] }).action, 'confirm');
  assert.equal(decide({ decision: 'no_findings', rules: [] }).action, 'allow');
});

test('no findings is allowed but never labelled safe or authorized', () => {
  const d = decide({ decision: 'no_findings', rules: [] });
  assert.equal(d.reason, 'no_findings');
  assert.equal(d.override, false);
  assert.equal('release_authorized' in d, false);
});

test('short payloads and unrelated hosts never reach the inspector', async () => {
  let called = 0;
  const inspect = async () => { called += 1; return { decision: 'block', rules: ['DOC-SECRET'] }; };
  assert.equal((await evaluateRequest({ url: 'https://example.test/x', method: 'POST', body: prompt }, inspect)).action, 'allow');
  assert.equal((await evaluateRequest({ url: 'https://chatgpt.com/a', method: 'POST', body: 'short' }, inspect)).action, 'allow');
  assert.equal(called, 0);
});

test('a prompt on a configured host is inspected and blocked', async () => {
  const seen = [];
  const inspect = async (request) => { seen.push(request); return { decision: 'block', rules: ['DOC-SECRET'] }; };
  const result = await evaluateRequest(
    { url: 'https://chatgpt.com/backend-api/conversation', method: 'POST', body: JSON.stringify({ text: prompt }) },
    inspect);
  assert.equal(result.action, 'block');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].endpoint, 'known_prompt_endpoint');
  assert.match(seen[0].text, /xxxx/);
});

test('an inspector that throws is treated as unavailable, not as approval', async () => {
  const inspect = async () => { throw new Error('native host missing'); };
  const result = await evaluateRequest(
    { url: 'https://chatgpt.com/backend-api/conversation', method: 'POST', body: JSON.stringify({ text: prompt }) },
    inspect);
  assert.equal(result.action, 'block');
  assert.equal(result.reason, 'inspection_unavailable');
  assert.equal(result.override, false);
});

test('the injected hosts and the enforced hosts cannot drift apart', async () => {
  const { readFileSync } = await import('node:fs');
  const manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'));
  const fromMatches = list => list.map(pattern => new URL(pattern.replace('/*', '/')).hostname).sort();
  assert.deepEqual(fromMatches(manifest.host_permissions), [...HOSTS].sort());
  for (const script of manifest.content_scripts) {
    assert.deepEqual(fromMatches(script.matches), [...HOSTS].sort());
  }
  // The MAIN-world wrapper must load before the page's own scripts.
  const injected = manifest.content_scripts.find(s => s.world === 'MAIN');
  assert.equal(injected.run_at, 'document_start');
  assert.deepEqual(injected.js, ['inject.js']);
});
