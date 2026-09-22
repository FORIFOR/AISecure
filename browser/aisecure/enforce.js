/* Decision logic for in-page enforcement. Pure functions only: no DOM, no
   chrome APIs, no network. Everything here is unit-tested by enforce.test.js.

   Boundary: this stops a prompt that the page sends through window.fetch on a
   configured host. It is best effort against a careless user (A1/A2 in
   docs/security/THREAT_MODEL.md). It is NOT a boundary against a user who
   wants to bypass it, or against a hostile page: both share the MAIN world
   with the wrapper and can restore the original fetch. */

/* Hosts whose prompt traffic is inspected. Subdomains are matched explicitly,
   never by suffix, so "chatgpt.com.evil.test" cannot opt itself in or out. */
export const HOSTS = ['chatgpt.com', 'chat.openai.com', 'claude.ai', 'gemini.google.com'];

/* Known prompt endpoints, used only to label a request in the audit record.
   Inspection does not depend on them: vendors rename these paths, and a
   rename must not silently create a hole. */
const KNOWN = [
  [/^chatgpt\.com|^chat\.openai\.com/, /^\/backend-api\/(f\/)?conversation\b/],
  [/^claude\.ai/, /^\/api\/organizations\/[^/]+\/chat_conversations\/[^/]+\/(completion|retry_completion)\b/],
  [/^gemini\.google\.com/, /StreamGenerate|GenerateContent/],
];

export const MIN_TEXT = 40;        // shorter payloads are navigation/telemetry noise
export const MAX_TEXT = 262144;    // matches the native host limit

export function inspectedHost(hostname) {
  return HOSTS.includes(hostname);
}

/* Which requests are candidates for inspection. Deliberately broad: any
   state-changing request on a configured host. extractText() then decides
   whether there is enough text to be worth a verdict. */
export function candidate(url, method) {
  let parsed;
  try { parsed = new URL(url, 'https://invalid.localhost'); } catch { return false; }
  if (!inspectedHost(parsed.hostname)) return false;
  return ['POST', 'PUT', 'PATCH'].includes(String(method || 'GET').toUpperCase());
}

export function endpointLabel(url) {
  let parsed;
  try { parsed = new URL(url, 'https://invalid.localhost'); } catch { return 'unparsable'; }
  const known = KNOWN.some(([host, path]) => host.test(parsed.hostname) && path.test(parsed.pathname + parsed.search));
  return known ? 'known_prompt_endpoint' : 'other_request';
}

/* Collect the human-readable strings from a JSON body. Returns null when the
   body exists but cannot be read as text — an upload we cannot see is not the
   same as an upload we checked and cleared. */
export function extractText(body) {
  if (body === null || body === undefined) return '';
  if (typeof body !== 'string') return null;
  let parsed;
  try { parsed = JSON.parse(body); } catch { return body.slice(0, MAX_TEXT); }
  const parts = [];
  let budget = MAX_TEXT;
  const walk = (value, depth) => {
    if (budget <= 0 || depth > 12) return;
    if (typeof value === 'string') { parts.push(value.slice(0, budget)); budget -= value.length; return; }
    if (Array.isArray(value)) { for (const item of value) walk(item, depth + 1); return; }
    if (value && typeof value === 'object') { for (const item of Object.values(value)) walk(item, depth + 1); }
  };
  walk(parsed, 0);
  return parts.join('\n').slice(0, MAX_TEXT);
}

/* Turn an inspection outcome into what the wrapper must do.
   - block:      a secret pattern matched. No override offered.
   - confirm:    something needs a human decision before it leaves.
   - allow:      nothing matched. Never presented as "safe" (see THREAT_MODEL §5).
   Unreadable bodies and an unreachable service both stop the request; the
   difference is that only the unreadable body can be confirmed through. */
export function decide(outcome) {
  if (!outcome || typeof outcome !== 'object') {
    return { action: 'block', reason: 'unexpected_response', override: false };
  }
  if (outcome.uninspectable) {
    return { action: 'confirm', reason: 'uninspectable_body', override: true, rules: [] };
  }
  if (outcome.error || typeof outcome.decision !== 'string') {
    // Fail closed: an unavailable inspector must not silently become approval.
    return { action: 'block', reason: 'inspection_unavailable', override: false };
  }
  const rules = Array.isArray(outcome.rules) ? outcome.rules.slice(0, 24) : [];
  if (outcome.decision === 'block') return { action: 'block', reason: 'secret_detected', override: false, rules };
  if (outcome.decision === 'review') return { action: 'confirm', reason: 'review_required', override: true, rules };
  return { action: 'allow', reason: 'no_findings', override: false, rules };
}

/* One entry point for the wrapper, so the ordering of the checks is testable
   rather than spread through the injected script. `inspect` is injected. */
export async function evaluateRequest({ url, method, body }, inspect) {
  if (!candidate(url, method)) return { action: 'allow', reason: 'not_a_candidate', override: false };
  const text = extractText(body);
  if (text === null) return decide({ uninspectable: true });
  if (text.trim().length < MIN_TEXT) return { action: 'allow', reason: 'below_threshold', override: false };
  // A throwing inspector is an unavailable inspector, never an approval, so the
  // fail-closed path stays inside the unit that is tested.
  let outcome;
  try { outcome = await inspect({ text, endpoint: endpointLabel(url) }); }
  catch { return decide({ error: 'inspection_failed' }); }
  return decide(outcome);
}
