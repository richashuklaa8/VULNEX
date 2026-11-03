import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuditContent, requestAudit, clearCapabilityCache, buildRequestBody, extractJson } from '../server/ai-audit.js';
import { fixture, startMockOpenRouter, completion } from './support/helpers.js';

const SRC = fixture('VulnerableBank.sol');
const LINES = SRC.split('\n');
const lineOf = s => LINES.findIndex(l => l.includes(s)) + 1;
const FUNCS = [
  { contract: 'VulnerableBank', name: 'withdraw', kind: 'function', implemented: true, line: lineOf('function withdraw()'), endLine: lineOf('function withdraw()') + 8 },
  { contract: 'VulnerableBank', name: 'closeBank', kind: 'function', implemented: true, line: lineOf('function closeBank()'), endLine: lineOf('function closeBank()') + 2 },
];
const KEY = 'sk-or-v1-test-key-that-must-never-leak';
const quiet = { info() {}, warn() {} };
const good = {
  summary: 'Reviewed VulnerableBank.',
  findings: [{
    severity: 'High', title: 'Reentrancy in withdraw', category: 'reentrancy',
    description: 'ETH is sent before the balance is cleared.', function: 'withdraw', lines: [lineOf('msg.sender.call{value: amount}')],
    evidence: '(bool ok, ) = msg.sender.call{value: amount}("");', remediation: 'Update state first.', confidence: 0.9,
  }],
};
const run = (base, extra = {}) => requestAudit(Object.assign({ apiKey: KEY, base, model: 'anthropic/claude-sonnet-5.5', source: SRC, fileName: 'VulnerableBank.sol', compiler: { status: 'passed', version: '0.8.37' }, functions: FUNCS, timeoutMs: 5000, log: quiet }, extra));

beforeEach(() => clearCapabilityCache());

/* ---------- parsing and validation against the source ---------- */

test('valid JSON findings are located in the source and placed in their function', () => {
  const r = parseAuditContent(JSON.stringify(good), SRC, FUNCS);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.deepEqual(f.lines, [lineOf('msg.sender.call{value: amount}')]);
  assert.equal(f.located, 'evidence');
  assert.equal(f.evidenceMatched, true);
  assert.equal(f.function, 'withdraw');
  assert.equal(f.contract, 'VulnerableBank');
  assert.equal(f.confidence, 0.9);
});

test('JSON inside a Markdown fence is accepted', () => {
  const r = parseAuditContent('Here you go:\n```json\n' + JSON.stringify(good) + '\n```', SRC, FUNCS);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 1);
});

test('invalid JSON is an error, not zero findings', () => {
  const r = parseAuditContent('I found a reentrancy bug in withdraw. {not json', SRC, FUNCS);
  assert.equal(r.ok, false);
  assert.equal(r.code, 'invalid_json');
});

test('a response without a findings array is an error', () => {
  const r = parseAuditContent(JSON.stringify({ summary: 'ok', issues: [] }), SRC, FUNCS);
  assert.equal(r.ok, false);
  assert.equal(r.code, 'invalid_schema');
});

test('an explicit empty findings array is a valid clean answer', () => {
  const r = parseAuditContent(JSON.stringify({ summary: 'none', findings: [] }), SRC, FUNCS);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 0);
});

test('wrong line numbers are corrected from the quoted evidence', () => {
  const g = structuredClone(good); g.findings[0].lines = [2];
  const r = parseAuditContent(JSON.stringify(g), SRC, FUNCS);
  assert.deepEqual(r.findings[0].lines, [lineOf('msg.sender.call{value: amount}')]);
});

test('evidence copied with line-number prefixes still matches', () => {
  const g = structuredClone(good); const n = lineOf('msg.sender.call{value: amount}');
  g.findings[0].evidence = String(n).padStart(4) + '| ' + LINES[n - 1] + '\n' + String(n + 1).padStart(4) + '| ' + LINES[n];
  const r = parseAuditContent(JSON.stringify(g), SRC, FUNCS);
  assert.deepEqual(r.findings[0].lines, [n, n + 1]);
});

test('evidence that is not in the source keeps valid line numbers but is flagged', () => {
  const g = structuredClone(good); g.findings[0].evidence = 'payable(attacker).transfer(everything);';
  const r = parseAuditContent(JSON.stringify(g), SRC, FUNCS);
  assert.equal(r.findings[0].located, 'lines');
  assert.equal(r.findings[0].evidenceMatched, false);
});

test('findings with no valid lines and no matching evidence are unlocated, not silently kept or dropped', () => {
  const g = structuredClone(good); g.findings[0].lines = [9999]; g.findings[0].evidence = 'nothing like this exists';
  const r = parseAuditContent(JSON.stringify(g), SRC, FUNCS);
  assert.equal(r.findings.length, 0);
  assert.equal(r.unlocated.length, 1);
});

test('severity and confidence are normalized; unknown severities are dropped and counted', () => {
  const g = { findings: [
    Object.assign({}, good.findings[0], { severity: 'informational', confidence: 85 }),
    Object.assign({}, good.findings[0], { severity: 'catastrophic' }),
  ] };
  const r = parseAuditContent(JSON.stringify(g), SRC, FUNCS);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].severity, 'Low');
  assert.equal(r.findings[0].confidence, 0.85);
  assert.equal(r.dropped, 1);
});

test('extractJson handles surrounding prose', () => {
  assert.deepEqual(extractJson('Result: {"findings": []} done'), { findings: [] });
  assert.equal(extractJson(''), undefined);
});

/* ---------- the OpenRouter request ---------- */

test('structured outputs are requested when supported, without unsupported temperature', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify(good))) });
  try {
    const r = await run(or.base);
    assert.equal(r.status, 'completed');
    assert.equal(r.findings.length, 1);
    assert.equal(r.structured, true);
    assert.equal(r.httpStatus, 200);
    assert.equal(r.modelUsed, 'anthropic/claude-sonnet-5.5');
    const body = or.requests.find(q => q.url === '/chat/completions').body;
    assert.equal(body.model, 'anthropic/claude-sonnet-5.5');
    assert.equal(body.response_format.type, 'json_schema');
    assert.equal(body.response_format.json_schema.strict, true);
    assert.deepEqual(body.provider, { require_parameters: true });
    assert.equal('temperature' in body, false);
    assert.ok(body.messages[1].content.includes(LINES[lineOf('function withdraw()') - 1]), 'the full source is in the prompt');
    const auth = or.requests.find(q => q.url === '/chat/completions').headers.authorization;
    assert.equal(auth, 'Bearer ' + KEY);
    assert.equal(JSON.stringify(r).includes(KEY), false, 'the key is never in the result');
  } finally { await or.close(); }
});

test('if the model capabilities cannot be read, the request uses JSON instructions instead of a schema', async () => {
  const or = await startMockOpenRouter({ endpointsStatus: 500, chat: (rec, send) => send(200, completion(JSON.stringify(good))) });
  try {
    const r = await run(or.base);
    assert.equal(r.status, 'completed');
    assert.equal(r.structured, false);
    assert.equal('response_format' in or.requests.find(q => q.url === '/chat/completions').body, false);
  } finally { await or.close(); }
});

test('a rejected json_schema request is retried once with JSON instructions', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send, chats) => chats.length === 1 ? send(400, { error: { code: 400, message: 'response_format json_schema is not supported by this provider' } }) : send(200, completion(JSON.stringify(good))) });
  try {
    const r = await run(or.base);
    assert.equal(r.status, 'completed');
    assert.equal(r.structured, false);
    assert.match(r.fallback, /retried with JSON instructions/);
    assert.equal(or.requests.filter(q => q.url === '/chat/completions').length, 2);
  } finally { await or.close(); }
});

for (const [status, code] of [[401, 'bad_key'], [402, 'no_credits'], [404, 'bad_model'], [429, 'rate_limited'], [500, 'upstream_error'], [503, 'upstream_unavailable']]) {
  test('HTTP ' + status + ' is a failed review with code ' + code, async () => {
    const or = await startMockOpenRouter({ chat: (rec, send) => send(status, { error: { code: status, message: 'error ' + status } }) });
    try {
      const r = await run(or.base);
      assert.equal(r.status, 'failed');
      assert.equal(r.error.code, code);
      assert.equal(r.httpStatus, status);
      assert.equal(r.findings.length, 0);
      assert.equal(JSON.stringify(r).includes(KEY), false);
    } finally { await or.close(); }
  });
}

test('an error object inside a 200 response is a failure', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, { error: { code: 502, message: 'provider overloaded' } }) });
  try { const r = await run(or.base); assert.equal(r.status, 'failed'); assert.equal(r.error.code, 'upstream_unavailable'); } finally { await or.close(); }
});

test('an empty AI response is a failure, not a clean result', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion('')) });
  try { const r = await run(or.base); assert.equal(r.status, 'failed'); assert.equal(r.error.code, 'empty_response'); } finally { await or.close(); }
});

test('no choices is a failure', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, { id: 'x', choices: [] }) });
  try { const r = await run(or.base); assert.equal(r.status, 'failed'); assert.equal(r.error.code, 'empty_response'); } finally { await or.close(); }
});

test('invalid JSON from the model is a failure', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion('The contract looks fine to me!')) });
  try { const r = await run(or.base); assert.equal(r.status, 'failed'); assert.equal(r.error.code, 'invalid_json'); } finally { await or.close(); }
});

test('a truncated answer with broken JSON is a failure; with valid JSON it is incomplete', async () => {
  const cut = JSON.stringify(good).slice(0, 60);
  const or1 = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(cut, { choices: [{ finish_reason: 'length', message: { content: cut } }] })) });
  try { const r = await run(or1.base); assert.equal(r.status, 'failed'); assert.equal(r.error.code, 'truncated'); } finally { await or1.close(); }
  const full = JSON.stringify(good);
  const or2 = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(full, { choices: [{ finish_reason: 'length', message: { content: full } }] })) });
  try { const r = await run(or2.base); assert.equal(r.status, 'incomplete'); assert.equal(r.findings.length, 1); } finally { await or2.close(); }
});

test('findings that are all malformed fail the review instead of becoming zero findings', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify({ findings: ['reentrancy in withdraw', 42] }))) });
  try { const r = await run(or.base); assert.equal(r.status, 'failed'); assert.equal(r.error.code, 'invalid_schema'); } finally { await or.close(); }
});

test('unlocated findings make the review incomplete', async () => {
  const g = structuredClone(good); g.findings.push({ severity: 'Medium', title: 'Ghost issue', category: 'other', description: 'Somewhere.', function: '', lines: [], evidence: 'not in file', remediation: '', confidence: 0.4 });
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify(g))) });
  try { const r = await run(or.base); assert.equal(r.status, 'incomplete'); assert.equal(r.unlocated.length, 1); assert.equal(r.findings.length, 1); } finally { await or.close(); }
});

test('a slow API times out with status "timeout"', async () => {
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify(good)), 3000) });
  try {
    const t0 = Date.now();
    const r = await run(or.base, { timeoutMs: 400 });
    assert.equal(r.status, 'timeout');
    assert.equal(r.error.code, 'timeout');
    assert.ok(Date.now() - t0 < 2500);
  } finally { await or.close(); }
});

test('an unreachable API is a network failure', async () => {
  const r = await run('http://127.0.0.1:9');
  assert.equal(r.status, 'failed');
  assert.equal(r.error.code, 'network');
});

test('without a key nothing is sent', async () => {
  const r = await run('http://127.0.0.1:9', { apiKey: '' });
  assert.equal(r.status, 'not_configured');
});

test('request body only includes parameters the model supports', () => {
  const b = buildRequestBody({ model: 'm', source: 'contract A {}', fileName: 'A.sol', structured: false, params: ['max_tokens', 'temperature'] });
  assert.equal(b.temperature, 0);
  assert.equal(b.max_tokens, 8192);
  assert.equal('response_format' in b, false);
  assert.equal('provider' in b, false);
});
