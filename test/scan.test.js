// End-to-end tests of the server-side scan (POST /api/scan logic) with the real solc compiler
// and a fake OpenRouter, followed by the same merge/status logic the page runs.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createCompilerService } from '../server/compiler.js';
import { createScanner, ScanInputError } from '../server/scan.js';
import { clearCapabilityCache } from '../server/ai-audit.js';
import { fixture, tempDir, startSolcList, startMockOpenRouter, completion, loadPageLogic, plain } from './support/helpers.js';

const quiet = { info() {}, warn() {} };
const KEY = 'sk-or-v1-test-key';
const sha = s => '0x' + createHash('sha256').update(s, 'utf8').digest('hex');
let list, cache, compiler;
const P = loadPageLogic();

before(async () => {
  // The real list has every release; this one lists 0.8.19 but cannot serve it (like being offline).
  list = await startSolcList({ '0.8.19': 'soljson-v0.8.19+commit.7dd6d404.js', '0.8.37': 'soljson-v0.8.37+commit.f401782d.js' });
  cache = tempDir('vulnex-scan-');
  compiler = createCompilerService({ cacheDir: cache.dir, binariesUrl: list.base, log: quiet });
});
after(async () => { await list.close(); cache.cleanup(); });

function scanner(base, extra = {}) {
  clearCapabilityCache();
  const settings = Object.assign({ aiKey: KEY, aiBase: base, aiModel: 'anthropic/claude-sonnet-5.5', aiTimeoutMs: 5000 }, extra);
  return createScanner({ compiler, getSettings: () => settings, log: quiet });
}

// What the page does after /api/scan returns (see runScan → commitVersion in index.html).
function pageResult(source, resp) {
  if (resp.compiler.status === 'failed') return { status: 'compilation_failed', score: null, findings: [] };
  const an = P.analyze(source);
  const rules = P.ScanCore.rulesCoverage(an, resp.compiler.coverage);
  const ai = resp.ai;
  const merged = P.ScanCore.mergeFindings(an.findings, ai.status === 'completed' || ai.status === 'incomplete' ? ai.findings : [], an);
  const fin = P.ScanCore.finalize({ compiler: resp.compiler, ai, rules });
  return plain({ status: fin.status, reasons: fin.reasons, score: P.ScanCore.scoreFor(fin.status, P.countSev(merged)), findings: merged });
}

const aiAnswer = src => ({
  summary: 'Reviewed.',
  findings: [{
    severity: 'High', title: 'Reentrancy in withdraw', category: 'reentrancy', description: 'ETH sent before state update.',
    function: 'withdraw', lines: [src.split('\n').findIndex(l => l.includes('msg.sender.call{value: amount}')) + 1],
    evidence: '(bool ok, ) = msg.sender.call{value: amount}("");', remediation: 'Checks-effects-interactions.', confidence: 0.9,
  }],
});

test('the exact editor text is hashed, compiled and sent to OpenRouter', async () => {
  const src = fixture('VulnerableBank.sol');
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify(aiAnswer(src)))) });
  try {
    const r = await scanner(or.base)({ source: src, fileName: 'VulnerableBank.sol' });
    assert.equal(r.source.sha256, sha(src));
    assert.equal(r.compiler.status, 'passed');
    assert.equal(r.ai.status, 'completed');
    const prompt = or.requests.find(q => q.url === '/chat/completions').body.messages[1].content;
    for (const [i, line] of src.split('\n').entries()) assert.ok(prompt.includes(String(i + 1).padStart(4) + '| ' + line), 'line ' + (i + 1) + ' is in the prompt');
  } finally { await or.close(); }
});

test('an edited contract is scanned as edited, not as the previous version', async () => {
  const v1 = fixture('VulnerableBank.sol');
  const v2 = P.applyAllFixes(v1).source;
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify({ summary: 'ok', findings: [] }))) });
  try {
    const s = scanner(or.base);
    const r1 = await s({ source: v1, fileName: 'VulnerableBank.sol' });
    const r2 = await s({ source: v2, fileName: 'VulnerableBank.sol' });
    assert.notEqual(r1.source.sha256, r2.source.sha256);
    assert.equal(r2.source.sha256, sha(v2));
    // The fix pins the pragma to 0.8.19, which cannot be downloaded here: syntax-checked only.
    assert.equal(r2.compiler.status, 'unavailable');
    assert.equal(r2.compiler.syntax.status, 'passed');
    assert.equal(pageResult(v2, r2).status, 'partial');
    assert.equal(pageResult(v2, r2).score, null);
    const prompts = or.requests.filter(q => q.url === '/chat/completions').map(q => q.body.messages[1].content);
    assert.equal(prompts.length, 2);
    assert.ok(prompts[1].includes('modifier onlyOwner()'), 'second prompt has the fixed code');
    assert.ok(!prompts[0].includes('modifier onlyOwner()'));
  } finally { await or.close(); }
});

test('malformed Solidity is "compilation_failed": no AI call, no findings, no score', async () => {
  const src = fixture('Malformed.sol');
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify({ findings: [] }))) });
  try {
    const r = await scanner(or.base)({ source: src, fileName: 'VulnerableBank.sol' });
    assert.equal(r.compiler.status, 'failed');
    assert.equal(r.ai.status, 'skipped');
    assert.equal(or.requests.filter(q => q.url === '/chat/completions').length, 0);
    const page = pageResult(src, r);
    assert.equal(page.status, 'compilation_failed');
    assert.equal(page.score, null);
  } finally { await or.close(); }
});

test('the reported bug: fixed contract + garbage line no longer scores 100/100', async () => {
  const broken = P.applyAllFixes(fixture('VulnerableBank.sol')).source.replace('function deposit()', 'this is not solidity !!!\n    function deposit()');
  const r = await scanner('http://127.0.0.1:9')({ source: broken, fileName: 'VulnerableBank.sol' });
  assert.equal(r.compiler.status, 'failed');
  assert.equal(r.compiler.errors[0].type, 'ParserError');
  assert.equal(r.compiler.errors[0].line, broken.split('\n').findIndex(l => l.includes('this is not solidity')) + 1);
  assert.equal(r.ai.status, 'skipped');
  const page = pageResult(broken, r);
  assert.equal(page.status, 'compilation_failed');
  assert.equal(page.score, null);
});

for (const [name, chat, expected] of [
  ['an API error', (rec, send) => send(500, { error: { message: 'boom' } }), 'failed'],
  ['an empty AI response', (rec, send) => send(200, completion('')), 'failed'],
  ['invalid JSON from the AI', (rec, send) => send(200, completion('Looks secure!')), 'failed'],
  ['a timeout', (rec, send) => send(200, completion('{"findings":[]}'), 3000), 'timeout'],
]) {
  test(name + ' on a safe contract gives a partial scan with no score, never a clean 100', async () => {
    const src = fixture('SafeVault.sol');
    const or = await startMockOpenRouter({ chat });
    try {
      const r = await scanner(or.base, { aiTimeoutMs: 500 })({ source: src, fileName: 'SafeVault.sol' });
      assert.equal(r.compiler.status, 'passed');
      assert.equal(r.ai.status, expected);
      const page = pageResult(src, r);
      assert.equal(page.findings.length, 0, 'the rules find nothing in the safe contract');
      assert.equal(page.status, 'partial');
      assert.equal(page.score, null);
      assert.match(page.reasons.join(' '), /AI review/);
    } finally { await or.close(); }
  });
}

test('no API key: AI is "not_configured" and the scan is partial', async () => {
  const src = fixture('SafeVault.sol');
  const r = await scanner('http://127.0.0.1:9', { aiKey: '' })({ source: src, fileName: 'SafeVault.sol' });
  assert.equal(r.ai.status, 'not_configured');
  const page = pageResult(src, r);
  assert.equal(page.status, 'partial');
  assert.equal(page.score, null);
});

test('a safe contract with a completed AI review is the only way to a clean score', async () => {
  const src = fixture('SafeVault.sol');
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify({ summary: 'No issues found.', findings: [] }))) });
  try {
    const r = await scanner(or.base)({ source: src, fileName: 'SafeVault.sol' });
    const page = pageResult(src, r);
    assert.equal(page.status, 'completed');
    assert.equal(page.score, 100);
  } finally { await or.close(); }
});

test('reentrancy is found by the rules and confirmed by the AI as one merged finding', async () => {
  const src = fixture('Reentrancy.sol');
  const line = src.split('\n').findIndex(l => l.includes('msg.sender.call{value: bal}')) + 1;
  const answer = { summary: 'x', findings: [
    { severity: 'Critical', title: 'Reentrancy drains the contract', category: 'reentrancy', description: 'Balance zeroed after the call.', function: 'withdraw', lines: [line], evidence: '(bool sent, ) = msg.sender.call{value: bal}("");', remediation: 'Zero the balance first.', confidence: 0.95 },
    { severity: 'Low', title: 'No events', category: 'other', description: 'Withdrawals emit no event.', function: 'withdraw', lines: [line + 2], evidence: 'balances[msg.sender] = 0;', remediation: 'Emit an event.', confidence: 0.6 },
  ] };
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify(answer))) });
  try {
    const r = await scanner(or.base)({ source: src, fileName: 'Reentrancy.sol' });
    const page = pageResult(src, r);
    assert.equal(page.status, 'completed');
    const re = page.findings.find(f => f.rule === 'reentrancy-eth');
    assert.ok(re, 'rule finding present');
    assert.deepEqual(re.sources, ['rules', 'ai']);
    assert.equal(re.severity, 'High', 'the rule keeps its own severity');
    const aiOnly = page.findings.filter(f => f.source === 'ai');
    assert.equal(aiOnly.length, 1);
    assert.equal(aiOnly[0].key, 'ai:other@EtherStore.withdraw');
    assert.equal(page.findings.length, 2);
    assert.ok(page.score < 100);
  } finally { await or.close(); }
});

test('missing access control is found by the rules even if the AI misses it', async () => {
  const src = fixture('MissingAccessControl.sol');
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion(JSON.stringify({ summary: 'x', findings: [] }))) });
  try {
    const r = await scanner(or.base)({ source: src, fileName: 'MissingAccessControl.sol' });
    const page = pageResult(src, r);
    const rules = page.findings.map(f => f.rule).sort();
    assert.deepEqual(rules, ['unprotected-owner-change', 'unprotected-setter', 'unprotected-withdrawal']);
    assert.equal(page.status, 'completed');
    assert.ok(page.score < 100);
  } finally { await or.close(); }
});

test('interface-only code is not scored and not sent to the AI', async () => {
  const src = 'pragma solidity 0.8.37;\ninterface I { function f() external; }';
  const or = await startMockOpenRouter({ chat: (rec, send) => send(200, completion('{"findings":[]}')) });
  try {
    const r = await scanner(or.base)({ source: src, fileName: 'I.sol' });
    assert.equal(r.ai.status, 'skipped');
    assert.equal(r.ai.error.code, 'no_code');
    assert.equal(or.requests.filter(q => q.url === '/chat/completions').length, 0);
  } finally { await or.close(); }
});

test('bad input is rejected', async () => {
  const s = scanner('http://127.0.0.1:9');
  await assert.rejects(s({ source: '   ' }), e => e instanceof ScanInputError && e.code === 'empty_source');
  await assert.rejects(s({}), e => e instanceof ScanInputError && e.status === 400);
  await assert.rejects(s({ source: 'x'.repeat(200001) }), e => e instanceof ScanInputError && e.status === 413);
});
