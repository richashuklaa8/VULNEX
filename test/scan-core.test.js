// Status, score, merge and comparison rules used by the page (src/scan-core.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPageLogic, fixture, plain } from './support/helpers.js';

const P = loadPageLogic();
const { ScanCore } = P;
const passed = { status: 'passed', version: '0.8.37', errors: [], warnings: [], coverage: { hasCode: true, functions: [] } };
const rulesOk = { status: 'completed', parsed: 3, expected: 3, missing: [] };
const aiOk = { status: 'completed', findings: [] };

test('compilation failure → compilation_failed, no score', () => {
  const r = ScanCore.finalize({ compiler: { status: 'failed', errors: [{}] }, ai: { status: 'skipped' }, rules: null });
  assert.equal(r.status, 'compilation_failed');
  assert.equal(ScanCore.scoreFor(r.status, P.countSev([])), null);
});

test('every AI failure mode with zero rule findings is partial with no score', () => {
  for (const ai of [
    { status: 'failed', error: { code: 'upstream_error', message: 'boom' }, httpStatus: 500 },
    { status: 'failed', error: { code: 'invalid_json', message: 'not JSON' } },
    { status: 'failed', error: { code: 'empty_response', message: 'empty' } },
    { status: 'timeout', error: { code: 'timeout', message: 'slow' } },
    { status: 'incomplete', error: { code: 'truncated', message: 'cut' } },
    { status: 'not_configured', error: { code: 'not_configured', message: 'no key' } },
    null,
  ]) {
    const r = ScanCore.finalize({ compiler: passed, ai, rules: rulesOk });
    assert.equal(r.status, 'partial', JSON.stringify(ai));
    assert.equal(ScanCore.scoreFor(r.status, P.countSev([])), null, 'never 100 when the AI did not complete');
    assert.ok(r.reasons.length > 0);
  }
});

test('compiler unavailable is partial even if everything else completed', () => {
  const r = ScanCore.finalize({ compiler: { status: 'unavailable', reason: 'offline', errors: [] }, ai: aiOk, rules: rulesOk });
  assert.equal(r.status, 'partial');
});

test('the rule engine missing functions is partial', () => {
  const an = P.analyze(fixture('VulnerableBank.sol'));
  const coverage = { hasCode: true, functions: an.contracts[0].functions.map(f => ({ contract: 'VulnerableBank', name: f.name, implemented: f.hasBody })).concat([{ contract: 'VulnerableBank', name: 'hidden', implemented: true }]) };
  const rules = ScanCore.rulesCoverage(an, coverage);
  assert.equal(rules.status, 'partial');
  assert.deepEqual(plain(rules.missing), ['VulnerableBank.hidden']);
  assert.equal(ScanCore.finalize({ compiler: passed, ai: aiOk, rules }).status, 'partial');
});

test('no code to analyze is a failed scan', () => {
  const r = ScanCore.finalize({ compiler: { status: 'passed', errors: [], coverage: { hasCode: false, functions: [] } }, ai: { status: 'skipped' }, rules: rulesOk });
  assert.equal(r.status, 'failed');
});

test('only a fully completed scan gets a score', () => {
  const r = ScanCore.finalize({ compiler: passed, ai: aiOk, rules: rulesOk });
  assert.equal(r.status, 'completed');
  assert.equal(ScanCore.scoreFor(r.status, P.countSev([])), 100);
  assert.equal(ScanCore.scoreFor('completed', { Critical: 0, High: 1, Medium: 1, Low: 0 }), 78);
});

test('merging keeps sources, deduplicates and gives AI-only findings stable keys', () => {
  const src = fixture('VulnerableBank.sol'); const an = P.analyze(src);
  const lines = src.split('\n'); const at = s => lines.findIndex(l => l.includes(s)) + 1;
  const ai = [
    { severity: 'High', title: 'Reentrancy', category: 'reentrancy', description: 'd', function: 'withdraw', contract: 'VulnerableBank', lines: [at('msg.sender.call{value: amount}')], remediation: 'r', confidence: 0.9 },
    { severity: 'High', title: 'Owner takeover via tx.origin', category: 'access-control', description: 'd', function: 'transferOwnership', contract: 'VulnerableBank', lines: [at('tx.origin == owner')], remediation: 'r', confidence: 0.8 },
    { severity: 'Medium', title: 'Fee has no upper bound', category: 'business-logic', description: 'd', function: 'setWithdrawFee', contract: 'VulnerableBank', lines: [at('withdrawFeeBps = newFeeBps')], remediation: 'r', confidence: 0.7 },
    { severity: 'Low', title: 'Same fee issue, worded differently', category: 'business-logic', description: 'd', function: 'setWithdrawFee', contract: 'VulnerableBank', lines: [at('withdrawFeeBps = newFeeBps')], remediation: 'r', confidence: 0.5 },
  ];
  const merged = plain(ScanCore.mergeFindings(an.findings, ai, an));
  assert.equal(merged.length, an.findings.length + 1, 'two AI findings merged into rules, two AI duplicates became one');
  assert.deepEqual(merged.find(f => f.rule === 'reentrancy-eth').sources, ['rules', 'ai']);
  assert.deepEqual(merged.find(f => f.rule === 'tx-origin').sources, ['rules', 'ai']);
  assert.deepEqual(merged.find(f => f.rule === 'unchecked-lowlevel').sources, ['rules']);
  const aiOnly = merged.filter(f => f.source === 'ai');
  assert.equal(aiOnly.length, 1);
  assert.equal(aiOnly[0].key, 'ai:business-logic@VulnerableBank.setWithdrawFee');
  assert.equal(aiOnly[0].severity, 'Medium', 'the higher severity wins');
  assert.equal(aiOnly[0].ai.length, 2);
  assert.ok(aiOnly[0].fnLine > 0, 'placed inside setWithdrawFee for snippets and the explorer');
  assert.deepEqual(merged.map(f => f.id), merged.map((f, i) => 'F-' + String(i + 1).padStart(2, '0')));
});

test('comparing versions ignores AI-only findings unless both AI reviews completed', () => {
  const f = (key, src) => ({ key, sources: src });
  const A = { label: 'V1', analysis: { ai: { status: 'completed' } }, findings: [f('r1', ['rules']), f('ai:x@C.f', ['ai'])] };
  const B = { label: 'V2', analysis: { ai: { status: 'failed' } }, findings: [f('r1', ['rules'])] };
  const c = ScanCore.comparable(A, B);
  assert.equal(c.aiCompared, false);
  assert.deepEqual(plain(c.a).map(x => x.key), ['r1'], 'the AI-only finding is not shown as "resolved"');
  assert.match(c.note, /V2/);
  const C = { label: 'V3', analysis: { ai: { status: 'completed' } }, findings: [] };
  assert.equal(ScanCore.comparable(A, C).aiCompared, true);
});

test('reports record the analysis status and finding sources', () => {
  const src = fixture('VulnerableBank.sol'); const an = P.analyze(src);
  const findings = ScanCore.mergeFindings(an.findings, [], an);
  const analysis = { status: 'partial', reasons: ['The AI review failed: boom'], compiler: passed, rules: Object.assign({ checked: true }, rulesOk), ai: { status: 'failed', model: 'm', error: { code: 'upstream_error' } } };
  const v = { n: 1, label: 'V1', source: src, contractHash: '0x' + P.sha256(src), scannedAt: '2026-10-09T00:00:00Z', an, findings, counts: P.countSev(findings), score: null, analysis };
  const report = plain(P.buildReport('VulnerableBank.sol', [v], 0, '2026-10-09T00:00:00Z'));
  assert.equal(report.summary.score, null);
  assert.equal(report.analysis.status, 'partial');
  assert.equal(report.analysis.ai.status, 'failed');
  assert.match(report.summary.verdict, /^Partial analysis/);
  assert.ok(report.findings.every(x => x.source === 'rules'));
});
