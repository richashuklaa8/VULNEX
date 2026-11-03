// VULNEX · scan status, score and finding merge.
//
// Pure functions shared by the page and the tests (test/scan-core.test.js).
// Needs src/rules-engine.js loaded first (uses SEV_RANK and scoreOf).
//
// Status rules:
//   compilation_failed  solc reported errors → no findings, no score
//   failed              the scan could not run (server, compiler crash, no code, rule engine)
//   completed           solc passed AND the rules parsed every function AND the AI review completed
//   partial             anything else (AI off/failed/timed out/incomplete, compiler unavailable,
//                       rule engine missed functions) → findings shown, score withheld
// A score is only given for "completed". Empty results never turn into 100/100 on their own.
'use strict';
const ScanCore = (() => {
  // Rule ids and AI categories mapped to shared groups, used to spot the same issue twice.
  const RULE_GROUP = {
    'reentrancy-eth': 'reentrancy', 'reentrancy-no-eth': 'reentrancy', 'unsafe-ordering': 'reentrancy',
    'unchecked-lowlevel': 'unchecked', 'tx-origin': 'access',
    'unprotected-selfdestruct': 'access', 'unprotected-withdrawal': 'access', 'unprotected-owner-change': 'access', 'unprotected-setter': 'access',
    'integer-overflow': 'arithmetic', 'unchecked-arithmetic': 'arithmetic', 'floating-pragma': 'pragma', 'timestamp': 'time',
  };
  const AI_GROUP = {
    reentrancy: 'reentrancy', 'state-ordering': 'reentrancy', 'external-call': 'external', 'unchecked-call': 'unchecked',
    'access-control': 'access', authorization: 'access', selfdestruct: 'access', arithmetic: 'arithmetic',
    'compiler-pragma': 'pragma', timestamp: 'time', randomness: 'time',
  };
  const groupOfAi = a => AI_GROUP[a.category] || 'other:' + a.category;
  function compatible(a, b) {
    if (!a || !b) return false;
    if (a === b) return true;
    return (a === 'external' && (b === 'reentrancy' || b === 'unchecked')) || (b === 'external' && (a === 'reentrancy' || a === 'unchecked'));
  }
  const near = (a, b, slack) => a.some(x => b.some(y => Math.abs(x - y) <= slack));

  // Place an AI finding inside the rule engine's view of the contract (for snippets and the explorer).
  function aiToFinding(a, an) {
    let contract = a.contract || ''; let fn = a.function || ''; let fnLine = 0;
    const first = a.lines[0];
    for (const c of an.contracts) {
      for (const f of c.functions) {
        if (f.hasBody && f.line <= first && first <= f.endLine && (!contract || c.name === contract)) { contract = c.name; fn = f.name; fnLine = f.line; }
      }
    }
    if (!fnLine && fn) {
      for (const c of an.contracts) { const f = c.functions.find(x => x.name === fn && x.hasBody && (!contract || c.name === contract)); if (f) { contract = c.name; fnLine = f.line; break; } }
    }
    return {
      rule: 'ai:' + a.category, source: 'ai', sources: ['ai'], title: a.title, severity: a.severity, swc: '—',
      contract, fn, fnLine, lines: a.lines.slice(), evidence: a.description, meta: {}, key: '',
      fixable: false, patched: null, ai: [a], aiInfo: a,
    };
  }

  // Keep rule and AI findings separate but merge duplicates. A rule finding that the AI also
  // reported keeps the rule's severity and gets sources ['rules','ai'] plus the AI's notes.
  function mergeFindings(ruleFindings, aiFindings, an) {
    const merged = ruleFindings.map(f => Object.assign({}, f, { source: 'rules', sources: ['rules'], ai: [] }));
    const extra = [];
    for (const a of aiFindings || []) {
      if (!a || !Array.isArray(a.lines) || !a.lines.length) continue;
      const g = groupOfAi(a);
      const target = merged.find(m => compatible(RULE_GROUP[m.rule], g) && (near(a.lines, m.lines, 1) || (a.function && m.fn === a.function && (!a.contract || !m.contract || a.contract === m.contract))));
      if (target) { if (!target.sources.includes('ai')) target.sources.push('ai'); target.ai.push(a); continue; }
      const dup = extra.find(x => groupOfAi(x.aiInfo) === g && near(a.lines, x.lines, 0));
      if (dup) {
        dup.ai.push(a);
        if (SEV_RANK[a.severity] < SEV_RANK[dup.severity]) { dup.severity = a.severity; dup.title = a.title; dup.evidence = a.description; dup.aiInfo = a; }
        continue;
      }
      extra.push(aiToFinding(a, an));
    }
    const seen = {};
    for (const f of extra) {
      const base = 'ai:' + f.aiInfo.category + '@' + (f.contract || '') + '.' + (f.fn || 'file');
      seen[base] = (seen[base] || 0) + 1;
      f.key = seen[base] > 1 ? base + '#' + seen[base] : base;
    }
    const all = merged.concat(extra);
    all.sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity] || (x.lines[0] || 0) - (y.lines[0] || 0));
    all.forEach((f, i) => { f.id = 'F-' + String(i + 1).padStart(2, '0'); });
    return all;
  }

  // Did the rule engine parse every implemented function the compiler found?
  function rulesCoverage(an, coverage) {
    const have = {}; let parsed = 0;
    an.contracts.forEach(c => c.functions.forEach(f => { if (f.hasBody) { parsed++; const k = c.name + '.' + f.name; have[k] = (have[k] || 0) + 1; } }));
    if (!coverage) return { status: 'completed', checked: false, parsed, expected: null, missing: [], findings: an.findings.length };
    const impl = coverage.functions.filter(f => f.implemented);
    const missing = [];
    impl.forEach(f => { const k = (f.contract || '(file)') + '.' + f.name; if (have[k] > 0) have[k]--; else missing.push(k); });
    return { status: missing.length ? 'partial' : 'completed', checked: true, parsed, expected: impl.length, missing, findings: an.findings.length };
  }

  function aiReason(ai) {
    if (!ai) return 'The AI review did not run.';
    const msg = ai.error && ai.error.message ? ai.error.message : '';
    switch (ai.status) {
      case 'completed': return '';
      case 'not_configured': return 'The AI review is off: OPENROUTER_API_KEY is not set in .env.';
      case 'timeout': return 'The AI review timed out. ' + msg;
      case 'skipped': return 'The AI review was skipped. ' + msg;
      case 'incomplete': return 'The AI review is incomplete: ' + msg;
      case 'not_run': return 'The AI review was not run.';
      default: return 'The AI review failed: ' + (msg || ai.status) + (ai.httpStatus && ai.httpStatus !== 200 ? ' (HTTP ' + ai.httpStatus + ')' : '');
    }
  }

  function finalize({ compiler, ai, rules }) {
    if (!compiler || compiler.status === 'error') return { status: 'failed', reasons: [(compiler && compiler.reason) || 'The compiler did not run.'] };
    if (compiler.status === 'failed') return { status: 'compilation_failed', reasons: [compiler.errors.length + ' compiler error' + (compiler.errors.length === 1 ? '' : 's') + '.'] };
    if (compiler.coverage && !compiler.coverage.hasCode) return { status: 'failed', reasons: ['The file has no contract or library code to analyze.'] };
    if (!rules || rules.status === 'failed') return { status: 'failed', reasons: ['The rule engine did not run.'] };
    const reasons = [];
    if (compiler.status !== 'passed') reasons.push('The code was not compiler-validated: ' + (compiler.reason || compiler.status));
    if (rules.status !== 'completed') reasons.push('The rule engine parsed ' + rules.parsed + ' of ' + rules.expected + ' functions' + (rules.missing.length ? ' (missed ' + rules.missing.slice(0, 4).join(', ') + ')' : '') + '.');
    if (!ai || ai.status !== 'completed') reasons.push(aiReason(ai).trim());
    return { status: reasons.length ? 'partial' : 'completed', reasons };
  }

  function scoreFor(status, counts) { return status === 'completed' ? scoreOf(counts) : null; }

  // Compare two versions fairly: AI-only findings are only compared when both AI reviews completed.
  function comparable(A, B) {
    const aiOk = v => !!(v && v.analysis && v.analysis.ai && v.analysis.ai.status === 'completed');
    const both = aiOk(A) && aiOk(B);
    const pick = v => (both ? v.findings : v.findings.filter(f => (f.sources || ['rules']).includes('rules')));
    const missing = [A, B].filter(v => !aiOk(v)).map(v => v.label);
    return { a: pick(A), b: pick(B), aiCompared: both, note: both ? '' : 'The AI review did not complete for ' + missing.join(' and ') + ', so only rule findings are compared.' };
  }

  return { RULE_GROUP, AI_GROUP, mergeFindings, aiToFinding, rulesCoverage, finalize, scoreFor, comparable, aiReason };
})();
