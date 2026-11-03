// VULNEX · deterministic Solidity rule engine (13 rules), hashing and report building.
// Runs in the page and in the tests (test/rules-engine.test.js). It only finds the selected
// classes it has rules for; the compiler and the AI review run separately on the server.
'use strict';
/* ============================== ENGINE START ============================== */
const ENGINE_ID = 'vulnex-rules 0.1 (prototype)';
const SEVS = ['Critical', 'High', 'Medium', 'Low'];
const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SEV_WEIGHT = { Critical: 25, High: 15, Medium: 7, Low: 2 };
const SELECTOR = '0x83c30871'; // keccak256("attest(bytes32,bytes32,bytes32)")[0:4]

const RULES = {
  'reentrancy-eth':           { family: 'Reentrancy', name: 'Reentrancy: ETH sent before state update', short: 'Reentrancy', severity: 'High', swc: 'SWC-107' },
  'reentrancy-no-eth':        { family: 'Reentrancy', name: 'Reentrancy: low-level call before state update', short: 'Reentrancy', severity: 'Medium', swc: 'SWC-107' },
  'unsafe-ordering':          { family: 'State-change ordering', name: 'State updated after an external contract call', short: 'Unsafe ordering', severity: 'Medium', swc: 'SWC-107' },
  'unchecked-lowlevel':       { family: 'Unchecked calls', name: 'Unchecked low-level call', short: 'Unchecked call', severity: 'Medium', swc: 'SWC-104' },
  'tx-origin':                { family: 'Dangerous authorization', name: 'Authorization through tx.origin', short: 'tx.origin auth', severity: 'High', swc: 'SWC-115' },
  'unprotected-selfdestruct': { family: 'Access control', name: 'Unprotected selfdestruct', short: 'Open selfdestruct', severity: 'Critical', swc: 'SWC-106' },
  'unprotected-withdrawal':   { family: 'Access control', name: 'Unprotected ether withdrawal', short: 'Open withdrawal', severity: 'High', swc: 'SWC-105' },
  'unprotected-owner-change': { family: 'Access control', name: 'Unprotected ownership change', short: 'Open owner change', severity: 'High', swc: '—' },
  'unprotected-setter':       { family: 'Access control', name: 'Missing access control on a privileged function', short: 'Missing access control', severity: 'High', swc: '—' },
  'integer-overflow':         { family: 'Arithmetic', name: 'Integer overflow or underflow (pre-0.8 compiler)', short: 'Overflow risk', severity: 'Medium', swc: 'SWC-101' },
  'unchecked-arithmetic':     { family: 'Arithmetic', name: 'State arithmetic inside an unchecked block', short: 'Unchecked math', severity: 'Low', swc: 'SWC-101' },
  'floating-pragma':          { family: 'Compiler pragma', name: 'Floating pragma', short: 'Floating pragma', severity: 'Low', swc: 'SWC-103' },
  'timestamp':                { family: 'Timestamp dependence', name: 'Block timestamp used in a condition', short: 'Timestamp', severity: 'Low', swc: 'SWC-116' },
};
const RECS = {
  'reentrancy-eth': 'Update state before the external call (checks-effects-interactions), or add a reentrancy guard.',
  'reentrancy-no-eth': 'Update state before the external call, or add a reentrancy guard.',
  'unsafe-ordering': 'Finish all state updates before calling other contracts, or add a reentrancy guard.',
  'unchecked-lowlevel': 'Check the boolean result of call/send and revert when it is false.',
  'tx-origin': 'Use msg.sender for authorization checks.',
  'unprotected-selfdestruct': 'Restrict the function to the owner, or remove selfdestruct entirely.',
  'unprotected-withdrawal': 'Restrict withdrawals of the contract balance to the owner or an authorized role.',
  'unprotected-owner-change': 'Restrict ownership changes to the current owner.',
  'unprotected-setter': 'Add an owner or role check to this function and validate the new value.',
  'integer-overflow': 'Compile with Solidity 0.8 or later (checked arithmetic), or use SafeMath.',
  'unchecked-arithmetic': 'Remove the unchecked block unless overflow is impossible and documented.',
  'floating-pragma': 'Pin the compiler version you tested and audited with.',
  'timestamp': 'Do not use block.timestamp for randomness or tight deadlines; allow for drift.',
};

const ID_RE = '[A-Za-z_$][\\w$]*';
const SENDER = '(?:msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\)|tx\\s*\\.\\s*origin)';
const AUTH_BODY = new RegExp(
  '\\b(?:require|assert)\\s*\\([^;]*' + SENDER + '[^;]*(?:==|!=)' +
  '|\\b(?:require|assert)\\s*\\([^;]*(?:==|!=)\\s*' + SENDER +
  '|\\bif\\s*\\([^{;]*' + SENDER + '[^{;]*(?:==|!=)' +
  '|\\bif\\s*\\([^{;]*(?:==|!=)\\s*' + SENDER +
  '|\\b(?:hasRole|_checkRole|_checkOwner|_onlyOwner|_requireOwner|_authorize\\w*)\\s*\\(');
const AUTH_MOD_NAME = /^(only|auth|requiresAuth|restricted|ownerOnly|adminOnly|isOwner|whenOwner)/i;
const PRIV_VAR = /^_?(owner|admin|governance|governor|operator|minter|treasury|implementation|pendingOwner|guardian)$/i;
const SENSITIVE_NAME = /^(set|update|change|configure)[A-Z_0-9]|^(mint|burn|burnFrom|pause|unpause|upgrade|upgradeTo\w*|withdrawAll|emergencyWithdraw|sweep|rescue\w*|kill|destroy|initialize|init)$/;
const GUARD_MOD = /nonReentrant|noReentran|reentrancyGuard|^lock$/i;

function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function lineStarts(t) { const a = [0]; for (let i = 0; i < t.length; i++) if (t.charCodeAt(i) === 10) a.push(i + 1); return a; }
function lineAt(starts, off) { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; } return lo + 1; }
function matchClose(t, i, o, c) { let d = 0; for (let k = i; k < t.length; k++) { const ch = t[k]; if (ch === o) d++; else if (ch === c) { d--; if (d === 0) return k; } } return t.length - 1; }
function splitTop(s) { const out = []; let d = 0, cur = ''; for (const ch of s) { if ('([{'.includes(ch)) d++; else if (')]}'.includes(ch)) d--; if (ch === ',' && d === 0) { out.push(cur); cur = ''; } else cur += ch; } out.push(cur); return out.map(x => x.trim()).filter(Boolean); }
function parseVersion(t) { const m = /(\d+)\.(\d+)\.(\d+)/.exec(t || ''); return m ? { major: +m[1], minor: +m[2], patch: +m[3], text: m[0] } : null; }
function listCode(names) { const q = names.map(n => '`' + n + '`'); return q.length <= 1 ? (q[0] || '') : q.slice(0, -1).join(', ') + ' and ' + q[q.length - 1]; }
function lineList(ls) { const a = [...new Set(ls)].sort((x, y) => x - y); const parts = []; for (let i = 0; i < a.length;) { let j = i; while (j + 1 < a.length && a[j + 1] === a[j] + 1) j++; parts.push(i === j ? String(a[i]) : a[i] + '–' + a[j]); i = j + 1; } return parts.join(', '); }
function plural(n, one, many) { return n === 1 ? one : (many || one + 's'); }

/* Replace comments and string contents with spaces, keeping every offset and newline. */
function maskSource(src) {
  const out = src.split('');
  const n = src.length; let i = 0;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') { out[i] = ' '; i++; } continue; }
    if (c === '/' && d === '*') { out[i] = out[i + 1] = ' '; i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] !== '\n') out[i] = ' '; i++; } if (i < n) { out[i] = ' '; if (i + 1 < n) out[i + 1] = ' '; i += 2; } continue; }
    if (c === '"' || c === "'") { const q = c; i++; while (i < n && src[i] !== q && src[i] !== '\n') { if (src[i] === '\\' && i + 1 < n && src[i + 1] !== '\n') { out[i] = ' '; i++; } out[i] = ' '; i++; } i++; continue; }
    i++;
  }
  return out.join('');
}

function parseParams(p) {
  return splitTop(p).map(s => {
    const toks = s.split(/\s+/); const type = toks[0]; const last = toks[toks.length - 1];
    const name = toks.length > 1 && !/^(memory|calldata|storage|payable|indexed)$/.test(last) ? last : '';
    return { type, name };
  });
}

function writeRegex(n) {
  const e = escRe(n);
  return new RegExp(
    '(?:^|[^\\w$.])' + e + '(?:\\s*\\[[^\\]]*\\])*(?:\\s*\\.\\s*' + ID_RE + ')*\\s*(?:=(?!=)|\\+=|-=|\\*=|\\/=|%=|\\|=|&=|\\^=|<<=|>>=|\\+\\+|--)' +
    '|(?:\\+\\+|--)\\s*' + e + '\\b' +
    '|\\bdelete\\s+' + e + '\\b' +
    '|(?:^|[^\\w$.])' + e + '(?:\\s*\\[[^\\]]*\\])*\\s*\\.\\s*(?:push|pop)\\s*\\(');
}

function findCalls(t, typeOf) {
  const out = []; let m;
  if (/\.\s*call\s*\{[^}]*\bvalue\s*:/.test(t) || /\.\s*call\s*\.\s*value\s*\(/.test(t)) out.push({ kind: 'call-value', expr: 'call{value: …}' });
  else if (/\.\s*call\s*[({]/.test(t)) out.push({ kind: 'call', expr: 'call' });
  if (/\.\s*delegatecall\s*\(/.test(t)) out.push({ kind: 'delegatecall', expr: 'delegatecall' });
  if (/\.\s*send\s*\(/.test(t)) out.push({ kind: 'send', expr: 'send' });
  const tr = /\.\s*transfer\s*\(/g;
  while ((m = tr.exec(t))) { const open = m.index + m[0].length - 1; const close = matchClose(t, open, '(', ')'); if (splitTop(t.slice(open + 1, close)).length <= 1) out.push({ kind: 'transfer-eth', expr: 'transfer' }); }
  const re = /(?:\b([A-Z][\w$]*)\s*\(\s*[^()]*\)|\b([A-Za-z_$][\w$]*))\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g;
  while ((m = re.exec(t))) {
    const method = m[3];
    if (/^(call|delegatecall|staticcall|send|value|gas|push|pop|encode\w*|decode|selector|length|concat)$/.test(method)) continue;
    if (method === 'transfer') { const open = m.index + m[0].length - 1; const close = matchClose(t, open, '(', ')'); if (splitTop(t.slice(open + 1, close)).length <= 1) continue; }
    if (m[1]) { if (!/^(SafeMath|Math|Strings|Address|SafeERC20|ECDSA|SignedMath)$/.test(m[1])) out.push({ kind: 'ext', expr: m[1] + '(…).' + method }); continue; }
    const recv = m[2];
    if (/^(msg|tx|block|abi|this|super|type|address|payable|bytes|string|Math|SafeMath)$/.test(recv)) continue;
    const ty = typeOf(recv);
    if (ty && /^[A-Z]/.test(ty)) out.push({ kind: 'ext', expr: recv + '.' + method });
  }
  return out;
}

function analyze(srcIn) {
  const src = srcIn.replace(/\r\n?/g, '\n');
  const masked = maskSource(src);
  const starts = lineStarts(src);
  const L = off => lineAt(starts, off);
  const lines = src.split('\n'), mLines = masked.split('\n');
  let pragma = null;
  const pm = /\bpragma\s+solidity\s+([^;]+);/.exec(masked);
  if (pm) pragma = { text: pm[1].trim(), line: L(pm.index), version: parseVersion(pm[1]), floating: /[\^~><]/.test(pm[1]) };
  const usesSafeMath = /\busing\s+SafeMath\b/.test(masked);

  const contracts = [];
  const cRe = /\b(abstract\s+contract|contract|library|interface)\s+([A-Za-z_$][\w$]*)([^{;]*)\{/g;
  let m;
  while ((m = cRe.exec(masked))) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open, '{', '}');
    const inh = /\bis\b([\s\S]*)$/.exec(m[3]);
    const c = { kind: m[1].replace(/\s+/g, ' '), name: m[2], line: L(m.index), openLine: L(open), endLine: L(close), open, close,
      inherits: inh ? splitTop(inh[1]).map(s => s.split(/[\s(]/)[0]) : [], functions: [], modifiers: [], stateVars: [], indent: '    ' };
    parseMembers(c);
    contracts.push(c);
    cRe.lastIndex = close + 1;
  }

  function parseMembers(c) {
    const bodyStart = c.open + 1, bodyEnd = c.close;
    const region = masked.slice(0, bodyEnd);
    const re = /\b(function\s+[A-Za-z_$][\w$]*|function|constructor|receive|fallback|modifier\s+[A-Za-z_$][\w$]*|struct\s+[A-Za-z_$][\w$]*|enum\s+[A-Za-z_$][\w$]*)\s*([({])/g;
    re.lastIndex = bodyStart;
    const blanks = []; let mm;
    while ((mm = re.exec(region))) {
      const words = mm[1].split(/\s+/); const kw = words[0];
      const tokIdx = mm.index + mm[0].length - 1;
      if (kw === 'struct' || kw === 'enum') {
        if (mm[2] !== '{') continue;
        const e = matchClose(masked, tokIdx, '{', '}'); blanks.push([mm.index, e]); re.lastIndex = e + 1; continue;
      }
      let pOpen = -1, pClose = -1, after = tokIdx, k;
      if (mm[2] === '(') {
        pOpen = tokIdx; pClose = matchClose(masked, tokIdx, '(', ')'); after = pClose + 1;
        let depth = 0;
        for (k = after; k < bodyEnd; k++) { const ch = masked[k]; if (ch === '(') depth++; else if (ch === ')') depth--; else if (depth === 0 && (ch === '{' || ch === ';')) break; }
      } else k = tokIdx;
      if (k >= bodyEnd) break;
      const hasBody = masked[k] === '{';
      const bodyClose = hasBody ? matchClose(masked, k, '{', '}') : k;
      blanks.push([mm.index, bodyClose]);
      re.lastIndex = bodyClose + 1;
      const kind = kw === 'function' ? (words[1] ? 'function' : 'fallback') : kw;
      const name = kw === 'function' ? (words[1] || 'fallback') : (kw === 'modifier' ? words[1] : kw);
      const item = { kind, name, contract: c.name, line: L(mm.index), bodyLine: L(k), endLine: L(bodyClose), hasBody,
        header: masked.slice(mm.index, k).replace(/\s+/g, ' ').trim(), params: pOpen >= 0 ? parseParams(masked.slice(pOpen + 1, pClose)) : [] };
      if (kind === 'modifier') { item.bodyText = hasBody ? masked.slice(k + 1, bodyClose) : ''; c.modifiers.push(item); continue; }
      const tail = masked.slice(after, k).replace(/\breturns\s*\((?:[^()]|\([^()]*\))*\)/g, ' ').replace(/\boverride\s*\([^)]*\)/g, ' override ');
      const callRe = /([A-Za-z_$][\w$]*)\s*(\((?:[^()]|\([^()]*\))*\))?/g;
      const mods = []; let vis = null, mut = 'nonpayable', cm;
      while ((cm = callRe.exec(tail))) {
        const w = cm[1];
        if (['public', 'external', 'internal', 'private'].includes(w)) vis = w;
        else if (['view', 'pure', 'payable', 'constant'].includes(w)) mut = w === 'constant' ? 'view' : w;
        else if (!['virtual', 'override', 'returns', 'memory', 'storage', 'calldata'].includes(w)) mods.push(w);
      }
      item.visibility = vis || (kind === 'function' ? 'public' : (kind === 'constructor' ? 'public' : 'external'));
      item.mutability = mut; item.modifiers = mods; item.stmts = []; item.bodyText = '';
      if (hasBody) {
        item.bodyText = masked.slice(k + 1, bodyClose);
        const ln0 = L(k + 1); let dep = 0;
        item.bodyText.split('\n').forEach((s, i) => { item.stmts.push({ line: ln0 + i, text: s, depth: dep }); for (const ch of s) { if (ch === '{') dep++; else if (ch === '}') dep--; } });
      }
      c.functions.push(item);
    }
    // state variables: the contract body with every member blanked out
    const arr = masked.slice(bodyStart, bodyEnd).split('');
    for (const [a, b] of blanks) for (let i = Math.max(a, bodyStart); i <= Math.min(b, bodyEnd - 1); i++) if (arr[i - bodyStart] !== '\n') arr[i - bodyStart] = ' ';
    const body = arr.join('');
    let segStart = 0;
    for (let i = 0; i <= body.length; i++) {
      if (i < body.length && body[i] !== ';') continue;
      const raw = body.slice(segStart, i); const abs = bodyStart + segStart; segStart = i + 1;
      const t = raw.trim(); if (!t) continue;
      if (/^(event|error|using|emit|import|pragma|type)\b/.test(t)) continue;
      let decl = t; const eq = t.search(/(?<![=!<>])=(?![=>])/);
      if (eq >= 0) decl = t.slice(0, eq);
      decl = decl.replace(/mapping\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)/g, 'mapping ');
      const toks = decl.trim().split(/\s+/); if (toks.length < 2) continue;
      const vname = toks[toks.length - 1];
      if (!new RegExp('^' + ID_RE + '$').test(vname)) continue;
      const lead = raw.length - raw.replace(/^\s+/, '').length;
      c.stateVars.push({ name: vname, type: toks[0], line: L(abs + lead), constant: /\b(constant|immutable)\b/.test(t) });
    }
    const firstMember = Math.min(...[...c.stateVars.map(v => v.line), ...c.functions.map(f => f.line), ...c.modifiers.map(f => f.line), c.endLine]);
    const ind = (lines[firstMember - 1] || '').match(/^\s*/)[0];
    if (ind && firstMember !== c.endLine) c.indent = ind;
  }

  const findings = []; const seen = {};
  const add = (rule, c, fn, ls, evidence, meta) => {
    const r = RULES[rule];
    const base = rule + '@' + (c ? c.name : '') + '.' + (fn ? fn.name : '*');
    seen[base] = (seen[base] || 0) + 1;
    findings.push({ rule, title: r.name, severity: r.severity, swc: r.swc, contract: c ? c.name : '', fn: fn ? fn.name : '', fnLine: fn ? fn.line : 0,
      lines: [...new Set(ls)].sort((a, b) => a - b), evidence, meta: meta || {}, key: seen[base] > 1 ? base + '#' + seen[base] : base });
  };

  for (const c of contracts) {
    const svTypes = {}; c.stateVars.forEach(v => { svTypes[v.name] = v.type; });
    const writeRes = c.stateVars.filter(v => !v.constant).map(v => [v.name, writeRegex(v.name)]);
    const writesIn = text => writeRes.filter(([, re]) => re.test(text)).map(([n]) => n);
    const authMods = new Set(c.modifiers.filter(md => AUTH_BODY.test(md.bodyText)).map(md => md.name));
    for (const fn of c.functions) {
      if (!fn.hasBody) { fn.info = { writes: [], calls: [], auth: null }; continue; }
      const readOnly = fn.mutability === 'view' || fn.mutability === 'pure';
      const typeOf = n => svTypes[n] || (fn.params.find(p => p.name === n) || {}).type || '';
      const facts = fn.stmts.filter(s => s.text.trim()).map(s => ({ ...s, calls: findCalls(s.text, typeOf), writes: writesIn(s.text) }));
      const authByMod = fn.modifiers.filter(md => AUTH_MOD_NAME.test(md) || authMods.has(md));
      const authInBody = AUTH_BODY.test(fn.bodyText);
      fn.info = { writes: [...new Set(facts.flatMap(f => f.writes))], calls: facts.flatMap(f => f.calls.map(k => ({ ...k, line: f.line }))), auth: authByMod.length ? authByMod.join(', ') : authInBody ? 'inline check' : null };
      const guarded = fn.modifiers.some(md => GUARD_MOD.test(md));

      // Reentrancy / state-change ordering
      if (!readOnly && !guarded && fn.kind !== 'constructor') {
        const lowIdx = facts.findIndex(f => f.calls.some(k => k.kind === 'call-value' || k.kind === 'call'));
        const extIdx = facts.findIndex(f => f.calls.some(k => k.kind === 'ext'));
        const idx = lowIdx >= 0 ? lowIdx : extIdx;
        if (idx >= 0) {
          const after = facts.slice(idx + 1).filter(f => f.writes.length);
          if (after.length) {
            const names = [...new Set(after.flatMap(f => f.writes))];
            const wl = after.map(f => f.line);
            const meta = { callLine: facts[idx].line, writeLines: wl, callDepth: facts[idx].depth, writeDepths: after.map(f => f.depth) };
            if (lowIdx >= 0) {
              const withValue = facts[idx].calls.some(k => k.kind === 'call-value');
              add(withValue ? 'reentrancy-eth' : 'reentrancy-no-eth', c, fn, [facts[idx].line, ...wl],
                `The low-level call on line ${facts[idx].line} ${withValue ? 'sends ETH ' : ''}before ${listCode(names)} ${names.length > 1 ? 'are' : 'is'} updated on ${plural(wl.length, 'line')} ${lineList(wl)}.`, meta);
            } else {
              const ex = facts[idx].calls.find(k => k.kind === 'ext');
              add('unsafe-ordering', c, fn, [facts[idx].line, ...wl],
                `\`${ex.expr}\` on line ${facts[idx].line} runs before ${listCode(names)} ${names.length > 1 ? 'are' : 'is'} updated on ${plural(wl.length, 'line')} ${lineList(wl)}.`, meta);
            }
          }
        }
      }

      // Unchecked low-level calls
      facts.forEach((f, i) => {
        const k = /\.\s*(call|send|delegatecall|staticcall)\b\s*(?:\{[^}]*\}\s*)?(?:\.\s*value\s*\([^)]*\)\s*)?\(/.exec(f.text);
        if (!k) return;
        const before = f.text.slice(0, k.index);
        if (/\b(require|assert|if|return|while)\b|\|\||&&|!\s*$/.test(before)) return;
        const assigned = /(?:^|[^=!<>])=(?![=>])/.test(before);
        let v = null;
        if (assigned) {
          const vm = /\(\s*(?:bool\s+)?([A-Za-z_$][\w$]*)\s*,/.exec(before) || /\bbool\s+([A-Za-z_$][\w$]*)\s*=/.exec(before) || /([A-Za-z_$][\w$]*)\s*=\s*[^=]*$/.exec(before);
          v = vm && vm[1];
          if (!v) return;
          const e = escRe(v);
          const useRe = new RegExp('\\b(?:require|assert)\\s*\\([^;]*\\b' + e + '\\b|\\bif\\s*\\([^)]*\\b' + e + '\\b|\\breturn\\b[^;]*\\b' + e + '\\b|\\b' + e + '\\b\\s*(?:==|!=|&&|\\|\\|)|!\\s*' + e + '\\b');
          if (facts.slice(i + 1).some(g => useRe.test(g.text))) return;
        }
        add('unchecked-lowlevel', c, fn, [f.line],
          assigned ? `The result of \`.${k[1]}\` on line ${f.line} is stored in \`${v}\` but never checked.` : `The boolean returned by \`.${k[1]}\` on line ${f.line} is discarded, so a failed transfer goes unnoticed.`,
          { line: f.line, kind: k[1], varName: v, bare: !assigned });
      });

      // tx.origin authorization
      for (const f of facts) {
        if (/\btx\s*\.\s*origin\b/.test(f.text) && /(==|!=)/.test(f.text) && !/(tx\s*\.\s*origin\s*[!=]=\s*msg\s*\.\s*sender|msg\s*\.\s*sender\s*[!=]=\s*tx\s*\.\s*origin)/.test(f.text))
          add('tx-origin', c, fn, [f.line], `Line ${f.line} compares \`tx.origin\` to decide whether the caller is allowed.`, { line: f.line });
      }

      // Access control
      if (fn.kind === 'function' && (fn.visibility === 'public' || fn.visibility === 'external') && !readOnly && !authByMod.length && !authInBody) {
        const sd = facts.find(f => /\b(selfdestruct|suicide)\s*\(/.test(f.text));
        const priv = facts.filter(f => f.writes.some(n => PRIV_VAR.test(n)));
        const drain = facts.find(f => /address\s*\(\s*this\s*\)\s*\.\s*balance/.test(f.text) && f.calls.some(k => ['call-value', 'call', 'transfer-eth', 'send'].includes(k.kind)));
        const anyW = facts.filter(f => f.writes.length);
        const vis = `\`${fn.name}()\` is ${fn.visibility} with no access check`;
        if (sd) add('unprotected-selfdestruct', c, fn, [fn.line, sd.line], `${vis}, and line ${sd.line} calls \`selfdestruct\`.`, {});
        else if (priv.length) { const ns = [...new Set(priv.flatMap(f => f.writes.filter(n => PRIV_VAR.test(n))))]; add('unprotected-owner-change', c, fn, [fn.line, ...priv.map(f => f.line)], `${vis}, and it writes ${listCode(ns)} on ${plural(priv.length, 'line')} ${lineList(priv.map(f => f.line))}.`, {}); }
        else if (drain) add('unprotected-withdrawal', c, fn, [fn.line, drain.line], `${vis}, and line ${drain.line} sends the contract's entire balance.`, {});
        else if (SENSITIVE_NAME.test(fn.name) && anyW.length) { const ns = [...new Set(anyW.flatMap(f => f.writes))]; add('unprotected-setter', c, fn, [fn.line, ...anyW.map(f => f.line)], `${vis}, and it changes ${listCode(ns)} on ${plural(anyW.length, 'line')} ${lineList(anyW.map(f => f.line))}.`, {}); }
      }

      // Arithmetic
      const arith = t => /(\+=|-=|\*=|\+\+|--)/.test(t) || /=[^=>][^;]*[\w)\]]\s*[+\-*]\s*[\w(]/.test(t);
      if (pragma && pragma.version && pragma.version.major === 0 && pragma.version.minor < 8 && !usesSafeMath) {
        const ar = facts.filter(f => f.writes.length && arith(f.text));
        if (ar.length) add('integer-overflow', c, fn, ar.map(f => f.line), `Compiler \`${pragma.text}\` has no built-in overflow checks, and \`${fn.name}()\` does arithmetic on state on ${plural(ar.length, 'line')} ${lineList(ar.map(f => f.line))}.`, {});
      } else {
        const ui = facts.findIndex(f => /\bunchecked\s*\{/.test(f.text));
        if (ui >= 0) {
          const d0 = facts[ui].depth; const inner = [];
          for (let j = ui + 1; j < facts.length && facts[j].depth > d0; j++) if (facts[j].writes.length && arith(facts[j].text)) inner.push(facts[j]);
          if (inner.length) add('unchecked-arithmetic', c, fn, [facts[ui].line, ...inner.map(f => f.line)], `State arithmetic on ${plural(inner.length, 'line')} ${lineList(inner.map(f => f.line))} runs inside the \`unchecked\` block opened on line ${facts[ui].line}, so overflow wraps silently.`, { openLine: facts[ui].line });
        }
      }

      // Timestamp dependence
      const ts = facts.filter(f => /\bblock\s*\.\s*timestamp\b|\bnow\b/.test(f.text) && /\b(require|assert|if|while|return)\b/.test(f.text) && /(<|>|==|!=|%)/.test(f.text));
      if (ts.length) add('timestamp', c, fn, ts.map(f => f.line), `\`block.timestamp\` decides a condition on ${plural(ts.length, 'line')} ${lineList(ts.map(f => f.line))}.`, {});
    }
  }
  if (pragma && pragma.floating) add('floating-pragma', null, null, [pragma.line], `\`pragma solidity ${pragma.text}\` lets the contract compile with versions other than the one it was tested with.`, {});

  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.lines[0] - b.lines[0]);
  findings.forEach((f, i) => { f.id = 'F-' + String(i + 1).padStart(2, '0'); });
  const an = { source: src, masked, lines, mLines, pragma, contracts, findings, usesSafeMath };
  for (const f of findings) {
    const fx = FIXERS[f.rule]; let patched = null;
    try { patched = fx ? fx(src, f, an) : null; } catch (e) { patched = null; }
    f.fixable = !!patched && patched !== src; f.patched = f.fixable ? patched : null;
  }
  an.counts = countSev(findings); an.score = scoreOf(an.counts);
  return an;
}

function countSev(fs) { const c = { Critical: 0, High: 0, Medium: 0, Low: 0 }; fs.forEach(f => c[f.severity]++); return c; }
function scoreOf(c) { return Math.max(0, 100 - SEVS.reduce((s, k) => s + c[k] * SEV_WEIGHT[k], 0)); }
function fnOf(an, f) { const c = an.contracts.find(x => x.name === f.contract); return c ? c.functions.find(fn => fn.line === f.fnLine) : null; }
function freeName(text, cands) { return cands.find(n => !new RegExp('\\b' + n + '\\b').test(text)) || 'ok_' + Date.now() % 1000; }

/* ---- rule-based fixes: each returns patched source or null (manual) ---- */
function fixReorder(src, f, an) {
  const { callLine, writeLines, callDepth, writeDepths } = f.meta;
  if (!writeLines || !writeLines.length || writeDepths.some(d => d !== callDepth)) return null;
  if (writeLines.some(n => !/;\s*$/.test(an.mLines[n - 1].trim()))) return null;
  const prev = (an.mLines.slice(0, callLine - 1).reverse().find(s => s.trim()) || '').trim();
  if (prev && !/[;{}]$/.test(prev)) return null;
  const declared = new Set();
  const dre = /\b(?:bool|address|uint\d*|int\d*|bytes\d*|string)\s+(?:memory\s+|calldata\s+|storage\s+|payable\s+)?([A-Za-z_$][\w$]*)/g;
  for (let n = callLine; n < Math.max(...writeLines); n++) { let m; const t = an.mLines[n - 1]; dre.lastIndex = 0; while ((m = dre.exec(t))) declared.add(m[1]); }
  for (const n of writeLines) for (const v of declared) if (new RegExp('\\b' + escRe(v) + '\\b').test(an.mLines[n - 1])) return null;
  const lines = src.split('\n');
  const indent = lines[callLine - 1].match(/^\s*/)[0];
  const moved = writeLines.map(n => indent + lines[n - 1].trim());
  const kept = lines.filter((_, i) => !writeLines.includes(i + 1));
  kept.splice(callLine - 1, 0, ...moved);
  return kept.join('\n');
}
function fixUnchecked(src, f, an) {
  const n = f.meta.line; const lines = src.split('\n'); const raw = lines[n - 1]; const m = an.mLines[n - 1];
  if (!/;\s*$/.test(m.trim())) return null;
  const indent = raw.match(/^\s*/)[0];
  const fn = fnOf(an, f); const body = fn ? fn.bodyText : '';
  if (f.meta.bare) {
    const prev = (an.mLines.slice(0, n - 1).reverse().find(s => s.trim()) || '').trim();
    if (prev && !/[;{}]$/.test(prev)) return null;
    const semi = m.lastIndexOf(';'); const start = m.search(/\S/);
    const expr = raw.slice(start, semi).trim(); const tail = raw.slice(semi + 1);
    if (f.meta.kind === 'send') lines[n - 1] = indent + 'require(' + expr + ', "Send failed");' + tail;
    else { const v = freeName(body, ['ok', 'success', 'callOk']); lines.splice(n - 1, 1, indent + '(bool ' + v + ', ) = ' + expr + ';' + tail, indent + 'require(' + v + ', "Call failed");'); }
  } else {
    if (!f.meta.varName) return null;
    lines.splice(n, 0, indent + 'require(' + f.meta.varName + ', "Call failed");');
  }
  return lines.join('\n');
}
function fixTxOrigin(src, f) {
  const lines = src.split('\n'); const n = f.meta.line;
  const next = lines[n - 1].replace(/\btx\s*\.\s*origin\b/g, 'msg.sender');
  if (next === lines[n - 1]) return null;
  lines[n - 1] = next; return lines.join('\n');
}
function fixOnlyOwner(src, f, an) {
  const c = an.contracts.find(x => x.name === f.contract); const fn = fnOf(an, f);
  if (!c || !fn) return null;
  const lines = src.split('\n'); let done = false;
  for (let n = fn.line; n <= fn.bodyLine && !done; n++) {
    const vm = /\b(external|public)\b/.exec(an.mLines[n - 1]);
    if (vm) { const raw = lines[n - 1]; const at = vm.index + vm[0].length; lines[n - 1] = raw.slice(0, at) + ' onlyOwner' + raw.slice(at); done = true; }
  }
  if (!done) return null;
  const hasMod = c.modifiers.some(md => md.name === 'onlyOwner') || c.inherits.some(b => /Ownable/.test(b));
  if (!hasMod) {
    const ind = c.indent;
    const ownerVar = c.stateVars.find(v => /^_?owner$/i.test(v.name) && /^address/.test(v.type));
    const block = [];
    let at;
    if (ownerVar) at = Math.max(...c.stateVars.map(v => v.line));
    else { at = c.openLine; block.push(ind + 'address public owner = msg.sender;'); }
    block.push('', ind + 'modifier onlyOwner() {', ind + ind + 'require(msg.sender == ' + (ownerVar ? ownerVar.name : 'owner') + ', "Not owner");', ind + ind + '_;', ind + '}');
    if (!ownerVar && (lines[at] || '').trim()) block.push('');
    lines.splice(at, 0, ...block);
  }
  return lines.join('\n');
}
function fixPinPragma(src, f, an) {
  const p = an.pragma; if (!p || !p.version) return null;
  const lines = src.split('\n'); const next = lines[p.line - 1].replace(/pragma\s+solidity\s+[^;]+;/, 'pragma solidity ' + p.version.text + ';');
  if (next === lines[p.line - 1]) return null; lines[p.line - 1] = next; return lines.join('\n');
}
function fixPragmaUpgrade(src, f, an) {
  const p = an.pragma; if (!p) return null;
  const lines = src.split('\n'); const next = lines[p.line - 1].replace(/pragma\s+solidity\s+[^;]+;/, 'pragma solidity 0.8.20;');
  if (next === lines[p.line - 1]) return null; lines[p.line - 1] = next; return lines.join('\n');
}
function fixRemoveUnchecked(src, f, an) {
  const open = f.meta.openLine; const lt = an.mLines[open - 1];
  if (!/^\s*unchecked\s*\{\s*$/.test(lt)) return null;
  const starts = lineStarts(src); const oi = starts[open - 1] + lt.indexOf('{');
  const ci = matchClose(an.masked, oi, '{', '}'); const cl = lineAt(starts, ci);
  if (!/^\s*\}\s*$/.test(an.mLines[cl - 1])) return null;
  const lines = src.split('\n');
  const inner = lines.slice(open, cl - 1).map(s => s.replace(/^( {4}|\t)/, ''));
  lines.splice(open - 1, cl - open + 1, ...inner);
  return lines.join('\n');
}
const FIXERS = {
  'reentrancy-eth': fixReorder, 'reentrancy-no-eth': fixReorder, 'unsafe-ordering': fixReorder,
  'unchecked-lowlevel': fixUnchecked, 'tx-origin': fixTxOrigin,
  'unprotected-selfdestruct': fixOnlyOwner, 'unprotected-withdrawal': fixOnlyOwner, 'unprotected-owner-change': fixOnlyOwner, 'unprotected-setter': fixOnlyOwner,
  'integer-overflow': fixPragmaUpgrade, 'unchecked-arithmetic': fixRemoveUnchecked, 'floating-pragma': fixPinPragma, 'timestamp': null,
};
function applyAllFixes(src) {
  let cur = src; const tried = new Set(); let applied = 0;
  for (let i = 0; i < 30; i++) {
    const an = analyze(cur);
    const f = an.findings.find(x => x.fixable && !tried.has(x.rule + '|' + x.key));
    if (!f) break;
    tried.add(f.rule + '|' + f.key);
    cur = f.patched; applied++;
  }
  return { source: cur, applied };
}

/* ---- line diff ---- */
function diffLines(a, b) {
  const n = a.length, m = b.length; let s = 0;
  while (s < n && s < m && a[s] === b[s]) s++;
  let e = 0; while (e < n - s && e < m - s && a[n - 1 - e] === b[m - 1 - e]) e++;
  const A = a.slice(s, n - e), B = b.slice(s, m - e); const ops = [];
  for (let i = 0; i < s; i++) ops.push({ t: ' ', o: i + 1, n: i + 1, s: a[i] });
  if (A.length * B.length > 2e6) { A.forEach((x, i) => ops.push({ t: '-', o: s + i + 1, n: null, s: x })); B.forEach((x, i) => ops.push({ t: '+', o: null, n: s + i + 1, s: x })); }
  else {
    const N = A.length, M = B.length; const dp = Array.from({ length: N + 1 }, () => new Uint32Array(M + 1));
    for (let i = N - 1; i >= 0; i--) for (let j = M - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    let i = 0, j = 0;
    while (i < N || j < M) {
      if (i < N && j < M && A[i] === B[j]) { ops.push({ t: ' ', o: s + i + 1, n: s + j + 1, s: A[i] }); i++; j++; }
      else if (i < N && (j >= M || dp[i + 1][j] >= dp[i][j + 1])) { ops.push({ t: '-', o: s + i + 1, n: null, s: A[i] }); i++; }
      else { ops.push({ t: '+', o: null, n: s + j + 1, s: B[j] }); j++; }
    }
  }
  for (let k = 0; k < e; k++) ops.push({ t: ' ', o: n - e + k + 1, n: m - e + k + 1, s: a[n - e + k] });
  return ops;
}
function hunks(ops, ctx) {
  ctx = ctx == null ? 2 : ctx;
  const idx = []; ops.forEach((o, i) => { if (o.t !== ' ') idx.push(i); });
  const out = []; let cur = null;
  for (const i of idx) { const lo = Math.max(0, i - ctx), hi = Math.min(ops.length - 1, i + ctx); if (cur && lo <= cur.hi + 1) cur.hi = Math.max(cur.hi, hi); else { cur = { lo, hi }; out.push(cur); } }
  return out.map(h => ops.slice(h.lo, h.hi + 1));
}

/* ---- hashing ---- */
const sha256 = (() => {
  const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  return function (str) {
    const msg = new TextEncoder().encode(str); const l = msg.length;
    const total = Math.ceil((l + 9) / 64) * 64; const buf = new Uint8Array(total);
    buf.set(msg); buf[l] = 0x80;
    const dv = new DataView(buf.buffer); const bits = l * 8;
    dv.setUint32(total - 8, Math.floor(bits / 0x100000000)); dv.setUint32(total - 4, bits >>> 0);
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const W = new Uint32Array(64);
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) { const a = W[i - 15], b = W[i - 2]; W[i] = (W[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + W[i - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) >>> 0; }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7].map(x => x.toString(16).padStart(8, '0')).join('');
  };
})();
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}
function encodeBytes32(s) { let hex = ''; for (const ch of s) hex += ch.charCodeAt(0).toString(16).padStart(2, '0'); return '0x' + hex.padEnd(64, '0').slice(0, 64); }
function verdictFor(c) {
  if (c.Critical || c.High) return 'Blocking findings: not ready for deployment.';
  if (c.Medium) return 'Review the medium findings before deployment.';
  if (c.Low) return 'No blocking findings in the scanned classes.';
  return 'No findings in the scanned classes.';
}
function buildReport(file, versions, idx, generatedAt, auditIdOverride) {
  const v = versions[idx]; const first = versions[0]; const an = v.analysis || {};
  const vk = new Set(v.findings.map(f => f.key));
  const c0 = v.an.contracts[0];
  const report = {
    schema: 'vulnex/audit-report@1',
    auditId: auditIdOverride || ('TSX-' + sha256(v.contractHash + generatedAt).slice(0, 6).toUpperCase()),
    generatedAt,
    engine: ENGINE_ID,
    contract: { file, name: c0 ? c0.name : 'Unknown', version: v.label, compiler: v.an.pragma ? 'solidity ' + v.an.pragma.text : 'not declared', lines: v.an.lines.length, contractHash: v.contractHash },
    summary: { total: v.findings.length, critical: v.counts.Critical, high: v.counts.High, medium: v.counts.Medium, low: v.counts.Low, score: v.score, verdict: (an.status === 'completed' ? '' : 'Partial analysis: ' + ((an.reasons && an.reasons[0]) || 'not every check completed.') + ' ') + verdictFor(v.counts), resolvedSinceV1: first.findings.filter(f => !vk.has(f.key)).length },
    analysis: {
      status: an.status || 'unknown',
      reasons: an.reasons || [],
      compiler: { status: (an.compiler && an.compiler.status) || 'not_run', version: (an.compiler && an.compiler.version) || null, pragma: (an.compiler && an.compiler.requested) || null, warnings: (an.compiler && an.compiler.warnings || []).length },
      rules: { status: (an.rules && an.rules.status) || 'unknown', rules: Object.keys(RULES).length, findings: v.findings.filter(f => (f.sources || ['rules']).includes('rules')).length, functionsParsed: an.rules ? an.rules.parsed : null, functionsInSource: an.rules ? an.rules.expected : null },
      ai: { status: (an.ai && an.ai.status) || 'not_run', model: (an.ai && (an.ai.modelUsed || an.ai.model)) || null, structuredOutput: !!(an.ai && an.ai.structured), findings: v.findings.filter(f => (f.sources || []).includes('ai')).length, error: (an.ai && an.ai.error && an.ai.error.code) || null },
    },
    findings: v.findings.map(f => Object.assign({ id: f.id, source: (f.sources || ['rules']).join('+'), rule: f.rule, reference: f.swc, title: f.title, severity: f.severity, location: (f.fn ? f.fn + '()' : 'file') + ' L' + lineList(f.lines), evidence: f.evidence, recommendation: f.aiInfo ? (f.aiInfo.remediation || '') : RECS[f.rule] }, f.aiInfo && f.aiInfo.confidence != null ? { confidence: f.aiInfo.confidence } : {})),
    history: versions.slice(0, idx + 1).map(x => ({ version: x.label, status: (x.analysis && x.analysis.status) || 'unknown', contractHash: x.contractHash, scannedAt: x.scannedAt, findings: x.findings.length, score: x.score })),
    scope: 'Compiler validation with solc, ' + Object.keys(RULES).length + ' deterministic rules for selected classes (reentrancy, state-change ordering, unchecked calls, tx.origin authorization, access control, arithmetic, floating pragma, timestamp dependence) and, when configured, an AI review through OpenRouter. Neither the rules nor the AI review is exhaustive.',
    disclaimer: 'Findings come from automated rules and an AI model; false positives and false negatives are possible. A verified attestation proves this record has not been altered. It does not prove the contract is secure.',
  };
  return report;
}
/* =============================== ENGINE END =============================== */
