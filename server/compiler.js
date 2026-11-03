// VULNEX · Solidity compiler validation (solc-js).
//
// Every scan is compiled before any security analysis is trusted. The compiler version is
// chosen from the file's `pragma solidity` the same way Hardhat and Foundry do it: the newest
// released solc that satisfies every pragma. The npm `solc` package bundles one version; any
// other version is downloaded once from binaries.soliditylang.org, checked against the
// published SHA-256, and cached in .solc-cache/.
//
// A file that does not compile returns status "failed" with the compiler's own diagnostics.
// If the right compiler cannot be obtained, status is "unavailable" (never "passed").

import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { mkdir, writeFile, rename, readFile } from 'node:fs/promises';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const semver = require('semver');

export const DEFAULT_BINARIES_URL = 'https://binaries.soliditylang.org/bin';
const MAX_DIAGNOSTICS = 50;

/* ------------------------------ pragma handling ------------------------------ */

// Blank out comments and string literals (keeping offsets) so a pragma inside a comment is ignored.
export function maskCommentsAndStrings(src) {
  const out = src.split('');
  let i = 0; const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') out[i++] = ' '; continue; }
    if (c === '/' && d === '*') { out[i++] = ' '; out[i++] = ' '; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] !== '\n') out[i] = ' '; i++; } if (i < n) { out[i++] = ' '; if (i < n) out[i++] = ' '; } continue; }
    if (c === '"' || c === "'") { const q = c; i++; while (i < n && src[i] !== q && src[i] !== '\n') { if (src[i] === '\\') { out[i++] = ' '; } if (i < n) out[i++] = ' '; } i++; continue; }
    i++;
  }
  return out.join('');
}

export function pragmaRanges(src) {
  const masked = maskCommentsAndStrings(src);
  const found = [];
  const re = /\bpragma\s+solidity\s+([^;]+);/g;
  let m;
  while ((m = re.exec(masked))) found.push({ raw: src.slice(m.index, m.index + m[0].length).replace(/^pragma\s+solidity\s+/, '').replace(/;$/, '').trim(), index: m.index });
  return found;
}

export function normalizeRange(raw) {
  return semver.validRange(String(raw).replace(/\s+/g, ' ').trim());
}

// Newest release (no prereleases/nightlies) that satisfies every pragma range.
export function pickVersion(ranges, versions) {
  const ok = versions.filter(v => semver.valid(v) && !semver.prerelease(v) && ranges.every(r => semver.satisfies(v, r)));
  return ok.length ? semver.rsort(ok.slice())[0] : null;
}

/* ------------------------------ offsets → lines ------------------------------ */

function lineStarts(text) { const a = [0]; for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) a.push(i + 1); return a; }
function lineAt(starts, idx) { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1; } return lo + 1; }

// solc reports byte offsets into the UTF-8 encoding; JavaScript strings index UTF-16 units.
function makeLocator(source) {
  const buf = Buffer.from(source, 'utf8');
  const starts = lineStarts(source);
  const charIndex = byte => buf.subarray(0, Math.max(0, Math.min(byte, buf.length))).toString('utf8').length;
  return {
    fromByte(byte) {
      if (typeof byte !== 'number' || byte < 0) return null;
      const ci = charIndex(byte);
      const line = lineAt(starts, ci);
      return { line, column: ci - starts[line - 1] + 1 };
    },
    fromSrc(src) { // "start:length:fileIndex"
      const p = String(src || '').split(':').map(Number);
      if (p.length < 2 || p[0] < 0) return null;
      const a = this.fromByte(p[0]); const b = this.fromByte(p[0] + Math.max(0, p[1] - 1));
      return a && b ? { line: a.line, endLine: b.line } : null;
    },
    lineOfChar(ci) { return lineAt(starts, ci); },
  };
}

function toDiagnostic(e, loc, fileName) {
  const sl = e.sourceLocation && (!e.sourceLocation.file || e.sourceLocation.file === fileName) ? e.sourceLocation : null;
  const a = sl ? loc.fromByte(sl.start) : null;
  const b = sl ? loc.fromByte(Math.max(sl.start, sl.end - 1)) : null;
  const sev = e.severity === 'error' ? 'error' : e.severity === 'info' ? 'info' : 'warning';
  return {
    severity: sev,
    type: e.type || null,
    code: e.errorCode || null,
    message: String(e.message || '').slice(0, 1000),
    line: a ? a.line : null,
    column: a ? a.column : null,
    endLine: b ? b.line : null,
    formatted: String(e.formattedMessage || e.message || '').slice(0, 2000),
  };
}

/* ------------------------------ AST coverage ------------------------------ */

// What the compiler says the file contains. Used to check that the rule engine parsed
// every function, and to place AI findings inside the right function.
export function astCoverage(ast, source) {
  if (!ast || typeof ast !== 'object') return null;
  const loc = makeLocator(source);
  const contracts = []; const functions = []; const modifiers = [];
  const walk = (node, contract) => {
    if (!node || typeof node !== 'object') return;
    if (node.nodeType === 'ContractDefinition') {
      const r = loc.fromSrc(node.src) || {};
      contracts.push({ name: node.name, kind: node.contractKind || 'contract', abstract: !!node.abstract, line: r.line || null, endLine: r.endLine || null });
      (node.nodes || []).forEach(ch => walk(ch, node.name));
      return;
    }
    if (node.nodeType === 'FunctionDefinition') {
      const r = loc.fromSrc(node.src) || {};
      const kind = node.kind || (node.isConstructor ? 'constructor' : node.name === '' ? 'fallback' : 'function');
      functions.push({
        contract: contract || null,
        name: kind === 'function' || kind === 'freeFunction' ? node.name : kind,
        kind,
        implemented: node.implemented !== false && !!node.body,
        visibility: node.visibility || null,
        stateMutability: node.stateMutability || null,
        modifiers: (node.modifiers || []).map(m => (m.modifierName && (m.modifierName.name || m.modifierName.namePath)) || null).filter(Boolean),
        line: r.line || null, endLine: r.endLine || null,
      });
      return;
    }
    if (node.nodeType === 'ModifierDefinition') {
      const r = loc.fromSrc(node.src) || {};
      modifiers.push({ contract: contract || null, name: node.name, line: r.line || null, endLine: r.endLine || null });
      return;
    }
    if (Array.isArray(node.nodes)) node.nodes.forEach(ch => walk(ch, contract));
  };
  walk(ast, null);
  const implemented = functions.filter(f => f.implemented).length;
  const codeContracts = contracts.filter(c => c.kind === 'contract' || c.kind === 'library').length;
  return {
    contracts, functions, modifiers,
    implementedFunctions: implemented,
    hasCode: codeContracts > 0 || functions.some(f => f.kind === 'freeFunction' && f.implemented),
  };
}

/* ------------------------------ compiler service ------------------------------ */

export function sanitizeFileName(name) {
  let f = String(name || 'Contract.sol').split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
  if (!/\.sol$/i.test(f)) f += '.sol';
  return f;
}

export function createCompilerService(opts = {}) {
  // Absolute, so require() of a cached build does not resolve relative to this module.
  const cacheDir = path.resolve(opts.cacheDir || '.solc-cache');
  const binUrl = String(opts.binariesUrl || DEFAULT_BINARIES_URL).replace(/\/+$/, '');
  const fetchImpl = opts.fetch || globalThis.fetch;
  const listTimeoutMs = opts.listTimeoutMs || 15000;
  const downloadTimeoutMs = opts.downloadTimeoutMs || 120000;
  const log = opts.log || console;
  const loaded = new Map();
  let bundled = null;
  let listCache = null;
  let listFailedAt = 0;

  function getBundled() {
    if (!bundled) {
      const solc = require('solc');
      const long = solc.version();
      bundled = { compiler: solc, version: semver.coerce(long).version, long };
    }
    return bundled;
  }

  function bundledVersion() {
    try { return JSON.parse(readFileSync(require.resolve('solc/package.json'), 'utf8')).version; } catch (e) { return null; }
  }

  async function ensureCacheDir() {
    await mkdir(cacheDir, { recursive: true });
    // soljson builds are CommonJS; this keeps Node from treating them as ES modules.
    const pj = path.join(cacheDir, 'package.json');
    if (!existsSync(pj)) await writeFile(pj, '{"type":"commonjs"}\n');
  }

  async function loadList() {
    if (listCache && Date.now() - listCache.at < 6 * 3600 * 1000) return listCache.data;
    const file = path.join(cacheDir, 'list.json');
    const readDiskCopy = async () => { try { return JSON.parse(await readFile(file, 'utf8')); } catch (e) { return null; } };
    // After a failed download, wait 5 minutes before trying the network again.
    if (listFailedAt && Date.now() - listFailedAt < 5 * 60 * 1000) return readDiskCopy();
    try {
      const r = await fetchImpl(binUrl + '/list.json', { signal: AbortSignal.timeout(listTimeoutMs) });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      if (!data || typeof data.releases !== 'object') throw new Error('unexpected list format');
      listCache = { at: Date.now(), data };
      await ensureCacheDir();
      await writeFile(file, JSON.stringify(data));
      return data;
    } catch (e) {
      listFailedAt = Date.now();
      log.warn && log.warn('[VULNEX] solc release list unavailable (' + e.message + '); using bundled or cached compilers only.');
      return readDiskCopy();
    }
  }

  function cachedBuilds() {
    try {
      return readdirSync(cacheDir)
        .map(f => /^soljson-v(\d+\.\d+\.\d+)\+commit\.[0-9a-f]+\.js$/.exec(f))
        .filter(Boolean)
        .map(m => ({ version: m[1], file: m[0] }));
    } catch (e) { return []; }
  }

  async function resolveVersion(source) {
    const pragmas = pragmaRanges(source);
    const b = bundledVersion() || getBundled().version;
    if (!pragmas.length) return { version: b, bundled: true, requested: null, note: 'No pragma solidity found, so the bundled solc ' + b + ' was used.' };
    const requested = pragmas.map(p => p.raw).join(' ');
    const ranges = pragmas.map(p => normalizeRange(p.raw));
    // An unparseable pragma is a source error: let solc report it with the bundled compiler.
    if (ranges.some(r => !r)) return { version: b, bundled: true, requested };
    const list = await loadList();
    if (list) {
      const best = pickVersion(ranges, Object.keys(list.releases));
      if (!best) return { error: 'no_matching_compiler', requested, pragmaIndex: pragmas[0].index };
      if (best === b) return { version: best, bundled: true, requested };
      const file = list.releases[best];
      const build = (list.builds || []).find(x => x.path === file) || {};
      return { version: best, bundled: false, requested, file, sha256: build.sha256 || null };
    }
    if (pickVersion(ranges, [b])) return { version: b, bundled: true, requested, note: 'The solc release list was unreachable; used the bundled solc ' + b + ', which satisfies the pragma.' };
    const cached = cachedBuilds();
    const best = pickVersion(ranges, cached.map(c => c.version));
    if (best) return { version: best, bundled: false, requested, file: cached.find(c => c.version === best).file, sha256: null };
    return { error: 'compiler_unavailable', requested };
  }

  async function loadCompiler(info) {
    if (info.bundled) return getBundled().compiler;
    if (loaded.has(info.file)) return loaded.get(info.file);
    const fp = path.join(cacheDir, info.file);
    if (!existsSync(fp)) {
      await ensureCacheDir();
      log.info && log.info('[VULNEX] downloading solc ' + info.version + ' …');
      const r = await fetchImpl(binUrl + '/' + info.file, { signal: AbortSignal.timeout(downloadTimeoutMs) });
      if (!r.ok) throw Object.assign(new Error('download failed with HTTP ' + r.status), { code: 'download_failed' });
      const buf = Buffer.from(await r.arrayBuffer());
      if (info.sha256) {
        const want = String(info.sha256).toLowerCase().replace(/^0x/, '');
        const got = createHash('sha256').update(buf).digest('hex');
        if (got !== want) throw Object.assign(new Error('checksum mismatch for ' + info.file), { code: 'integrity' });
      }
      const tmp = fp + '.part-' + process.pid;
      await writeFile(tmp, buf);
      await rename(tmp, fp);
    }
    const wrapper = require('solc/wrapper');
    const compiler = wrapper(require(fp));
    loaded.set(info.file, compiler);
    if (loaded.size > 3) loaded.delete(loaded.keys().next().value);
    return compiler;
  }

  // The exact solc could not be obtained. If the pragma asks for the bundled compiler's own
  // 0.x series, the bundled solc can still parse the file (pragma blanked, offsets kept), so
  // syntax errors are reported. Types are not checked, so a clean parse stays "unavailable".
  function syntaxFallback(source, file, loc, base) {
    const ranges = pragmaRanges(source).map(p => normalizeRange(p.raw));
    if (!ranges.length || ranges.some(r => !r)) return base;
    const b = getBundled();
    const lows = ranges.map(r => semver.minVersion(r)).filter(Boolean);
    if (!lows.length || lows.some(v => v.major !== semver.major(b.version) || v.minor !== semver.minor(b.version))) return base;
    const masked = maskCommentsAndStrings(source);
    let blanked = source; const re = /\bpragma\s+solidity\s+[^;]+;/g; let m;
    while ((m = re.exec(masked))) blanked = blanked.slice(0, m.index) + ' '.repeat(m[0].length) + blanked.slice(m.index + m[0].length);
    let out;
    try {
      const input = { language: 'Solidity', sources: { [file]: { content: blanked } }, settings: { stopAfter: 'parsing', outputSelection: { '*': { '': ['ast'] } } } };
      out = JSON.parse(b.compiler.compile(JSON.stringify(input), { import: () => ({ error: 'Imports are not available in the VULNEX workspace.' }) }));
    } catch (e) { return base; }
    const errors = (out.errors || []).map(e => toDiagnostic(e, loc, file)).filter(d => d.severity === 'error');
    const note = 'solc ' + (base.version || base.requested) + ' was not available, so the syntax was checked with the bundled solc ' + b.version + ' (parsing only, no type checking).';
    if (errors.length) return Object.assign({}, base, { status: 'failed', syntaxOnly: true, version: b.version, longVersion: b.long, bundled: true, errors: errors.slice(0, MAX_DIAGNOSTICS), notes: [note] });
    const ast = out.sources && out.sources[file] && out.sources[file].ast;
    return Object.assign({}, base, { syntax: { status: 'passed', version: b.version }, coverage: astCoverage(ast, source), notes: [note], reason: base.reason + ' The syntax was checked with the bundled solc ' + b.version + ' and has no errors, but types were not checked.' });
  }

  async function compileSource(source, fileName) {
    const t0 = Date.now();
    const file = sanitizeFileName(fileName);
    const done = r => Object.assign({ status: 'error', version: null, longVersion: null, requested: null, bundled: null, errors: [], warnings: [], notes: [], reason: null, coverage: null, fileName: file }, r, { durationMs: Date.now() - t0 });
    const loc = makeLocator(source);

    let info;
    try { info = await resolveVersion(source); }
    catch (e) { return done({ status: 'unavailable', reason: 'Could not choose a compiler version: ' + e.message }); }

    if (info.error === 'no_matching_compiler') {
      const ln = loc.lineOfChar(info.pragmaIndex);
      return done({ status: 'failed', requested: info.requested, errors: [{ severity: 'error', type: 'VersionError', code: null, message: 'No released Solidity compiler matches "pragma solidity ' + info.requested + '".', line: ln, column: 1, endLine: ln, formatted: '' }] });
    }
    if (info.error === 'compiler_unavailable') {
      return done(syntaxFallback(source, file, loc, { status: 'unavailable', requested: info.requested, reason: 'solc for "pragma solidity ' + info.requested + '" is not bundled and could not be downloaded. Connect to the internet once so VULNEX can download and cache it.' }));
    }

    let compiler;
    try { compiler = await loadCompiler(info); }
    catch (e) { return done(syntaxFallback(source, file, loc, { status: 'unavailable', requested: info.requested, version: info.version, reason: 'Could not load solc ' + info.version + ' (' + e.message + ').' })); }

    let out;
    try {
      const input = {
        language: 'Solidity',
        sources: { [file]: { content: source } },
        // ABI forces full semantic analysis (type checking) without generating bytecode.
        settings: { outputSelection: { '*': { '*': ['abi'], '': ['ast'] } } },
      };
      const importCallback = p => ({ error: 'Imports are not available in the VULNEX workspace ("' + p + '"). Paste one self-contained file.' });
      out = JSON.parse(compiler.compile(JSON.stringify(input), { import: importCallback }));
    } catch (e) {
      return done({ status: 'error', requested: info.requested, version: info.version, reason: 'The compiler stopped unexpectedly: ' + e.message });
    }

    const diags = (out.errors || []).map(e => toDiagnostic(e, loc, file));
    const errors = diags.filter(d => d.severity === 'error');
    const warnings = diags.filter(d => d.severity !== 'error');
    const longVersion = typeof compiler.version === 'function' ? compiler.version() : info.version;
    const res = {
      status: errors.length ? 'failed' : 'passed',
      version: (semver.coerce(longVersion) || {}).version || info.version,
      longVersion,
      requested: info.requested,
      bundled: !!info.bundled,
      errors: errors.slice(0, MAX_DIAGNOSTICS),
      warnings: warnings.slice(0, MAX_DIAGNOSTICS),
      notes: info.note ? [info.note] : [],
    };
    if (!errors.length) {
      const ast = out.sources && out.sources[file] && (out.sources[file].ast || out.sources[file].legacyAST);
      res.coverage = astCoverage(ast, source);
    }
    return done(res);
  }

  return { compileSource, resolveVersion, bundledVersion, cacheDir };
}
