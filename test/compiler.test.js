import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { createCompilerService, pickVersion, normalizeRange, pragmaRanges } from '../server/compiler.js';
import { fixture, tempDir, startSolcList } from './support/helpers.js';

const quiet = { info() {}, warn() {} };
let list, cache, svc;
before(async () => {
  list = await startSolcList();
  cache = tempDir('vulnex-solc-');
  svc = createCompilerService({ cacheDir: cache.dir, binariesUrl: list.base, log: quiet });
});
after(async () => { await list.close(); cache.cleanup(); });

test('valid contract compiles with a solc version that satisfies its pragma', async () => {
  const r = await svc.compileSource(fixture('VulnerableBank.sol'), 'VulnerableBank.sol');
  assert.equal(r.status, 'passed');
  assert.equal(r.version, '0.8.37');
  assert.equal(r.requested, '^0.8.19');
  assert.equal(r.errors.length, 0);
  assert.equal(r.coverage.hasCode, true);
  assert.equal(r.coverage.implementedFunctions, 8);
  assert.deepEqual(r.coverage.functions.filter(f => f.implemented).map(f => f.name), ['constructor', 'deposit', 'withdraw', 'setWithdrawFee', 'transferOwnership', 'payout', 'closeBank', 'bankBalance']);
});

test('malformed Solidity fails with the compiler diagnostic and its line number', async () => {
  const src = fixture('Malformed.sol');
  const r = await svc.compileSource(src, 'VulnerableBank.sol');
  assert.equal(r.status, 'failed');
  assert.equal(r.coverage, null);
  const e = r.errors[0];
  assert.equal(e.severity, 'error');
  assert.equal(e.type, 'ParserError');
  const badLine = src.split('\n').findIndex(l => l.includes('this is not solidity')) + 1;
  assert.equal(e.line, badLine);
  assert.ok(e.column >= 1);
});

test('type errors are reported, not ignored', async () => {
  const src = fixture('VulnerableBank.sol').replace('balances[msg.sender] += msg.value;', 'balances[msg.sender] += "x";');
  const r = await svc.compileSource(src, 'A.sol');
  assert.equal(r.status, 'failed');
  assert.equal(r.errors[0].type, 'TypeError');
  assert.equal(r.errors[0].line, src.split('\n').findIndex(l => l.includes('+= "x"')) + 1);
});

test('random text is a compilation failure', async () => {
  const r = await svc.compileSource('hello world\nthis is not a contract', 'A.sol');
  assert.equal(r.status, 'failed');
  assert.ok(r.errors.length >= 1);
});

test('interface-only files compile but have no code to analyze', async () => {
  const r = await svc.compileSource('pragma solidity ^0.8.0;\ninterface I { function f() external; }', 'I.sol');
  assert.equal(r.status, 'passed');
  assert.equal(r.coverage.hasCode, false);
});

test('imports are reported as a compilation error', async () => {
  const r = await svc.compileSource('pragma solidity ^0.8.0;\nimport "@openzeppelin/contracts/access/Ownable.sol";\ncontract A {}', 'A.sol');
  assert.equal(r.status, 'failed');
  assert.match(r.errors[0].message, /Imports are not available/);
});

test('a pragma no release satisfies is a compilation failure at the pragma line', async () => {
  const r = await svc.compileSource('// header\npragma solidity ^0.99.0;\ncontract A {}', 'A.sol');
  assert.equal(r.status, 'failed');
  assert.equal(r.errors[0].line, 2);
  assert.match(r.errors[0].message, /No released Solidity compiler/);
});

test('version selection follows the pragma and ignores pragmas in comments', () => {
  assert.equal(pickVersion([normalizeRange('^0.8.19')], ['0.8.19', '0.8.37', '0.9.0', '0.8.40-nightly.2026.1.1']), '0.8.37');
  assert.equal(pickVersion([normalizeRange('0.8.19')], ['0.8.19', '0.8.37']), '0.8.19');
  assert.equal(pickVersion([normalizeRange('>=0.6.0 <0.8.0')], ['0.6.12', '0.7.6', '0.8.37']), '0.7.6');
  assert.equal(pickVersion([normalizeRange('^0.8.0'), normalizeRange('<0.8.20')], ['0.8.19', '0.8.37']), '0.8.19');
  assert.deepEqual(pragmaRanges('// pragma solidity 0.4.0;\n/* pragma solidity 0.5.0; */\npragma solidity ^0.8.19;').map(p => p.raw), ['^0.8.19']);
});

test('without network, a pinned version that is not bundled is "unavailable", never "passed"', async () => {
  const c = tempDir('vulnex-solc-off-');
  try {
    const off = createCompilerService({ cacheDir: c.dir, binariesUrl: 'http://127.0.0.1:9', log: quiet, listTimeoutMs: 2000 });
    const pinned = await off.compileSource(fixture('VulnerableBank.sol').replace('^0.8.19', '0.8.19'), 'A.sol');
    assert.equal(pinned.status, 'unavailable');
    assert.match(pinned.reason, /could not be downloaded/);
    const floating = await off.compileSource(fixture('VulnerableBank.sol'), 'A.sol');
    assert.equal(floating.status, 'passed', 'the bundled solc satisfies ^0.8.19 offline');
  } finally { c.cleanup(); }
});

test('offline with a pinned 0.8.x pragma, the bundled solc still catches syntax errors', async () => {
  const c = tempDir('vulnex-solc-off2-');
  try {
    const off = createCompilerService({ cacheDir: c.dir, binariesUrl: 'http://127.0.0.1:9', log: quiet, listTimeoutMs: 2000 });
    const pin = s => s.replace('^0.8.19', '0.8.19');
    const bad = pin(fixture('Malformed.sol'));
    const r = await off.compileSource(bad, 'A.sol');
    assert.equal(r.status, 'failed');
    assert.equal(r.syntaxOnly, true);
    assert.equal(r.errors[0].type, 'ParserError');
    assert.equal(r.errors[0].line, bad.split('\n').findIndex(l => l.includes('this is not solidity')) + 1);
    const ok = await off.compileSource(pin(fixture('VulnerableBank.sol')), 'A.sol');
    assert.equal(ok.status, 'unavailable', 'a clean parse is not a passed compile');
    assert.equal(ok.syntax.status, 'passed');
    assert.equal(ok.coverage.implementedFunctions, 8);
    const old = await off.compileSource('pragma solidity 0.4.24;\ncontract A { function () payable {} }', 'A.sol');
    assert.equal(old.status, 'unavailable', 'other 0.x series are not parsed with the 0.8 compiler');
    assert.equal(old.syntax, undefined);
  } finally { c.cleanup(); }
});

test('a downloaded compiler is checked against its SHA-256 and then cached', async () => {
  const require = createRequire(import.meta.url);
  const bytes = readFileSync(require.resolve('solc/soljson.js'));
  const file = 'soljson-v0.8.38+commit.00000000.js';
  const good = await startSolcList({ '0.8.37': 'soljson-v0.8.37+commit.f401782d.js', '0.8.38': file }, { [file]: bytes }, [{ path: file, sha256: '0x' + createHash('sha256').update(bytes).digest('hex') }]);
  const c = tempDir('vulnex-solc-dl-');
  try {
    // A relative cache dir (as SOLC_CACHE_DIR may be) must work too.
    const s = createCompilerService({ cacheDir: path.relative(process.cwd(), c.dir), binariesUrl: good.base, log: quiet });
    const r = await s.compileSource('pragma solidity ^0.8.0;\ncontract A { function f() external pure returns (uint) { return 1; } }', 'A.sol');
    assert.equal(r.status, 'passed');
    assert.ok(existsSync(c.dir + '/' + file), 'downloaded build is cached');
    assert.equal(good.requests.filter(q => q.url === '/' + file).length, 1);
    await s.compileSource('pragma solidity ^0.8.0;\ncontract B {}', 'B.sol');
    assert.equal(good.requests.filter(q => q.url === '/' + file).length, 1, 'second compile uses the cache');
  } finally { await good.close(); c.cleanup(); }
});

test('a tampered compiler download is rejected and not cached', async () => {
  const file = 'soljson-v0.8.19+commit.7dd6d404.js';
  const bad = await startSolcList({ '0.8.19': file, '0.8.37': 'soljson-v0.8.37+commit.f401782d.js' }, { [file]: Buffer.from('module.exports = "not a compiler";') }, [{ path: file, sha256: '0x' + '11'.repeat(32) }]);
  const c = tempDir('vulnex-solc-bad-');
  try {
    const s = createCompilerService({ cacheDir: c.dir, binariesUrl: bad.base, log: quiet });
    const r = await s.compileSource(fixture('VulnerableBank.sol').replace('^0.8.19', '0.8.19'), 'A.sol');
    assert.equal(r.status, 'unavailable');
    assert.match(r.reason, /checksum mismatch/);
    assert.equal(readdirSync(c.dir).filter(f => f.startsWith('soljson')).length, 0);
  } finally { await bad.close(); c.cleanup(); }
});
