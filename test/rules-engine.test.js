// The deterministic rule engine on deliberately vulnerable and safe contracts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPageLogic, fixture, plain } from './support/helpers.js';

const P = loadPageLogic();
const rulesOf = src => plain(P.analyze(src).findings.map(f => f.rule + '@' + (f.fn || 'file')).sort());

test('VulnerableBank: every planted vulnerability is found', () => {
  assert.deepEqual(rulesOf(fixture('VulnerableBank.sol')), [
    'floating-pragma@file', 'reentrancy-eth@withdraw', 'tx-origin@transferOwnership',
    'unchecked-lowlevel@payout', 'unprotected-selfdestruct@closeBank', 'unprotected-setter@setWithdrawFee',
  ]);
});

test('SafeVault: no rule findings', () => {
  assert.deepEqual(rulesOf(fixture('SafeVault.sol')), []);
});

test('Reentrancy: state written after the external call is flagged', () => {
  assert.deepEqual(rulesOf(fixture('Reentrancy.sol')), ['reentrancy-eth@withdraw']);
});

test('MissingAccessControl: unprotected owner change, setter and withdrawal are flagged', () => {
  assert.deepEqual(rulesOf(fixture('MissingAccessControl.sol')), ['unprotected-owner-change@setOwner', 'unprotected-setter@setLimit', 'unprotected-withdrawal@sweep']);
});

test('applying every automatic fix leaves no rule findings', () => {
  const fixed = P.applyAllFixes(fixture('VulnerableBank.sol'));
  assert.equal(fixed.applied, 6);
  assert.deepEqual(rulesOf(fixed.source), []);
});

test('the rule engine alone cannot tell broken code from clean code (why the compiler gate exists)', () => {
  // The reported bug: the fixed contract plus a line of garbage. The regex rules see nothing wrong,
  // so before the fix this scored 100/100. The compiler now rejects it before any score is given.
  const broken = P.applyAllFixes(fixture('VulnerableBank.sol')).source.replace('function deposit()', 'this is not solidity !!!\n    function deposit()');
  assert.deepEqual(rulesOf(broken), []);
});
