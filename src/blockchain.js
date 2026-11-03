// VULNEX · MetaMask + Ethereum Sepolia integration (ethers v6).
//
// What this module does:
//   - connects to MetaMask (never asks for or stores keys or seed phrases),
//   - checks that MetaMask is on Sepolia and offers a switch the user confirms,
//   - sends attest(reportHash, contractHash) to the AuditRegistry contract,
//   - reads verify(reportHash) back from Sepolia for verification,
//   - can deploy AuditRegistry through MetaMask if no address is configured.
//
// Every transaction is signed in MetaMask after the user confirms it.
// The page talks to this module through window.VulnexChain.

import {
  BrowserProvider, JsonRpcProvider, Contract, ContractFactory, getAddress,
} from 'ethers';

const CFG = window.VULNEX_CONFIG || {};

export const SEPOLIA_CHAIN_ID = 11155111;
const SEPOLIA_HEX = '0xaa36a7';
export const EXPLORER = 'https://sepolia.etherscan.io';
// Public Sepolia RPC MetaMask may use if it has to add the network (it normally knows Sepolia already).
const PUBLIC_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';
// Read-only calls go through the local server, which forwards them to SEPOLIA_RPC_URL from .env.
const READ_RPC = location.origin + '/api/rpc';
const LS_REGISTRY = 'vulnex-registry-address';

// Matches contracts/AuditRegistry.sol.
export const ABI = [
  'function attest(bytes32 reportHash, bytes32 contractHash)',
  'function verify(bytes32 reportHash) view returns (bytes32, bytes32, address, uint256, uint256)',
  'function attestations(bytes32) view returns (bytes32 reportHash, bytes32 contractHash, address auditor, uint256 timestamp, uint256 blockNumber)',
  'event Attested(bytes32 indexed reportHash, bytes32 indexed contractHash, address indexed auditor)',
];

/* ------------------------------------------------------------------ */
/* Friendly errors: the page shows title + detail, never raw errors.   */
/* ------------------------------------------------------------------ */
const MESSAGES = {
  no_wallet:       ['MetaMask is not installed.', 'Please install MetaMask to attest this audit.'],
  connect_rejected:['Connection request rejected.', 'Connect MetaMask to attest this audit. Nothing was shared.'],
  request_pending: ['MetaMask is waiting for you.', 'Open the MetaMask extension and finish the request that is already open.'],
  wrong_network:   ['Please switch MetaMask to Sepolia.', 'Attestations are recorded on the Ethereum Sepolia testnet (chain ID 11155111).'],
  switch_rejected: ['Network switch cancelled.', 'MetaMask is still on another network. Switch to Sepolia to continue.'],
  no_address:      ['No AuditRegistry contract is configured.', 'Paste your deployed contract address into .env as AUDIT_REGISTRY_ADDRESS and reload the page, or deploy one below.'],
  bad_address:     ['The AuditRegistry address is not valid.', 'Check AUDIT_REGISTRY_ADDRESS in .env. It must be 0x followed by 40 hex characters.'],
  no_contract:     ['No AuditRegistry contract at this address on Sepolia.', 'Nothing is deployed there. A wallet address will not work; use the address of the deployed AuditRegistry contract.'],
  no_funds:        ['Not enough Sepolia ETH.', 'Your wallet needs a little Sepolia test ETH to pay for gas. Get some free from a faucet, then try again.'],
  tx_rejected:     ['Transaction rejected.', 'No changes were made to the blockchain.'],
  tx_cancelled:    ['Transaction cancelled in MetaMask.', 'No attestation was recorded.'],
  reverted:        ['Transaction reverted.', 'The contract did not record the attestation. No hashes were stored.'],
  call_failed:     ['The contract call failed.', 'The registry contract rejected the call. Check that the address points to an AuditRegistry contract.'],
  pending:         ['Transaction still pending.', 'It was sent to Sepolia but is not confirmed yet. Check its status again in a moment.'],
  network:         ['Could not reach Sepolia.', 'Check your internet connection and try again.'],
  bad_input:       ['This report cannot be attested.', 'The report or contract hash is missing. Generate the report again.'],
  unknown:         ['Something went wrong.', 'Try again. If it keeps failing, the browser console has technical details.'],
};

export class ChainError extends Error {
  constructor(code, extra = {}) {
    const [title, detail] = MESSAGES[code] || MESSAGES.unknown;
    super(title);
    this.name = 'ChainError';
    this.code = MESSAGES[code] ? code : 'unknown';
    this.title = title;
    this.detail = detail;
    Object.assign(this, extra);
  }
}

function rpcCode(err) {
  for (const e of [err, err?.error, err?.info?.error, err?.data?.originalError, err?.error?.data?.originalError]) {
    if (e && typeof e.code === 'number') return e.code;
  }
  return null;
}

function friendly(err, phase) {
  if (err instanceof ChainError) return err;
  const code = err?.code;
  const rpc = rpcCode(err);
  const msg = String(err?.shortMessage || err?.message || '').toLowerCase();
  if (code === 'ACTION_REJECTED' || rpc === 4001 || /user (rejected|denied)/.test(msg)) {
    return new ChainError(phase === 'connect' ? 'connect_rejected' : phase === 'switch' ? 'switch_rejected' : 'tx_rejected');
  }
  if (rpc === -32002) return new ChainError('request_pending');
  if (code === 'INSUFFICIENT_FUNDS' || /insufficient funds/.test(msg)) return new ChainError('no_funds');
  if (code === 'CALL_EXCEPTION') return new ChainError(phase === 'wait' ? 'reverted' : 'call_failed');
  if (['NETWORK_ERROR', 'TIMEOUT', 'SERVER_ERROR'].includes(code) || /failed to fetch|network|timeout/.test(msg)) {
    return new ChainError('network');
  }
  console.error('[VULNEX] blockchain error during ' + phase + ':', err);
  return new ChainError('unknown');
}

/* ------------------------------------------------------------------ */
/* Wallet + configuration state                                        */
/* ------------------------------------------------------------------ */
let discoveredProvider = null;

if (typeof window !== 'undefined') {
  window.addEventListener('eip6963:announceProvider', event => {
    if (event.detail && event.detail.provider) {
      const info = event.detail.info || {};
      if (info.name && info.name.toLowerCase().includes('metamask')) {
        discoveredProvider = event.detail.provider;
      } else if (!discoveredProvider) {
        discoveredProvider = event.detail.provider;
      }
      init();
    }
  });
  try { window.dispatchEvent(new Event('eip6963:requestProvider')); } catch (e) {}

  window.addEventListener('ethereum#initialized', () => {
    init();
  }, { once: true });
}

function wallet() {
  if (discoveredProvider) return discoveredProvider;
  if (typeof window === 'undefined') return null;
  const e = window.ethereum;
  if (!e) return null;
  if (Array.isArray(e.providers) && e.providers.length) {
    return e.providers.find(p => p.isMetaMask) || e.providers[0];
  }
  return e;
}

function normalizeAddress(raw) {
  const s = String(raw || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return null;
  return getAddress(s.toLowerCase());
}

function registryInfo() {
  const fromEnv = String(CFG.registryAddress || '').trim();
  if (fromEnv) {
    const a = normalizeAddress(fromEnv);
    return a ? { address: a, source: 'env' } : { address: null, source: 'env', error: 'bad_address' };
  }
  let saved = null;
  try { saved = localStorage.getItem(LS_REGISTRY); } catch (e) { /* storage blocked */ }
  const a = normalizeAddress(saved);
  if (a) return { address: a, source: 'browser' };
  return { address: null, source: null, error: 'no_address' };
}

function requireRegistry() {
  const r = registryInfo();
  if (!r.address) throw new ChainError(r.error || 'no_address');
  return r.address;
}

const isBytes32 = h => typeof h === 'string' && /^0x[0-9a-fA-F]{64}$/.test(h);
const live = { account: null, chainId: null };
const subscribers = new Set();

export function getStatus() {
  const r = registryInfo();
  const w = wallet();
  return {
    ready: true,
    installed: !!w,
    account: live.account,
    chainId: live.chainId,
    onSepolia: live.chainId === SEPOLIA_CHAIN_ID,
    registry: r.address,
    registrySource: r.source,
    registryError: r.error || null,
  };
}

function emit() {
  const s = getStatus();
  subscribers.forEach(fn => { try { fn(s); } catch (e) { console.error(e); } });
  window.dispatchEvent(new CustomEvent('vulnex-chain', { detail: s }));
}

export function onChange(fn) { subscribers.add(fn); return () => subscribers.delete(fn); }

let listeningOn = null;
export async function init() {
  const e = wallet();
  if (!e) { emit(); return; }
  try {
    const acc = await e.request({ method: 'eth_accounts' });
    live.account = acc && acc[0] ? getAddress(acc[0]) : null;
  } catch (err) { /* locked or not approved */ }
  try {
    const cid = await e.request({ method: 'eth_chainId' });
    live.chainId = parseInt(cid, 16);
  } catch (err) { /* unknown */ }
  if (typeof e.on === 'function' && listeningOn !== e) {
    listeningOn = e;
    e.on('accountsChanged', acc => { live.account = acc && acc[0] ? getAddress(acc[0]) : null; emit(); });
    e.on('chainChanged', id => { live.chainId = parseInt(id, 16); emit(); });
  }
  emit();
}

// Check repeatedly in case MetaMask was injected after script load
if (typeof window !== 'undefined') {
  [50, 150, 300, 600, 1200, 2500, 5000].forEach(ms => {
    setTimeout(() => {
      if (wallet()) init();
    }, ms);
  });
}

/* ------------------------------------------------------------------ */
/* Connect + network                                                   */
/* ------------------------------------------------------------------ */
export async function connect() {
  const e = wallet();
  if (!e) throw new ChainError('no_wallet');
  try {
    const provider = new BrowserProvider(e);
    const accounts = await provider.send('eth_requestAccounts', []);
    live.account = accounts && accounts[0] ? getAddress(accounts[0]) : null;
    live.chainId = Number((await provider.getNetwork()).chainId);
  } catch (err) {
    throw friendly(err, 'connect');
  }
  emit();
  if (!live.account) throw new ChainError('connect_rejected');
  return getStatus();
}

// Asks MetaMask to switch; MetaMask shows its own confirmation. Never switches silently.
export async function switchToSepolia() {
  const e = wallet();
  if (!e) throw new ChainError('no_wallet');
  try {
    await e.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: SEPOLIA_HEX }] });
  } catch (err) {
    if (rpcCode(err) === 4902) {
      try {
        await e.request({
          method: 'wallet_addEthereumChain',
          params: [{
            chainId: SEPOLIA_HEX, chainName: 'Sepolia',
            nativeCurrency: { name: 'Sepolia Ether', symbol: 'SepoliaETH', decimals: 18 },
            rpcUrls: [PUBLIC_RPC], blockExplorerUrls: [EXPLORER],
          }],
        });
      } catch (err2) { throw friendly(err2, 'switch'); }
    } else {
      throw friendly(err, 'switch');
    }
  }
  try { live.chainId = parseInt(await e.request({ method: 'eth_chainId' }), 16); } catch (err) { /* keep last */ }
  emit();
  if (live.chainId !== SEPOLIA_CHAIN_ID) throw new ChainError('wrong_network');
  return getStatus();
}

async function sepoliaWallet() {
  const e = wallet();
  if (!e) throw new ChainError('no_wallet');
  await connect();
  const provider = new BrowserProvider(e);
  let chainId;
  try { chainId = Number((await provider.getNetwork()).chainId); } catch (err) { throw friendly(err, 'read'); }
  live.chainId = chainId; emit();
  if (chainId !== SEPOLIA_CHAIN_ID) throw new ChainError('wrong_network');
  return provider;
}

async function readProvider() {
  const e = wallet();
  if (e) {
    try {
      const id = parseInt(await e.request({ method: 'eth_chainId' }), 16);
      if (id === SEPOLIA_CHAIN_ID) return { provider: new BrowserProvider(e), via: 'MetaMask' };
    } catch (err) { /* fall back to the local RPC proxy */ }
  }
  return {
    provider: new JsonRpcProvider(READ_RPC, SEPOLIA_CHAIN_ID, { staticNetwork: true, batchMaxCount: 1 }),
    via: 'Sepolia RPC',
  };
}

/* ------------------------------------------------------------------ */
/* Attest                                                              */
/* ------------------------------------------------------------------ */
// on.step(name, data) is called with: 'connect', 'network', 'sign', 'pending'.
export async function attest(reportHash, contractHash, on = {}) {
  const step = (k, d) => { try { on.step && on.step(k, d || {}); } catch (e) { console.error(e); } };
  if (!isBytes32(reportHash) || !isBytes32(contractHash)) throw new ChainError('bad_input');
  if (!wallet()) throw new ChainError('no_wallet');
  const registry = requireRegistry();

  step('connect');
  const provider = await sepoliaWallet();
  const account = live.account;
  step('network', { account });

  let code;
  try { code = await provider.getCode(registry); } catch (err) { throw friendly(err, 'read'); }
  if (!code || code === '0x') throw new ChainError('no_contract', { registry });

  const signer = await provider.getSigner(account);
  const contract = new Contract(registry, ABI, signer);

  // Check gas money before MetaMask opens, so the user gets a clear message.
  try {
    const [balance, gas, fee] = await Promise.all([
      provider.getBalance(account),
      contract.attest.estimateGas(reportHash, contractHash),
      provider.getFeeData(),
    ]);
    const price = fee.maxFeePerGas ?? fee.gasPrice ?? 0n;
    if (balance === 0n || (price > 0n && balance < gas * price)) throw new ChainError('no_funds', { account });
  } catch (err) {
    throw friendly(err, 'estimate');
  }

  step('sign', { account, registry });
  let tx;
  try { tx = await contract.attest(reportHash, contractHash); } catch (err) { throw friendly(err, 'send'); }
  step('pending', { txHash: tx.hash, url: txUrl(tx.hash) });
  return finish(provider, tx.hash, tx, registry);
}

async function finish(provider, hash, tx, registry) {
  let receipt;
  try {
    receipt = tx ? await tx.wait(1) : await provider.waitForTransaction(hash, 1, 90000);
  } catch (err) {
    if (err?.code === 'TRANSACTION_REPLACED') {
      // "Speed up" in MetaMask replaces the tx with a new one; "Cancel" drops it.
      if (!err.cancelled && err.receipt) { receipt = err.receipt; hash = err.replacement?.hash || err.receipt.hash; }
      else throw new ChainError('tx_cancelled', { txHash: hash });
    } else if (err?.code === 'CALL_EXCEPTION') {
      throw new ChainError('reverted', { txHash: hash });
    } else {
      const fe = friendly(err, 'wait');
      if (fe.code === 'network' || fe.code === 'unknown') throw new ChainError('pending', { txHash: hash, registry });
      throw fe;
    }
  }
  if (!receipt) throw new ChainError('pending', { txHash: hash, registry });
  if (receipt.status !== 1) throw new ChainError('reverted', { txHash: hash });
  let timestamp = Date.now();
  try { const b = await provider.getBlock(receipt.blockNumber); if (b) timestamp = b.timestamp * 1000; } catch (e) { /* use local time */ }
  let input = tx ? tx.data : null;
  if (!input) { try { const t = await provider.getTransaction(hash); input = t ? t.data : null; } catch (e) { /* optional */ } }
  return {
    txHash: receipt.hash || hash,
    blockNumber: receipt.blockNumber,
    timestamp,
    auditor: getAddress(receipt.from),
    registry,
    chainId: SEPOLIA_CHAIN_ID,
    gasUsed: receipt.gasUsed != null ? receipt.gasUsed.toString() : null,
    input,
  };
}

// Re-check a transaction that was sent but not confirmed while the page was waiting.
export async function checkTransaction(hash, registry) {
  if (!isBytes32(hash)) throw new ChainError('bad_input');
  const { provider } = await readProvider();
  return finish(provider, hash, null, registry || requireRegistry());
}

/* ------------------------------------------------------------------ */
/* Verify (read-only, no MetaMask popup)                               */
/* ------------------------------------------------------------------ */
export async function readAttestation(reportHash) {
  if (!isBytes32(reportHash)) throw new ChainError('bad_input');
  const registry = requireRegistry();
  const { provider, via } = await readProvider();
  try {
    const code = await provider.getCode(registry);
    if (!code || code === '0x') throw new ChainError('no_contract', { registry });
    const c = new Contract(registry, ABI, provider);
    const [rh, ch, auditor, ts, bn] = await c.verify(reportHash);
    const found = ts > 0n;
    let txHash = null;
    if (found) {
      try {
        const logs = await c.queryFilter(c.filters.Attested(reportHash), Number(bn), Number(bn));
        if (logs.length) txHash = logs[logs.length - 1].transactionHash;
      } catch (e) { /* the transaction link is optional */ }
    }
    return {
      found,
      reportHash: found ? rh.toLowerCase() : null,
      contractHash: found ? ch.toLowerCase() : null,
      auditor: found ? getAddress(auditor) : null,
      timestamp: found ? Number(ts) * 1000 : null,
      blockNumber: found ? Number(bn) : null,
      txHash,
      registry,
      via,
    };
  } catch (err) {
    throw friendly(err, 'read');
  }
}

/* ------------------------------------------------------------------ */
/* Optional: deploy AuditRegistry through MetaMask                     */
/* ------------------------------------------------------------------ */
export async function deployRegistry(on = {}) {
  const step = (k, d) => { try { on.step && on.step(k, d || {}); } catch (e) { console.error(e); } };
  step('connect');
  const provider = await sepoliaWallet();
  const account = live.account;
  let artifact;
  try {
    const r = await fetch('/contracts/AuditRegistry.json', { cache: 'no-store' });
    artifact = await r.json();
  } catch (err) { throw new ChainError('network'); }
  try {
    const balance = await provider.getBalance(account);
    if (balance === 0n) throw new ChainError('no_funds', { account });
  } catch (err) { throw friendly(err, 'read'); }
  const signer = await provider.getSigner(account);
  const factory = new ContractFactory(artifact.abi, artifact.bytecode, signer);
  step('sign', { account });
  let contract;
  try { contract = await factory.deploy(); } catch (err) { throw friendly(err, 'send'); }
  const tx = contract.deploymentTransaction();
  step('pending', { txHash: tx.hash, url: txUrl(tx.hash) });
  let receipt;
  try { receipt = await tx.wait(1); } catch (err) { throw friendly(err, 'wait'); }
  if (!receipt || receipt.status !== 1 || !receipt.contractAddress) throw new ChainError('reverted', { txHash: tx.hash });
  const address = getAddress(receipt.contractAddress);
  try { localStorage.setItem(LS_REGISTRY, address); } catch (e) { /* storage blocked */ }
  emit();
  return { address, txHash: tx.hash, blockNumber: receipt.blockNumber };
}

/* ------------------------------------------------------------------ */
/* Links + formatting                                                  */
/* ------------------------------------------------------------------ */
export const txUrl = h => EXPLORER + '/tx/' + h;
export const addressUrl = a => EXPLORER + '/address/' + a;
export const blockUrl = n => EXPLORER + '/block/' + n;
export const shortAddr = a => (a ? a.slice(0, 6) + '…' + a.slice(-4) : '');

window.VulnexChain = Object.freeze({
  SEPOLIA_CHAIN_ID, EXPLORER, ABI,
  getStatus, onChange, connect, switchToSepolia,
  attest, checkTransaction, readAttestation, deployRegistry,
  txUrl, addressUrl, blockUrl, shortAddr,
});

init().catch(err => console.error('[VULNEX] wallet init failed', err))
  .finally(() => window.dispatchEvent(new Event('vulnex-chain-ready')));
