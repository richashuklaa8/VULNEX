// VULNEX local server.
//
// Serves the app at http://localhost:5173 and does three small jobs:
//   GET  /config.js   public settings for the page (registry address, AI on/off). Never the API key.
//   POST /api/rpc     forwards read-only Sepolia JSON-RPC calls to SEPOLIA_RPC_URL.
//   POST /api/ai      sends AI fix prompts to OpenRouter with the key from .env.
//
// It only listens on 127.0.0.1, so nothing outside this computer can reach it.
// No wallet keys or seed phrases are used anywhere; MetaMask signs in the browser.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENV_FILE = path.join(ROOT, '.env');

function parseEnv(text) {
  const out = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
    else val = val.replace(/\s+#.*$/, '');
    out[key] = val;
  }
  return out;
}

// .env is re-read on every request, so editing it only needs a page reload.
function settings() {
  let file = {};
  try { file = parseEnv(readFileSync(ENV_FILE, 'utf8')); } catch (e) { /* no .env yet */ }
  const get = k => String(file[k] ?? process.env[k] ?? '').trim();
  const groqKey = get('GROQ_API_KEY');
  const openRouterKey = get('OPENROUTER_API_KEY');
  const provider = (get('AI_PROVIDER') || (groqKey ? 'groq' : 'openrouter')).toLowerCase();
  const isGroq = provider === 'groq';

  return {
    registry: get('AUDIT_REGISTRY_ADDRESS') || get('VITE_AUDIT_REGISTRY_ADDRESS'),
    rpcUrl: get('SEPOLIA_RPC_URL') || 'https://ethereum-sepolia-rpc.publicnode.com',
    provider: isGroq ? 'groq' : 'openrouter',
    aiKey: isGroq ? groqKey : openRouterKey,
    aiModel: isGroq ? (get('GROQ_MODEL') || 'openai/gpt-oss-120b') : (get('OPENROUTER_MODEL') || 'anthropic/claude-sonnet-5.5'),
    aiBase: isGroq
      ? (get('GROQ_BASE_URL') || 'https://api.groq.com/openai/v1').replace(/\/+$/, '')
      : (get('OPENROUTER_BASE_URL') || 'https://openrouter.ai/api/v1').replace(/\/+$/, ''),
  };
}

const startEnv = (() => { try { return parseEnv(readFileSync(ENV_FILE, 'utf8')); } catch (e) { return {}; } })();
const PORT = Number(process.env.PORT || startEnv.PORT || 5173);
const HOST = '127.0.0.1';

const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/src/blockchain.js': ['src/blockchain.js', 'text/javascript; charset=utf-8'],
  '/vendor/ethers.min.js': ['node_modules/ethers/dist/ethers.min.js', 'text/javascript; charset=utf-8'],
  '/vendor/qrious.min.js': ['node_modules/qrious/dist/qrious.min.js', 'text/javascript; charset=utf-8'],
  '/contracts/AuditRegistry.json': ['contracts/AuditRegistry.json', 'application/json; charset=utf-8'],
  '/contracts/AuditRegistry.sol': ['contracts/AuditRegistry.sol', 'text/plain; charset=utf-8'],
  '/samples/VulnerableBank.sol': ['samples/VulnerableBank.sol', 'text/plain; charset=utf-8'],
};

const READ_METHODS = new Set([
  'eth_chainId', 'net_version', 'eth_blockNumber', 'eth_call', 'eth_getCode', 'eth_getLogs',
  'eth_getBlockByNumber', 'eth_getBlockByHash', 'eth_getTransactionByHash', 'eth_getTransactionReceipt',
  'eth_getBalance', 'eth_gasPrice', 'eth_feeHistory', 'eth_maxPriorityFeePerGas',
]);

const AI_STATUS = { 400: 'invalid_request', 401: 'bad_key', 402: 'no_credits', 403: 'bad_key', 404: 'bad_model', 408: 'upstream_error', 413: 'prompt_too_large', 429: 'rate_limited' };

function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra });
  res.end(data);
}

// Only this machine's own pages may call the API (blocks other websites and DNS rebinding).
function localRequest(req) {
  const okHost = h => new RegExp('^(localhost|127\\.0\\.0\\.1|\\[::1\\]):' + PORT + '$').test(h || '');
  if (!okHost(req.headers.host)) return false;
  const origin = req.headers.origin;
  if (origin && !okHost(origin.replace(/^https?:\/\//, ''))) return false;
  return true;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function handleRpc(req, res) {
  const s = settings();
  let payload;
  try { payload = JSON.parse(await readBody(req, 64 * 1024)); } catch (e) { return send(res, 400, { error: 'invalid json' }); }
  const calls = Array.isArray(payload) ? payload : [payload];
  if (!calls.length || calls.length > 20 || calls.some(c => !c || !READ_METHODS.has(c.method))) {
    return send(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32601, message: 'Only read-only methods are allowed here.' } });
  }
  try {
    const r = await fetch(s.rpcUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(20000) });
    send(res, r.status, await r.text());
  } catch (e) {
    send(res, 502, { jsonrpc: '2.0', id: calls[0].id ?? null, error: { code: -32000, message: 'Could not reach SEPOLIA_RPC_URL.' } });
  }
}

async function handleAi(req, res) {
  const s = settings();
  if (!s.aiKey) return send(res, 503, { code: 'ai_disabled' });
  if (!/^application\/json/i.test(req.headers['content-type'] || '')) return send(res, 415, { code: 'invalid_request' });
  let body;
  try { body = JSON.parse(await readBody(req, 256 * 1024)); } catch (e) { return send(res, e.status || 400, { code: e.status === 413 ? 'prompt_too_large' : 'invalid_request' }); }
  const prompt = String(body.prompt || '');
  if (!prompt.trim()) return send(res, 400, { code: 'invalid_request' });
  if (prompt.length > 120000) return send(res, 413, { code: 'prompt_too_large' });
  const wantJson = !!body.json;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 120000);
  res.on('close', () => { if (!res.writableFinished) ctl.abort(); });
  try {
    const headers = {
      'Authorization': 'Bearer ' + s.aiKey,
      'Content-Type': 'application/json',
    };
    if (s.provider !== 'groq') {
      headers['HTTP-Referer'] = 'http://localhost:' + PORT;
      headers['X-Title'] = 'VULNEX';
    }
    const r = await fetch(s.aiBase + '/chat/completions', {
      method: 'POST',
      signal: ctl.signal,
      headers,
      body: JSON.stringify({
        model: s.aiModel,
        temperature: 0.2,
        max_tokens: 1800,
        messages: [
          { role: 'system', content: 'You are a careful smart contract security reviewer helping a developer fix Solidity code.' + (wantJson ? ' Reply with exactly one valid JSON object and nothing else: no prose and no Markdown code fences.' : '') },
          { role: 'user', content: prompt },
        ],
      }),
    });
    const data = await r.json().catch(() => null);
    if (!r.ok || !data || data.error) {
      const status = r.ok ? (data?.error?.code || 502) : r.status;
      const msg = String(data?.error?.message || '');
      let code = AI_STATUS[status] || 'upstream_error';
      if (code === 'invalid_request' && /context|too long|maximum.*tokens/i.test(msg)) code = 'prompt_too_large';
      console.warn('[VULNEX] ' + (s.provider === 'groq' ? 'Groq' : 'OpenRouter') + ' error', status, msg.slice(0, 200));
      return send(res, 502, { code });
    }
    const choice = data.choices && data.choices[0];
    let text = choice?.message?.content;
    if (Array.isArray(text)) text = text.map(p => (typeof p === 'string' ? p : p?.text || '')).join('');
    text = String(text || '');
    if (!text.trim()) return send(res, 502, { code: 'empty_completion' });
    send(res, 200, { text, model: data.model || s.aiModel, provider: s.provider, truncated: choice?.finish_reason === 'length' });
  } catch (e) {
    if (ctl.signal.aborted && res.writableEnded) return;
    console.warn('[VULNEX] ' + (s.provider === 'groq' ? 'Groq' : 'OpenRouter') + ' request failed:', e.message);
    send(res, 502, { code: 'upstream_error' });
  } finally {
    clearTimeout(timer);
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (!localRequest(req)) return send(res, 403, { error: 'forbidden' });

    if (url.pathname === '/config.js' && (req.method === 'GET' || req.method === 'HEAD')) {
      const s = settings();
      const cfg = { registryAddress: s.registry, chainId: 11155111, ai: !!s.aiKey, aiProvider: s.provider, aiModel: s.aiKey ? s.aiModel : null };
      return send(res, 200, 'window.VULNEX_CONFIG = ' + JSON.stringify(cfg).replace(/</g, '\\u003c') + ';\n', 'text/javascript; charset=utf-8');
    }
    if (url.pathname === '/api/rpc' && req.method === 'POST') return handleRpc(req, res);
    if (url.pathname === '/api/ai' && req.method === 'POST') return handleAi(req, res);
    if (url.pathname === '/api/health') {
      const s = settings();
      return send(res, 200, { ok: true, registry: s.registry || null, ai: !!s.aiKey, provider: s.provider, model: s.aiKey ? s.aiModel : null });
    }

    if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
    const entry = FILES[url.pathname];
    if (!entry || (req.method !== 'GET' && req.method !== 'HEAD')) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    const file = path.join(ROOT, entry[0]);
    if (!existsSync(file)) {
      const hint = entry[0].startsWith('node_modules') ? 'Run npm install first.' : 'File missing: ' + entry[0];
      return send(res, 500, hint, 'text/plain; charset=utf-8');
    }
    const data = await readFile(file);
    send(res, 200, req.method === 'HEAD' ? '' : data, entry[1]);
  } catch (e) {
    console.error('[VULNEX] request failed', e);
    if (!res.headersSent) send(res, 500, { error: 'server error' });
  }
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error('\nPort ' + PORT + ' is already in use. Close the other app, or add PORT=5174 to .env and run again.\n');
  else console.error(e);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  const s = settings();
  const ethersOk = existsSync(path.join(ROOT, 'node_modules/ethers/dist/ethers.min.js'));
  console.log('\n  VULNEX is running at http://localhost:' + PORT + '\n');
  console.log('  AuditRegistry : ' + (s.registry || 'not set yet (deploy it from the Report page, then paste the address into .env)'));
  console.log('  Sepolia reads : ' + s.rpcUrl);
  console.log('  AI review/fix : ' + (s.aiKey ? 'on (' + s.aiModel + ' via ' + (s.provider === 'groq' ? 'Groq' : 'OpenRouter') + ')' : 'off (add GROQ_API_KEY or OPENROUTER_API_KEY to .env)'));
  if (!ethersOk) console.log('\n  ethers is missing. Run npm install, then npm start again.');
  console.log('\n  Press Ctrl+C to stop.\n');
});
