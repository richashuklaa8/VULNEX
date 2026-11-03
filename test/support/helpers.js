// Shared test helpers: load the page's scan logic in a sandbox, serve fake OpenRouter and
// solc release endpoints on localhost, and read fixtures. No test touches the internet.
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import http from 'node:http';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const fixture = name => readFileSync(path.join(ROOT, 'test/fixtures', name), 'utf8');
export const plain = x => JSON.parse(JSON.stringify(x));

// The same files the browser loads: src/rules-engine.js then src/scan-core.js.
export function loadPageLogic() {
  const code = ['src/rules-engine.js', 'src/scan-core.js'].map(f => readFileSync(path.join(ROOT, f), 'utf8')).join('\n;\n');
  const ctx = vm.createContext({ TextEncoder, console });
  return vm.runInContext(code + '\n;({ analyze, applyAllFixes, sha256, canonical, buildReport, countSev, scoreOf, RULES, ScanCore })', ctx);
}

export function tempDir(prefix) {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export async function startServer(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', async () => {
      let parsed = null; try { parsed = body ? JSON.parse(body) : null; } catch (e) { parsed = body; }
      const rec = { method: req.method, url: req.url, headers: req.headers, body: parsed };
      requests.push(rec);
      const send = (status, payload, delayMs) => {
        const go = () => {
          if (res.destroyed || res.writableEnded) return;
          const isBuf = Buffer.isBuffer(payload);
          res.writeHead(status, { 'content-type': isBuf ? 'application/octet-stream' : 'application/json' });
          res.end(isBuf || typeof payload === 'string' ? payload : JSON.stringify(payload));
        };
        if (delayMs) setTimeout(go, delayMs); else go();
      };
      try { await handler(rec, send, requests); } catch (e) { send(500, { error: { message: String(e) } }); }
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return {
    base: 'http://127.0.0.1:' + server.address().port,
    requests,
    close: () => new Promise(r => { if (server.closeAllConnections) server.closeAllConnections(); server.close(() => r()); }),
  };
}

// A fake OpenRouter. `chat` decides the /chat/completions answer; `params` are the model's supported parameters.
export async function startMockOpenRouter({ chat, params = ['max_tokens', 'response_format', 'structured_outputs'], endpointsStatus = 200 } = {}) {
  return startServer(async (rec, send, all) => {
    if (rec.method === 'GET' && /\/models\/.+\/endpoints$/.test(rec.url)) {
      if (endpointsStatus !== 200) return send(endpointsStatus, { error: { message: 'nope' } });
      return send(200, { data: { id: 'anthropic/claude-sonnet-5.5', endpoints: [{ provider_name: 'Test', supported_parameters: params }] } });
    }
    if (rec.method === 'POST' && rec.url === '/chat/completions') return chat(rec, send, all.filter(r => r.url === '/chat/completions'));
    send(404, { error: { message: 'not found' } });
  });
}

export function completion(content, extra = {}) {
  return Object.assign({
    id: 'gen-test-1',
    model: 'anthropic/claude-sonnet-5.5',
    choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content } }],
    usage: { prompt_tokens: 100, completion_tokens: 50 },
  }, extra);
}

// A fake binaries.soliditylang.org that only lists the bundled solc, so nothing is downloaded.
export async function startSolcList(releases = { '0.8.37': 'soljson-v0.8.37+commit.f401782d.js' }, files = {}, builds = []) {
  return startServer((rec, send) => {
    if (rec.url === '/list.json') return send(200, { builds, releases, latestRelease: Object.keys(releases).sort().pop() });
    const name = rec.url.slice(1);
    if (files[name]) return send(200, files[name]);
    send(404, 'missing');
  });
}
