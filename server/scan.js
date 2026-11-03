// VULNEX · /api/scan orchestration.
//
// 1. Take the exact source the editor sent (no defaults, no cache) and hash it.
// 2. Compile it with the solc version its pragma asks for.
// 3. If it compiled, send the full source to OpenRouter for an AI security review.
// The deterministic rule engine runs in the page on the same source; the page merges
// both result sets and decides the final status (see src/scan-core.js).

import { createHash, randomUUID } from 'node:crypto';
import { requestAudit } from './ai-audit.js';
import { sanitizeFileName } from './compiler.js';

export const MAX_SOURCE_CHARS = 200000;
export const MAX_AI_SOURCE_CHARS = 120000;

export function sha256Hex(text) { return '0x' + createHash('sha256').update(text, 'utf8').digest('hex'); }

export class ScanInputError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export function createScanner({ compiler, getSettings, fetchImpl = globalThis.fetch, log = console, referer }) {
  return async function scan(input) {
    const t0 = Date.now();
    if (!input || typeof input.source !== 'string') throw new ScanInputError(400, 'invalid_request', 'Send {"source": "<Solidity code>"}.');
    const source = input.source;
    if (!source.trim()) throw new ScanInputError(400, 'empty_source', 'The editor is empty.');
    if (source.length > MAX_SOURCE_CHARS) throw new ScanInputError(413, 'too_large', 'The source is larger than ' + MAX_SOURCE_CHARS.toLocaleString('en') + ' characters.');
    const fileName = sanitizeFileName(input.fileName);
    const settings = getSettings();

    const result = {
      scanId: randomUUID(),
      receivedAt: new Date().toISOString(),
      source: { sha256: sha256Hex(source), chars: source.length, lines: source.split('\n').length, fileName },
      compiler: null,
      ai: null,
      durationMs: null,
    };

    result.compiler = await compiler.compileSource(source, fileName);
    const cov = result.compiler.coverage;

    const aiBase = { model: settings.aiModel || null, findings: [], unlocated: [] };
    if (result.compiler.status === 'failed') {
      result.ai = Object.assign(aiBase, { status: 'skipped', error: { code: 'compilation_failed', message: 'The contract does not compile.' } });
    } else if (result.compiler.status === 'error') {
      result.ai = Object.assign(aiBase, { status: 'skipped', error: { code: 'compiler_error', message: 'The compiler stopped unexpectedly.' } });
    } else if (cov && !cov.hasCode) {
      result.ai = Object.assign(aiBase, { status: 'skipped', error: { code: 'no_code', message: 'The file has no contract or library code to review.' } });
    } else if (!settings.aiKey) {
      result.ai = Object.assign(aiBase, { status: 'not_configured', error: { code: 'not_configured', message: 'OPENROUTER_API_KEY is not set in .env.' } });
    } else if (source.length > MAX_AI_SOURCE_CHARS) {
      result.ai = Object.assign(aiBase, { status: 'skipped', error: { code: 'too_large', message: 'The file is too large to send for AI review.' } });
    } else {
      result.ai = await requestAudit({
        apiKey: settings.aiKey,
        base: settings.aiBase,
        model: settings.aiModel,
        timeoutMs: settings.aiTimeoutMs,
        source,
        fileName,
        compiler: result.compiler,
        functions: cov ? cov.functions : [],
        referer,
        fetchImpl,
        log,
      });
    }
    result.durationMs = Date.now() - t0;
    return result;
  };
}
