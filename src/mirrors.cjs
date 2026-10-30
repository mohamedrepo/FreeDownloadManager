const crypto = require('node:crypto');
const net = require('./network.cjs');

const MAX_MIRRORS = 8;
const SAMPLE_BYTES = 64 * 1024;

// Mirrors are optional alternate URLs for the *same* file. They are parsed
// here and fully verified against the primary source before the engine is
// allowed to read a single byte from them, so a wrong or truncated mirror can
// never corrupt a download.
function parseMirrors(value, primary = '') {
  const rows = (Array.isArray(value) ? value : String(value == null ? '' : value).split(/[\r\n]+/))
    .map(row => String(row || '').trim())
    .filter(Boolean);
  if (rows.length > MAX_MIRRORS) throw Error(`You can add up to ${MAX_MIRRORS} mirror links for one file.`);
  const urls = [];
  for (const row of rows) {
    const url = net.validateURL(row, ['http:', 'https:']);
    if (url.href === primary || urls.includes(url.href)) continue;
    urls.push(url.href);
  }
  return urls;
}

async function sample(url, start, end, options) {
  const headers = { ...options.headers, range: `bytes=${start}-${end}` };
  const response = await net.request(url, { ...options, headers });
  try {
    if (response.statusCode !== 206) return null;
    const expected = end - start + 1;
    let size = 0;
    const chunks = [];
    for await (const chunk of response) {
      size += chunk.length;
      if (size > expected) return null;
      chunks.push(chunk);
    }
    if (size !== expected) return null;
    return crypto.createHash('sha256').update(Buffer.concat(chunks)).digest('hex');
  } finally {
    response.destroy();
  }
}

// Returns the mirrors that provably serve the same bytes as the primary source.
// A reference sample is taken from the middle of the file (not the start, where
// unrelated files often share headers) and compared byte-for-byte.
async function verified(primaryURL, info, mirrors, options = {}) {
  const size = Number(info?.size) || 0;
  if (!mirrors?.length || !info?.resumable || size <= 0) return [];
  const headersOf = options.headersOf || (() => ({}));
  const span = Math.min(SAMPLE_BYTES, size);
  const start = Math.max(0, Math.min(size - span, Math.floor(size / 2) - Math.floor(span / 2)));
  const end = start + span - 1;
  const reference = await sample(primaryURL, start, end, { headers: headersOf(primaryURL), settings: options.settings, signal: options.signal });
  if (!reference) return [];
  const usable = [];
  for (const url of mirrors) {
    try {
      const probe = await net.probe(url, { headers: headersOf(url), settings: options.settings, signal: options.signal });
      if (!probe.resumable || Number(probe.size) !== size) continue;
      const digest = await sample(url, start, end, { headers: headersOf(url), settings: options.settings, signal: options.signal });
      if (digest === reference) usable.push(url);
    } catch {
      // A mirror that is down, slow or refuses ranges is simply skipped.
    }
  }
  return usable;
}

module.exports = { parseMirrors, verified, MAX_MIRRORS, SAMPLE_BYTES };
