// functions/api/[[path]].js  –  ShareItNow
//
// ── Required environment variables ────────────────────────────────────────
//   PASSWORD       – access password
//   GITHUB_TOKEN   – GitHub personal access token (repo scope)
//   GITHUB_OWNER   – GitHub username / org
//   GITHUB_REPO    – repository name
//   GITHUB_BRANCH  – branch (default: "main")
//   GITHUB_FOLDER  – root upload folder in repo (default: "uploads")
//
// ── Required KV binding ────────────────────────────────────────────────────
//   RATE_LIMIT_KV  – Cloudflare KV namespace (variable name must be exact)
//   Pages → Settings → Functions → KV namespace bindings → Add
//   Variable name: RATE_LIMIT_KV

const MAX_ATTEMPTS = 3;
const LOCKOUT_MS   = 5 * 60 * 1000; // 5 minutes

const SEC_HEADERS = {
  'Content-Type'          : 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options'       : 'DENY',
  'Referrer-Policy'       : 'no-referrer',
  'Cache-Control'         : 'no-store',
};

const ok  = (d, s = 200, x = {}) => new Response(JSON.stringify(d), { status: s, headers: { ...SEC_HEADERS, ...x } });
const err = (m, s = 400, x = {}) => ok({ error: m }, s, x);

// ── Constant-time password comparison ─────────────────────────────────────
async function pwMatch(a, b) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode('__cmp__'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.sign('HMAC', k, enc.encode(a)),
    crypto.subtle.sign('HMAC', k, enc.encode(b)),
  ]);
  const ua = new Uint8Array(ha), ub = new Uint8Array(hb);
  let d = 0; for (let i = 0; i < ua.length; i++) d |= ua[i] ^ ub[i];
  return d === 0;
}

// ── Rate limiting ──────────────────────────────────────────────────────────
const rlKey = ip => `rl:${ip}`;

async function getRl(ip, env) {
  if (!env.RATE_LIMIT_KV) return { count: 0, until: 0 };
  return await env.RATE_LIMIT_KV.get(rlKey(ip), 'json').catch(() => null) || { count: 0, until: 0 };
}

async function setRl(ip, data, env) {
  if (!env.RATE_LIMIT_KV) return;
  const ttl = data.until ? Math.max(Math.ceil((data.until - Date.now()) / 1000) + 120, 60) : 600;
  await env.RATE_LIMIT_KV.put(rlKey(ip), JSON.stringify(data), { expirationTtl: ttl }).catch(() => {});
}

async function clearRl(ip, env) {
  if (!env.RATE_LIMIT_KV) return;
  await env.RATE_LIMIT_KV.delete(rlKey(ip)).catch(() => {});
}

// ── GitHub helpers ─────────────────────────────────────────────────────────
function ghHeaders(token) {
  return {
    Authorization : `token ${token}`,
    Accept        : 'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
    'User-Agent'  : 'ShareItNow',
  };
}

function cfg(env) {
  return {
    owner : env.GITHUB_OWNER,
    repo  : env.GITHUB_REPO,
    branch: env.GITHUB_BRANCH || 'main',
    root  : env.GITHUB_FOLDER || 'uploads',
    token : env.GITHUB_TOKEN,
  };
}

// Build full path inside repo: root/subpath
function fullPath(root, subpath) {
  const clean = (subpath || '').replace(/\.\./g, '').replace(/^\/+|\/+$/g, '').trim();
  return clean ? `${root}/${clean}` : root;
}

// List a folder's contents (files + subdirs, hide .gitkeep)
async function listFolder(env, subpath) {
  const { owner, repo, branch, root, token } = cfg(env);
  const path = fullPath(root, subpath);
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`,
    { headers: ghHeaders(token) }
  );
  if (res.status === 404) return { dirs: [], files: [] };
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).message || `GitHub ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data)) return { dirs: [], files: [] };
  const dirs  = data.filter(i => i.type === 'dir');
  const files = data.filter(i => i.type === 'file' && i.name !== '.gitkeep');
  return { dirs, files };
}

// Create a file (or overwrite existing)
async function putFile(env, repoPath, b64, message) {
  const { owner, repo, branch, token } = cfg(env);
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(repoPath)}`;
  let sha = null;
  const check = await fetch(`${apiUrl}?ref=${branch}`, { headers: ghHeaders(token) });
  if (check.ok) sha = (await check.json()).sha;
  const res = await fetch(apiUrl, {
    method : 'PUT',
    headers: ghHeaders(token),
    body   : JSON.stringify({ message, content: b64, branch, ...(sha ? { sha } : {}) }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).message || `GitHub ${res.status}`);
}

// Delete a file
async function deleteFile(env, repoPath, sha) {
  const { owner, repo, branch, token } = cfg(env);
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(repoPath)}`,
    {
      method : 'DELETE',
      headers: ghHeaders(token),
      body   : JSON.stringify({ message: `Delete ${repoPath}`, sha, branch }),
    }
  );
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).message || `GitHub ${res.status}`);
}

// Sanitise a single path component (no slashes, no traversal)
function sanitiseName(name) {
  return String(name)
    .replace(/\.\./g, '')
    .replace(/[/\\:*?"<>|]/g, '')
    .replace(/[^a-zA-Z0-9._\-()\s]/g, '_')
    .trim()
    .slice(0, 200);
}

// Sanitise a relative subpath (allow slashes between segments)
function sanitisePath(p) {
  return (p || '')
    .split('/')
    .map(s => sanitiseName(s))
    .filter(Boolean)
    .join('/');
}

// ── Main handler ───────────────────────────────────────────────────────────
export async function onRequest({ request, env, params }) {
  const method = request.method;

  if (!['GET', 'POST', 'DELETE', 'OPTIONS'].includes(method)) return err('Method not allowed', 405);
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: SEC_HEADERS });

  const ip = request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() || 'unknown';

  const segments = params.path || [];
  const route    = segments.join('/');

  // ── POST /api/auth ─────────────────────────────────────────────────────
  if (route === 'auth' && method === 'POST') {
    const now  = Date.now();
    const rl   = await getRl(ip, env);

    if (rl.until && rl.until > now) {
      return err('Access denied. Too many failed attempts.', 429, {
        'Retry-After'   : String(Math.ceil((rl.until - now) / 1000)),
        'X-Locked-Until': String(rl.until),
      });
    }

    const body = await request.json().catch(() => ({}));
    const submitted = typeof body.password === 'string' ? body.password : '';

    if (await pwMatch(submitted, env.PASSWORD || '')) {
      await clearRl(ip, env);
      return ok({ ok: true });
    }

    const count = (rl.count || 0) + 1;
    if (count >= MAX_ATTEMPTS) {
      const until = now + LOCKOUT_MS;
      await setRl(ip, { count: 0, until }, env);
      return err('Access denied. Too many failed attempts. Try again in 5 minutes.', 429, {
        'Retry-After'   : String(Math.ceil(LOCKOUT_MS / 1000)),
        'X-Locked-Until': String(until),
      });
    }

    await setRl(ip, { count, until: 0 }, env);
    const remaining = MAX_ATTEMPTS - count;
    return err(
      remaining === 1 ? 'Incorrect password. 1 attempt remaining.'
                      : `Incorrect password. ${remaining} attempts remaining.`,
      401,
      { 'X-Attempts-Remaining': String(remaining) }
    );
  }

  // ── Auth gate for all other routes ─────────────────────────────────────
  const pw = request.headers.get('X-Password') || '';
  if (!pw || !(await pwMatch(pw, env.PASSWORD || ''))) return err('Unauthorized', 401);

  // ── GET /api/meta ──────────────────────────────────────────────────────
  if (route === 'meta' && method === 'GET') {
    return ok({ repo: `${env.GITHUB_OWNER}/${env.GITHUB_REPO}`, folder: env.GITHUB_FOLDER || 'uploads' });
  }

  // ── GET /api/files?path=sub/folder ────────────────────────────────────
  if (route === 'files' && method === 'GET') {
    const url     = new URL(request.url);
    const subpath = sanitisePath(url.searchParams.get('path') || '');
    try { return ok(await listFolder(env, subpath)); }
    catch (e) { return err(e.message, 502); }
  }

  // ── POST /api/mkdir  { name, path } ───────────────────────────────────
  if (route === 'mkdir' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const name    = sanitiseName(body.name || '');
    const subpath = sanitisePath(body.path || '');
    if (!name) return err('Invalid folder name');

    const { root } = cfg(env);
    const folderPath = subpath ? `${root}/${subpath}/${name}` : `${root}/${name}`;
    const keepPath   = `${folderPath}/.gitkeep`;

    try {
      await putFile(env, keepPath, '', `Create folder ${name}`);
      return ok({ ok: true, name });
    } catch (e) { return err(e.message, 502); }
  }

  // ── POST /api/upload  { name, content, path } ─────────────────────────
  if (route === 'upload' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const { name, content } = body;
    const subpath = sanitisePath(body.path || '');

    if (typeof name !== 'string' || typeof content !== 'string') return err('Invalid field types');
    if (!name || !content) return err('Missing name or content');

    const safe = sanitiseName(name);
    if (!safe || safe.startsWith('.')) return err('Invalid filename');
    if (content.length > 55 * 1024 * 1024) return err('File too large');
    if (!/^[A-Za-z0-9+/]+=*$/.test(content)) return err('Invalid file encoding');

    const { root } = cfg(env);
    const repoPath = subpath ? `${root}/${subpath}/${safe}` : `${root}/${safe}`;

    try {
      await putFile(env, repoPath, content, `Upload ${safe}`);
      return ok({ ok: true, name: safe });
    } catch (e) { return err(e.message, 502); }
  }

  // ── GET /api/download?name=file&path=sub ──────────────────────────────
  if (route === 'download' && method === 'GET') {
    const url      = new URL(request.url);
    const name     = sanitiseName(url.searchParams.get('name') || '');
    const subpath  = sanitisePath(url.searchParams.get('path') || '');
    if (!name || name.startsWith('.')) return err('Invalid filename', 400);

    const { owner, repo, branch, root, token } = cfg(env);
    const repoPath = subpath ? `${root}/${subpath}/${name}` : `${root}/${name}`;
    const rawUrl   = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${repoPath}`;

    const ghRes = await fetch(rawUrl, { headers: { Authorization: `token ${token}`, 'User-Agent': 'ShareItNow' } });
    if (!ghRes.ok) return new Response('File not found', { status: 404 });

    const encoded = encodeURIComponent(name).replace(/'/g, '%27');
    return new Response(ghRes.body, {
      status: 200,
      headers: {
        'Content-Type'          : ghRes.headers.get('Content-Type') || 'application/octet-stream',
        'Content-Disposition'   : `attachment; filename*=UTF-8''${encoded}`,
        'Content-Length'        : ghRes.headers.get('Content-Length') || '',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control'         : 'no-store',
      },
    });
  }

  // ── DELETE /api/delete  { name, sha, path } ───────────────────────────
  if (route === 'delete' && method === 'DELETE') {
    const body = await request.json().catch(() => ({}));
    const { name, sha } = body;
    const subpath = sanitisePath(body.path || '');

    if (typeof name !== 'string' || typeof sha !== 'string') return err('Invalid field types');
    if (!name || !sha) return err('Missing name or sha');
    if (!/^[0-9a-f]{40}$/i.test(sha)) return err('Invalid sha');

    const safe = sanitiseName(name);
    if (!safe) return err('Invalid filename');

    const { root } = cfg(env);
    const repoPath = subpath ? `${root}/${subpath}/${safe}` : `${root}/${safe}`;

    try { await deleteFile(env, repoPath, sha); return ok({ ok: true }); }
    catch (e) { return err(e.message, 502); }
  }

  return new Response('Not found', { status: 404, headers: SEC_HEADERS });
}
