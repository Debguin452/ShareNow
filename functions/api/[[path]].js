// functions/api/[[path]].js  —  StoreGit by Deb Guin
// ─────────────────────────────────────────────────────────
// Operator sets these four CF Pages environment variables ONCE:
//   TOKEN_SECRET            — random 48+ char string  (openssl rand -hex 32)
//   REGISTRY_GITHUB_TOKEN   — GitHub token with repo scope on the registry repo
//   REGISTRY_GITHUB_OWNER   — owner of the registry repo
//   REGISTRY_GITHUB_REPO    — name of the registry repo  (e.g. "storegit-registry")
//
// Optionally bind a KV namespace named RATE_LIMIT_KV for persistent rate limiting.
// Users do NOT configure any environment variables.
// ─────────────────────────────────────────────────────────

'use strict';

// ── Constants ─────────────────────────────────────────────
const SESSION_TTL       = 8  * 60 * 60 * 1000;
const RATE_WINDOW_MS    = 15 * 60 * 1000;
const RATE_MAX_LOGIN    = 5;
const RATE_MAX_SIGNUP   = 3;
const MAX_FILE_BYTES    = 95 * 1024 * 1024;
const LARGE_THRESH      = 20 * 1024 * 1024;
const SHA_RE            = /^[0-9a-f]{40}$/i;
const USERNAME_RE       = /^[a-zA-Z0-9_\-]{3,32}$/;
const CLEAN_NAME_RE     = /^[a-zA-Z0-9][a-zA-Z0-9._\-()\s]{0,253}$/;
const REGISTRY_BRANCH   = 'main';

const BLOCKED_EXTS = new Set([
  'exe','bat','cmd','com','msi','ps1','psm1',
  'sh','bash','zsh','fish','command',
  'php','php3','php4','php5','php7','php8','phtml','phar',
  'asp','aspx','cshtml','jsp','jspx',
  'py','pyc','pyw','rb','pl','cgi','lua',
  'js','mjs','cjs','ts','tsx','jsx',
  'html','htm','xhtml','svg','xml',
  'htaccess','htpasswd',
  'dll','so','dylib','sys',
  'vbs','vbe','wsf','wsh','hta',
  'jar','war','ear','class',
  'scr','pif','reg','lnk',
  'app','dmg','pkg','deb','rpm','apk',
]);

const BLOCKED_MAGIC = [
  [0,[0x4D,0x5A]],
  [0,[0x7F,0x45,0x4C,0x46]],
  [0,[0xFE,0xED,0xFA,0xCE]],[0,[0xFE,0xED,0xFA,0xCF]],
  [0,[0xCE,0xFA,0xED,0xFE]],[0,[0xCF,0xFA,0xED,0xFE]],
  [0,[0xCA,0xFE,0xBA,0xBE]],
  [0,[0x23,0x21]],
  [0,[0x3C,0x3F,0x70,0x68,0x70]],
  [0,[0x3C,0x73,0x63,0x72,0x69,0x70,0x74]],
  [0,[0x3C,0x68,0x74,0x6D,0x6C]],[0,[0x3C,0x48,0x54,0x4D,0x4C]],
];

const _memRate = new Map();

// ── Security headers ──────────────────────────────────────
const SEC_HEADERS = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'no-referrer',
  'Permissions-Policy':        'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none';",
  'Cache-Control': 'no-store',
};

function corsHeaders(req) {
  const o = req.headers.get('Origin') || '';
  const h = req.headers.get('Host')   || '';
  const ok = o === `https://${h}` || o === `http://${h}`;
  return {
    'Access-Control-Allow-Origin':      ok ? o : 'null',
    'Access-Control-Allow-Methods':     'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type,X-Session-Token',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

function jsonResponse(req, data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SEC_HEADERS, ...corsHeaders(req), 'Content-Type': 'application/json', ...extra },
  });
}

const HTTP_MSG = {
  400:'Bad request', 401:'Invalid credentials', 403:'Forbidden',
  404:'Not found',   409:'Username already taken',
  413:'File too large', 415:'File type not permitted',
  429:'Too many attempts — please wait and try again',
  500:'Server error', 502:'Upstream error',
};
const fail = (req, code) => jsonResponse(req, { error: HTTP_MSG[code] || 'Error' }, code);

// ── Encoding helpers ──────────────────────────────────────
const ENC = new TextEncoder();
const DEC = new TextDecoder();

function b64Encode(u8) {
  const CHUNK = 0x8000; let s = '';
  for (let i = 0; i < u8.length; i += CHUNK)
    s += String.fromCharCode(...u8.subarray(i, Math.min(i + CHUNK, u8.length)));
  return btoa(s);
}
function b64Decode(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function b64urlEncode(u8) { return b64Encode(u8).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
function b64urlDecode(s) {
  const pad = s.replace(/-/g,'+').replace(/_/g,'/');
  return b64Decode(pad + '='.repeat((4 - pad.length % 4) % 4));
}
function ab2b64(buf) { return b64Encode(new Uint8Array(buf)); }
function hexEncode(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2,'0')).join(''); }

// ── Crypto core ───────────────────────────────────────────

// Derive a 32-byte key via HKDF from TOKEN_SECRET + context label
async function deriveKey(secret, label, usage) {
  const raw = await crypto.subtle.importKey('raw', ENC.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt: ENC.encode('ShareItNow-v1'), info: ENC.encode(label) },
    raw, { name:'AES-GCM', length:256 }, false, usage
  );
}

// AES-256-GCM encrypt — returns { iv, ct } both base64url
async function aesEncrypt(plaintext, secret, label = 'encrypt') {
  const key = await deriveKey(secret, label, ['encrypt']);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, ENC.encode(plaintext));
  return { iv: b64urlEncode(iv), ct: b64urlEncode(new Uint8Array(ct)) };
}

// AES-256-GCM decrypt — throws on wrong key
async function aesDecrypt(enc, secret, label = 'encrypt') {
  const key = await deriveKey(secret, label, ['decrypt']);
  const iv  = b64urlDecode(enc.iv);
  const ct  = b64urlDecode(enc.ct);
  const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return DEC.decode(pt);
}

// HMAC-SHA256 — returns base64url
async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', ENC.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, ENC.encode(data));
  return b64urlEncode(new Uint8Array(sig));
}

// Constant-time equality (via double-HMAC)
async function timingSafeEqual(a, b) {
  const key = await crypto.subtle.importKey(
    'raw', ENC.encode('_cmp_'), { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  );
  const [ha, hb] = await Promise.all([
    crypto.subtle.sign('HMAC', key, ENC.encode(String(a))),
    crypto.subtle.sign('HMAC', key, ENC.encode(String(b))),
  ]);
  const ua = new Uint8Array(ha), ub = new Uint8Array(hb);
  let d = 0; for (let i = 0; i < ua.length; i++) d |= ua[i] ^ ub[i];
  return d === 0;
}

// PBKDF2-SHA256 password hashing (100k iterations)
async function pbkdf2Hash(password, salt /* Uint8Array */) {
  const km = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt, iterations:100000, hash:'SHA-256' }, km, 256
  );
  return new Uint8Array(bits);
}

// ── Session tokens ────────────────────────────────────────
// Format: base64url(AES-GCM-encrypted JSON payload) + "." + HMAC(ciphertext)
// Payload: { jti, exp, username, ghToken (encrypted), ghOwner, ghRepo, ghBranch, folder }
// The payload itself is AES-encrypted so ghToken is never visible to the client.

async function createSessionToken(payload, secret) {
  const jti     = hexEncode(crypto.getRandomValues(new Uint8Array(16)));
  const full    = { ...payload, jti, exp: Date.now() + SESSION_TTL };
  const enc     = await aesEncrypt(JSON.stringify(full), secret, 'session');
  const body    = b64urlEncode(ENC.encode(JSON.stringify(enc)));
  const sig     = await hmacSign(body, secret);
  return `${body}.${sig}`;
}

async function verifySessionToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const sig  = token.slice(dot + 1);
  const expected = await hmacSign(body, secret);
  if (!(await timingSafeEqual(sig, expected))) return null;
  try {
    const enc     = JSON.parse(DEC.decode(b64urlDecode(body)));
    const payload = JSON.parse(await aesDecrypt(enc, secret, 'session'));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ── Rate limiting ─────────────────────────────────────────
function getClientIP(req) {
  return req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0].trim() || 'unknown';
}

async function checkRateLimit(key, max, env) {
  const now = Date.now();
  let r = null;
  if (env.RATE_LIMIT_KV) r = await env.RATE_LIMIT_KV.get(key, 'json').catch(() => null);
  else r = _memRate.get(key) || null;

  if (!r || now > r.resetAt) {
    const fresh = { count: 1, resetAt: now + RATE_WINDOW_MS };
    if (env.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.put(key, JSON.stringify(fresh), { expirationTtl: Math.ceil(RATE_WINDOW_MS/1000) }).catch(()=>{});
    else _memRate.set(key, fresh);
    return false;
  }
  r.count++;
  if (env.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.put(key, JSON.stringify(r), { expirationTtl: Math.ceil((r.resetAt-now)/1000) }).catch(()=>{});
  else _memRate.set(key, r);
  if (_memRate.size > 20000) { for (const [k,v] of _memRate) if (now>v.resetAt) _memRate.delete(k); }
  return r.count > max;
}

async function clearRateLimit(key, env) {
  if (env.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.delete(key).catch(()=>{});
  else _memRate.delete(key);
}

// ── File validation ───────────────────────────────────────
function sanitizeFilename(name) {
  if (!name || typeof name !== 'string') return null;
  const s = name.replace(/\0/g,'').replace(/\.\./g,'').replace(/[/\\]/g,'').trim();
  if (!s) return null;
  const safe = s.replace(/[^a-zA-Z0-9._\-()\s]/g, '_');
  if (!CLEAN_NAME_RE.test(safe)) return null;
  const ext = safe.split('.').pop()?.toLowerCase() || '';
  if (BLOCKED_EXTS.has(ext)) return null;
  return safe;
}

function checkMagicBytes(bytes) {
  for (const [off, pat] of BLOCKED_MAGIC) {
    let ok = true;
    for (let i = 0; i < pat.length; i++) { if (bytes[off+i] !== pat[i]) { ok=false; break; } }
    if (ok) return false;
  }
  return true;
}

// ── Registry GitHub helpers ───────────────────────────────
function regHeaders(env) {
  return {
    Authorization:  `token ${env.REGISTRY_GITHUB_TOKEN}`,
    Accept:         'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
    'User-Agent':   'StoreGit/1',
  };
}

function regBase(env) {
  return `https://api.github.com/repos/${env.REGISTRY_GITHUB_OWNER}/${env.REGISTRY_GITHUB_REPO}`;
}

async function readRegistryFile(path, env) {
  const url = `${regBase(env)}/contents/${path}?ref=${REGISTRY_BRANCH}`;
  const res = await fetch(url, { headers: regHeaders(env) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('registry_read_fail');
  const data = await res.json();
  return { content: JSON.parse(atob(data.content.replace(/\s/g,''))), sha: data.sha };
}

async function writeRegistryFile(path, content, message, env, existingSha = null) {
  const url = `${regBase(env)}/contents/${path}`;
  const body = {
    message,
    content: btoa(JSON.stringify(content, null, 2)),
    branch:  REGISTRY_BRANCH,
    ...(existingSha ? { sha: existingSha } : {}),
  };
  const res = await fetch(url, { method:'PUT', headers: regHeaders(env), body: JSON.stringify(body) });
  if (!res.ok) throw new Error('registry_write_fail');
  return (await res.json()).content?.sha;
}

// ── User record helpers ───────────────────────────────────
function userPath(username) { return `users/${username.toLowerCase()}.json`; }

async function getUser(username, env) {
  if (!USERNAME_RE.test(username)) return null;
  try {
    const rec = await readRegistryFile(userPath(username), env);
    return rec;
  } catch { return null; }
}

async function userExists(username, env) {
  const u = await getUser(username, env);
  return u !== null;
}

// ── User GitHub helpers ───────────────────────────────────
function userGhHeaders(token) {
  return {
    Authorization:  `token ${token}`,
    Accept:         'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
    'User-Agent':   'StoreGit/1',
  };
}

async function listUserFiles(sess) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${folder}?ref=${ghBranch}`;
  const res = await fetch(url, { headers: userGhHeaders(ghToken) });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error('list_fail');
  const data = await res.json();
  return Array.isArray(data)
    ? data.filter(f => f.type === 'file').map(f => ({ name: f.name, size: f.size, sha: f.sha }))
    : [];
}

async function uploadSmall(sess, filename, base64) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const path = `${folder}/${filename}`;
  const url  = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${path}`;
  let sha = null;
  const chk = await fetch(`${url}?ref=${ghBranch}`, { headers: userGhHeaders(ghToken) });
  if (chk.ok) sha = (await chk.json()).sha;
  const res = await fetch(url, {
    method: 'PUT', headers: userGhHeaders(ghToken),
    body: JSON.stringify({ message: `Upload ${filename}`, content: base64, branch: ghBranch, ...(sha?{sha}:{}) }),
  });
  if (!res.ok) throw new Error('upload_fail');
}

async function uploadLarge(sess, filename, buf) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const gh   = userGhHeaders(ghToken);
  const base = `https://api.github.com/repos/${ghOwner}/${ghRepo}`;

  const blobRes = await fetch(`${base}/git/blobs`, {
    method:'POST', headers:gh, body: JSON.stringify({ content: ab2b64(buf), encoding:'base64' }),
  });
  if (!blobRes.ok) throw new Error('blob_fail');
  const { sha: blobSha } = await blobRes.json();

  const refRes = await fetch(`${base}/git/ref/heads/${ghBranch}`, { headers: gh });
  if (!refRes.ok) throw new Error('ref_fail');
  const { object: { sha: commitSha } } = await refRes.json();

  const commitRes = await fetch(`${base}/git/commits/${commitSha}`, { headers: gh });
  if (!commitRes.ok) throw new Error('commit_read_fail');
  const { tree: { sha: treeSha } } = await commitRes.json();

  const treeRes = await fetch(`${base}/git/trees`, {
    method:'POST', headers:gh,
    body: JSON.stringify({ base_tree: treeSha, tree: [{ path:`${folder}/${filename}`, mode:'100644', type:'blob', sha:blobSha }] }),
  });
  if (!treeRes.ok) throw new Error('tree_fail');
  const { sha: newTreeSha } = await treeRes.json();

  const newCommitRes = await fetch(`${base}/git/commits`, {
    method:'POST', headers:gh,
    body: JSON.stringify({ message:`Upload ${filename}`, tree: newTreeSha, parents:[commitSha] }),
  });
  if (!newCommitRes.ok) throw new Error('commit_fail');
  const { sha: newCommit } = await newCommitRes.json();

  const updateRes = await fetch(`${base}/git/refs/heads/${ghBranch}`, {
    method:'PATCH', headers:gh, body: JSON.stringify({ sha: newCommit, force: false }),
  });
  if (!updateRes.ok) throw new Error('ref_update_fail');
}

async function deleteUserFile(sess, filename, sha) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${folder}/${filename}`;
  const res = await fetch(url, {
    method:'DELETE', headers: userGhHeaders(ghToken),
    body: JSON.stringify({ message:`Delete ${filename}`, sha, branch: ghBranch }),
  });
  if (!res.ok) throw new Error('delete_fail');
}

// ── Safe MIME types ───────────────────────────────────────
const SAFE_MIMES = {
  pdf:'application/pdf', doc:'application/msword',
  docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls:'application/vnd.ms-excel',
  xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt:'application/vnd.ms-powerpoint',
  pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  txt:'text/plain;charset=utf-8', csv:'text/plain;charset=utf-8',
  md:'text/plain;charset=utf-8',  rtf:'application/rtf',
  jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png',
  gif:'image/gif',  webp:'image/webp', bmp:'image/bmp',
  mp3:'audio/mpeg', wav:'audio/wav',   ogg:'audio/ogg',
  flac:'audio/flac', m4a:'audio/mp4',  aac:'audio/aac',
  mp4:'video/mp4',  webm:'video/webm', mov:'video/quicktime',
  avi:'video/x-msvideo', mkv:'video/x-matroska',
  zip:'application/zip', gz:'application/gzip',
  tar:'application/x-tar', '7z':'application/x-7z-compressed', rar:'application/vnd.rar',
  json:'text/plain;charset=utf-8', yaml:'text/plain;charset=utf-8', yml:'text/plain;charset=utf-8',
};
const safeMime = name => SAFE_MIMES[name.split('.').pop()?.toLowerCase()||''] || 'application/octet-stream';

// ══════════════════════════════════════════════════════════
// MAIN HANDLER
// ══════════════════════════════════════════════════════════
export async function onRequest({ request, env, params }) {
  const method = request.method.toUpperCase();
  const route  = (params.path || []).join('/');

  if (method === 'OPTIONS') {
    return new Response(null, { status:204, headers: { ...SEC_HEADERS, ...corsHeaders(request) } });
  }

  const secret = env.TOKEN_SECRET;
  if (!secret) return fail(request, 500);

  // ── GET /api/status ─────────────────────────────────────
  // Returns {ready: true/false} — frontend uses this on load
  if (route === 'status' && method === 'GET') {
    const ready = !!(env.REGISTRY_GITHUB_TOKEN && env.REGISTRY_GITHUB_OWNER && env.REGISTRY_GITHUB_REPO);
    return jsonResponse(request, { ready });
  }

  // ── POST /api/signup ────────────────────────────────────
  if (route === 'signup' && method === 'POST') {
    const ip = getClientIP(request);
    if (await checkRateLimit(`signup:${ip}`, RATE_MAX_SIGNUP, env)) return fail(request, 429);

    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, password, ghToken, ghOwner, ghRepo, ghBranch = 'main', folder = 'uploads' } = body || {};

    // Validate inputs
    if (!username || !password || !ghToken || !ghOwner || !ghRepo) return fail(request, 400);
    if (!USERNAME_RE.test(username)) return jsonResponse(request, { error:'Username must be 3–32 chars, letters/numbers/_/-' }, 400);
    if (password.length < 8) return jsonResponse(request, { error:'Password must be at least 8 characters' }, 400);

    // Check username not taken
    if (await userExists(username, env)) return fail(request, 409);

    // Validate the user's GitHub token and repo
    const repoCheck = await fetch(
      `https://api.github.com/repos/${ghOwner}/${ghRepo}`,
      { headers: { Authorization:`token ${ghToken}`, Accept:'application/vnd.github.v3+json', 'User-Agent':'StoreGit/1' } }
    );
    if (repoCheck.status === 401) return jsonResponse(request, { error:'Invalid GitHub token' }, 400);
    if (repoCheck.status === 404) return jsonResponse(request, { error:'Repository not found' }, 400);
    if (!repoCheck.ok) return jsonResponse(request, { error:'GitHub validation failed' }, 400);

    const repoData = await repoCheck.json();
    if (!repoData.permissions?.push && !repoData.permissions?.admin) {
      return jsonResponse(request, { error:'GitHub token requires write access to the repository' }, 400);
    }

    // Hash password
    const salt   = crypto.getRandomValues(new Uint8Array(16));
    const pwHash = await pbkdf2Hash(password, salt);

    // Encrypt GitHub token with TOKEN_SECRET (server-only, user cannot decrypt)
    const encGhToken = await aesEncrypt(ghToken, secret, `user-token:${username.toLowerCase()}`);

    // Build user record
    const userRecord = {
      username:    username.toLowerCase(),
      displayName: username,
      pwSalt:      b64urlEncode(salt),
      pwHash:      b64urlEncode(pwHash),
      encGhToken,
      ghOwner,
      ghRepo,
      ghBranch,
      folder,
      createdAt:   new Date().toISOString(),
    };

    // Write to registry
    try {
      await writeRegistryFile(userPath(username), userRecord, `Register user ${username.toLowerCase()}`, env);
    } catch {
      return fail(request, 502);
    }

    // Upload an initial README to their storage folder so it exists
    const readmePath   = `${folder}/.storegit`;
    const readmeUrl    = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${readmePath}`;
    const readmeCheck  = await fetch(`${readmeUrl}?ref=${ghBranch}`, { headers: userGhHeaders(ghToken) });
    if (readmeCheck.status === 404) {
      await fetch(readmeUrl, {
        method: 'PUT',
        headers: userGhHeaders(ghToken),
        body: JSON.stringify({
          message: 'Initialize StoreGit storage',
          content: btoa(`# StoreGit Storage\nManaged by StoreGit. Do not delete this file.\nUser: ${username}\n`),
          branch: ghBranch,
        }),
      }).catch(() => {});
    }

    return jsonResponse(request, { ok: true });
  }

  // ── POST /api/auth ──────────────────────────────────────
  if (route === 'auth' && method === 'POST') {
    const ip = getClientIP(request);
    if (await checkRateLimit(`login:${ip}`, RATE_MAX_LOGIN, env)) return fail(request, 429);

    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, password } = body || {};
    if (!username || !password) return fail(request, 400);

    // Load user record
    const rec = await getUser(username, env);
    if (!rec) {
      // Spend time hashing anyway to prevent user enumeration via timing
      const fakeSalt = crypto.getRandomValues(new Uint8Array(16));
      await pbkdf2Hash(password, fakeSalt);
      await new Promise(r => setTimeout(r, 100 + Math.random()*200));
      return fail(request, 401);
    }

    const { content: user } = rec;
    const salt   = b64urlDecode(user.pwSalt);
    const stored = b64urlDecode(user.pwHash);
    const derived = await pbkdf2Hash(password, salt);

    let diff = 0; for (let i = 0; i < 32; i++) diff |= derived[i] ^ (stored[i] ?? 0);
    if (diff !== 0) {
      await new Promise(r => setTimeout(r, 300 + Math.random()*200));
      return fail(request, 401);
    }

    await clearRateLimit(`login:${ip}`, env);

    // Decrypt GitHub token so it can be embedded in session
    let ghToken;
    try {
      ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`);
    } catch {
      return fail(request, 500);
    }

    // Create encrypted session token (ghToken is AES-encrypted inside, not visible to client)
    const sessionPayload = {
      username:  user.username,
      display:   user.displayName || user.username,
      ghToken,
      ghOwner:   user.ghOwner,
      ghRepo:    user.ghRepo,
      ghBranch:  user.ghBranch,
      folder:    user.folder,
    };

    const token = await createSessionToken(sessionPayload, secret);
    return jsonResponse(request, { ok:true, display: user.displayName || user.username }, 200, {
      'Set-Cookie':      `sg_sess=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL/1000}`,
      'X-Session-Token': token,
    });
  }

  // ── POST /api/logout ────────────────────────────────────
  if (route === 'logout' && method === 'POST') {
    return jsonResponse(request, { ok:true }, 200, {
      'Set-Cookie': 'sg_sess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
    });
  }

  // ── Auth guard ───────────────────────────────────────────
  const rawToken = request.headers.get('X-Session-Token') || '';
  const sess     = await verifySessionToken(rawToken, secret);
  if (!sess) return fail(request, 401);

  // ── GET /api/me ─────────────────────────────────────────
  if (route === 'me' && method === 'GET') {
    return jsonResponse(request, {
      username: sess.username,
      display:  sess.display,
      repo:     `${sess.ghOwner}/${sess.ghRepo}`,
      folder:   sess.folder,
    });
  }

  // ── GET /api/files ───────────────────────────────────────
  if (route === 'files' && method === 'GET') {
    try {
      return jsonResponse(request, await listUserFiles(sess));
    } catch { return fail(request, 502); }
  }

  // ── POST /api/upload — binary multipart ─────────────────
  if (route === 'upload' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('multipart/form-data')) return fail(request, 400);
    let fd; try { fd = await request.formData(); } catch { return fail(request, 400); }

    const blob    = fd.get('file');
    const rawName = fd.get('name');
    if (!blob || !rawName) return fail(request, 400);
    if (blob.size > MAX_FILE_BYTES) return fail(request, 413);

    const safe = sanitizeFilename(String(rawName));
    if (!safe) return fail(request, 415);

    const buf   = await blob.arrayBuffer();
    const bytes = new Uint8Array(buf);
    if (!checkMagicBytes(bytes)) return fail(request, 415);

    try {
      if (buf.byteLength > LARGE_THRESH) await uploadLarge(sess, safe, buf);
      else await uploadSmall(sess, safe, ab2b64(buf));
      return jsonResponse(request, { ok:true, name:safe, size:buf.byteLength });
    } catch (e) {
      return fail(request, e.message?.includes('blob') ? 413 : 502);
    }
  }

  // ── GET /api/download?name= ──────────────────────────────
  // Proxied — raw GitHub URLs never reach the browser
  if (route === 'download' && method === 'GET') {
    const name = new URL(request.url).searchParams.get('name') || '';
    const safe = sanitizeFilename(name);
    if (!safe) return fail(request, 400);

    const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
    const rawUrl = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}/${folder}/${encodeURIComponent(safe)}`;

    let ghRes;
    try {
      ghRes = await fetch(rawUrl, {
        headers: { Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' },
      });
    } catch { return fail(request, 502); }

    if (ghRes.status === 404) return fail(request, 404);
    if (!ghRes.ok) return fail(request, 502);

    const len = ghRes.headers.get('Content-Length') || '';
    return new Response(ghRes.body, {
      status: 200,
      headers: {
        ...SEC_HEADERS, ...corsHeaders(request),
        'Content-Type':        safeMime(safe),
        'Content-Disposition': `attachment; filename="${safe.replace(/"/g,'\\"')}"`,
        ...(len ? { 'Content-Length': len } : {}),
        'Accept-Ranges': 'bytes',
      },
    });
  }

  // ── DELETE /api/delete ───────────────────────────────────
  if (route === 'delete' && method === 'DELETE') {
    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { name, sha } = body || {};
    if (typeof name !== 'string' || typeof sha !== 'string') return fail(request, 400);
    if (!SHA_RE.test(sha)) return fail(request, 400);
    const safe = sanitizeFilename(name);
    if (!safe) return fail(request, 400);
    try { await deleteUserFile(sess, safe, sha); return jsonResponse(request, { ok:true }); }
    catch { return fail(request, 502); }
  }

  return fail(request, 404);
}
