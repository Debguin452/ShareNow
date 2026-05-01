// functions/api/[[path]].js
// Cloudflare Pages Function — handles all /api/* routes
// Secrets set in Cloudflare Pages dashboard (Settings → Environment Variables):
//   PASSWORD, GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, GITHUB_BRANCH, GITHUB_FOLDER

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Password',
};

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function fail(msg, status = 400) {
  return respond({ error: msg }, status);
}

// ── GitHub helpers ────────────────────────────────────────
function ghHeaders(token) {
  return {
    Authorization: `token ${token}`,
    Accept: 'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
    'User-Agent': 'ShareNow/1.0',
  };
}

function cfg(env) {
  return {
    owner:  env.GITHUB_OWNER,
    repo:   env.GITHUB_REPO,
    branch: env.GITHUB_BRANCH || 'main',
    folder: env.GITHUB_FOLDER || 'uploads',
    token:  env.GITHUB_TOKEN,
  };
}

async function listFiles(env) {
  const { owner, repo, branch, folder, token } = cfg(env);
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${folder}?ref=${branch}`;
  const res = await fetch(url, { headers: ghHeaders(token) });
  if (res.status === 404) return [];
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.message || `GitHub error ${res.status}`);
  }
  const data = await res.json();
  return Array.isArray(data) ? data.filter(f => f.type === 'file') : [];
}

async function uploadFile(env, filename, base64Content) {
  const { owner, repo, branch, folder, token } = cfg(env);
  const path = `${folder}/${filename}`;
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

  // Check if file already exists (to get sha for update)
  let sha = null;
  const check = await fetch(`${apiUrl}?ref=${branch}`, { headers: ghHeaders(token) });
  if (check.ok) {
    const existing = await check.json();
    sha = existing.sha;
  }

  const body = {
    message: `Upload ${filename}`,
    content: base64Content,
    branch,
    ...(sha ? { sha } : {}),
  };

  const res = await fetch(apiUrl, {
    method: 'PUT',
    headers: ghHeaders(token),
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.message || `Upload failed: ${res.status}`);
  }
  return true;
}

async function deleteFile(env, filename, sha) {
  const { owner, repo, branch, folder, token } = cfg(env);
  const path = `${folder}/${filename}`;
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

  const res = await fetch(apiUrl, {
    method: 'DELETE',
    headers: ghHeaders(token),
    body: JSON.stringify({ message: `Delete ${filename}`, sha, branch }),
  });

  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.message || `Delete failed: ${res.status}`);
  }
  return true;
}

// ── Main handler ──────────────────────────────────────────
export async function onRequest(context) {
  const { request, env, params } = context;
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  // Route = path segments after /api/
  const segments = params.path || [];
  const route = segments.join('/');

  // ── POST /api/auth ─────────────────────────────────────
  if (route === 'auth' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (body.password === env.PASSWORD) return respond({ ok: true });
    return fail('Wrong password', 401);
  }

  // ── All other routes require auth ──────────────────────
  const pw = request.headers.get('X-Password') || '';
  if (pw !== env.PASSWORD) return fail('Unauthorized', 401);

  // ── GET /api/meta ──────────────────────────────────────
  if (route === 'meta' && method === 'GET') {
    return respond({
      repo: `${env.GITHUB_OWNER}/${env.GITHUB_REPO}`,
      folder: env.GITHUB_FOLDER || 'uploads',
    });
  }

  // ── GET /api/files ─────────────────────────────────────
  if (route === 'files' && method === 'GET') {
    try {
      const files = await listFiles(env);
      return respond(files);
    } catch (e) {
      return fail(e.message, 502);
    }
  }

  // ── POST /api/upload ───────────────────────────────────
  if (route === 'upload' && method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return fail('Invalid JSON body'); }

    const { name, content } = body;
    if (!name || !content) return fail('Missing name or content');

    // Sanitise filename — keep only safe characters
    const safe = name.replace(/[^a-zA-Z0-9._\-()\s]/g, '_').trim();
    if (!safe) return fail('Invalid filename');

    try {
      await uploadFile(env, safe, content);
      return respond({ ok: true, name: safe });
    } catch (e) {
      return fail(e.message, 502);
    }
  }

  // ── DELETE /api/delete ─────────────────────────────────
  if (route === 'delete' && method === 'DELETE') {
    let body;
    try { body = await request.json(); }
    catch { return fail('Invalid JSON body'); }

    const { name, sha } = body;
    if (!name || !sha) return fail('Missing name or sha');

    try {
      await deleteFile(env, name, sha);
      return respond({ ok: true });
    } catch (e) {
      return fail(e.message, 502);
    }
  }

  return new Response('Not found', { status: 404 });
      }
