# StoreGit

A file storage service where each user stores files in their own GitHub repository. Users can securely upload, access, download, and manage files from any device using their **username** and **password**.

---

## How It Works

```
┌──────────────────────────────────────────────────────┐
│              Cloudflare Pages (Operator Managed)               │
│                                                                │
│   User A ─────► GitHub Repo A (Files)                         │
│   User B ─────► GitHub Repo B (Files)                         │
│   User C ─────► GitHub Repo C (Files)                         │
│                                                                │
│   Registry Repo ─────► Stores All User Accounts               │
└──────────────────────────────────────────────────────┘
```

- The **operator** deploys once and sets four environment variables.
- **Users** sign up with a username, password, and their own GitHub repository. No server or hosting required on their end.
- Passwords are hashed with **PBKDF2-SHA256** (100,000 iterations). GitHub tokens are **AES-256-GCM encrypted** server-side. Session tokens are **AES-256-GCM encrypted and HMAC-SHA256 signed** — the client sees an opaque blob.
- Files up to **95 MB** are supported (20 MB via Contents API, above that via Git Blobs API).

---

## User Setup

Users visit the website `https://storegit.pages.dev` and click **Create one** on the login page.

They need:
1. A GitHub account
2. A GitHub repository (any name, **private**(*recommended*) or public)
3. A GitHub token with **repo** scope for that repository

The setup wizard walks them through creating the repository and **token**, verifies access, and registers their account. Their GitHub token is **encrypted** server-side before storage and is never visible after the setup step completes.

Once registered, users can **sign in** from any device using their username and password.

---

## Security Overview

| Concern | Implementation |
|---|---|
| Password storage | PBKDF2-SHA256, 100,000 iterations, random 16-byte salt per user |
| GitHub token storage | AES-256-GCM, key derived from TOKEN_SECRET + username via HKDF |
| Session tokens | AES-256-GCM encrypted payload + HMAC-SHA256 signature, 8-hour expiry |
| GitHub URLs | Never sent to the browser — all downloads go through a server-side proxy |
| Brute force | 5 attempts per 15-minute window per IP, with artificial delay on failure |
| File upload | Extension blocklist + magic byte scanner (PE, ELF, Mach-O, PHP, scripts) |
| CORS | Same-origin only, no wildcard |
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Timing attacks | Constant-time comparison for all credential verification |

---

## File Size Limits

| Plan | Effective upload limit |
|---|---|
| Cloudflare Pages Free | ~70 MB |
| Cloudflare Pages Pro | ~95 MB |
| GitHub Git Blobs API | 100 MB hard cap |

Files at or below 20 MB use the GitHub Contents API. Files above 20 MB automatically use the Git Data API (blob → tree → commit → ref update), which supports up to 95 MB within Cloudflare's request body limits.

---

## Blocked File Types

The following extensions are blocked on both the client and server. The server additionally scans the first 16 bytes of every file for known executable signatures (Windows PE, ELF, Mach-O, Java class, shell shebangs, PHP headers, HTML/script tags), regardless of extension.

`exe bat cmd com msi ps1 sh bash zsh php asp aspx jsp py rb pl lua js ts html htm svg xml htaccess dll so dylib vbs jar scr reg lnk dmg pkg apk` and others.
