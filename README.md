# ShareNow — Setup Guide (Cloudflare Pages)

No CLI needed. Done entirely through GitHub and Cloudflare websites.

---

## Files to upload to your GitHub repo

```
your-repo/
├── index.html
└── functions/
    └── api/
        └── [[path]].js
```

---

## Step 1 — Create GitHub repo

1. Go to github.com → New repository
2. Name: sharenow (or anything), set Public
3. Click Create repository
4. Upload the files above using Add file → Upload files
5. Also create uploads/.gitkeep  (Add file → Create new file, type that path, commit)

---

## Step 2 — Create GitHub Token

1. github.com → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token (classic)
3. Check: repo (full control)
4. Generate and COPY the token

---

## Step 3 — Deploy on Cloudflare Pages

1. dash.cloudflare.com
2. Workers & Pages → Create → Pages → Connect to Git
3. Select your repo
4. Build settings: leave everything blank (no framework, no build command)
5. Save and Deploy

---

## Step 4 — Add Environment Variables

Pages project → Settings → Environment variables → Add variable

  PASSWORD      = your chosen password
  GITHUB_TOKEN  = token from step 2
  GITHUB_OWNER  = your GitHub username
  GITHUB_REPO   = your repo name
  GITHUB_BRANCH = main
  GITHUB_FOLDER = uploads

Mark them all as Encrypted. Save, then go to Deployments → Retry deployment.

---

## Done!

Your site: https://your-project.pages.dev

Open on any device, enter password, upload and download files freely.

Max file size: ~50 MB per file.
