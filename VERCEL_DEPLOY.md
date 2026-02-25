# Deploy SciBrain to Vercel

The **frontend** is set up to deploy to Vercel. The **backend** (Node + auth) must be hosted elsewhere (e.g. Railway, Render). The backend can use **SQLite** (local file) or **Turso** (hosted libSQL) for the database.

---

## 1. Deploy frontend to Vercel

1. Push your code to GitHub (if you haven’t already).
2. Go to [vercel.com](https://vercel.com) and sign in with GitHub.
3. **Import** your `scibrain` repo.
4. Vercel will detect the project. Keep:
   - **Framework Preset:** Other
   - **Build Command:** `node scripts/inject-config.js` (or leave blank; it’s in `vercel.json`)
   - **Output Directory:** leave default (root)
5. Add an **Environment Variable** (only if you have a separate backend):
   - **Name:** `API_URL`
   - **Value:** your backend URL, e.g. `https://your-app.railway.app` (no trailing slash)
6. Click **Deploy**.

Your site will be at `https://your-project.vercel.app`. If `API_URL` is set, the app will call that URL for login, signup, and API requests.

---

## 2. (Optional) Deploy backend to Railway (with Turso)

To have auth and data work in production:

1. **Create a Turso database** (recommended for production):
   - Sign up at [turso.tech](https://turso.tech), install the CLI, then:  
     `turso db create scibrain`  
   - Get URL and token:  
     `turso db show scibrain --url` and `turso db tokens create scibrain`
2. Go to [railway.app](https://railway.app) and sign in with GitHub.
3. **New Project** → **Deploy from GitHub repo** → select your repo.
4. Set **Root Directory** to `backend`. Set **Start Command** to `node server.js` (or `npm start`).
5. In **Variables**, add:
   - `TURSO_DATABASE_URL` = your Turso URL (e.g. `libsql://scibrain-your-org.turso.io`)
   - `TURSO_AUTH_TOKEN` = your Turso auth token  
   (If you omit these, the backend will use **local SQLite**; that’s fine for a single-instance deploy but data is ephemeral on Railway unless you add a volume.)
6. Under **Settings**, add a **Public Domain** (e.g. `scibrain-api.railway.app`).
7. In **Vercel**, set **Environment Variable** `API_URL` to that URL (e.g. `https://scibrain-api.railway.app`). Redeploy the frontend.

**Note:** With **Turso**, your data is stored in a hosted libSQL database and persists across deploys. Without Turso, the backend uses a local SQLite file (ephemeral on Railway unless you use a volume).

---

## 3. Local development

- **Frontend only:** open `index.html` or run any static server from the project root. API calls go to `http://127.0.0.1:3000` when the host is localhost.
- **Full stack:** run the backend with `cd backend && node server.js`, then use the app at `http://localhost:3000` (backend serves the frontend) or your static server with `API_URL` left unset so the app uses the same host.

---

## Summary

| Part       | Where it runs | Purpose |
|-----------|----------------|---------|
| Frontend  | Vercel         | HTML, JS, CSS; uses `API_URL` for API base |
| Backend   | Railway/Render | Auth, API; use **Turso** or SQLite; set backend URL as `API_URL` in Vercel |
