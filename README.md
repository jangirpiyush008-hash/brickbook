# BricBook

The site plan for construction collaboration — and India's directory of architects.

**Production:** [bricbook.com](https://bricbook.com)
**Ops panel:** [admin.bricbook.com](https://admin.bricbook.com) (restricted)

## What's inside

- **Architect marketplace** — verified architects across India with rich profile pages, briefs, and booking flow.
- **Client + studio dashboards** — single sign-in, routed to the right surface by role.
- **Project workspace** — photos, drawings, chat, folders — every module scoped to floor + space.
- **Handover certificate** — printable, stamped by the studio.
- **India map view** — every project pinned by city with progress on hover.

## Stack

- **Frontend:** single-file HTML/CSS/JS SPA (`index.html`) — no build step
- **Server:** tiny Node HTTP server (`server.js`) with SPA fallback + host-based routing for `admin.bricbook.com`
- **Backend:** Supabase (Postgres + Auth + Storage + Realtime) in Mumbai (`ap-south-1`)
- **Auth:** Google OAuth + email/password (phone OTP planned)
- **Deploy:** Railway auto-deploys from `main`

## Auth

- Public users sign in on `/login` — Google or email/password
- Studios sign up at `/signup/architect`, clients at `/signup/client`
- Role is stored in `profiles.role` (`client` / `studio_member` / `studio_owner` / `ops_admin` / `super_admin`)
- Ops admins are provisioned only by SQL — no self-service or Google sign-in on the admin panel

## Run locally

```bash
node server.js
# Serves on http://localhost:8080
```

Legacy: opening `index.html` directly in a browser also renders the SPA, but the folder-indexed pages (`/privacy`, `/terms`, `/admin/`) need the Node server to resolve correctly.

## Files

| Path | Purpose |
|---|---|
| `index.html` | Main SPA (marketplace + dashboards + auth) |
| `server.js` | Static + SPA fallback + host redirect + security headers |
| `package.json` | Node 18+, `npm start` |
| `admin/` | Ops-only dashboard, served at `admin.bricbook.com` |
| `privacy/` | Privacy Policy (DPDPA 2023) |
| `terms/` | Terms of Service |
| `robots.txt`, `sitemap.xml` | SEO |

## Security notes

- Publishable Supabase key is safe to expose (row-level security enforces access at the database)
- Service-role key never lives in the browser or repo — server-side only, if used at all
- All admin actions run under signed-in user identity; database policies (`is_platform_admin()`) enforce ops-only writes
- CSP, HSTS, X-Frame-Options, Referrer-Policy set by `server.js`
