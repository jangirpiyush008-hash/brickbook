# BricBook

The site plan for construction collaboration — and India's directory of architects.

**Live demo:** open `index.html` in any browser, or serve the folder and visit the root.

## What's inside

A single-file prototype (`index.html` / `bricbook.html`) that ships:

- **Architect marketplace landing** — 12 verified architects, detailed search bar (project type / city / budget / start-by / built-up area), refine chips, popular tags, individual architect profile pages with portfolio + reviews + booking sidebar.
- **Dual dashboards** — Studio (architects) and Customer (clients) with a login toggle. Each sees only what they should. Unique per-project Customer IDs.
- **Four project modules** — Gallery, Files, Chat, Folders. Every module scoped to floor + space.
- **Full gallery lightbox** with a drawing toolbar — pencil / rectangle / square / circle / arrow, six colors, three sizes. Every mark becomes a linked comment. Undo, clear, keyboard shortcuts.
- **WhatsApp delivery** everywhere — send photos, drawings, and project updates to clients in one click; each send is logged in the project timeline.
- **Handover certificate** — printable, signed by Ar. Nishant Yadav, stamped by the studio.
- **India map view** — every project pinned by city with progress on hover.
- **Skeleton loader** on sign-in, light + dark themes.

## Demo credentials

| Role | Email | Password |
|---|---|---|
| Studio / Architect | `demo@bricbook.com` | `demo1234` |
| Customer / Client | `client@kaustubh.com` | `client1234` |
| BricBook admin | `admin@bricbook.com` | `admin1234` |

Google sign-in button is a mock — clicks straight through to the respective dashboard.

## Deploy

Any static host works — Netlify Drop, Vercel, GitHub Pages, Cloudflare Pages.

**GitHub Pages:** Settings → Pages → Source: `main` / `/ (root)` → Save. The site will be live at `https://<user>.github.io/brickbook/` in ~30 seconds.

**Netlify Drop:** drag the whole folder onto https://app.netlify.com/drop — instant URL.

## Stack

Vanilla HTML/CSS/JS in one file. No build step, no dependencies, no external requests. All SVG illustrations are inline — works offline.
