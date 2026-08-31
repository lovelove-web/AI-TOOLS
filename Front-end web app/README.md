# Pulse — BMI Calculator

A modern, responsive BMI calculator with an animated gauge, dark mode, health
recommendations, and local history tracking. Static HTML/CSS/JS — no build
step, no dependencies.

## Files

```
index.html    Markup
style.css     Design tokens, layout, gauge, light/dark themes
script.js     BMI math, gauge animation, history (localStorage), theme toggle
vercel.json   Static deployment config (security headers, clean URLs)
```

## Run locally

Just open `index.html` in a browser, or serve it with any static server:

```bash
npx serve .
```

## Deploy to Vercel

**Option A — Vercel CLI**
```bash
npm install -g vercel
vercel
```
Follow the prompts; when asked for a framework preset, choose "Other" (this
is a static site, no build command needed).

**Option B — Git + Vercel dashboard**
1. Push this folder to a GitHub/GitLab/Bitbucket repo.
2. In the Vercel dashboard, click **New Project** and import the repo.
3. Framework preset: **Other**. Build command: none. Output directory: `.`
4. Deploy.

## Notes

- All data (history, theme preference) is stored in the browser's
  `localStorage` — nothing is sent to a server.
- BMI zone thresholds: Underweight < 18.5, Healthy 18.5–24.9,
  Overweight 25–29.9, Obese ≥ 30 (standard WHO adult ranges).
- The recommendations are general wellness information, not medical advice —
  see the in-app disclaimer.
