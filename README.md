# TRAINKUB (เทรนคับ)

(Formerly TRAINKRUB / เทรนครับ. The web address and the repository name keep the old spelling so that links keep working.)

A single-page PWA for booking and managing personal trainers.

## Files

- `index.html` — the entire app (HTML/CSS/JS in one file)
- `manifest.webmanifest` — PWA manifest (name, icons, colors)
- `service-worker.js` — offline caching
- `icons/` — app icons in all standard sizes, plus `favicon.ico`
- `vendor/` — the Supabase client library and the QR code library, served from this site
- `privacy.html`, `terms.html` — the privacy policy and the terms of use (linked from the sign-in page and from the profile)
- `richmenu/` — the two chat-menu pictures of the LINE Official Account (the `line` function reads them from this site)
- `supabase/functions/` — the two Edge Functions to paste into Supabase: `push-send` (phone pop-ups) and `line` (LINE)
- `database/` — the Supabase setup scripts (not published on the website)
- `backup/` and `.github/workflows/backup.yml` — the nightly encrypted backup with a daily check that warns when data goes missing (start with `backup/README.md`, Thai guide in `backup/GUIDE_TH.md`)

## Database (Supabase)

The browser never touches the data table. Every action goes through a small set of
server functions that check who is asking (sign-in token), what they may see or change,
and how often they may try. Passwords are stored only as bcrypt hashes in a private
schema. See `database/README.md` for the install steps.

Security notes for whoever maintains this:

- The Project URL and the *publishable* key inside `index.html` are public by design.
  Never put a `service_role` / secret key in this repo.
- Turn on two-step verification for the GitHub, Supabase and Google accounts that own this app.
- In Supabase → Authentication, switch off e-mail sign-ups (only Google sign-in is used).
- The admin sign-in is created with `select app_private.admin_set(...)` and is never stored in the code.

## LINE (sign in and messages)

The website can be opened from inside the LINE app (LIFF). Signing in there, linking an account and the notices that arrive as
LINE messages all go through one Supabase Edge Function, `supabase/functions/line/index.ts`; the browser never holds a LINE secret.
Setup steps: run `database/10_update_line.sql`, paste the function (Verify JWT off), add the three secrets
(`LINE_CHANNEL_SECRET`, `LINE_CHANNEL_ACCESS_TOKEN`, `DB_SECRET`) in Supabase → Edge Functions → Secrets, set the webhook of the
Official Account to `<project url>/functions/v1/line`, then run `select app_private.line_ping();` and `select app_private.line_setup();`.
Trainer links and QR codes keep the plain web address until `LINE_LAUNCHED` in `index.html` is set to `true`, which is done only
after the LINE Login channel has been published.
