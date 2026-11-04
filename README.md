# TRAINKRUB (เทรนครับ)

A single-page PWA for booking and managing personal trainers.

## Files

- `index.html` — the entire app (HTML/CSS/JS in one file)
- `manifest.webmanifest` — PWA manifest (name, icons, colors)
- `service-worker.js` — offline caching
- `icons/` — app icons in all standard sizes, plus `favicon.ico`
- `vendor/` — the Supabase client library, served from this site
- `database/` — the Supabase setup scripts (not published on the website)

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
