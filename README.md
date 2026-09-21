# TRAINKRUB (เทรนครับ)

A single-page PWA for booking and managing personal trainers.

## Files

- `index.html` — the entire app (HTML/CSS/JS in one file)
- `manifest.webmanifest` — PWA manifest (name, icons, colors)
- `service-worker.js` — offline caching
- `icons/` — app icons in all standard sizes, plus `favicon.ico`

## Connect a real database (Supabase)

By default the app stores everything in the browser only (`localStorage`),
so data doesn't sync between visitors/devices. To make it a real shared
backend:

1. Create a free project at [supabase.com](https://supabase.com).
2. In your project, go to **SQL Editor → New query**, paste in the contents
   of `supabase-setup.sql` from this ZIP, and run it. This creates the
   single table the app uses for all its data.
3. Go to **Project Settings → API**. Copy the **Project URL** and the
   **anon public** key (not the `service_role` key — never put that one in
   a public file).
4. Open `index.html` in a text editor and find these two lines near the
   top of the `<script>` block:
   ```js
   const SUPABASE_URL = '';
   const SUPABASE_ANON_KEY = '';
   ```
   Paste your values in between the quotes, e.g.
   ```js
   const SUPABASE_URL = 'https://xxxxxxxxxxxx.supabase.co';
   const SUPABASE_ANON_KEY = 'eyJhbGciOi...';
   ```
5. Save, re-upload `index.html` to GitHub (or push the change), done.

**Note on security:** the SQL script leaves the table open to anyone with
your anon key (matching how the app's own login already works — it's
enforced in the browser, not the database). That's fine for a demo, but
don't store anything sensitive in it as-is. If you need real security,
wire up Supabase Auth and swap the four `using (true)` policies for rules
based on `auth.uid()`.

If you leave `SUPABASE_URL`/`SUPABASE_ANON_KEY` blank, the app keeps
working exactly as before, just without cross-device syncing.

## Deploy to GitHub Pages

1. Create a new repository on GitHub (e.g. `trainkrub`).
2. Upload all the files/folders in this ZIP to the root of that repository
   (keep the `icons/` folder as-is).
3. Go to **Settings → Pages**.
4. Under **Build and deployment**, set **Source** to `Deploy from a branch`,
   branch `main`, folder `/ (root)`, then **Save**.
5. Wait a minute, then open the URL GitHub gives you
   (usually `https://<your-username>.github.io/trainkrub/`).

That's it — no build step, no server required. On phones, visitors can use
"Add to Home Screen" to install it like an app.
