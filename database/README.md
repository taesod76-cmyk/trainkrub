# Database scripts

Run these in the Supabase dashboard → SQL Editor.

## First install (in this order)

1. `01_install.sql` — adds the private tables and the server functions. Safe to run more than once.
   The website keeps working while it runs. Existing passwords are converted to bcrypt hashes.
2. Create the admin sign-in (choose your own name and a long password; do not keep it in any file):

   ```sql
   select app_private.admin_set('your-admin-name', 'a-long-password-of-12-or-more-characters');
   ```

   Running it again later replaces the admin password, signs the admin out everywhere and clears any
   lockout (use it if the admin is ever locked out).
3. Publish the new website version (this repo → GitHub Pages).
4. `02_lockdown.sql` — only after step 3. Removes the old open policies so nobody can read or write the
   table directly any more; only the server functions can.

After step 4 nobody (including someone holding the public key) can read the data table, list users, or
read a password, and every sign-in attempt, wrong password and sensitive action is logged in
`app_private.audit` (kept 180 days; readable only from the SQL editor).

## Updating a database that is already installed

- `03_update_trainer_signup.sql` — trainers who apply are accepted at once (no waiting for the admin).
  Run it once, **before** publishing the website version that goes with it. Safe to run more than once;
  it only replaces server functions and does not touch any data.

`01_install.sql` already contains everything in `03_update_trainer_signup.sql`, so a brand-new install
does not need it.

## Trainer sign-up

A trainer applies with a password or with Google. The server creates the trainer account, the trainer
code and the sign-in token in one step, and the app opens the trainer dashboard straight away.
Certificate pictures are uploaded one by one before that step with a single-use upload token. If the
upload step is cut off, the application is completed the next time the applicant signs in with the same
password or the same Google account. The admin can still suspend any trainer from the admin page.
