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

`01_install.sql` always contains everything in the update scripts below, so a brand-new install needs
only the four steps above.

## Updating a database that is already installed

Run the updates you have not run yet, in this order. Each is safe to run more than once and only replaces
server functions (`05` also closes out requests that were still waiting, see below).
Run it **before** publishing the website version that goes with it.

- `03_update_trainer_signup.sql` — trainers who apply are accepted at once (no waiting for the admin).
- `04_update_light_refresh.sql` — lighter background refresh: a small call for the admin dashboard numbers,
  no profile pictures in the admin's lists, and suspending a user keeps the stored picture.
- `05_update_auto_confirm.sql` — a customer's booking is confirmed at once and goes straight onto the trainer's
  schedule (the trainer already set the notice time). Requests that were still waiting today are turned into
  bookings: when two people asked for the same time the first one gets it and the other is declined, and times
  that have already passed are closed. After it ran, no booking stays "pending".

## Trainer sign-up

A trainer applies with a password or with Google. The server creates the trainer account, the trainer
code and the sign-in token in one step, and the app opens the trainer dashboard straight away.
Certificate pictures are uploaded one by one before that step with a single-use upload token. If the
upload step is cut off, the application is completed the next time the applicant signs in with the same
password or the same Google account. The admin can still suspend any trainer from the admin page.
