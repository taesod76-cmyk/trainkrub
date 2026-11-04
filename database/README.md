# Database scripts

Run these in the Supabase dashboard → SQL Editor, in this order.

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
