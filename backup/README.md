# TRAINKUB nightly backup

Every night at 03:40 (Thailand time) GitHub runs `.github/workflows/backup.yml`:

1. Signs in to the database with a **read-only** login (`backup_ro`, made by `database/09_backup_access.sql`). It can read the five data tables and nothing else; it cannot change or delete anything and cannot call any app function.
2. Reads the five tables in one consistent snapshot: `public.kv_store`, `app_private.cred`, `app_private.push_config`, `app_private.push_subs`, `app_private.audit`.
3. **Checks the numbers against the last good night.** If a group of data dropped too far (for example all bookings gone, or 10% of the customers) the job fails, GitHub e-mails the owner, and the numbers are **not** taken as the new normal, so the alarm repeats every night until somebody looks.
4. Packs the data and **locks it with the public certificate** `backup/backup_cert.pem`. Only the private key (`D:\TRAINKUB_BACKUP_KEY\backup_private.pem`, kept on the owner's own computer) opens it. The locked file is kept 90 days as a workflow artifact.
5. A second job checks that the website and the database door answer.

The log of this repository is public, so the job never prints a count or a name: only group names and percentages.

## One-time setup

1. Supabase > SQL Editor: run `database/09_backup_access.sql`. The result shows a one-time **password** for the login `backup_ro`. Copy it.
2. Supabase > Connect > **Session pooler**: copy the host (looks like `aws-0-xx-xxxx-x.pooler.supabase.com`). Use the Session pooler, not the "Direct connection" (that one needs IPv6, GitHub does not have it) and not the Transaction pooler.
3. GitHub > repository > Settings > Secrets and variables > Actions:
   - Secrets > New repository secret: name `BACKUP_DB_PASSWORD`, value = the password from step 1.
   - Variables > New repository variable: name `BACKUP_DB_HOST`, value = the host from step 2.
4. The key pair: run `backup/gen_backup_key.ps1` once on the owner's computer. It writes the private key to `D:\TRAINKUB_BACKUP_KEY\` and the public certificate next to it; put the certificate at `backup/backup_cert.pem` in this repository (the round 19 deploy already did). **Copy `backup_private.pem` to a second place (a USB stick). Without it no backup can be opened, and nobody (not GitHub, not Anthropic, not the developer) can make a new one for old backups.**
5. GitHub > Actions > "Nightly backup and check" > Run workflow. It should end green. Then run it again with **simulate_alarm** ticked: it must end red and GitHub must send an e-mail (check GitHub > Settings > Notifications > Actions that e-mail is on for failed workflows).

If the database password is changed (running `09_backup_access.sql` again makes a new one), update the secret `BACKUP_DB_PASSWORD` too.

## If the alarm comes (the e-mail says DATA LOOKS MISSING)

1. Open the failed run on GitHub > Actions. The log names the group (for example `every "booking" row is gone`) and a percentage.
2. Look at the app. If the data really is gone, restore (below). Do **not** run anything that deletes more.
3. If the drop was meant (for example you cleared old test data on purpose), run the workflow once with **accept** ticked: tonight's numbers become the new normal and the alarm stops.

## If the backup fails (the e-mail says BACKUP FAILED)

Open the log. The usual causes: the password in the secret is old (run `09_backup_access.sql` again and update the secret), the Supabase project is paused (open the Supabase dashboard and restore it), or the host is not the Session pooler.

## Restoring

Needs Python and Git for Windows on the owner's computer (already there).

1. GitHub > Actions > a green run > Artifacts > `backup-...` (a zip). Unzip it and put the `.cms` file in `D:\TRAINKUB_BACKUPS\`.
2. `powershell -ExecutionPolicy Bypass -File backup\restore_backup.ps1 -Mode missing`
   writes `RESTORE_01.sql`, `RESTORE_02.sql` ... into `D:\TRAINKUB_RESTORE\<time>_missing\` (nothing touches the database yet).
3. Paste the files one by one into Supabase > SQL Editor and press Run, in order.

| Mode | What happens | Use it for |
|---|---|---|
| `missing` (default) | rows that are gone are put back; rows that exist stay exactly as they are | something was deleted |
| `overwrite` | rows are put back and a row that exists is replaced by the backup copy | a wrong change must be undone |
| `replace` | the tables are emptied first, then filled from the backup | a brand-new database (after `01_install.sql`) or a total reset |

Filters: `-Prefix booking,custpkg` (only those groups of kv_store), `-Keys customer:c_ab12,trainer:t_x` (only those rows). `replace` cannot be combined with a filter.

Restoring old notices never pops them up on phones again (the push trigger is switched off while the files run and back on after).

A whole new database: run `database/01_install.sql`, then restore with `-Mode replace`, then run `database/09_backup_access.sql` again and update the secret.

## What is not in the backup

The structure of the database (tables, functions, rules) is not backed up because it is in `database/01_install.sql`. Supabase's own sign-in table is not used by the app. The app's code is this repository.

## Limits to know

- Files are kept 90 days. A loss noticed later than that cannot be restored from GitHub: download one backup a month to `D:\TRAINKUB_BACKUPS\` and keep it.
- GitHub switches scheduled jobs off after 60 days without activity in a public repository. The job refreshes this itself each night; look at the Actions page once a month and check for a green tick from last night.
- In a public repository anybody signed in to GitHub can download the artifact, but it is locked: it only opens with the private key. Moving the repository to private is still better.
- The cost is zero (GitHub Actions on a public repository is free).
