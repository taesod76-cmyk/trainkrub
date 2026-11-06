# TRAINKUB: opens a nightly backup on THIS computer and writes the restore SQL files (it never touches the database).
#   powershell -ExecutionPolicy Bypass -File restore_backup.ps1                          newest backup in D:\TRAINKUB_BACKUPS, mode "missing"
#   powershell -ExecutionPolicy Bypass -File restore_backup.ps1 -Mode overwrite -Prefix booking,custpkg
#   powershell -ExecutionPolicy Bypass -File restore_backup.ps1 -Backup D:\somewhere\trainkub-backup-XXXX.tar.gz.cms -Mode replace
# Modes: missing (put back only rows that are gone) | overwrite (also replace rows that exist) | replace (empty the tables first: new database only)
param(
  [string]$Backup = '',
  [ValidateSet('missing', 'overwrite', 'replace')][string]$Mode = 'missing',
  [string]$Prefix = '',
  [string]$Keys = '',
  [string]$Key = 'D:\TRAINKUB_BACKUP_KEY\backup_private.pem',
  [string]$BackupDir = 'D:\TRAINKUB_BACKUPS',
  [string]$Out = ''
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Backup) {
  $f = Get-ChildItem $BackupDir -Filter '*.cms' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
  if (-not $f) { Write-Host ('No backup file in ' + $BackupDir + '. Download one from GitHub > Actions and put it there.'); return }
  $Backup = $f.FullName
}
if (-not (Test-Path $Key)) { Write-Host ('The private key is not at ' + $Key); return }
if (-not $Out) { $Out = 'D:\TRAINKUB_RESTORE\' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + $Mode }
Write-Host ('backup: ' + $Backup)
$args2 = @((Join-Path $here 'restore_make_sql.py'), '--cms', $Backup, '--key', $Key, '--out', $Out, '--mode', $Mode)
if ($Prefix) { $args2 += @('--prefix', $Prefix) }
if ($Keys) { $args2 += @('--keys', $Keys) }
& python @args2
if ($LASTEXITCODE -ne 0) { Write-Host 'Failed - nothing was written to the database (it never is by this script).'; return }
Write-Host ''
Write-Host ('Next: open each RESTORE_xx.sql in ' + $Out + ' in order, paste it into Supabase > SQL Editor, press Run.')
try { Start-Process explorer.exe $Out } catch { }
