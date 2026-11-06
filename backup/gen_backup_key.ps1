# TRAINKUB: makes the key pair for the nightly backup (run once).
#   - backup_cert.pem    the PUBLIC certificate. It goes into the repository; it can only LOCK backups.
#   - backup_private.pem the PRIVATE key. It stays on this computer; it is the only thing that can OPEN a backup.
# Never put backup_private.pem into the repository, an e-mail or a chat. Keep two copies (this computer + a USB stick).
param(
  [string]$KeyDir = 'D:\TRAINKUB_BACKUP_KEY',
  [string]$Log = ''
)
$ErrorActionPreference = 'Continue'
function Say($m) { Write-Host $m; if ($Log) { Add-Content -Path $Log -Value $m -Encoding ascii } }
if ($Log) { Set-Content -Path $Log -Value 'START' -Encoding ascii }
try {
  $ossl = $null
  foreach ($c in 'C:\Program Files\Git\mingw64\bin\openssl.exe', 'C:\Program Files\Git\usr\bin\openssl.exe', 'C:\Program Files (x86)\Git\mingw64\bin\openssl.exe') {
    if (Test-Path $c) { $ossl = $c; break }
  }
  if (-not $ossl) { $x = Get-Command openssl -ErrorAction SilentlyContinue; if ($x) { $ossl = $x.Source } }
  if (-not $ossl) { Say 'FAIL: openssl was not found (install Git for Windows)'; Say 'END'; return }
  Say ('openssl: ' + $ossl)
  foreach ($cnf in 'C:\Program Files\Git\mingw64\etc\ssl\openssl.cnf', 'C:\Program Files\Git\usr\ssl\openssl.cnf') {
    if (Test-Path $cnf) { $env:OPENSSL_CONF = $cnf; break }
  }
  if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Path $KeyDir -Force | Out-Null }
  $priv = Join-Path $KeyDir 'backup_private.pem'
  $cert = Join-Path $KeyDir 'backup_cert.pem'
  if ((Test-Path $priv) -and (Test-Path $cert)) {
    Say 'The key pair already exists - nothing was changed.'
  } elseif ((Test-Path $priv) -or (Test-Path $cert)) {
    Say 'FAIL: only one of the two files exists in the key folder - stop, nothing was changed'; Say 'END'; return
  } else {
    & $ossl req -x509 -newkey rsa:4096 -nodes -keyout $priv -out $cert -days 36500 -subj '/CN=TRAINKUB-backup' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $priv) -or -not (Test-Path $cert)) { Say ('FAIL: could not make the key pair, exit ' + $LASTEXITCODE); Say 'END'; return }
    try { & icacls $priv /inheritance:r /grant:r ($env:USERNAME + ':(R,W)') 2>&1 | Out-Null } catch { }
    Say 'key pair made'
  }
  # self test: lock a small file with the certificate, open it with the key, compare
  $tmp = Join-Path $KeyDir 'selftest'
  Set-Content -Path ($tmp + '.txt') -Value ('trainkub self test ' + [guid]::NewGuid().ToString('N')) -Encoding ascii
  & $ossl cms -encrypt -binary -aes-256-cbc -outform DER -in ($tmp + '.txt') -out ($tmp + '.cms') $cert 2>&1 | Out-Null
  & $ossl cms -decrypt -binary -inform DER -in ($tmp + '.cms') -inkey $priv -out ($tmp + '.out') 2>&1 | Out-Null
  $a = (Get-FileHash ($tmp + '.txt') -Algorithm SHA256).Hash
  $b = ''
  if (Test-Path ($tmp + '.out')) { $b = (Get-FileHash ($tmp + '.out') -Algorithm SHA256).Hash }
  Remove-Item ($tmp + '.txt'), ($tmp + '.cms'), ($tmp + '.out') -Force -ErrorAction SilentlyContinue
  Say ('self test (lock with certificate, open with key): ' + ($a -eq $b))
  if ($a -ne $b) { Say 'FAIL: the key pair does not work'; Say 'END'; return }
  $pubTxt = Get-Content $cert -Raw
  Say ('certificate is public: ' + $pubTxt.StartsWith('-----BEGIN CERTIFICATE-----'))
  Say ('private key file is private: ' + ((Get-Content $priv -Raw).Contains('PRIVATE KEY')))
  Say ('cert sha256: ' + (Get-FileHash $cert -Algorithm SHA256).Hash.ToLower())
  Say ('KEYDIR: ' + $KeyDir)
  Say 'KEYPAIR OK'
} catch {
  Say ('EXCEPTION: ' + $_.Exception.Message)
}
Say 'END'
