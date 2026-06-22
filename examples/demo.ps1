#!/usr/bin/env pwsh
# ce-pin killer demo (Windows / PowerShell), mirror of examples/demo.sh.
#
# Spins up TWO local CE nodes on distinct ports (a publisher and a pinning host), grants the
# publisher a `pin:store` capability rooted at the host, pins a file on the publisher (which
# replicates it to the host over the mesh), then fetches it back BY CID from a fresh client against
# the host node — proving content-availability across the mesh with content-addressed integrity.
#
# Requirements: a `ce` binary on PATH (the CE node) and `ce-pin` built (`cargo build --release`).
# Run with: pwsh examples/demo.ps1   (PowerShell 7+ on Windows, macOS, or Linux).

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
# On Windows the built binaries carry the .exe suffix; elsewhere they do not.
$Exe   = if ($IsWindows) { '.exe' } else { '' }
$CePin = if ($env:CE_PIN) { $env:CE_PIN } else { Join-Path $Root "target/release/ce-pin$Exe" }
$Ce    = if ($env:CE) { $env:CE } else { "ce$Exe" }

$PubPort  = 8851
$HostPort = 8852

# Per-run scratch directories under the OS temp dir (Path.GetTempPath()); cleaned up on exit.
$TmpRoot  = Join-Path ([System.IO.Path]::GetTempPath()) ("ce-pin-demo-" + [System.Guid]::NewGuid().ToString('N'))
$PubData  = Join-Path $TmpRoot 'pub'
$HostData = Join-Path $TmpRoot 'host'
$Work     = Join-Path $TmpRoot 'work'
New-Item -ItemType Directory -Force -Path $PubData, $HostData, $Work | Out-Null

$Procs = [System.Collections.ArrayList]::new()
function Log($msg) { Write-Host "[demo] $msg" -ForegroundColor Cyan }
function Cleanup {
  Log 'cleaning up...'
  foreach ($p in $Procs) {
    try { if ($p -and -not $p.HasExited) { $p.Kill() } } catch { }
  }
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TmpRoot
}
trap { Cleanup; break }

if (-not (Get-Command $Ce -ErrorAction SilentlyContinue)) {
  Write-Error "need a 'ce' node binary on PATH (set `$env:CE)"; exit 1
}
if (-not (Test-Path $CePin)) {
  Write-Error 'build ce-pin first: cargo build --release'; exit 1
}

function Start-Bg([string]$file, [string[]]$cargs) {
  $p = Start-Process -FilePath $file -ArgumentList $cargs -PassThru -NoNewWindow
  [void]$Procs.Add($p)
  return $p
}

try {
  # 1. Start two local nodes.
  Log "starting publisher node on :$PubPort and host node on :$HostPort"
  Start-Bg $Ce @('start', '--data-dir', $PubData,  '--api-port', "$PubPort",  '--no-mine') | Out-Null
  Start-Bg $Ce @('start', '--data-dir', $HostData, '--api-port', "$HostPort", '--no-mine') | Out-Null
  Start-Sleep -Seconds 4

  $PubApi  = "http://127.0.0.1:$PubPort"
  $HostApi = "http://127.0.0.1:$HostPort"

  $PubId  = (& $Ce id --data-dir $PubData).Trim()
  $HostId = (& $Ce id --data-dir $HostData).Trim()
  Log ("publisher = {0}...  host = {1}..." -f $PubId.Substring(0, 16), $HostId.Substring(0, 16))

  # 2. The HOST grants the PUBLISHER a pin:store capability (signed by the host's own key).
  Log 'host grants publisher a pin:store capability'
  $Caps = (& $Ce grant $PubId --can pin:store,pin:read,pin:audit --expires 1d --data-dir $HostData).Trim()

  # 3. Start the pinning host loop on the HOST node.
  Log "starting 'ce-pin serve' on the host"
  $env:CE_API_TOKEN = (Get-Content -Raw (Join-Path $HostData 'api.token')).Trim()
  Start-Bg $CePin @('--api', $HostApi, 'serve') | Out-Null
  Start-Sleep -Seconds 2

  # 4. Create a 2 MB random file and pin it on the PUBLISHER, replicating to the host.
  $DataFile = Join-Path $Work 'dataset.bin'
  $bytes = New-Object byte[] 2000000
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  [System.IO.File]::WriteAllBytes($DataFile, $bytes)
  Log "publishing $($bytes.Length) bytes from the publisher (replication 1)"

  $env:CE_API_TOKEN = (Get-Content -Raw (Join-Path $PubData 'api.token')).Trim()
  $env:CE_PIN_CAPS  = $Caps
  $PinSet = Join-Path $Work 'pins.json'
  $addOut = & $CePin --api $PubApi --pinset $PinSet add $DataFile --replication 1 --rent 0.001 --caps $Caps
  $addOut | Write-Host
  $Cid = ([regex]'-> ([0-9a-f]{64})').Match(($addOut -join "`n")).Groups[1].Value
  Log "object CID = $Cid"

  # 5. Fetch BY CID from a fresh client pointed at the HOST node — the killer move.
  Log 'fetching by CID from the HOST node (content-availability across the mesh)'
  $env:CE_API_TOKEN = (Get-Content -Raw (Join-Path $HostData 'api.token')).Trim()
  $Fetched = Join-Path $Work 'fetched.bin'
  & $CePin --api $HostApi get $Cid --out $Fetched

  # 6. Prove byte-for-byte integrity (content addressing guarantees it).
  $a = [System.IO.File]::ReadAllBytes($DataFile)
  $b = [System.IO.File]::ReadAllBytes($Fetched)
  if (($a.Length -eq $b.Length) -and (-not (Compare-Object $a $b -SyncWindow 0))) {
    Log 'SUCCESS: fetched bytes match the original exactly (CID-verified).'
  } else {
    Write-Error 'MISMATCH - fetched bytes differ (this should be impossible with content addressing)'
    exit 1
  }

  # 7. Audit retrievability across the mesh.
  Log 'running a proof-of-retrievability audit against the holder'
  $env:CE_API_TOKEN = (Get-Content -Raw (Join-Path $PubData 'api.token')).Trim()
  $env:CE_PIN_CAPS  = $Caps
  & $CePin --api $PubApi --pinset $PinSet status $Cid --caps $Caps --audit

  Log 'demo complete.'
}
finally {
  Cleanup
}
