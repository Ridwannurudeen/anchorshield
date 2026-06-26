$ErrorActionPreference = "Stop"

$repo = (Get-Location).Path
$drive = $repo.Substring(0, 1).ToLowerInvariant()
$rest = $repo.Substring(2).Replace("\", "/")
$wslRepo = "/mnt/$drive$rest"

wsl bash -lc "cd '$wslRepo' && node scripts/m1-circuit-smoke.js"
exit $LASTEXITCODE
