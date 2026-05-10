$ErrorActionPreference = 'Stop'
Write-Host '==> Build mail-bridge'
if (!(Test-Path dist)) { New-Item -ItemType Directory -Force dist | Out-Null }

$go = 'C:\Program Files\Go\bin\go.exe'
& $go version

Write-Host '==> go mod tidy'
& $go mod tidy | Tee-Object -FilePath build.log -Append

Write-Host '==> go build'
& $go build -v -o dist\mail-bridge.exe .\cmd\mail-bridge 2>&1 | Tee-Object -FilePath build.log -Append

if (Test-Path dist\mail-bridge.exe) {
  Write-Host '==> build OK'
} else {
  Write-Host '==> build FAILED. See build.log'
  exit 1
}



