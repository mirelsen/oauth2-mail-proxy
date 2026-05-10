# --- Instalează MailBridge ca serviciu cu NSSM (fără user/parolă) ---
# Rulează ca Administrator.

$svcName     = "MailBridge"
$exePath     = "C:\proxy-mail\dist\mail-bridge.exe"
$configPath  = "C:\proxy-mail\mail-bridge.yml"
$workDir     = "C:\proxy-mail"
$logPathOut  = "C:\proxy-mail\mail-bridge.out.log"
$logPathErr  = "C:\proxy-mail\mail-bridge.err.log"

# 0) Verificări
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { throw "Deschide PowerShell 'Run as Administrator'." }
if (-not (Test-Path $exePath))    { throw "Nu găsesc EXE: $exePath" }
if (-not (Test-Path $configPath)) { throw "Nu găsesc config: $configPath" }
if (-not (Test-Path $workDir))    { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }

# 1) Ia NSSM (2.24) dacă nu e deja
$nssmDir  = Join-Path $workDir "nssm"
$nssmExe  = Join-Path $nssmDir "nssm.exe"
if (-not (Test-Path $nssmExe)) {
  Write-Host "-> Descarc NSSM..."
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $zipUrl = "https://nssm.cc/release/nssm-2.24.zip"
  $zip    = Join-Path $workDir "nssm.zip"
  Invoke-WebRequest -Uri $zipUrl -OutFile $zip
  if (Test-Path $nssmDir) { Remove-Item $nssmDir -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $workDir -Force
  Remove-Item $zip -Force
  $srcExe = Join-Path $workDir "nssm-2.24\win64\nssm.exe"
  if (-not (Test-Path $srcExe)) { throw "Nu găsesc nssm.exe în arhivă." }
  New-Item -ItemType Directory -Path $nssmDir -Force | Out-Null
  Copy-Item $srcExe $nssmExe -Force
}

# 2) Șterge serviciu vechi (dacă există)
$old = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($old) {
  & $nssmExe stop $svcName | Out-Null
  sc.exe delete $svcName | Out-Null
  Start-Sleep -Seconds 1
}

# 3) Instalează serviciul
& $nssmExe install $svcName $exePath | Out-Null
# Parametri aplicație (argumente)
& $nssmExe set $svcName AppParameters ("--config `"$configPath`"") | Out-Null
# Director de lucru
& $nssmExe set $svcName AppDirectory $workDir | Out-Null
# Auto start
& $nssmExe set $svcName Start SERVICE_AUTO_START | Out-Null
# Delayed Auto Start
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name DelayedAutoStart -Value 1
# Restart policy
sc.exe failure $svcName reset= 86400 actions= restart/600/restart/600/restart/600 | Out-Null
sc.exe failureflag $svcName 1 | Out-Null
# Loguri
& $nssmExe set $svcName AppStdout $logPathOut | Out-Null
& $nssmExe set $svcName AppStderr $logPathErr | Out-Null
& $nssmExe set $svcName AppStdoutCreationDisposition 4 | Out-Null  # append
& $nssmExe set $svcName AppStderrCreationDisposition 4 | Out-Null  # append
& $nssmExe set $svcName AppRotateFiles 1 | Out-Null
& $nssmExe set $svcName AppRotateOnline 1 | Out-Null
& $nssmExe set $svcName AppRotateBytes 10485760 | Out-Null  # 10 MB

# 4) Pornește serviciul
& $nssmExe start $svcName | Out-Null
Start-Sleep -Seconds 2
Get-Service -Name $svcName

Write-Host "`n✅ Gata. UI (dacă e activ) pe: http://127.0.0.1:7777"
Write-Host "Log OUT: $logPathOut"
Write-Host "Log ERR: $logPathErr"
Write-Host "Comenzi utile: `n  & `"$nssmExe`" restart $svcName  `n  & `"$nssmExe`" stop $svcName  `n  sc.exe delete $svcName"
