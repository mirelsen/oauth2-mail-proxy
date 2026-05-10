# oauth2-mail-proxy

Proxy local IMAP/SMTP cu autentificare OAuth2 (Gmail si Microsoft 365), plus UI de administrare web.

## Ce face proiectul

- expune local SMTP pe `127.0.0.1:1025`
- expune local IMAP pe `127.0.0.1:1143`
- expune Admin UI pe `127.0.0.1:7777`
- permite folosirea clientilor clasici de mail fara parolele reale de provider

## Cerinte

- Windows 10/11
- Go 1.22+
- PowerShell

## Build rapid

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Executabilul rezultat va fi in `dist\mail-bridge.exe`.

## Configurare

1. Copiaza exemplul:

```powershell
copy .\scripts\mail-bridge.yml.example .\mail-bridge.yml
```

2. Completeaza in `mail-bridge.yml`:
- conturile (`accounts`)
- aplicatiile OAuth (`oauth_apps`)
- hash-ul pentru parola de admin (`security.admin_password_hash`)

Pentru hash parola poti folosi utilitarul:

```powershell
go run .\cmd\hashpw
```

## Rulare manuala

```powershell
.\dist\mail-bridge.exe --config .\mail-bridge.yml
```

## Instalare ca serviciu Windows (autostart)

Scriptul `service.ps1` instaleaza serviciul prin NSSM, seteaza restart policy si pornire automata.

Ruleaza PowerShell ca Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\service.ps1
```

Serviciul va porni automat dupa restart.

## Fisiere sensibile

Fisierul local `mail-bridge.yml` este ignorat in Git (contine secrete). Commit-urile trebuie facute fara credentiale reale.
