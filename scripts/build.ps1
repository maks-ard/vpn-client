# Собирает vpnclient.exe и кладёт рядом sing-box.exe и пример профиля.
# Использование: .\scripts\build.ps1 [-Version dev]
param([string]$Version = "dev")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)

New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -X main.version=$Version" -o dist\vpnclient.exe .\cmd\vpnclient
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Test-Path dist\sing-box.exe)) { & "$PSScriptRoot\fetch-singbox.ps1" -Dest dist }
Copy-Item profiles\example.yaml dist\example.yaml -Force
Write-Host "Готово: dist\vpnclient.exe"
