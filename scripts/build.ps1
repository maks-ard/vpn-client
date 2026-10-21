# Собирает vpnclient.exe так же, как релиз: со встроенным sing-box,
# иконкой и манифестом. Использование: .\scripts\build.ps1 [-Version dev] [-Arch amd64]
param(
    [string]$Version = "dev",
    [string]$SingBoxVersion = "1.14.3",
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)

New-Item -ItemType Directory -Force -Path dist | Out-Null
& "$PSScriptRoot\fetch-singbox.ps1" -Version $SingBoxVersion -Arch $Arch -Dest internal\singboxbin
go run github.com/tc-hib/go-winres@v0.3.3 make --in winres\winres.json --arch $Arch --out cmd\vpnclient\rsrc --product-version $Version --file-version $Version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$env:GOOS = "windows"
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"
go build -trimpath -tags embed_singbox `
    -ldflags "-s -w -H windowsgui -X main.version=$Version -X github.com/maks-ard/vpn-client/internal/singboxbin.Version=$SingBoxVersion" `
    -o dist\vpnclient.exe .\cmd\vpnclient
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Готово: dist\vpnclient.exe"
