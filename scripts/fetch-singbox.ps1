# Скачивает официальную сборку sing-box для Windows.
# Использование: .\scripts\fetch-singbox.ps1 [-Version 1.14.4] [-Dest dist]
param(
    [string]$Version = "1.14.4",
    [string]$Dest = "dist",
    [ValidateSet("amd64", "arm64", "386")]
    [string]$Arch = "amd64"
)
$ErrorActionPreference = "Stop"

$name = "sing-box-$Version-windows-$Arch"
$url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/$name.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp, $Dest | Out-Null
try {
    Write-Host "Скачиваю $url"
    Invoke-WebRequest -Uri $url -OutFile "$tmp\sb.zip" -UseBasicParsing
    Expand-Archive -Path "$tmp\sb.zip" -DestinationPath $tmp
    Copy-Item "$tmp\$name\sing-box.exe" -Destination $Dest -Force
    & "$Dest\sing-box.exe" version
} finally {
    Remove-Item -Recurse -Force $tmp
}
