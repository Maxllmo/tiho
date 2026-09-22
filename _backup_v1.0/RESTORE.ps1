$ErrorActionPreference = "Stop"
$backup = $PSScriptRoot
$project = Split-Path $backup -Parent
$from = Join-Path $backup "ProxyHub"
$to = Join-Path $project "ProxyHub"

Write-Host "Останавливаю ProxyHub, если он запущен..."
Get-Process -Name "ProxyHub" -ErrorAction SilentlyContinue | Stop-Process -Force

if (-not (Test-Path $from)) {
    throw "Не найдена папка $from"
}

New-Item -ItemType Directory -Force -Path $to | Out-Null
& robocopy $from $to /E /XD bin obj /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
$code = $LASTEXITCODE
if ($code -ge 8) {
    throw "robocopy завершился с кодом $code"
}

Write-Host "Восстановлена версия 1.0 из _backup_v1.0"
Write-Host "Пересоберите: dotnet build `"$to\ProxyHub.csproj`" -c Release"
