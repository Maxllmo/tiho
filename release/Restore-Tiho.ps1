param([switch]$RunInstaller)
$ErrorActionPreference = 'Stop'
$Manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Tiho-Windows.manifest.json') -Raw | ConvertFrom-Json
$Ready = Join-Path $PSScriptRoot 'ready'
New-Item -ItemType Directory -Force $Ready | Out-Null
$Archive = Join-Path $Ready 'Tiho-Windows.zip'
$Temporary = $Archive + '.' + [Guid]::NewGuid().ToString('N') + '.partial'
try {
    foreach ($Part in $Manifest.parts) {
        if ([IO.Path]::GetFileName([string]$Part.name) -ne $Part.name) { throw 'Invalid archive part name.' }
        $Path = Join-Path $PSScriptRoot $Part.name
        if (!(Test-Path -LiteralPath $Path)) { throw "Missing archive part: $($Part.name). Download the whole repository ZIP and extract it first." }
        Write-Host "Checking $($Part.name)..."
        if ((Get-Item -LiteralPath $Path).Length -ne $Part.size) { throw "Wrong file size: $($Part.name)" }
        if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Part.sha256) { throw "Checksum mismatch: $($Part.name)" }
    }
    Write-Host 'Restoring Tiho installer...'
    $Destination = [IO.File]::Open($Temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        foreach ($Part in $Manifest.parts) {
            $Source = [IO.File]::OpenRead((Join-Path $PSScriptRoot $Part.name))
            try { $Source.CopyTo($Destination) } finally { $Source.Dispose() }
        }
    } finally { $Destination.Dispose() }
    if ((Get-FileHash -LiteralPath $Temporary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Manifest.archive_sha256) { throw 'Archive checksum mismatch.' }
    Move-Item -LiteralPath $Temporary -Destination $Archive -Force
    Expand-Archive -LiteralPath $Archive -DestinationPath $Ready -Force
    $Installer = Join-Path $Ready 'Tiho-Setup.exe'
    if ((Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Manifest.installer_sha256) { throw 'Installer checksum mismatch.' }
    Write-Host "Ready: $Installer"
    if ($RunInstaller) { Start-Process -FilePath $Installer -Verb RunAs }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
} finally {
    if (Test-Path -LiteralPath $Temporary) { Remove-Item -LiteralPath $Temporary -Force }
}
