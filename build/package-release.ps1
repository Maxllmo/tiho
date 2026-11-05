$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$Installer = Join-Path $Root 'output/Tiho-Setup.exe'
if (!(Test-Path -LiteralPath $Installer)) { throw 'Build output/Tiho-Setup.exe first.' }
$Work = Join-Path $Root 'work'
$Release = Join-Path $Root 'release'
New-Item -ItemType Directory -Force $Work, $Release | Out-Null
$Archive = Join-Path $Work 'Tiho-Windows.zip'
if (Test-Path -LiteralPath $Archive) { Remove-Item -LiteralPath $Archive -Force }
# The installer is already compressed with LZMA. Wrapping it in ZIP avoids a second slow compression pass.
Compress-Archive -LiteralPath $Installer -DestinationPath $Archive -CompressionLevel NoCompression
Get-ChildItem -LiteralPath $Release -Filter 'Tiho-Windows.zip.*' | Remove-Item -Force
$Parts = @()
$ArchiveInput = [IO.File]::OpenRead($Archive)
try {
    $Buffer = New-Object byte[] (1MB)
    $Index = 1
    while ($ArchiveInput.Position -lt $ArchiveInput.Length) {
        $Name = 'Tiho-Windows.zip.{0:D3}' -f $Index
        $Path = Join-Path $Release $Name
        $PartOutput = [IO.File]::Create($Path)
        try {
            $Remaining = 90MB
            while ($Remaining -gt 0) {
                $Count = $ArchiveInput.Read($Buffer, 0, [Math]::Min($Buffer.Length, $Remaining))
                if ($Count -eq 0) { break }
                $PartOutput.Write($Buffer, 0, $Count)
                $Remaining -= $Count
            }
        } finally { $PartOutput.Dispose() }
        $Parts += @{ name = $Name; size = (Get-Item -LiteralPath $Path).Length; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
        $Index++
    }
} finally { $ArchiveInput.Dispose() }
$Manifest = @{
    version = '2.1.1'; format = 'split-zip'; archive_name = 'Tiho-Windows.zip'
    archive_sha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    installer_sha256 = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
    parts = $Parts
}
$Manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Release 'Tiho-Windows.manifest.json') -Encoding UTF8
Write-Host 'Release archive created in release/.'
