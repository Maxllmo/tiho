param([string]$Nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe")
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root
Get-Command dotnet -ErrorAction Stop | Out-Null
Get-Command go -ErrorAction Stop | Out-Null
if (!(Test-Path $Nsis)) { throw 'Install NSIS 3.11+ or pass -Nsis with the full path to makensis.exe.' }
$Lock = Get-Content "$PSScriptRoot/core-lock.json" -Raw | ConvertFrom-Json
$Work = Join-Path $Root 'work'
New-Item -ItemType Directory -Force $Work, "$Root/output" | Out-Null
foreach ($Arch in @('x64','arm64','x86')) {
    $Entry = $Lock.$Arch
    $Archive = Join-Path $Work "sing-box-$Arch.zip"
    Invoke-WebRequest -Uri $Entry.url -OutFile $Archive
    if ((Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Entry.sha256) { throw "Checksum mismatch: $Arch" }
    $Extract = Join-Path $Work "sing-box-$Arch"
    Expand-Archive $Archive -DestinationPath $Extract -Force
    $Core = Join-Path $Root "ProxyHub/Core/$Arch"
    New-Item -ItemType Directory -Force $Core | Out-Null
    $Exe = Get-ChildItem $Extract -Recurse -Filter sing-box.exe | Select-Object -First 1
    Copy-Item $Exe.FullName "$Core/sing-box.exe" -Force
    $env:GOOS = 'windows'
    $env:GOARCH = switch ($Arch) { 'x64' {'amd64'} 'x86' {'386'} 'arm64' {'arm64'} }
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'go1.25.12'
    Push-Location "$Root/awg-core"
    try { go build -trimpath '-ldflags=-H=windowsgui' -o "$Core/tiho-awg.exe" .; if ($LASTEXITCODE) { throw 'AWG build failed' } }
    finally { Pop-Location }
    $Publish = "$Root/dist/win-$Arch"
    dotnet publish ProxyHub/ProxyHub.csproj -r "win-$Arch" -c Release --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o $Publish
    if ($LASTEXITCODE) { throw '.NET publish failed' }
    Copy-Item "$Root/THIRD-PARTY-NOTICES.txt" $Publish -Force
    Copy-Item "$Root/licenses" $Publish -Recurse -Force
}
& $Nsis "$Root/installer/Tiho.nsi"
if ($LASTEXITCODE) { throw 'Installer build failed' }
Write-Host "Created $Root/output/Tiho-Setup.exe"
