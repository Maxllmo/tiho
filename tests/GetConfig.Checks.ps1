$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../release/Get-Config.ps1')
function Assert($Condition, [string]$Message) { if (!$Condition) { throw $Message }; Write-Host "PASS $Message" }
$key = [Convert]::ToBase64String((New-Object byte[] 32))
$script:Valid = "[Interface]`nPrivateKey = $key`nAddress = 10.8.1.3/32`n[Peer]`nPublicKey = $key`nPresharedKey = $key`nEndpoint = 198.51.100.10:43798`n"
$script:Calls = New-Object 'System.Collections.Generic.List[object]'
$script:Mode = ''; $script:Downloads = 0
function scp.exe {
    $arguments = @($args)
    $script:Calls.Add(@('scp') + $arguments)
    $global:LASTEXITCODE = 0
    $source = [string]$arguments[$arguments.Count - 2]
    $target = [string]$arguments[$arguments.Count - 1]
    if ($source.StartsWith('root@')) {
        $script:Downloads++
        if ($script:Mode -eq 'fail' -or ($script:Mode -eq 'retry' -and $script:Downloads -eq 1)) {
            [IO.File]::WriteAllText($target, '[Interface]'); $global:LASTEXITCODE = 1; return
        }
        [IO.File]::WriteAllText($target, $(if ($script:Mode -eq 'invalid') { '[Interface]' } else { $script:Valid }))
    }
}
function ssh.exe {
    $script:Calls.Add(@('ssh') + @($args))
    $global:LASTEXITCODE = if ($script:Mode -eq 'ssh-fail') { 1 } else { 0 }
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('tiho config checks ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $directory | Out-Null
try {
    foreach ($mode in @('normal','retry','fail','invalid','ssh-fail')) {
        $script:Mode = $mode; $script:Calls.Clear(); $script:Downloads = 0
        $profile = Join-Path $directory 'Tiho-PC.conf'; [IO.File]::WriteAllText($profile, 'existing working profile')
        $failed = $false
        try { Get-TihoConfig -Server '198.51.100.10' -DeviceName 'Tiho-PC' -Destination $directory -NoOpen | Out-Null }
        catch { if ($mode -in @('normal','retry')) { throw }; $failed = $true }
        if ($mode -in @('normal','retry')) {
            Assert (!$failed -and [IO.File]::ReadAllText($profile) -eq $script:Valid) "$mode downloads and validates the profile"
            Assert ($script:Downloads -eq $(if ($mode -eq 'retry') { 2 } else { 1 })) "$mode performs the expected number of attempts"
        } else {
            Assert ($failed -and [IO.File]::ReadAllText($profile) -eq 'existing working profile') "$mode preserves the existing profile"
        }
        Assert (@(Get-ChildItem -LiteralPath $directory -Force -Filter '*.partial').Count -eq 0) "$mode removes partial downloads"
        $command = [string]$script:Calls[1][-1]
        Assert ($command.Contains('--reuse') -and $command.Contains('status=$?; rm -f ') -and $command.EndsWith('exit $status')) "$mode resumes creation and preserves remote exit status"
    }
    $script:Mode = 'normal'; $script:Calls.Clear(); $script:Downloads = 0
    Get-TihoConfig -Server '[2001:db8::10]' -DeviceName 'Tiho-IPv6' -SshPort 2222 -Container 'amnezia-awg' -Destination $directory -NoOpen | Out-Null
    Assert ($script:Calls[0][-1] -match '^root@\[2001:db8::10\]:/root/tiho-create-client-[a-f0-9]+\.py$') 'IPv6 scp destination is bracketed and upload is unique'
    Assert ($script:Calls[1][-1].Contains('--container amnezia-awg')) 'Explicit container is forwarded'
    Assert ($script:Calls[0] -contains 2222 -and $script:Calls[1] -contains 2222) 'Custom SSH port reaches ssh and scp'
    foreach ($invalid in @(@{Server='x;touch /tmp/x';DeviceName='Tiho-PC'}, @{Server='198.51.100.10';DeviceName='x;exit'}, @{Server='198.51.100.10';DeviceName='Tiho-PC';Container='x;exit'})) {
        $script:Calls.Clear(); $failed = $false
        try { Get-TihoConfig @invalid -Destination $directory -NoOpen | Out-Null } catch { $failed = $true }
        Assert ($failed -and $script:Calls.Count -eq 0) 'Invalid input is rejected before SSH'
    }
} finally { Remove-Item -LiteralPath $directory -Recurse -Force }
Write-Host 'All Get-Config checks passed.'
