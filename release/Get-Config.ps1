param([string]$Server, [string]$DeviceName, [ValidateRange(1,65535)][int]$SshPort = 22, [string]$Container, [string]$Destination, [switch]$NoOpen)
$ErrorActionPreference = 'Stop'

function Test-TihoClientConfig([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.Length -eq 0 -or $file.Length -gt 1MB) { throw 'Получен пустой или слишком большой .conf. Рабочий файл не заменён.' }
    $sections = @{}; $current = $null
    foreach ($raw in [IO.File]::ReadAllLines($Path)) {
        $line = $raw.Trim().TrimStart([char]0xFEFF)
        if (!$line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line.StartsWith('[')) {
            if ($line -notin @('[Interface]','[Peer]') -or $sections.ContainsKey($line)) { throw 'Получен некорректный клиентский .conf.' }
            $current = @{}; $sections[$line] = $current; continue
        }
        $pair = $line.Split(@('='), 2)
        if ($null -eq $current -or $pair.Count -ne 2) { throw 'Получен некорректный клиентский .conf.' }
        $current[$pair[0].Trim()] = $pair[1].Trim()
    }
    if (!$sections.ContainsKey('[Interface]') -or !$sections.ContainsKey('[Peer]')) { throw 'В .conf нет секций клиента и сервера.' }
    foreach ($entry in @(@('[Interface]','PrivateKey'), @('[Peer]','PublicKey'), @('[Peer]','PresharedKey'))) {
        $value = $sections[$entry[0]][$entry[1]]
        try { if (!$value -or [Convert]::FromBase64String($value).Length -ne 32) { throw 'key' } }
        catch { throw 'В скачанном .conf некорректный ключ. Рабочий файл не заменён.' }
    }
    if (!$sections['[Interface]']['Address'] -or !$sections['[Peer]']['Endpoint']) { throw 'В .conf нет Address или Endpoint.' }
}

function Get-TihoConfig {
    param([string]$Server, [string]$DeviceName, [int]$SshPort = 22, [string]$Container, [string]$Destination, [switch]$NoOpen)
    foreach ($command in @('ssh.exe','scp.exe')) {
        if (!(Get-Command $command -ErrorAction SilentlyContinue)) { throw 'Включите «Клиент OpenSSH» в дополнительных компонентах Windows: нужны ssh.exe и scp.exe.' }
    }
    if (!$Server) { $Server = Read-Host 'IP сервера из кабинета Amnezia Hosting' }
    $Server = $Server.Trim().Trim('[',']')
    $parsedIp = $null
    $isIp = [Net.IPAddress]::TryParse($Server, [ref]$parsedIp)
    if ($isIp) { $Server = $parsedIp.ToString() }
    if ((!$isIp -and $Server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$') -or $Server.Contains('%')) { throw 'Введите IP сервера или имя без http:// и без порта.' }
    if (!$DeviceName) {
        $DeviceName = ('Tiho-' + $env:COMPUTERNAME) -replace '[^A-Za-z0-9_-]', '-'
        if ($DeviceName.Length -gt 40) { $DeviceName = $DeviceName.Substring(0, 40) }
    }
    if ($DeviceName -notmatch '^[A-Za-z0-9_-]{1,40}$') { throw 'Имя устройства: 1–40 латинских букв, цифр, дефисов или подчёркиваний.' }
    if ($Container -and $Container -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$') { throw 'Некорректное имя контейнера.' }
    if ($SshPort -lt 1 -or $SshPort -gt 65535) { throw 'Порт SSH: 1–65535.' }
    $Creator = Join-Path (Split-Path $PSScriptRoot -Parent) 'build/create-client.py'
    if (!(Test-Path -LiteralPath $Creator)) { throw 'Сначала распакуйте весь ZIP проекта. Не найден build/create-client.py.' }
    if (!$Destination) {
        # Respect Downloads redirected to another drive or OneDrive.
        $folders = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue
        $Destination = [Environment]::ExpandEnvironmentVariables([string]$folders.'{374DE290-123F-4565-9164-39C4925E467B}')
        if (!$Destination) { $Destination = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads' }
    }
    New-Item -ItemType Directory -Force $Destination | Out-Null
    $Destination = (Get-Item -LiteralPath $Destination).FullName
    $ProfilePath = Join-Path $Destination ($DeviceName + '.conf')
    $Temporary = Join-Path $Destination ('.' + $DeviceName + '.' + [Guid]::NewGuid().ToString('N') + '.partial')
    $RemoteHost = if ($Server.Contains(':')) { 'root@[' + $Server + ']' } else { 'root@' + $Server }
    $Options = @('-o','ConnectTimeout=15','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=3')
    # A unique helper avoids simultaneous uploads overwriting a script another PC is executing.
    $RemoteHelper = '/root/tiho-create-client-' + [Guid]::NewGuid().ToString('N') + '.py'
    try {
        Write-Host 'Загружаю помощник. На запрос SSH введите пароль root от сервера. Символы пароля не отображаются.'
        & scp.exe @Options -P $SshPort $Creator "${RemoteHost}:$RemoteHelper"
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить помощник. Проверьте IP, порт SSH и пароль; при повторном запуске профиль не потеряется.' }
        Write-Host 'Получаю профиль устройства. Если он уже создан, проверю его и скачаю повторно.'
        $Create = "python3 $RemoteHelper --endpoint $Server --name $DeviceName --reuse"
        if ($Container) { $Create += " --container $Container" }
        # Preserve Python's exit status while removing the temporary helper on success or failure.
        $RemoteCommand = "$Create; status=`$?; rm -f $RemoteHelper; exit `$status"
        & ssh.exe @Options -p $SshPort -l root $Server $RemoteCommand
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось получить профиль. Причина указана выше. Если профиль устарел, запустите с другим -DeviceName; если контейнеров несколько, укажите -Container.' }
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            & scp.exe @Options -P $SshPort "${RemoteHost}:/root/tiho-clients/$DeviceName.conf" $Temporary
            if ($LASTEXITCODE -eq 0) { break }
            if ($attempt -eq 2) { throw 'Скачивание не завершилось. Запустите Get-Config.cmd ещё раз: созданный профиль останется на сервере и будет скачан повторно.' }
            Write-Host 'Соединение при скачивании прервалось. Повторяю; на запрос введите пароль ещё раз.'
        }
        Test-TihoClientConfig $Temporary
        Move-Item -LiteralPath $Temporary -Destination $ProfilePath -Force
        Write-Host "Готово: $ProfilePath" -ForegroundColor Green
        Write-Host 'В Tiho: Настройки → Импортировать .conf. Затем нажмите «Подключить». Файл .conf никому не отправляйте.'
        if (!$NoOpen) {
            try { Start-Process explorer.exe -ArgumentList ('/select,"' + $ProfilePath + '"') }
            catch { Write-Host "Не удалось открыть Проводник. Файл сохранён: $ProfilePath" }
            Read-Host 'Нажмите Enter, чтобы закрыть' | Out-Null
        }
        return $ProfilePath
    } finally {
        Remove-Item -LiteralPath $Temporary -Force -ErrorAction SilentlyContinue
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Get-TihoConfig -Server $Server -DeviceName $DeviceName -SshPort $SshPort -Container $Container -Destination $Destination -NoOpen:$NoOpen | Out-Null }
    catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
}
