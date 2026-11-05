param([string]$Server, [string]$DeviceName)
$ErrorActionPreference = 'Stop'
try {
    Get-Command ssh.exe -ErrorAction Stop | Out-Null
    Get-Command scp.exe -ErrorAction Stop | Out-Null
    if (!$Server) { $Server = Read-Host 'IP сервера из кабинета Amnezia Hosting' }
    $Server = $Server.Trim()
    if ($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$') { throw 'Введите IPv4 сервера или имя без http:// и без порта.' }
    if (!$DeviceName) {
        $DeviceName = ('Tiho-' + $env:COMPUTERNAME) -replace '[^A-Za-z0-9_-]', '-'
        if ($DeviceName.Length -gt 40) { $DeviceName = $DeviceName.Substring(0, 40) }
    }
    if ($DeviceName -notmatch '^[A-Za-z0-9_-]{1,40}$') { throw 'Имя устройства: 1–40 латинских букв, цифр, дефисов или подчёркиваний.' }
    $Creator = Join-Path (Split-Path $PSScriptRoot -Parent) 'build/create-client.py'
    if (!(Test-Path -LiteralPath $Creator)) { throw 'Сначала распакуйте весь ZIP проекта. Не найден build/create-client.py.' }
    $Destination = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
    New-Item -ItemType Directory -Force $Destination | Out-Null
    $ProfilePath = Join-Path $Destination ($DeviceName + '.conf')
    Write-Host 'Загружаю помощник. На запрос SSH введите пароль root от сервера. Символы пароля не отображаются.'
    & scp.exe $Creator "root@${Server}:/root/tiho-create-client.py"
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить помощник. Проверьте IP и пароль.' }
    Write-Host 'Создаю отдельный профиль устройства. Существующие профили не перезаписываются.'
    & ssh.exe "root@$Server" "python3 /root/tiho-create-client.py --endpoint $Server --name $DeviceName"
    if ($LASTEXITCODE -ne 0) { throw 'Сервер не создал профиль. Посмотрите сообщение выше. Если файл уже существует, скачайте его через scp или выберите другое имя устройства.' }
    & scp.exe "root@${Server}:/root/tiho-clients/$DeviceName.conf" $ProfilePath
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось скачать профиль. Он остался на сервере в /root/tiho-clients/.' }
    Write-Host "Готово: $ProfilePath" -ForegroundColor Green
    Write-Host 'В Tiho: Настройки → Импортировать .conf. Затем нажмите «Подключить». Файл .conf никому не отправляйте.'
    Start-Process explorer.exe -ArgumentList ('/select,"' + $ProfilePath + '"')
    Read-Host 'Нажмите Enter, чтобы закрыть' | Out-Null
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host 'Нужны команды SSH и scp. Если они не найдены, включите «Клиент OpenSSH» в дополнительных компонентах Windows.'
    exit 1
}
