Proxy Hub — копия версии 1.0 (до списка серверов / VPN как в HAPP)

Снята: 2026-09-17
Содержит исходники ProxyHub без bin/obj.

КАК ВЕРНУТЬСЯ НА ЭТУ ВЕРСИЮ
1. Закройте Proxy Hub.
2. Запустите RESTORE.ps1 из этой папки (двойной щелчок или в PowerShell):
     powershell -ExecutionPolicy Bypass -File "C:\Cursor\Proxy\_backup_v1.0\RESTORE.ps1"
3. Пересоберите проект:
     dotnet build "C:\Cursor\Proxy\ProxyHub\ProxyHub.csproj" -c Release

Либо вручную скопируйте содержимое ProxyHub из этой папки поверх C:\Cursor\Proxy\ProxyHub
(папки bin и obj можно не трогать — они пересоберутся).
