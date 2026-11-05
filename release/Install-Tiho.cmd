@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Restore-Tiho.ps1" -RunInstaller
if errorlevel 1 pause
endlocal
