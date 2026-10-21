@echo off
rem Запускает VPN с правами администратора. Ctrl+C или закрытие окна отключает VPN.
chcp 65001 >nul
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
vpnclient.exe run
pause
