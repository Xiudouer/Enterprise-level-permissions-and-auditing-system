@echo off
cd /d "%~dp0"
if exist "BackendSecurityKit.exe" (
  BackendSecurityKit.exe demo
) else (
  python run.py demo
)
echo.
pause
