@echo off
cd /d "%~dp0"
if exist "BackendSecurityKit.exe" (
  if not exist "private-state" BackendSecurityKit.exe init
  BackendSecurityKit.exe serve
) else (
  if not exist "private-state" python run.py init
  python run.py serve
)
echo.
pause
