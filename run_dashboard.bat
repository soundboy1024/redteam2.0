@echo off
setlocal
set PORT=8503
set PROJECT=redteam2.0 control panel
cd /d "%~dp0"

echo === %PROJECT% on port %PORT% ===
echo Stopping any Streamlit already running on port %PORT%...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%PORT% ^| findstr LISTENING') do (
    taskkill /f /pid %%a >nul 2>&1
)

if not exist .venv\ (
    echo Creating virtual environment...
    python -m venv .venv || goto :err
)

echo Ensuring dependencies are installed...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto :err

start "" http://localhost:%PORT%
".venv\Scripts\python.exe" -m streamlit run dashboard\app.py --server.port %PORT%
goto :eof

:err
echo.
echo Setup failed. Make sure Python 3.11+ is on PATH.
pause
