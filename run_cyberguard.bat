@echo off
setlocal
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Creating the virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Could not create the virtual environment. Make sure Python is installed.
        pause
        exit /b 1
    )
)

echo Checking dependencies...
"venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Could not install dependencies.
    pause
    exit /b 1
)

start "Cyberguard Server" /min cmd /c ""%~dp0venv\Scripts\python.exe" "%~dp0app.py""
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:5000"

echo Cyberguard is running at http://127.0.0.1:5000
echo Close the "Cyberguard Server" window to stop the application.
pause
