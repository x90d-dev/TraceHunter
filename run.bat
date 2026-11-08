@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title TraceHunter - Automated Host Audit Bootstrapper

echo ============================================================================
echo  TraceHunter: Host-Based Threat Hunting ^& Live Process Forensic Engine
echo  Repository: https://github.com/x90d-dev/TraceHunter
echo ============================================================================
echo.


set "PY_CMD="

:: Check Python Launcher (`py -3`) first
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if %ERRORLEVEL% EQU 0 set "PY_CMD=py -3"
)


if "%PY_CMD%"=="" (
    where python >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
        if %ERRORLEVEL% EQU 0 set "PY_CMD=python"
    )
)


if "%PY_CMD%"=="" (
    for %%P in (
        "%LocalAppData%\Programs\Python\Python313\python.exe"
        "%LocalAppData%\Programs\Python\Python312\python.exe"
        "%LocalAppData%\Programs\Python\Python311\python.exe"
        "%LocalAppData%\Programs\Python\Python310\python.exe"
        "%LocalAppData%\Programs\Python\Python39\python.exe"
        "%ProgramFiles%\Python313\python.exe"
        "%ProgramFiles%\Python312\python.exe"
        "%ProgramFiles%\Python311\python.exe"
        "%ProgramFiles%\Python310\python.exe"
        "%ProgramFiles%\Python39\python.exe"
    ) do (
        if exist %%P (
            if "%PY_CMD%"=="" set "PY_CMD=%%P"
        )
    )
)


if "%PY_CMD%"=="" (
    echo [WARN] Python 3.9+ was not detected on this system.
    where winget >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [INFO] Attempting automatic Python 3.11 installation via Windows Package Manager ^(winget^)...
        winget install -e --id Python.Python.3.11 --scope user --accept-package-agreements --accept-source-agreements
        if exist "%LocalAppData%\Programs\Python\Python311\python.exe" (
            set "PY_CMD="%LocalAppData%\Programs\Python\Python311\python.exe""
        )
    )
)

if "%PY_CMD%"=="" (
    echo.
    echo [ERROR] Python 3.9+ runtime is not installed or not in system PATH.
    echo         Please install Python 3.11+ from https://www.python.org/downloads/
    echo         and check "Add python.exe to PATH" during installation.
    goto :HOLD_TERMINAL
)

for /f "delims=" %%V in ('%PY_CMD% --version 2^>^&1') do set "PY_VER=%%V"
echo [INFO] Detected Python Runtime: %PY_VER%


if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating isolated virtual environment in .venv ...
    %PY_CMD% -m venv .venv
    if %ERRORLEVEL% NEQ 0 (
        echo [WARN] Standard venv creation failed. Ensuring virtualenv/pip is available...
        %PY_CMD% -m ensurepip --upgrade >nul 2>&1
        %PY_CMD% -m venv .venv
    )
)

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Could not create ".venv\Scripts\python.exe". Falling back to system Python.
    set "VENV_PY=%PY_CMD%"
) else (
    set "VENV_PY=".venv\Scripts\python.exe""
    if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"
)


%VENV_PY% -c "import rich, psutil" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist ".venv\installed_marker.txt" del /f /q ".venv\installed_marker.txt" >nul 2>&1
)

if not exist ".venv\installed_marker.txt" (
    echo [INFO] Preparing and upgrading pip / wheel / setuptools...
    %VENV_PY% -m ensurepip --upgrade >nul 2>&1
    %VENV_PY% -m pip install --upgrade pip setuptools wheel >nul 2>&1

    echo [INFO] Installing required packages ^(rich, psutil, yara-python, cryptography^)...
    if exist "requirements.txt" (
        %VENV_PY% -m pip install --prefer-binary -r requirements.txt
    ) else (
        %VENV_PY% -m pip install --prefer-binary rich psutil yara-python cryptography
    )

    
    %VENV_PY% -c "import rich, psutil" >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [WARN] Retrying individual package installation with pre-compiled binary wheels...
        %VENV_PY% -m pip install --prefer-binary rich psutil cryptography
        %VENV_PY% -m pip install --prefer-binary yara-python >nul 2>&1
    )

    %VENV_PY% -c "import rich, psutil" >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        if not exist ".venv" mkdir ".venv" >nul 2>&1
        echo Installed on %DATE% %TIME% > ".venv\installed_marker.txt"
        echo [INFO] All required packages are installed and ready.
        echo.
    ) else (
        echo [WARN] Some optional packages could not be installed. Proceeding with built-in OS engines...
        echo.
    )
)


if not exist "tracehunter.py" (
    echo [ERROR] "tracehunter.py" was not found in directory: %CD%
    echo         Make sure you extracted the entire ZIP archive before running run.bat.
    goto :HOLD_TERMINAL
)

echo [INFO] Running TraceHunter host forensic inspection...
echo.
if "%~1"=="" (
    %VENV_PY% tracehunter.py --scan-all
) else (
    %VENV_PY% tracehunter.py %*
)

echo.
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] TraceHunter exited with status code %ERRORLEVEL%.
) else (
    echo [INFO] TraceHunter scan finished.
)

:HOLD_TERMINAL
echo.
echo ============================================================================
echo  Window is kept open so you can review the forensic audit output above.
echo  You can also run custom commands directly in this terminal, for example:
echo    python tracehunter.py --scan-all --lang id
echo    python tracehunter.py --scan-all --output-format stix --output-file stix.json
echo ============================================================================
echo.
cmd /k
