@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  run_tutty.bat
REM  Clones, installs, and runs nbahraini/TUTTY (pytty) on Windows
REM ============================================================

set "REPO_URL=https://github.com/nbahraini/TUTTY.git"
set "INSTALL_DIR=%~dp0TUTTY"
set "VENV_DIR=%INSTALL_DIR%\.venv"

echo.
echo === Checking prerequisites ===

where git >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Git was not found on PATH. Install it from https://git-scm.com/download/win and re-run this script.
    goto :end
)

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH. Install Python 3.10+ from https://www.python.org/downloads/ and re-run this script.
    echo         Make sure to check "Add python.exe to PATH" during install.
    goto :end
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set "PYVER=%%v"
echo Found Python %PYVER%
echo.

REM ============================================================
REM  Clone or update the repository
REM ============================================================
if exist "%INSTALL_DIR%\.git" (
    echo === Updating existing clone ===
    pushd "%INSTALL_DIR%"
    git pull
    popd
) else (
    echo === Cloning repository ===
    git clone "%REPO_URL%" "%INSTALL_DIR%"
    if errorlevel 1 (
        echo [ERROR] git clone failed.
        goto :end
    )
)
echo.

REM ============================================================
REM  Create virtual environment (only if missing)
REM ============================================================
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo === Creating virtual environment ===
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        goto :end
    )
)

echo === Activating virtual environment ===
call "%VENV_DIR%\Scripts\activate.bat"
echo.

REM ============================================================
REM  Install / update the package
REM ============================================================
echo === Installing pytty and dependencies ===
pushd "%INSTALL_DIR%"
python -m pip install --upgrade pip
python -m pip install -e ".[keyring]"
if errorlevel 1 (
    echo [WARN] Install with keyring extra failed, retrying without it...
    python -m pip install -e .
)
popd
echo.

REM ============================================================
REM  Run pytty
REM ============================================================
echo === Launching pytty ===
echo (Close the pytty window / press q to quit and return here)
echo.
pytty %*

:end
echo.
echo Done. Press any key to close this window.
pause >nul
endlocal