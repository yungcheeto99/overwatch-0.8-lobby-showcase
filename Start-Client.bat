@echo off
setlocal DisableDelayedExpansion
title Overwatch 0.8 - Client Launcher
pushd "%~dp0" || exit /b 2
rem An explicit interpreter must be the first option; launch.py consumes it.
if /i "%~1"=="--python" goto explicit
if defined OW08_PYTHON goto configured
where py >nul 2>nul
if errorlevel 1 goto try_python_path
py -3 -c "import sys,struct; sys.exit(not (sys.version_info >= (3,11) and struct.calcsize('P') == 8))" >nul 2>nul
if not errorlevel 1 goto python_launcher
:try_python_path
where python >nul 2>nul
if errorlevel 1 goto missing_python
python -c "import sys,struct; sys.exit(not (sys.version_info >= (3,11) and struct.calcsize('P') == 8))" >nul 2>nul
if not errorlevel 1 goto python_path
:missing_python
echo Install Windows x64 Python 3.11 or newer from https://www.python.org/downloads/
echo Or run Start-Client.bat --python "C:\path\python.exe"
set "OW08_EXIT=2"
goto done
:explicit
"%~2" -u "%~dp0launch.py" client %*
goto result
:configured
"%OW08_PYTHON%" -u "%~dp0launch.py" client %*
goto result
:python_launcher
py -3 -u "%~dp0launch.py" client %*
goto result
:python_path
python -u "%~dp0launch.py" client %*
:result
set "OW08_EXIT=%ERRORLEVEL%"
:done
popd
if not "%OW08_EXIT%"=="0" if not defined OW08_NO_PAUSE pause
exit /b %OW08_EXIT%
