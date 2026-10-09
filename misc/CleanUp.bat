@echo off
setlocal DisableDelayedExpansion
title Overwatch 0.8 - Cleanup
set "OW08_CLEAN_PREVIEW="
set "OW08_CLEAN_YES="
:options
if "%~1"=="" goto run
if /i "%~1"=="--help" goto help
if /i "%~1"=="--dry-run" goto preview
if /i "%~1"=="--yes" goto confirmed
echo Unknown cleanup option. Use CleanUp.bat --help.
exit /b 2
:preview
set "OW08_CLEAN_PREVIEW=-Preview"
shift /1
goto options
:confirmed
set "OW08_CLEAN_YES=-Yes"
shift /1
goto options
:run
rem Cleanup uses Windows PowerShell, so it works without Python or .venv.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0cleanup.ps1" %OW08_CLEAN_PREVIEW% %OW08_CLEAN_YES%
set "OW08_CLEAN_EXIT=%ERRORLEVEL%"
if not defined OW08_CLEAN_PREVIEW if not defined OW08_CLEAN_YES if not defined OW08_NO_PAUSE pause
exit /b %OW08_CLEAN_EXIT%
:help
echo Usage: CleanUp.bat [--dry-run] [--yes]
echo.
echo Close the server, command window and client launchers first.
echo Removes generated environments, accounts, keys, captures and Python caches.
echo The code, launchers, cleanup files and guide are kept.
echo --dry-run  List the cleanup targets without deleting anything.
echo --yes      Delete the listed targets without the interactive confirmation.
exit /b 0
