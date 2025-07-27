@echo off
REM r2inspect Docker wrapper script for Windows

REM Get current directory
set CURRENT_DIR=%cd%

REM Create directories if they don't exist
if not exist "%CURRENT_DIR%\samples" mkdir "%CURRENT_DIR%\samples"
if not exist "%CURRENT_DIR%\output" mkdir "%CURRENT_DIR%\output"

REM Check if image exists
docker images -q r2inspect:latest 2>nul
if errorlevel 1 (
    echo Building r2inspect Docker image...
    docker build -t r2inspect:latest "%~dp0"
)

REM Run r2inspect with mounted volumes
docker run --rm ^
    -v "%CURRENT_DIR%\samples:/samples" ^
    -v "%CURRENT_DIR%\output:/output" ^
    -v "%CURRENT_DIR%:/current" ^
    r2inspect %*