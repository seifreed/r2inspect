@echo off
REM r2inspect Docker wrapper script for Windows
REM Provides easy interface to run r2inspect in Docker container

setlocal enabledelayedexpansion

REM Configuration
set IMAGE_NAME=r2inspect:latest
set CONTAINER_NAME=r2inspect-analysis
set SAMPLES_DIR=%SAMPLES_DIR%
if "%SAMPLES_DIR%"=="" set SAMPLES_DIR=.\samples
set OUTPUT_DIR=%OUTPUT_DIR%
if "%OUTPUT_DIR%"=="" set OUTPUT_DIR=.\output
set CONFIG_DIR=%CONFIG_DIR%
if "%CONFIG_DIR%"=="" set CONFIG_DIR=.\config

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker is not installed or not in PATH
    exit /b 1
)

REM Parse command line arguments
if "%1"=="" goto :show_help
if "%1"=="--help" goto :show_help
if "%1"=="-h" goto :show_help
if "%1"=="--build" goto :build_image
if "%1"=="--batch" goto :run_batch
if "%1"=="--shell" goto :run_shell
if "%1"=="--cleanup" goto :cleanup

REM Default: run analysis
goto :run_analysis

:build_image
echo Building r2inspect Docker image...
docker build -t %IMAGE_NAME% "%~dp0"
if %errorlevel% neq 0 (
    echo Error: Failed to build Docker image
    exit /b 1
)
echo Docker image built successfully!
goto :end

:setup_directories
if not exist "%SAMPLES_DIR%" mkdir "%SAMPLES_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
echo Directories ready: samples\, output\, config\
goto :eof

:check_image
docker images -q %IMAGE_NAME% 2>nul | findstr . >nul
if %errorlevel% neq 0 (
    echo Building r2inspect Docker image...
    docker build -t %IMAGE_NAME% "%~dp0"
    if !errorlevel! neq 0 (
        echo Error: Failed to build Docker image
        exit /b 1
    )
)
goto :eof

:run_analysis
call :setup_directories
call :check_image

REM Build Docker run command
set DOCKER_CMD=docker run --rm
set DOCKER_CMD=%DOCKER_CMD% --name %CONTAINER_NAME%
set DOCKER_CMD=%DOCKER_CMD% -v "%CD%\%SAMPLES_DIR%":/home/analyst/samples:ro
set DOCKER_CMD=%DOCKER_CMD% -v "%CD%\%OUTPUT_DIR%":/home/analyst/output:rw
set DOCKER_CMD=%DOCKER_CMD% -v "%CD%\%CONFIG_DIR%":/home/analyst/config:ro

REM Check if first argument is a file
if exist "%1" (
    REM Mount the file
    set DOCKER_CMD=%DOCKER_CMD% -v "%~f1":/tmp/analysis/%~nx1:ro
    set R2INSPECT_ARGS=/tmp/analysis/%~nx1
    shift
) else (
    set R2INSPECT_ARGS=%1
    shift
)

REM Add remaining arguments
:build_args
if "%1"=="" goto :execute_analysis
set R2INSPECT_ARGS=%R2INSPECT_ARGS% %1
shift
goto :build_args

:execute_analysis
set DOCKER_CMD=%DOCKER_CMD% --cap-drop=ALL
set DOCKER_CMD=%DOCKER_CMD% --cap-add=SYS_PTRACE
set DOCKER_CMD=%DOCKER_CMD% --cap-add=DAC_READ_SEARCH
set DOCKER_CMD=%DOCKER_CMD% --security-opt=no-new-privileges:true
set DOCKER_CMD=%DOCKER_CMD% --memory=2g
set DOCKER_CMD=%DOCKER_CMD% --cpus=2
set DOCKER_CMD=%DOCKER_CMD% %IMAGE_NAME% %R2INSPECT_ARGS%

%DOCKER_CMD%
goto :end

:run_batch
call :setup_directories
call :check_image

set BATCH_DIR=%2
if "%BATCH_DIR%"=="" set BATCH_DIR=%SAMPLES_DIR%

if not exist "%BATCH_DIR%" (
    echo Error: Directory %BATCH_DIR% not found
    exit /b 1
)

echo Running batch analysis on %BATCH_DIR%...

docker run --rm ^
    --name %CONTAINER_NAME% ^
    -v "%CD%\%BATCH_DIR%":/home/analyst/samples:ro ^
    -v "%CD%\%OUTPUT_DIR%":/home/analyst/output:rw ^
    -v "%CD%\%CONFIG_DIR%":/home/analyst/config:ro ^
    --cap-drop=ALL ^
    --cap-add=SYS_PTRACE ^
    --cap-add=DAC_READ_SEARCH ^
    --security-opt=no-new-privileges:true ^
    --memory=2g ^
    --cpus=2 ^
    %IMAGE_NAME% --batch /home/analyst/samples -o /home/analyst/output/batch_results.csv

goto :end

:run_shell
call :setup_directories
call :check_image

echo Starting interactive shell in r2inspect container...

docker run --rm -it ^
    --name %CONTAINER_NAME% ^
    -v "%CD%\%SAMPLES_DIR%":/home/analyst/samples:ro ^
    -v "%CD%\%OUTPUT_DIR%":/home/analyst/output:rw ^
    -v "%CD%\%CONFIG_DIR%":/home/analyst/config:ro ^
    --cap-drop=ALL ^
    --cap-add=SYS_PTRACE ^
    --cap-add=DAC_READ_SEARCH ^
    --security-opt=no-new-privileges:true ^
    --memory=2g ^
    --cpus=2 ^
    --entrypoint /bin/bash ^
    %IMAGE_NAME%

goto :end

:cleanup
echo Cleaning up Docker resources...
docker stop %CONTAINER_NAME% 2>nul
docker rm %CONTAINER_NAME% 2>nul
echo Cleanup complete!
goto :end

:show_help
echo Usage: %0 [OPTIONS] [FILE^|DIRECTORY] [R2INSPECT_ARGS]
echo.
echo Options:
echo     --build         Force rebuild of Docker image
echo     --batch DIR     Run batch analysis on directory
echo     --shell         Start interactive shell in container
echo     --cleanup       Clean up Docker resources
echo     --help          Show this help message
echo.
echo Environment Variables:
echo     SAMPLES_DIR     Directory for samples (default: .\samples)
echo     OUTPUT_DIR      Directory for output (default: .\output)
echo     CONFIG_DIR      Directory for config/YARA rules (default: .\config)
echo.
echo Examples:
echo     %0 malware.exe                    # Analyze single file
echo     %0 --batch .\samples               # Batch analyze directory
echo     %0 malware.exe -j -v              # Analyze with JSON output and verbose
echo     %0 --shell                        # Interactive shell
echo     %0 --cleanup                      # Clean up resources
echo.

:end
endlocal