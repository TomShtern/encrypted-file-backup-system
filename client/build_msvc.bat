@echo off
REM Enhanced MSVC build script
REM filepath: c:\Users\tom7s\Desktopp\Claude Folder 2\Encrypted Client–Server File Backup System\client\build_msvc.bat

echo ================================
echo Building Backup Client with MSVC
echo ================================

REM Try to find and setup Visual Studio environment
echo Searching for Visual Studio installation...
set "VS_FOUND=0"

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Found Visual Studio 2022 Community
    set "VS_FOUND=1"
    goto :build
)

call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Found Visual Studio 2022 Professional
    set "VS_FOUND=1"
    goto :build
)

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Found Visual Studio 2022 Enterprise
    set "VS_FOUND=1"
    goto :build
)

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Found Visual Studio 2019 Community
    set "VS_FOUND=1"
    goto :build
)

if "%VS_FOUND%"=="0" (
    echo ================================
    echo ERROR: Visual Studio not found
    echo ================================
    echo Please install Visual Studio with C++ tools
    echo Download from: https://visualstudio.microsoft.com/
    pause
    exit /b 1
)

:build
REM Create build directory
if not exist "build" mkdir build

REM Clean previous build artifacts
del /Q build\*.obj 2>nul
del /Q build\*.pdb 2>nul

REM Compile with MSVC
echo.
echo Compiling with detailed output...
echo Command: cl /std:c++17 /EHsc /W3 /Iinclude /Fe:build/backup_client.exe src/main.cpp src/client.cpp src/crypto.cpp src/protocol.cpp src/network.cpp ws2_32.lib
echo.

cl /std:c++17 /EHsc /W3 /Iinclude /Fe:build/backup_client.exe src/main.cpp src/client.cpp src/crypto.cpp src/protocol.cpp src/network.cpp ws2_32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================
    echo ✓ Build successful!
    echo ================================
    echo Executable: build/backup_client.exe
    if exist "build/backup_client.exe" (
        for %%I in ("build/backup_client.exe") do echo File size: %%~zI bytes
    )
    echo.
    echo Testing executable...
    .\build\backup_client.exe
) else (
    echo.
    echo ================================
    echo ✗ Build failed with error code %ERRORLEVEL%
    echo ================================
    echo.
    echo Common solutions:
    echo 1. Check that all source files exist
    echo 2. Verify Windows SDK is installed
    echo 3. Make sure Visual Studio C++ tools are installed
    pause
)
