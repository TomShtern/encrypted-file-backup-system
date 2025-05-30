@echo off
rem Simple build script using MSVC
rem filepath: c:\Users\tom7s\Desktopp\Claude Folder 2\Encrypted Client–Server File Backup System\client\build.bat

echo Building C++ Client with MSVC...

rem Try to find and setup Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if %ERRORLEVEL% NEQ 0 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
    if %ERRORLEVEL% NEQ 0 (
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
        if %ERRORLEVEL% NEQ 0 (
            call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
            if %ERRORLEVEL% NEQ 0 (
                echo ERROR: Visual Studio not found
                echo Please install Visual Studio with C++ tools
                pause
                exit /b 1
            )
        )
    )
)

rem Create build directory if it doesn't exist
if not exist "build" mkdir build

rem Compile with MSVC
echo Compiling with MSVC...
cl /std:c++17 /EHsc /Iinclude /Fe:build/backup_client.exe src/main.cpp src/client.cpp src/crypto.cpp src/protocol.cpp src/network.cpp ws2_32.lib

rem Check if build was successful
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================
    echo SUCCESS: Build completed cleanly!
    echo Executable: build/backup_client.exe
    echo ================================
    echo.
    echo Testing the executable:
    echo.
    .\build\backup_client.exe
) else (
    echo.
    echo ================================
    echo FAILED: Build failed with errors
    echo ================================
    pause
)
