# Simple Build Script for Backup Client (MSVC)
Write-Host "Building Backup Client with MSVC..." -ForegroundColor Green

# Check for Visual Studio environment
Write-Host "Setting up Visual Studio environment..." -ForegroundColor Yellow
$vsPath = ""
$vsPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
)

foreach ($path in $vsPaths) {
    if (Test-Path $path) {
        $vsPath = $path
        break
    }
}

if (-not $vsPath) {
    Write-Host "ERROR: Visual Studio not found" -ForegroundColor Red
    Write-Host "Please install Visual Studio with C++ tools" -ForegroundColor Yellow
    exit 1
}

# Create build directory
if (!(Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

# Create a simple batch file to handle the compilation
$tempBat = "temp_simple_build.bat"
@"
@echo off
call "$vsPath"
cl /std:c++17 /EHsc /Iinclude /Fe:build/backup_client.exe src/main.cpp src/client.cpp src/crypto.cpp src/protocol.cpp src/network.cpp ws2_32.lib
"@ | Out-File -FilePath $tempBat -Encoding ASCII

# Compile with MSVC
Write-Host "Compiling with MSVC..." -ForegroundColor Yellow

try {
    & cmd /c $tempBat
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Build successful! Executable: build/backup_client.exe" -ForegroundColor Green
    } else {
        throw "Compilation failed"
    }
} catch {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
} finally {
    # Clean up
    if (Test-Path $tempBat) {
        Remove-Item $tempBat -Force
    }
}
