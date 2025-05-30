# Start Secure File Backup Server
Write-Host "Starting Secure File Backup Server..." -ForegroundColor Green

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found Python: $pythonVersion" -ForegroundColor Yellow
} catch {
    Write-Host "Python is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "Please install Python and try again." -ForegroundColor Red
    exit 1
}

# Install requirements if needed
if (Test-Path "requirements.txt") {
    Write-Host "Installing Python requirements..." -ForegroundColor Yellow
    pip install -r requirements.txt
}

# Start the server
Write-Host "Starting server..." -ForegroundColor Green
Set-Location src
python server.py
