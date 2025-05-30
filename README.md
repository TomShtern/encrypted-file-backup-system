# Secure Client-Server File Backup System

A secure file backup system implementing RSA and AES encryption for secure client-server communication over TCP.

## Architecture

- **Client**: C++ application with RSA (1024-bit) key exchange and AES-CBC (256-bit) encryption
- **Server**: Python server for file storage and retrieval with integrity checking
- **Protocol**: Little-endian binary packet protocol with multi-packet support
- **Security**: CRC verification for data integrity

## Project Structure

```
├── client/                 # C++ client application
│   ├── src/               # Client source files
│   ├── include/           # Client header files
│   └── CMakeLists.txt     # CMake build configuration
├── server/                # Python server application
│   ├── src/               # Server source files
│   └── requirements.txt   # Python dependencies
├── config/                # Configuration files
├── docs/                  # Documentation
└── README.md              # This file
```

## Building and Running

### Client (C++)

**Option 1: Using Build Scripts (Recommended)**
- Windows Batch: `build.bat`
- Windows PowerShell: `build.ps1`
- Linux/Mac: `build.sh`

**Option 2: Manual Compilation**
```bash
# Create build directory
mkdir build

# Compile with MSVC on Windows (Recommended)
cl /std:c++17 /EHsc /Iinclude src/*.cpp /Fe:build/backup_client.exe ws2_32.lib

# Alternative: g++ (MinGW - deprecated)
g++ -std=c++17 -Iinclude src/*.cpp -o build/backup_client.exe -lws2_32
```

**Prerequisites for C++ Client:**
- C++17 compatible compiler (MSVC recommended, g++ supported)
- Windows: Visual Studio 2019/2022 with C++ tools (recommended) or MinGW-w64 (deprecated)
- Linux/Mac: build-essential package

### Server (Python)

**Using Run Scripts:**
- Windows Batch: `run_server.bat`
- Windows PowerShell: `run_server.ps1`

**Manual:**
```bash
cd server
pip install -r requirements.txt
python src/server.py
```

## Features

- RSA 1024-bit key exchange
- AES-CBC 256-bit payload encryption
- TCP-based communication
- Binary packet protocol with multi-packet support
- CRC data integrity verification
- Secure file backup and retrieval

## Security

This system implements industry-standard encryption protocols:
- RSA encryption for secure key exchange
- AES-CBC for fast symmetric encryption of file data
- CRC checksums for data integrity verification
