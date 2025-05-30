# Simple File Backup System

A basic client-server file backup system with C++ client and Python server.

## Quick Start

### 1. Start the Server
```bash
cd server
start_server.bat
```
The server will start on `localhost:8080`

### 2. Build and Run the Client
```bash
cd client
simple_build.bat
build\backup_client.exe
```

## Project Structure

```
├── server/
│   ├── src/server.py          # Main server application
│   ├── start_server.bat       # Server startup script
│   └── storage/               # File storage directory
├── client/
│   ├── src/main.cpp           # Main client application
│   ├── simple_build.bat       # Build script
│   └── build/                 # Compiled executables
└── README.md                  # This file
```

## Features

- ✅ Basic TCP client-server communication
- ✅ Cross-platform C++ client (Windows/Linux)
- ✅ Python server with threading support
- ✅ Simple build system
- ⏳ File upload/download (coming soon)
- ⏳ Encryption (coming soon)
- ⏳ Authentication (coming soon)

## Requirements

- **Client**: GCC compiler with C++ support
- **Server**: Python 3.6+
- **Windows**: MinGW or similar GCC toolchain

## Testing

1. Start the server using `server/start_server.bat`
2. Build the client using `client/simple_build.bat`
3. Run the client executable to test the connection

The client will connect to the server, send a test message, and display the server's response.

## Troubleshooting

- **Server won't start**: Check if port 8080 is available
- **Client won't connect**: Make sure the server is running first
- **Build fails**: Ensure GCC is installed and in your PATH

## Next Steps

This is a basic boilerplate. You can extend it by:
- Adding file transfer functionality
- Implementing encryption (RSA + AES)
- Adding user authentication
- Creating a proper protocol for file operations
