# Build Instructions

This project has been updated to use **Microsoft Visual C++ (MSVC)** as the primary compiler instead of MinGW.

## Prerequisites

- **Visual Studio 2019 or 2022** with C++ development tools
  - Community, Professional, or Enterprise edition
  - Make sure "Desktop development with C++" workload is installed
  - Windows 10/11 SDK should be included

## Building the Client

### Option 1: Simple Build (Recommended)
```batch
# Using batch file
.\build.bat

# Using PowerShell
.\build.ps1
```

### Option 2: Enhanced MSVC Build
```batch
# Using enhanced batch script with detailed output
.\build_msvc.bat
```

### Option 3: Using CMake
```batch
mkdir build_cmake
cd build_cmake
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## Build Output

- Executable: `build/backup_client.exe`
- The build process will automatically:
  - Find and initialize Visual Studio environment
  - Compile all source files
  - Link with required Windows libraries (ws2_32.lib)
  - Test the executable

## Troubleshooting

If you encounter build errors:

1. **Visual Studio not found**: Install Visual Studio with C++ tools
2. **Missing Windows SDK**: Install Windows 10/11 SDK through Visual Studio Installer
3. **Permission errors**: Try running as Administrator
4. **Path issues**: Make sure you're in the `client` directory

## Deprecated Files

The following MinGW-related files are deprecated and should not be used:
- `build_mingw_deprecated.bat`
- `build_mingw_deprecated.ps1`
- `build_clean_mingw_deprecated.ps1`

## Compiler Flags Used

- `/std:c++17` - C++17 standard
- `/EHsc` - Exception handling
- `/W3` - Warning level 3
- `/Iinclude` - Include directory
- `ws2_32.lib` - Windows Sockets library
