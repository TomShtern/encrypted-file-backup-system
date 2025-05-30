cmake_minimum_required(VERSION 3.10)
project(BackupClient)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Prefer MSVC on Windows
if(WIN32)
    set(CMAKE_GENERATOR_PLATFORM x64)
    if(MSVC)
        # MSVC-specific settings
        add_compile_definitions(_WIN32_WINNT=0x0601)
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
    endif()
endif()

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/client.cpp
    src/crypto.cpp
    src/protocol.cpp
    src/network.cpp
)

# Create executable
add_executable(backup_client ${SOURCES})

# Windows libraries
if(WIN32)
    target_link_libraries(backup_client ws2_32)
endif()
