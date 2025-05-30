#include <iostream>
#include "client.h"

int main() {
    std::cout << "File Backup Client" << std::endl;
    std::cout << "==================" << std::endl;

    Client client;

    // Test connection
    std::cout << "Testing connection to 127.0.0.1:8080..." << std::endl;
    if (client.connect("127.0.0.1", 8080)) {
        std::cout << "[SUCCESS] Connected to server successfully" << std::endl;
        client.disconnect();
        std::cout << "[SUCCESS] Disconnected" << std::endl;
    } else {
        std::cout << "[FAILED] Failed to connect to server" << std::endl;
        std::cout << "  (This is expected if no server is running)" << std::endl;
    }

    return 0;
}
