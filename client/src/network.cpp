
/**
 * Network communication
 * TCP socket operations
 */

#include "network.h"
#include <iostream>
#include <cstring>

Network::Network() : socket_(INVALID_SOCKET), connected_(false) {
#ifdef _WIN32
    initialize_winsock();
#endif
}

Network::~Network() {
    disconnect();
#ifdef _WIN32
    cleanup_winsock();
#endif
}

bool Network::connect(const std::string& address, int port) {
    if (connected_) {
        disconnect();
    }

    socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_ == INVALID_SOCKET) {
        last_error_ = "Failed to create socket";
        return false;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<uint16_t>(port));

    // Use inet_addr for compatibility
    server_addr.sin_addr.s_addr = inet_addr(address.c_str());
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        last_error_ = "Invalid address";
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        return false;
    }

    if (::connect(socket_, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        last_error_ = "Failed to connect to server";
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        return false;
    }

    connected_ = true;
    return true;
}

void Network::disconnect() {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    connected_ = false;
}

bool Network::is_connected() const {
    return connected_;
}

bool Network::send_data(const std::vector<unsigned char>& data) {
    if (!connected_ || socket_ == INVALID_SOCKET) {
        last_error_ = "Not connected";
        return false;
    }

    size_t total_sent = 0;
    while (total_sent < data.size()) {
        int sent = send(socket_, reinterpret_cast<const char*>(data.data() + total_sent),
                       static_cast<int>(data.size() - total_sent), 0);
        if (sent == SOCKET_ERROR) {
            last_error_ = "Failed to send data";
            return false;
        }
        total_sent += sent;
    }

    return true;
}

std::vector<unsigned char> Network::receive_data(size_t expected_size) {
    std::vector<unsigned char> data;

    if (!connected_ || socket_ == INVALID_SOCKET) {
        last_error_ = "Not connected";
        return data;
    }

    if (expected_size == 0) {
        // Receive whatever is available
        char buffer[4096];
        int received = recv(socket_, buffer, sizeof(buffer), 0);
        if (received > 0) {
            data.assign(buffer, buffer + received);
        } else if (received == SOCKET_ERROR) {
            last_error_ = "Failed to receive data";
        }
    } else {
        // Receive exact amount
        data.resize(expected_size);
        size_t total_received = 0;
        while (total_received < expected_size) {
            int received = recv(socket_, reinterpret_cast<char*>(data.data() + total_received),
                              static_cast<int>(expected_size - total_received), 0);
            if (received == SOCKET_ERROR) {
                last_error_ = "Failed to receive data";
                data.clear();
                break;
            } else if (received == 0) {
                // Connection closed
                data.resize(total_received);
                break;
            }
            total_received += received;
        }
    }

    return data;
}

std::string Network::get_last_error() const {
    return last_error_;
}

#ifdef _WIN32
bool Network::initialize_winsock() {
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        last_error_ = "Failed to initialize Winsock";
        return false;
    }
    return true;
}

void Network::cleanup_winsock() {
    WSACleanup();
}
#else
bool Network::initialize_winsock() {
    return true; // No initialization needed on Unix
}

void Network::cleanup_winsock() {
    // No cleanup needed on Unix
}
#endif
