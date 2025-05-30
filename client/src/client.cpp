#include "client.h"
#include "network.h"
#include <iostream>
#include <vector>

Client::Client() : network_(new Network()) {
}

Client::~Client() {
    disconnect();
    delete network_;
}

bool Client::connect(const std::string& server_address, int port) {
    return network_->connect(server_address, port);
}

void Client::disconnect() {
    network_->disconnect();
}

bool Client::backup_file(const std::string& file_path) {
    std::cout << "Backing up file: " << file_path << std::endl;
    // TODO: Implement file backup logic
    return false;
}

bool Client::retrieve_file(const std::string& file_name, const std::string& output_path) {
    std::cout << "Retrieving file: " << file_name << " to " << output_path << std::endl;
    // TODO: Implement file retrieval logic
    return false;
}

std::vector<std::string> Client::list_files() {
    std::cout << "Listing files on server" << std::endl;
    // TODO: Implement file listing logic
    return {};
}

bool Client::authenticate(const std::string& username, const std::string& password) {
    std::cout << "Authenticating user: " << username << std::endl;
    // TODO: Implement authentication logic
    (void)password; // Suppress unused parameter warning
    return false;
}
