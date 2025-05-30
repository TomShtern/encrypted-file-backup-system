#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <vector>

class Network;

class Client {
public:
    Client();
    ~Client();

    // Connection management
    bool connect(const std::string& server_address, int port);
    void disconnect();

    // File operations
    bool backup_file(const std::string& file_path);
    bool retrieve_file(const std::string& file_name, const std::string& output_path);
    std::vector<std::string> list_files();

    // Authentication
    bool authenticate(const std::string& username, const std::string& password);

private:
    Network* network_;
};

#endif // CLIENT_H
