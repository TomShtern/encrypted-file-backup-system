#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

/**
 * Network communication class for TCP operations
 */
class Network {
public:
    Network();
    ~Network();
    
    // Connection management
    bool connect(const std::string& address, int port);
    void disconnect();
    bool is_connected() const;
    
    // Data transmission
    bool send_data(const std::vector<unsigned char>& data);
    std::vector<unsigned char> receive_data(size_t expected_size = 0);
    
    // Error handling
    std::string get_last_error() const;

private:
    SOCKET socket_;
    bool connected_;
    std::string last_error_;
    
    // Platform-specific initialization
    bool initialize_winsock();
    void cleanup_winsock();
};

#endif // NETWORK_H
