#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <vector>
#include <cstdint>
#include <cstddef>
#include <cstring>

/**
 * Binary packet protocol definitions and operations
 */

// Packet types
enum class PacketType : uint8_t {
    HANDSHAKE = 0x01,
    AUTH_REQUEST = 0x02,
    AUTH_RESPONSE = 0x03,
    FILE_UPLOAD = 0x04,
    FILE_DOWNLOAD = 0x05,
    FILE_LIST = 0x06,
    ACK = 0x07,
    ERROR = 0x08
};

// Packet header structure (little-endian)
#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;           // Magic number for packet validation
    PacketType type;          // Packet type
    uint32_t sequence;        // Sequence number for multi-packet support
    uint32_t total_packets;   // Total number of packets in sequence
    uint32_t payload_size;    // Size of payload data
    uint32_t crc32;          // CRC32 checksum of payload
};
#pragma pack(pop)

/**
 * Protocol handler class
 */
class Protocol {
public:
    static const uint32_t MAGIC_NUMBER = 0x12345678;
    static const uint32_t MAX_PAYLOAD_SIZE = 65536; // 64KB

    // Packet creation
    static std::vector<unsigned char> create_packet(PacketType type,
                                                   const std::vector<unsigned char>& payload,
                                                   uint32_t sequence = 0,
                                                   uint32_t total_packets = 1);

    // Packet parsing
    static bool parse_packet(const std::vector<unsigned char>& data,
                            PacketHeader& header,
                            std::vector<unsigned char>& payload);

    // CRC calculation
    static uint32_t calculate_crc32(const std::vector<unsigned char>& data);

    // Multi-packet support
    static std::vector<std::vector<unsigned char>> split_data(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> combine_packets(const std::vector<std::vector<unsigned char>>& packets);

    // Validation
    static bool validate_packet(const PacketHeader& header, const std::vector<unsigned char>& payload);
};

#endif // PROTOCOL_H
