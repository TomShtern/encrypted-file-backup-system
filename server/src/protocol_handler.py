"""
Protocol handler for binary packet processing
Handles packet creation, parsing, and CRC verification
"""

import struct
import zlib
from enum import IntEnum
from typing import List, Tuple, Optional
from dataclasses import dataclass

class PacketType(IntEnum):
    """Packet type enumeration"""
    HANDSHAKE = 0x01
    AUTH_REQUEST = 0x02
    AUTH_RESPONSE = 0x03
    FILE_UPLOAD = 0x04
    FILE_DOWNLOAD = 0x05
    FILE_LIST = 0x06
    ACK = 0x07
    ERROR = 0x08

@dataclass
class PacketHeader:
    """Packet header structure"""
    magic: int
    type: PacketType
    sequence: int
    total_packets: int
    payload_size: int
    crc32: int

class ProtocolHandler:
    """Handles binary packet protocol operations"""
    
    MAGIC_NUMBER = 0x12345678
    MAX_PAYLOAD_SIZE = 65536  # 64KB
    HEADER_SIZE = 21  # Size of packed header
    
    def create_packet(self, packet_type: PacketType, payload: bytes, 
                     sequence: int = 0, total_packets: int = 1) -> bytes:
        """Create a binary packet with header and payload"""
        
        # Calculate CRC32 of payload
        crc32 = zlib.crc32(payload) & 0xffffffff
        
        # Create header (little-endian format)
        header = struct.pack('<IBIBIII',
                           self.MAGIC_NUMBER,
                           packet_type,
                           sequence,
                           total_packets,
                           len(payload),
                           crc32)
        
        return header + payload
    
    def parse_packet(self, data: bytes) -> Tuple[Optional[PacketHeader], Optional[bytes]]:
        """Parse binary packet and return header and payload"""
        
        if len(data) < self.HEADER_SIZE:
            return None, None
        
        # Unpack header
        try:
            header_data = struct.unpack('<IBIBIII', data[:self.HEADER_SIZE])
            
            header = PacketHeader(
                magic=header_data[0],
                type=PacketType(header_data[1]),
                sequence=header_data[2],
                total_packets=header_data[3],
                payload_size=header_data[4],
                crc32=header_data[5]
            )
            
            # Validate magic number
            if header.magic != self.MAGIC_NUMBER:
                return None, None
            
            # Extract payload
            if len(data) < self.HEADER_SIZE + header.payload_size:
                return None, None
            
            payload = data[self.HEADER_SIZE:self.HEADER_SIZE + header.payload_size]
            
            # Verify CRC32
            if not self.verify_crc32(payload, header.crc32):
                return None, None
            
            return header, payload
            
        except (struct.error, ValueError):
            return None, None
    
    def verify_crc32(self, data: bytes, expected_crc: int) -> bool:
        """Verify CRC32 checksum"""
        calculated_crc = zlib.crc32(data) & 0xffffffff
        return calculated_crc == expected_crc
    
    def split_data(self, data: bytes) -> List[bytes]:
        """Split large data into multiple packets"""
        packets = []
        offset = 0
        
        while offset < len(data):
            chunk_size = min(self.MAX_PAYLOAD_SIZE, len(data) - offset)
            packets.append(data[offset:offset + chunk_size])
            offset += chunk_size
        
        return packets
    
    def combine_packets(self, packets: List[bytes]) -> bytes:
        """Combine multiple packet payloads into single data"""
        return b''.join(packets)
