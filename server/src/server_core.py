"""
Core server implementation
Handles client connections, authentication, and file operations
"""

import socket
import threading
from pathlib import Path

from .crypto_handler import CryptoHandler
from .protocol_handler import ProtocolHandler
from .file_manager import FileManager

class BackupServer:
    """Main backup server class"""

    def __init__(self, host: str = "localhost", port: int = 8080):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.clients = {}

        # Initialize components
        self.crypto = CryptoHandler()
        self.protocol = ProtocolHandler()
        self.file_manager = FileManager()

        # Create storage directory
        self.storage_path = Path("storage")
        self.storage_path.mkdir(exist_ok=True)

    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True

            print(f"Server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"New connection from {address}")

                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")

        except Exception as e:
            print(f"Server startup error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the server"""
        self.running = False
        if self.socket:
            self.socket.close()

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual client connection"""
        try:
            # TODO: Implement client handling logic
            # - Handshake
            # - Authentication
            # - Command processing
            pass
        except Exception as e:
            print(f"Client {address} error: {e}")
        finally:
            client_socket.close()
            print(f"Connection with {address} closed")
