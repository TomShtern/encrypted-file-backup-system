#!/usr/bin/env python3
"""
Simple File Backup Server - Working Version
"""

import socket
import threading
from pathlib import Path

class SimpleBackupServer:
    def __init__(self, host="localhost", port=8080):
        self.host = host
        self.port = port
        self.running = False
        self.storage_path = Path("storage")
        self.storage_path.mkdir(exist_ok=True)
        print(f"Storage directory: {self.storage_path.absolute()}")

    def start(self):
        """Start the server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((self.host, self.port))
            sock.listen(5)
            self.running = True

            print(f"✓ Server started successfully on {self.host}:{self.port}")
            print("✓ Ready to accept client connections")
            print("✓ Press Ctrl+C to stop the server")

            while self.running:
                try:
                    client_socket, address = sock.accept()
                    print(f"✓ Client connected from {address}")

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
            print(f"✗ Server error: {e}")
        finally:
            sock.close()
            print("✓ Server socket closed")

    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        try:
            # Simple echo protocol for now
            data = client_socket.recv(1024)
            if data:
                message = data.decode()
                print(f"✓ Received from {address}: {message}")

                response = f"Server Echo: {message}"
                client_socket.send(response.encode())
                print(f"✓ Sent response to {address}")

        except Exception as e:
            print(f"✗ Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"✓ Client {address} disconnected")

    def stop(self):
        """Stop the server"""
        self.running = False
        print("✓ Server stopping...")

def main():
    """Main server entry point"""
    print("=" * 50)
    print("  Simple File Backup Server")
    print("=" * 50)

    server = SimpleBackupServer()

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n✓ Shutdown signal received")
        server.stop()
    except Exception as e:
        print(f"✗ Server error: {e}")

if __name__ == "__main__":
    main()
