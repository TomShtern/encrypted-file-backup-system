import socket
import threading
import struct
import uuid
import os
import time
import logging
import re
import signal
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any, Tuple

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Server Configuration Constants ---
SERVER_VERSION = 3
DEFAULT_PORT = 1256
PORT_CONFIG_FILE = "port.info"
DATABASE_NAME = "defensive.db"
FILE_STORAGE_DIR = "received_files" # Directory to store received files

# Behavior Configuration
CLIENT_SOCKET_TIMEOUT = 60.0  # Timeout for individual socket operations with a client
CLIENT_SESSION_TIMEOUT = 10 * 60  # Overall inactivity timeout for a client session (10 minutes)
PARTIAL_FILE_TIMEOUT = 15 * 60 # Timeout for incomplete multi-packet file transfers (15 minutes)
MAINTENANCE_INTERVAL = 60.0 # How often to run maintenance tasks (seconds)
MAX_PAYLOAD_READ_LIMIT = (16 * 1024 * 1024) + 1024  # Max size for a single payload read (16MB chunk + headers)
MAX_ORIGINAL_FILE_SIZE = 4 * 1024 * 1024 * 1024 # Max original file size (e.g., 4GB) - for sanity checking
MAX_CONCURRENT_CLIENTS = 50 # Max number of concurrent client connections

MAX_CLIENT_NAME_LENGTH = 100 # As per spec (implicit from me.info and general limits)
MAX_FILENAME_FIELD_SIZE = 255 # Size of the filename field in protocol
MAX_ACTUAL_FILENAME_LENGTH = 250 # Practical limit for actual filename within the field
RSA_PUBLIC_KEY_SIZE = 160 # Bytes, X.509 format (for 1024-bit RSA)
AES_KEY_SIZE_BYTES = 32 # 256-bit AES

# Logging Configuration
LOG_FORMAT = '%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more verbose output
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("server.log", mode='a'), # Append mode
        logging.StreamHandler(sys.stdout) # Also log to console
    ]
)
logger = logging.getLogger(__name__)

# --- Protocol Codes ---
# Request codes from client
REQ_REGISTER = 1025
REQ_SEND_PUBLIC_KEY = 1026
REQ_RECONNECT = 1027
REQ_SEND_FILE = 1028
REQ_CRC_OK = 1029
REQ_CRC_INVALID_RETRY = 1030
REQ_CRC_FAILED_ABORT = 1031

# Response codes to client
RESP_REG_OK = 1600
RESP_REG_FAIL = 1601
RESP_PUBKEY_AES_SENT = 1602
RESP_FILE_CRC = 1603
RESP_ACK = 1604
RESP_RECONNECT_AES_SENT = 1605
RESP_RECONNECT_FAIL = 1606
RESP_GENERIC_SERVER_ERROR = 1607

# --- Custom Exceptions ---
class ServerError(Exception):
    """Base class for server-specific exceptions."""
    pass

class ProtocolError(ServerError):
    """Indicates an error in protocol adherence by the client."""
    pass

class ClientError(ServerError):
    """Indicates an error related to client state or validity."""
    pass

class FileError(ServerError):
    """Indicates an error related to file operations or validity."""
    pass

# --- Client Representation ---
class Client:
    """
    Represents a connected client and stores its state.
    """
    def __init__(self, client_id: bytes, name: str, public_key_bytes: Optional[bytes] = None):
        """
        Initializes a Client object.

        Args:
            client_id: The unique UUID (bytes) of the client.
            name: The username of the client.
            public_key_bytes: The client's RSA public key in X.509 format (optional).
        """
        self.id: bytes = client_id
        self.name: str = name
        self.public_key_bytes: Optional[bytes] = public_key_bytes
        self.public_key_obj: Optional[RSA.RsaKey] = None # PyCryptodome RSA key object
        self.aes_key: Optional[bytes] = None # Current session AES key
        self.last_seen: float = time.monotonic() # Monotonic time for session timeout
        self.partial_files: Dict[str, Dict[str, Any]] = {} # For reassembling multi-packet files
        self.lock: threading.Lock = threading.Lock() # To protect concurrent access to client state

        if public_key_bytes:
            self._import_public_key()

    def _import_public_key(self):
        """Imports the RSA public key from bytes if available."""
        if self.public_key_bytes:
            try:
                self.public_key_obj = RSA.import_key(self.public_key_bytes)
                logger.debug(f"Client '{self.name}': Successfully imported public key.")
            except ValueError as e:
                logger.error(f"Client '{self.name}': Failed to import public key from stored bytes: {e}")
                self.public_key_obj = None # Ensure consistent state if import fails

    def update_last_seen(self):
        """Updates the last seen timestamp to the current monotonic time."""
        with self.lock:
            self.last_seen = time.monotonic()

    def set_public_key(self, public_key_bytes_data: bytes):
        """
        Sets and imports the client's RSA public key.

        Args:
            public_key_bytes_data: The public key in X.509 format.

        Raises:
            ProtocolError: If the key size is incorrect or the key format is invalid.
        """
        with self.lock:
            if len(public_key_bytes_data) != RSA_PUBLIC_KEY_SIZE:
                raise ProtocolError(f"Public key size is incorrect for client '{self.name}'. Expected {RSA_PUBLIC_KEY_SIZE}, got {len(public_key_bytes_data)}.")
            self.public_key_bytes = public_key_bytes_data
            self._import_public_key() # Attempt to parse and store the RsaKey object
            if not self.public_key_obj: # Check if import failed
                 raise ProtocolError(f"Invalid RSA public key format provided by client '{self.name}' (failed to import).")

    def get_aes_key(self) -> Optional[bytes]:
        """Returns the current session AES key."""
        # This might be accessed by the client's handler thread only after being set.
        # If other threads could modify/read it, a lock would be good practice.
        # For now, assuming primary access is serialized by client handler.
        return self.aes_key

    def set_aes_key(self, aes_key_data: bytes):
        """
        Sets the client's session AES key.

        Args:
            aes_key_data: The AES key (bytes).

        Raises:
            ValueError: If the AES key size is incorrect.
        """
        with self.lock: # Protect AES key modification
            if len(aes_key_data) != AES_KEY_SIZE_BYTES:
                 raise ValueError(f"AES key size for client '{self.name}' is incorrect. Expected {AES_KEY_SIZE_BYTES}, got {len(aes_key_data)}.")
            self.aes_key = aes_key_data
    
    def clear_partial_file(self, filename: str):
        """Removes partial file reassembly data for a given filename."""
        with self.lock:
            if filename in self.partial_files:
                del self.partial_files[filename]
                logger.debug(f"Client '{self.name}': Cleared partial file reassembly data for '{filename}'.")

    def cleanup_stale_partial_files(self) -> int:
        """
        Removes partial file data for transfers that haven't seen activity recently.

        Returns:
            The number of stale partial file transfers cleaned up for this client.
        """
        with self.lock:
            stale_files_to_remove = []
            current_monotonic_time = time.monotonic()
            for filename, data in self.partial_files.items():
                # Check if 'timestamp' key exists, default to 0 if not (should always exist)
                if current_monotonic_time - data.get("timestamp", 0) > PARTIAL_FILE_TIMEOUT:
                    stale_files_to_remove.append(filename)
            
            for filename in stale_files_to_remove:
                logger.warning(f"Client '{self.name}': Stale partial file transfer timed out for '{filename}'. Removing associated data.")
                del self.partial_files[filename] # Remove stale entry
            return len(stale_files_to_remove)


# --- Main Server Class ---
class BackupServer:
    """
    The main server class that handles client connections, protocol messages,
    encryption, file storage, and database interactions.
    """
    _CRC32_TABLE = ( # Standard POSIX cksum CRC32 table, used by _calculate_crc
        0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
        0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
        0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
        0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
        0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
        0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
        0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
        0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
        0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
        0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
        0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
        0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
        0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
        0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
        0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
        0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
        0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
        0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
        0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
        0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
    )

    def __init__(self):
        """Initializes the BackupServer instance."""
        self.clients: Dict[bytes, Client] = {} # In-memory store: client_id_bytes -> Client object
        self.clients_by_name: Dict[str, bytes] = {} # In-memory store: client_name_str -> client_id_bytes
        self.clients_lock: threading.Lock = threading.Lock() # Protects access to clients and clients_by_name
        self.port: int = self._read_port_config()
        self.server_socket: Optional[socket.socket] = None
        self.running: bool = False # Flag to control server main loop
        self.shutdown_event: threading.Event = threading.Event() # For coordinating graceful shutdown
        self.maintenance_thread: Optional[threading.Thread] = None
        self.client_connection_semaphore: threading.Semaphore = threading.Semaphore(MAX_CONCURRENT_CLIENTS)
        
        self._perform_startup_checks() # Perform pre-flight checks before extensive setup
        self._ensure_storage_dir() # Ensure 'received_files' directory exists
        self._init_database()      # Initialize SQLite database and tables
        
        # Setup signal handlers for graceful shutdown (Ctrl+C, kill)
        if hasattr(signal, 'SIGTERM'): # SIGTERM is not available on all platforms (e.g. Windows sometimes)
            signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler) # SIGINT is Ctrl+C


    def _perform_startup_checks(self):
        """Performs critical checks before the server starts listening."""
        logger.info("Performing server startup checks...")
        # Check write permissions for file storage directory
        if not os.access(FILE_STORAGE_DIR, os.W_OK):
            logger.critical(f"Fatal: No write permission for file storage directory: '{os.path.abspath(FILE_STORAGE_DIR)}'.")
            raise SystemExit(f"Startup failed: No write access to '{FILE_STORAGE_DIR}'.")

        # Check write permissions for the directory where the database file resides
        db_dir = os.path.dirname(os.path.abspath(DATABASE_NAME))
        if not os.access(db_dir or '.', os.W_OK): # Use current dir if DATABASE_NAME is relative with no path
            logger.critical(f"Fatal: No write permission for database directory: '{db_dir or os.path.abspath('.')}'.")
            raise SystemExit(f"Startup failed: No write access to database directory '{db_dir}'.")
        logger.info("Startup permission checks passed.")


    def _ensure_storage_dir(self):
        """Ensures that the file storage directory exists."""
        try:
            os.makedirs(FILE_STORAGE_DIR, exist_ok=True) # exist_ok=True means no error if dir already exists
            logger.info(f"File storage directory is set to: '{os.path.abspath(FILE_STORAGE_DIR)}'")
        except OSError as e:
            logger.critical(f"Fatal: Could not create or access file storage directory '{FILE_STORAGE_DIR}': {e}")
            raise # This is a critical failure, server cannot operate


    def _signal_handler(self, signum: int, frame: Optional[Any]):
        """Handles termination signals (SIGINT, SIGTERM) for graceful shutdown."""
        # Attempt to get a human-readable signal name
        sig_name = signal.Signals(signum).name if isinstance(signum, signal.Signals) else f"Signal {signum}"
        logger.warning(f"{sig_name} received by server. Initiating graceful shutdown sequence...")
        self.stop() # Trigger the server shutdown process


    def _db_execute(self, query: str, params: tuple = (), commit: bool = False, fetchone: bool = False, fetchall: bool = False) -> Any:
        """
        Helper function for executing SQLite database operations.
        Manages connection, cursor, commit, and error handling.

        Args:
            query: The SQL query string.
            params: A tuple of parameters for the query.
            commit: True if the transaction should be committed.
            fetchone: True to fetch a single row.
            fetchall: True to fetch all rows.

        Returns:
            Query result (row, list of rows, or cursor) or None on failure for non-SELECTs.

        Raises:
            ServerError: If a database read error occurs that prevents server operation.
        """
        try:
            # Using a timeout for the connection can prevent indefinite blocking if the DB is locked.
            # `check_same_thread=False` is generally needed if DB connection is shared across threads,
            # but here, each call creates a new connection, which is safer for SQLite threading.
            with sqlite3.connect(DATABASE_NAME, timeout=10.0) as conn: # `timeout` is for busy_timeout
                cursor = conn.cursor()
                cursor.execute(query, params)
                if commit:
                    conn.commit()
                if fetchone:
                    return cursor.fetchone()
                if fetchall:
                    return cursor.fetchall()
                return cursor # For operations where cursor properties (e.g., lastrowid) are needed
        except sqlite3.OperationalError as e: # Specific error for "database is locked", "no such table" etc.
            logger.error(f"Database operational error: {e} | Query: {query[:150]}... | Params: {params}")
            # Depending on severity, re-raise or return specific error indicator
            if "locked" in str(e).lower():
                logger.warning("Database was locked during operation. This might indicate contention or a long-running transaction.")
            # If it's a critical read operation (e.g., loading clients), we might need to halt.
            if not commit and (fetchone or fetchall): # This was a read operation
                raise ServerError(f"Critical database read error: {e}") from e
            return None # Indicate failure for write operations
        except sqlite3.Error as e: # Catch other, more general SQLite errors
            logger.error(f"General database error: {e} | Query: {query[:150]}... | Params: {params}")
            if not commit and (fetchone or fetchall):
                raise ServerError(f"General database read error: {e}") from e
            return None


    def _init_database(self):
        """Initializes the database schema if tables do not exist."""
        logger.info(f"Initializing database schema in '{DATABASE_NAME}' if needed...")
        # Client Table: Stores information about registered clients.
        # LastSeen is stored as ISO8601 UTC text for portability and readability.
        # AESKey is per spec, though session-based keys are usually not persisted this way.
        self._db_execute('''
            CREATE TABLE IF NOT EXISTS clients (
                ID BLOB(16) PRIMARY KEY,
                Name VARCHAR(255) UNIQUE NOT NULL,
                PublicKey BLOB(160),
                LastSeen TEXT NOT NULL, 
                AESKey BLOB(32) 
            )
        ''', commit=True)
        # Files Table: Stores information about files backed up by clients.
        # ON DELETE CASCADE ensures that if a client is deleted, their file records are also removed.
        self._db_execute('''
            CREATE TABLE IF NOT EXISTS files (
                ID BLOB(16) NOT NULL, 
                FileName VARCHAR(255) NOT NULL,
                PathName VARCHAR(255) NOT NULL, 
                Verified BOOLEAN DEFAULT 0,
                PRIMARY KEY (ID, FileName), 
                FOREIGN KEY (ID) REFERENCES clients(ID) ON DELETE CASCADE
            )
        ''', commit=True)
        logger.info("Database schema initialization complete.")


    def _load_clients_from_db(self):
        """Loads existing client data from the database into memory at server startup."""
        logger.info("Loading existing clients from database into memory...")
        try:
            rows = self._db_execute("SELECT ID, Name, PublicKey, LastSeen FROM clients", fetchall=True)
        except ServerError as e: # Raised by _db_execute on critical read failure
            logger.critical(f"CRITICAL FAILURE: Could not load client data from database: {e}. Server cannot continue.")
            # This is a fatal error for server operation.
            raise SystemExit(f"Startup aborted: Failed to load critical client data from database. Details: {e}")

        with self.clients_lock: # Ensure thread-safe access to shared client dictionaries
            self.clients.clear()
            self.clients_by_name.clear()
            loaded_count = 0
            if rows: # Check if any rows were returned
                for row_id, name, pk_bytes, last_seen_iso_utc in rows:
                    try:
                        client = Client(row_id, name, pk_bytes) # Create Client object
                        # last_seen_iso_utc is from DB. Internal client.last_seen is monotonic for session timeout.
                        # We don't directly use DB's LastSeen for session timeout upon loading,
                        # but it's good for audit/record. Session starts fresh.
                        self.clients[row_id] = client
                        self.clients_by_name[name] = row_id
                        loaded_count +=1
                    except Exception as e_obj: # Catch errors creating individual Client objects (e.g. bad PK)
                        logger.error(f"Error creating Client object for '{name}' (ID: {row_id.hex() if row_id else 'N/A'}) from DB row: {e_obj}")
            logger.info(f"Successfully loaded {loaded_count} client(s) from database.")


    def _save_client_to_db(self, client: Client):
        """Saves or updates a client's information in the database."""
        # Convert monotonic client.last_seen to a wall-clock datetime for storage.
        # For the DB's LastSeen, always use current UTC wall-clock time to reflect this update event.
        current_wall_time_utc_iso = datetime.now(timezone.utc).isoformat(timespec='seconds') + "Z"
        
        self._db_execute('''
            INSERT OR REPLACE INTO clients (ID, Name, PublicKey, LastSeen, AESKey) 
            VALUES (?, ?, ?, ?, ?)
        ''', (client.id, client.name, client.public_key_bytes, current_wall_time_utc_iso, client.get_aes_key()), commit=True)
        logger.debug(f"Client '{client.name}' data saved/updated in database (Recorded LastSeen: {current_wall_time_utc_iso}).")


    def _save_file_info_to_db(self, client_id: bytes, file_name: str, path_name: str, verified: bool):
        """Saves or updates file information in the database."""
        # Ensure path_name is stored consistently (e.g., relative to FILE_STORAGE_DIR or absolute)
        # Current implementation assumes path_name is the final, usable path.
        self._db_execute('''
            INSERT OR REPLACE INTO files (ID, FileName, PathName, Verified) 
            VALUES (?, ?, ?, ?)
        ''', (client_id, file_name, path_name, verified), commit=True)
        logger.debug(f"File info for '{file_name}' (Client ID: {client_id.hex()}) saved/updated in database. Verified status: {verified}.")


    def _read_port_config(self) -> int:
        """Reads server port from `port.info`, defaults to `DEFAULT_PORT` on error."""
        try:
            with open(PORT_CONFIG_FILE, 'r') as f:
                port_str = f.read().strip()
                if not port_str: # Handle case where port.info is empty
                    raise ValueError("Port configuration file is empty.")
                port = int(port_str)
                # Typically, ports 0-1023 are privileged. Users should use >1023.
                if not (1024 <= port <= 65535):
                    raise ValueError(f"Port number {port} is out of the recommended user range (1024-65535).")
                logger.info(f"Successfully read port {port} from configuration file '{PORT_CONFIG_FILE}'.")
                return port
        except FileNotFoundError:
            logger.warning(f"Port configuration file '{PORT_CONFIG_FILE}' not found. Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT
        except ValueError as e: # Catches empty file, non-integer content, and out-of-range errors
            logger.warning(f"Invalid port configuration in '{PORT_CONFIG_FILE}': {e}. Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT
        except Exception as e: # Catch-all for other potential I/O errors
            logger.error(f"Unexpected error reading port configuration file '{PORT_CONFIG_FILE}': {e}. Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT


    def _periodic_maintenance_job(self):
        """
        Runs periodically in a separate thread to perform maintenance tasks:
        - Cleans up inactive client sessions from memory.
        - Cleans up stale partial file transfer data for active clients.
        - Logs server status to console.
        """
        logger.info("Server maintenance thread started.")
        while not self.shutdown_event.is_set(): # Continue until server shutdown is signaled
            try:
                # --- Inactive client session cleanup (from memory, not DB) ---
                inactive_clients_removed_count = 0
                with self.clients_lock: # Ensure thread-safe access to shared client dictionaries
                    current_monotonic_time = time.monotonic()
                    # Identify client IDs that have been inactive longer than CLIENT_SESSION_TIMEOUT
                    inactive_client_ids_to_remove = [
                        cid for cid, client_obj in self.clients.items()
                        if (current_monotonic_time - client_obj.last_seen) > CLIENT_SESSION_TIMEOUT
                    ]
                    # Remove identified inactive clients
                    for cid in inactive_client_ids_to_remove:
                        client_obj = self.clients.pop(cid, None) # Safely remove from dict by ID
                        if client_obj: # If client was found and removed
                            self.clients_by_name.pop(client_obj.name, None) # Also remove from dict by name
                            inactive_clients_removed_count += 1
                            logger.info(f"Client '{client_obj.name}' (ID: {cid.hex()}) session timed out due to inactivity. Removed from active memory pool.")
                
                # --- Stale partial file transfer data cleanup (for currently active clients) ---
                stale_partial_files_cleaned_count = 0
                with self.clients_lock: # Get a list of current clients to iterate over (snapshot)
                    active_clients_list = list(self.clients.values()) 
                
                for client_obj in active_clients_list: # client_obj here is a Client instance
                    stale_partial_files_cleaned_count += client_obj.cleanup_stale_partial_files()

                # --- Console Status Update (Basic UI Element) ---
                with self.clients_lock: # Get current count of active clients in memory
                    active_clients_in_memory = len(self.clients)
                
                # Query database for overall stats (handle potential DB errors gracefully for status reporting)
                try:
                    db_total_clients_row = self._db_execute("SELECT COUNT(*) FROM clients", fetchone=True)
                    db_total_clients_count = db_total_clients_row[0] if db_total_clients_row else "N/A (DB Error)"
                    db_total_files_row = self._db_execute("SELECT COUNT(*) FROM files", fetchone=True)
                    db_total_files_count = db_total_files_row[0] if db_total_files_row else "N/A (DB Error)"
                    db_verified_files_row = self._db_execute("SELECT COUNT(*) FROM files WHERE Verified = 1", fetchone=True)
                    db_verified_files_count = db_verified_files_row[0] if db_verified_files_row else "N/A (DB Error)"
                except ServerError: # If _db_execute raises ServerError due to DB issues
                    db_total_clients_count, db_total_files_count, db_verified_files_count = "DB_Error", "DB_Error", "DB_Error"

                # Construct a more structured status message for the console
                current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                status_header = f"[Server Status @ {current_time_str}]"
                status_lines = [
                    f"{status_header:<80}",
                    f"{'Active Client Sessions (In-Memory):':<40} {active_clients_in_memory:<10}",
                    f"{'Total Registered Clients (DB):':<40} {db_total_clients_count:<10}",
                    f"{'Total Files Stored (DB):':<40} {db_total_files_count:<10}",
                    f"{'Verified Files (DB):':<40} {db_verified_files_count:<10}",
                    f"{'Cleaned Inactive Sessions (This Cycle):':<40} {inactive_clients_removed_count:<10}",
                    f"{'Cleaned Stale Partial Files (This Cycle):':<40} {stale_partial_files_cleaned_count:<10}",
                    f"{'-' * 80}"
                ]
                # Log to file normally, print to console in a block
                logger.info("\n" + "\n".join(status_lines))


            except Exception as e: # Catch-all for any unexpected errors within the maintenance loop
                logger.critical(f"Critical error in server's periodic maintenance job: {e}", exc_info=True)
            
            # Wait for the defined maintenance interval or until server shutdown is signaled
            self.shutdown_event.wait(timeout=MAINTENANCE_INTERVAL) 
        logger.info("Server maintenance thread has stopped.")


    def start(self):
        """Starts the server: loads data, binds socket, and begins listening for connections."""
        if self.running:
            logger.warning("Server is already running. Start command ignored.")
            return

        self.running = True # Set running flag
        self.shutdown_event.clear() # Reset shutdown event for a fresh start
        
        try:
            self._load_clients_from_db() # Load initial client state from database
        except SystemExit as e: # If _load_clients_from_db determined a fatal error
            logger.critical(f"Server startup aborted due to critical error during data loading: {e}")
            self.running = False # Ensure server doesn't proceed
            self.shutdown_event.set() # Signal shutdown
            return


        # Initialize and configure the main server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
        try:
            self.server_socket.bind(('0.0.0.0', self.port)) # Bind to all available interfaces
            self.server_socket.listen(10) # Listen for incoming connections (backlog of 10)
            self.server_socket.settimeout(1.0) # Set a timeout on accept() to allow periodic checks of shutdown_event
        except OSError as e:
            logger.critical(f"Fatal: Failed to bind server socket to port {self.port}: {e}. Check if the port is already in use or if you have necessary permissions.")
            self.running = False
            self.shutdown_event.set()
            if self.server_socket: self.server_socket.close() # Clean up the socket if it was created
            return
            
        # Start the periodic maintenance thread
        self.maintenance_thread = threading.Thread(target=self._periodic_maintenance_job, daemon=True, name="MaintenanceThread")
        self.maintenance_thread.start()

        logger.info(f"Encrypted Backup Server Version {SERVER_VERSION} started successfully on port {self.port}.")
        logger.info(f"Maximum concurrent client handlers: {MAX_CONCURRENT_CLIENTS}.")
        logger.info("Server is now listening for incoming client connections...")
        
        # Main server loop: accepts new client connections
        try:
            while not self.shutdown_event.is_set(): # Continue as long as shutdown is not signaled
                try:
                    # Attempt to acquire semaphore before accepting. If full, this will block.
                    # Timeout on acquire to prevent indefinite block if shutdown is needed.
                    if not self.client_connection_semaphore.acquire(blocking=True, timeout=0.5):
                        continue # Semaphore not acquired, loop and check shutdown_event

                    client_conn, client_address = self.server_socket.accept()
                    # client_address is a tuple: (ip_string, port_integer)
                    logger.info(f"Accepted new connection from {client_address[0]}:{client_address[1]}. Starting handler thread.")
                    
                    # Create and start a new thread to handle this client connection
                    # Pass semaphore to handler so it can release it.
                    handler_thread = threading.Thread(
                        target=self._handle_client_connection, 
                        args=(client_conn, client_address, self.client_connection_semaphore), 
                        daemon=True, # Daemon threads will exit when the main program exits
                        name=f"ClientHandler-{client_address[0]}-{client_address[1]}" # Assign an informative name
                    )
                    handler_thread.start()
                except socket.timeout:
                    continue # Timeout on self.server_socket.accept() is normal, allows checking shutdown_event
                except OSError as e: # Socket might be closed if server is stopping
                     if not self.shutdown_event.is_set(): # Log only if this error is not part of a normal shutdown
                        logger.error(f"Socket error occurred while accepting connections: {e}")
                     break # Exit the accept loop if the server socket is no longer valid
        finally:
            self.running = False # Ensure running flag is cleared when loop exits
            logger.info("Server connection acceptance loop has terminated.")
            # Further cleanup (like stopping maintenance thread, closing socket) is handled in stop()


    def stop(self):
        """Initiates a graceful shutdown of the server."""
        if self.shutdown_event.is_set() and not self.running: # Check if already stopping or stopped
            logger.info("Server shutdown is already in progress or has completed.")
            return
            
        logger.warning("Server shutdown sequence initiated by call to stop()...")
        self.running = False # Primary flag to signal loops to stop
        self.shutdown_event.set() # Signal all threads/loops that rely on this event to terminate

        # Wait for the maintenance thread to finish its current cycle and stop
        if self.maintenance_thread and self.maintenance_thread.is_alive():
            logger.debug("Waiting for maintenance thread to complete its final cycle...")
            self.maintenance_thread.join(timeout=MAINTENANCE_INTERVAL / 2) # Give it a reasonable time
            if self.maintenance_thread.is_alive():
                logger.warning("Maintenance thread did not stop within the allocated timeout.")

        # Close the main server listening socket
        if self.server_socket:
            logger.debug("Closing the main server listening socket...")
            try:
                self.server_socket.close()
            except OSError as e: # Catch potential errors if socket is already closed or in a bad state
                logger.error(f"Error encountered while closing server socket: {e}")
            self.server_socket = None # Mark as closed
        
        # Note: Active client handler threads are daemon threads. They will be terminated automatically
        # when the main thread (or the last non-daemon thread) exits.
        # They also check `self.shutdown_event` and should exit their loops.
        # For an extremely graceful shutdown, one might implement a mechanism to track all
        # active client handler threads and explicitly join them with a timeout, but this
        # significantly increases complexity (e.g., if a client connection is stalled).

        logger.info("Server has been stopped.")


    def _read_exact(self, sock: socket.socket, num_bytes: int) -> bytes:
        """
        Reads exactly `num_bytes` from the socket.

        Args:
            sock: The socket to read from.
            num_bytes: The number of bytes to read.

        Returns:
            The bytes read from the socket.

        Raises:
            ValueError: If `num_bytes` is negative.
            ProtocolError: If `num_bytes` exceeds `MAX_PAYLOAD_READ_LIMIT`.
            TimeoutError: If a socket timeout occurs during read.
            ConnectionError: If the socket is closed or a socket error occurs.
        """
        if num_bytes < 0: raise ValueError("Cannot read a negative number of bytes.")
        if num_bytes == 0: return b'' # Reading zero bytes returns empty bytes
        if num_bytes > MAX_PAYLOAD_READ_LIMIT: # Protect server from extreme memory allocation requests
            raise ProtocolError(f"Requested read of {num_bytes} bytes exceeds server's MAX_PAYLOAD_READ_LIMIT ({MAX_PAYLOAD_READ_LIMIT}).")
        
        data_chunks = [] # List to store received chunks of data
        bytes_received_total = 0
        while bytes_received_total < num_bytes:
            try:
                # Calculate how many bytes are still needed, read up to 4096 at a time
                bytes_to_read_this_chunk = min(num_bytes - bytes_received_total, 4096)
                chunk = sock.recv(bytes_to_read_this_chunk)
            except socket.timeout: # This timeout is from client_conn.settimeout() set earlier
                raise TimeoutError(f"Socket timeout occurred while attempting to read {num_bytes} bytes (already received {bytes_received_total} bytes).")
            except socket.error as e: # Other socket-level errors (e.g., connection reset)
                raise ConnectionError(f"Socket error encountered during read operation: {e}")

            if not chunk: # An empty chunk indicates the socket was closed by the peer
                raise ConnectionError(f"Socket connection was broken by peer while attempting to read {num_bytes} bytes (already received {bytes_received_total} bytes).")
            
            data_chunks.append(chunk) # Add received chunk to the list
            bytes_received_total += len(chunk) # Update total bytes received
        return b''.join(data_chunks) # Concatenate all chunks to form the final data


    def _parse_request_header(self, header_data: bytes) -> Tuple[bytes, int, int, int]:
        """
        Parses the 23-byte request header.

        Args:
            header_data: The raw bytes of the header.

        Returns:
            A tuple: (client_id_bytes, version, code, payload_size).

        Raises:
            ProtocolError: If the header length is incorrect.
        """
        # RequestHeader structure (total 23 bytes):
        #   uint8_t  client_id[16];    // Client's UUID (all zeros on registration)
        #   uint8_t  version;          // Protocol version (must be SERVER_VERSION)
        #   uint16_t code;             // Request type code (little-endian)
        #   uint32_t payload_size;     // Size of payload following this header (little-endian)
        expected_header_len = 16 + 1 + 2 + 4 # Calculate expected length based on fields
        if len(header_data) != expected_header_len:
            raise ProtocolError(f"Invalid request header length. Expected {expected_header_len} bytes, but received {len(header_data)} bytes.")
        
        client_id = header_data[:16] # First 16 bytes are Client ID
        version = int(header_data[16]) # Next byte is Version (convert to int)
        # Use struct.unpack with little-endian format specifiers:
        # '<H' for unsigned short (2 bytes for request code)
        # '<I' for unsigned int (4 bytes for payload size)
        code = struct.unpack("<H", header_data[17:19])[0] # Bytes 17-18 for Code
        payload_size = struct.unpack("<I", header_data[19:23])[0] # Bytes 19-22 for Payload Size
        
        return client_id, version, code, payload_size


    def _send_response(self, sock: socket.socket, code: int, payload: bytes = b''):
        """
        Constructs and sends a response to the client socket.

        Args:
            sock: The client socket to send the response to.
            code: The response code.
            payload: The response payload (bytes).

        Raises:
            TimeoutError: If a socket timeout occurs during send.
            ConnectionError: If a socket error occurs during send.
        """
        # ResponseHeader structure (total 7 bytes before payload):
        #   uint8_t  version;          // Server's protocol version (SERVER_VERSION)
        #   uint16_t code;             // Response type code (little-endian)
        #   uint32_t payload_size;     // Size of the payload following this header (little-endian)
        # Use struct.pack with little-endian format specifiers:
        # '<B' for unsigned char (1 byte for version)
        # '<H' for unsigned short (2 bytes for response code)
        # '<I' for unsigned int (4 bytes for payload size)
        header_bytes = struct.pack("<BHI", SERVER_VERSION, code, len(payload))
        full_response_bytes = header_bytes + payload # Concatenate header and payload
        
        try:
            sock.sendall(full_response_bytes) # Send the complete response
            logger.debug(f"Successfully sent response: Code={code}, TotalSizeSent={len(full_response_bytes)} (Header:{len(header_bytes)}, Payload:{len(payload)})")
        except socket.timeout: # This timeout is from client_conn.settimeout()
            logger.error(f"Socket timeout occurred while attempting to send response (Code: {code}). Client may not have received it.")
            raise # Re-raise to allow the connection handler to manage the situation (usually close connection)
        except socket.error as e: # Other socket-level errors (e.g., connection reset by peer)
            logger.error(f"A socket error occurred during send operation (Code: {code}): {e}")
            raise ConnectionError(f"Failed to send response due to socket error: {e}") from e # Convert to a common ConnectionError


    def _handle_client_connection(self, client_conn: socket.socket, client_address: Tuple[str, int], conn_semaphore: threading.Semaphore):
        """
        Handles an individual client connection in a dedicated thread.
        Manages request-response cycle, protocol parsing, and error handling for this client.

        Args:
            client_conn: The socket object for the connected client.
            client_address: A tuple (ip_string, port_integer) for the client.
            conn_semaphore: The semaphore used to limit concurrent connections.
        """
        client_ip, client_port = client_address
        active_client_obj: Optional[Client] = None # Will store the resolved Client object for this connection
        log_client_identifier = f"{client_ip}:{client_port}" # Initial identifier for logging purposes

        try:
            client_conn.settimeout(CLIENT_SOCKET_TIMEOUT) # Set timeout for individual socket operations

            # Main loop for handling requests from this client
            while not self.shutdown_event.is_set(): # Continue as long as server is not shutting down
                # --- Read Request Header (23 bytes) ---
                header_bytes = self._read_exact(client_conn, 16 + 1 + 2 + 4) # client_id, version, code, payload_size
                client_id_from_header, version_from_header, code_from_header, payload_size_from_header = self._parse_request_header(header_bytes)
                
                # Update log identifier with Client ID if available, or note registration attempt
                current_log_id_str = client_id_from_header.hex() if any(client_id_from_header) else "REGISTRATION_ATTEMPT"
                log_client_identifier = f"{client_ip}:{client_port} (ID:{current_log_id_str})" # Used in subsequent log messages
                
                logger.info(f"Request received from {log_client_identifier}: Version={version_from_header}, Code={code_from_header}, PayloadSize={payload_size_from_header}")

                # --- Protocol Version Check ---
                if version_from_header != SERVER_VERSION: # Specification: Client version must be 3
                    logger.warning(f"Invalid client protocol version {version_from_header} received from {log_client_identifier}. Expected version {SERVER_VERSION}. Closing connection.")
                    self._send_response(client_conn, RESP_GENERIC_SERVER_ERROR) # Send generic error for version mismatch
                    break # Terminate this client's connection loop

                # --- Read Request Payload ---
                payload_bytes = self._read_exact(client_conn, payload_size_from_header) # Read payload based on size from header
                
                # --- Resolve Client Object & Update Last Seen Timestamp ---
                # For REQ_REGISTER, client_id_from_header is all zeros; active_client_obj will remain None initially.
                # For all other requests, client_id_from_header should be a valid client UUID.
                if code_from_header != REQ_REGISTER:
                    with self.clients_lock: # Ensure thread-safe access to shared self.clients dictionary
                        active_client_obj = self.clients.get(client_id_from_header)
                    
                    if not active_client_obj: # If client not found in memory (unknown ID or session timed out)
                        logger.warning(f"Request (Code:{code_from_header}) received from an unknown or previously timed-out client ID: {current_log_id_str}. Denying request.")
                        # Spec: "Unknown client reconnect -> Send response 1606".
                        # For other requests from an unrecognized ID, a generic error is safest.
                        if code_from_header == REQ_RECONNECT:
                             self._send_response(client_conn, RESP_RECONNECT_FAIL, client_id_from_header) # Send back the ID they attempted with
                        else:
                             self._send_response(client_conn, RESP_GENERIC_SERVER_ERROR)
                        break # Terminate connection with this client
                    
                    active_client_obj.update_last_seen() # Mark this client as active (resets session timeout timer)
                    log_client_identifier = f"{client_ip}:{client_port} (Name:'{active_client_obj.name}', ID:{current_log_id_str})" # Update log ID with client name
                
                # --- Process the Request ---
                # Dispatch to the appropriate handler based on the request code
                self._process_request(client_conn, client_id_from_header, active_client_obj, code_from_header, payload_bytes)

        except (TimeoutError, ConnectionError) as e: # Covers socket.timeout and custom ConnectionError from _read_exact
            logger.warning(f"Connection issue with {log_client_identifier}: {e}. Closing connection.")
        except ProtocolError as e: # Catch protocol violations (e.g., bad header, invalid payload)
            logger.error(f"Protocol error encountered with {log_client_identifier}: {e}. Sending generic error and closing connection.")
            if client_conn.fileno() != -1: # Check if socket is still somewhat valid before attempting to send
                try:
                    self._send_response(client_conn, RESP_GENERIC_SERVER_ERROR)
                except Exception as send_error_exception: # Catch errors during the sending of the error response itself
                    logger.error(f"Failed to send error response to {log_client_identifier} after a protocol error occurred: {send_error_exception}")
        except Exception as e: # Catch-all for any other unexpected errors within this client handler
            logger.critical(f"Unexpected critical error occurred while handling client {log_client_identifier}: {e}", exc_info=True)
            if client_conn.fileno() != -1: # If socket is still open
                try:
                    self._send_response(client_conn, RESP_GENERIC_SERVER_ERROR)
                except Exception as send_error_exception:
                    logger.error(f"Failed to send error response to {log_client_identifier} after an unexpected error: {send_error_exception}")
        finally:
            if client_conn: # Ensure the client socket is closed
                client_conn.close()
            conn_semaphore.release() # IMPORTANT: Release the semaphore slot for other clients
            logger.info(f"Connection with {log_client_identifier} has been closed and semaphore released.")


    def _process_request(self, sock: socket.socket, client_id_from_header: bytes, client: Optional[Client], code: int, payload: bytes):
        """
        Dispatches a client request to the appropriate handler method based on the request code.

        Args:
            sock: The client's socket.
            client_id_from_header: The Client ID received in the request header.
            client: The resolved Client object (None for registration requests).
            code: The request code.
            payload: The request payload.
        """
        
        handler_map = {
            REQ_REGISTER: self._handle_registration,
            REQ_SEND_PUBLIC_KEY: self._handle_send_public_key,
            REQ_RECONNECT: self._handle_reconnect,
            REQ_SEND_FILE: self._handle_send_file,
            REQ_CRC_OK: self._handle_crc_ok,
            REQ_CRC_INVALID_RETRY: self._handle_crc_invalid_retry,
            REQ_CRC_FAILED_ABORT: self._handle_crc_failed_abort,
        }

        handler_method = handler_map.get(code) # Get the method associated with the request code

        if handler_method:
            if code == REQ_REGISTER:
                # Registration is special: client_id_from_header is all zeros, and `client` object is not yet created/resolved.
                # The handler itself will generate the new client ID and create the Client object.
                handler_method(sock, payload) 
            elif client: 
                # For all other requests, a valid `client` object (resolved by client_id_from_header) must exist.
                # The `client` object contains the authoritative client ID (client.id).
                handler_method(sock, client, payload) 
            else: 
                # This state (handler method exists, but `client` object is None for a non-registration request)
                # indicates a logic flaw in the calling sequence (e.g., _handle_client_connection did not resolve client).
                logger.critical(f"INTERNAL SERVER ERROR: Client object is None for a non-registration request (Code: {code}, Header ID: {client_id_from_header.hex()}). This should have been caught earlier.")
                self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Send generic error
        else:
            # If the request code is not found in our handler_map
            client_name_for_log = client.name if client else client_id_from_header.hex() # Get a name for logging
            logger.warning(f"Unknown or unsupported request code {code} received from client '{client_name_for_log}'.")
            self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Respond with generic error


    def _parse_string_from_payload(self, payload_bytes: bytes, field_len: int, max_actual_len: int, field_name: str = "String") -> str:
        """
        Parses a null-terminated, zero-padded string from a fixed-length field within a payload.

        Args:
            payload_bytes: The byte slice containing the string field.
            field_len: The total expected length of this field in the payload (including padding).
            max_actual_len: The maximum allowed length of the actual string content (excluding null terminator and padding).
            field_name: A descriptive name for the field being parsed (for error messages).

        Returns:
            The parsed string.

        Raises:
            ProtocolError: If the field is malformed, too short, or content is invalid.
        """
        # Ensure we have enough bytes for the field itself before trying to slice
        if len(payload_bytes) < field_len:
            raise ProtocolError(f"Payload is too short to contain the '{field_name}' field. Expected at least {field_len} bytes, got {len(payload_bytes)}.")
        
        try:
            # Extract the fixed-length field portion from the payload
            field_data = payload_bytes[:field_len]
            # Find the first null terminator to get the actual string content
            # .split(b'\0', 1)[0] handles cases with or without null, and extra nulls.
            parsed_str = field_data.split(b'\0', 1)[0].decode('utf-8') # Decode as UTF-8
            
            # Validate the length of the actual decoded string content
            if not (1 <= len(parsed_str) <= max_actual_len):
                 raise ValueError(f"Actual content length of '{field_name}' ({len(parsed_str)}) is invalid. Must be between 1 and {max_actual_len} characters.")
            
            # Specific character validation for client names
            if field_name == "Client Name": 
                if not all(32 <= ord(c) <= 126 for c in parsed_str): # Check for printable ASCII
                     raise ValueError(f"'{field_name}' contains non-printable ASCII characters, which are not allowed.")
            # For filenames, a separate, more specific validation method (_is_valid_filename_for_storage) is used later.
            
            return parsed_str
        except UnicodeDecodeError: # If bytes are not valid UTF-8
            raise ProtocolError(f"The '{field_name}' field in the payload is not encoded in valid UTF-8.")
        except ValueError as e: # Catches custom ValueErrors raised for length/character issues
            raise ProtocolError(f"Invalid '{field_name}' field content: {e}")


    def _handle_registration(self, sock: socket.socket, payload: bytes):
        """
        Handles client registration request (Code 1025).
        Payload: char name[255]; (null-terminated, zero-padded)
        """
        name_field_protocol_len = 255 # Total length of the name field in the protocol
        if len(payload) != name_field_protocol_len: # Check if payload has the exact expected size for this request
            raise ProtocolError(f"Registration Request (1025): Invalid payload size. Expected {name_field_protocol_len} bytes, got {len(payload)}.")
        
        try:
            # Parse client name from payload, enforcing max actual length and character set
            client_name = self._parse_string_from_payload(payload, name_field_protocol_len, MAX_CLIENT_NAME_LENGTH, "Client Name")
            
            with self.clients_lock: # Ensure thread-safe access to shared client dictionaries
                if client_name in self.clients_by_name: # Check if username is already taken
                    logger.warning(f"Registration attempt failed: Username '{client_name}' is already registered.")
                    self._send_response(sock, RESP_REG_FAIL) # Send Registration Failed (1601), no payload
                    return
                
                # Generate a new unique client ID (UUID version 4)
                new_client_id_bytes = uuid.uuid4().bytes
                new_client = Client(new_client_id_bytes, client_name) # Create a new Client object
                
                # Add the new client to in-memory tracking structures
                self.clients[new_client_id_bytes] = new_client
                self.clients_by_name[client_name] = new_client_id_bytes
                
                self._save_client_to_db(new_client) # Persist the new client's basic info to the database
            
            logger.info(f"Client '{client_name}' successfully registered with New Client ID: {new_client_id_bytes.hex()}.")
            # Send Registration Success (1600) response with the new client ID as payload
            self._send_response(sock, RESP_REG_OK, new_client_id_bytes)
        
        except ProtocolError as e: # Catch errors from parsing or payload size validation
            logger.error(f"Registration protocol error: {e}")
            self._send_response(sock, RESP_REG_FAIL) # Send registration failure


    def _handle_send_public_key(self, sock: socket.socket, client: Client, payload: bytes):
        """
        Handles client's public key submission (Code 1026).
        Client object is already resolved by ID from request header.
        Payload: char name[255]; uint8_t public_key[160];
        """
        name_field_protocol_len = 255
        expected_payload_size = name_field_protocol_len + RSA_PUBLIC_KEY_SIZE # Total expected payload size
        if len(payload) != expected_payload_size:
            raise ProtocolError(f"SendPublicKey Request (1026): Invalid payload size. Expected {expected_payload_size} bytes, got {len(payload)}.")
        
        try:
            # Parse client name from the first part of the payload
            name_from_payload = self._parse_string_from_payload(payload, name_field_protocol_len, MAX_CLIENT_NAME_LENGTH, "Client Name")
            # Extract the public key bytes from the latter part of the payload
            public_key_bytes_from_payload = payload[name_field_protocol_len:] # Next RSA_PUBLIC_KEY_SIZE bytes

            # Validate that the name in payload matches the name associated with the client ID from header
            if client.name != name_from_payload:
                logger.warning(f"SendPublicKey: Name mismatch for Client ID {client.id.hex()}. Client's known name: '{client.name}', Name in payload: '{name_from_payload}'. This indicates a protocol violation or client-side inconsistency.")
                self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Use a generic error for this unexpected state
                return

            client.set_public_key(public_key_bytes_from_payload) # This validates size and imports the RSA key object
            
            # Generate a new AES session key for this client
            new_aes_key = get_random_bytes(AES_KEY_SIZE_BYTES) # 256-bit AES key
            client.set_aes_key(new_aes_key) # Store the new AES key in the client object
            
            # Encrypt the new AES key using the client's RSA public key (PKCS1_OAEP padding)
            if not client.public_key_obj: # Should have been caught by client.set_public_key if import failed
                 raise ServerError("Internal Server Error: Client's public key object is not available for RSA encryption after an import attempt. This should not happen.")
            cipher_rsa = PKCS1_OAEP.new(client.public_key_obj)
            encrypted_aes_key = cipher_rsa.encrypt(client.get_aes_key()) # client.get_aes_key() gets the new_aes_key
            
            # Update client's record in the database (PublicKey, LastSeen, and new session AESKey)
            self._save_client_to_db(client) 
            
            # Construct and send Response 1602 (Public Key ACK + AES Key)
            # Payload: client_id[16] (client's own ID), encrypted_aes_key[] (variable length from RSA encryption)
            response_payload = client.id + encrypted_aes_key
            self._send_response(sock, RESP_PUBKEY_AES_SENT, response_payload)
            logger.info(f"Public key successfully received and processed for client '{client.name}'. New AES session key has been sent (encrypted).")

        except (ProtocolError, ServerError, ValueError) as e: # ValueError can be raised by RSA operations
            logger.error(f"Error processing SendPublicKey request for client '{client.name}': {e}")
            self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Send generic error for crypto or protocol issues
        except Exception as e_crypto: # Catch any other unexpected cryptographic errors
            logger.critical(f"Unexpected critical error during RSA encryption for client '{client.name}': {e_crypto}", exc_info=True)
            self._send_response(sock, RESP_GENERIC_SERVER_ERROR)


    def _handle_reconnect(self, sock: socket.socket, client: Client, payload: bytes):
        """
        Handles client reconnection request (Code 1027).
        Client object is already resolved by ID from request header.
        Payload: char name[255]; (null-terminated, padded)
        """
        name_field_protocol_len = 255
        if len(payload) != name_field_protocol_len:
            raise ProtocolError(f"Reconnect Request (1027): Invalid payload size. Expected {name_field_protocol_len} bytes, got {len(payload)}.")
        
        try:
            name_from_payload = self._parse_string_from_payload(payload, name_field_protocol_len, MAX_CLIENT_NAME_LENGTH, "Client Name")

            # Validate that name in payload matches the known name for this client ID
            if client.name != name_from_payload:
                logger.warning(f"Reconnect: Name mismatch for Client ID {client.id.hex()}. Client's known name: '{client.name}', Name in payload: '{name_from_payload}'. Sending Reconnect Failed response.")
                # Response Payload (1606): client_id[16] (client's ID from header, as per spec)
                self._send_response(sock, RESP_RECONNECT_FAIL, client.id)
                return
            
            # Client must have a public key on record from a previous session to encrypt a new AES key
            if not client.public_key_obj: 
                logger.warning(f"Reconnect Failed: Client '{client.name}' (ID: {client.id.hex()}) attempting to reconnect, but has no public key on record. Cannot send a new AES key.")
                self._send_response(sock, RESP_RECONNECT_FAIL, client.id)
                return

            # Generate a new AES session key for this reconnected session
            new_aes_key = get_random_bytes(AES_KEY_SIZE_BYTES)
            client.set_aes_key(new_aes_key) # Store new AES key in client object
            
            # Encrypt the new AES key with the client's stored public RSA key
            cipher_rsa = PKCS1_OAEP.new(client.public_key_obj)
            encrypted_aes_key = cipher_rsa.encrypt(client.get_aes_key())
            
            # Update client's record in the database (updates LastSeen and current session AESKey)
            self._save_client_to_db(client)

            # Construct and send Response 1605 (Reconnect Success + AES Key)
            # Payload: client_id[16] (client's ID), encrypted_aes_key[]
            response_payload = client.id + encrypted_aes_key
            self._send_response(sock, RESP_RECONNECT_AES_SENT, response_payload)
            logger.info(f"Client '{client.name}' reconnected successfully. A new AES session key has been sent (encrypted).")

        except ProtocolError as e: # Errors from parsing or payload size
            logger.error(f"Reconnect protocol error for client '{client.name}': {e}")
            self._send_response(sock, RESP_RECONNECT_FAIL, client.id) # Send client's ID with failure
        except Exception as e_reconnect: # Catch RSA encryption errors or other unexpected issues
            logger.critical(f"Unexpected critical error during reconnect process for client '{client.name}': {e_reconnect}", exc_info=True)
            self._send_response(sock, RESP_RECONNECT_FAIL, client.id)


    def _is_valid_filename_for_storage(self, filename_str: str) -> bool:
        """
        Validates a filename string for storage on the server.
        Checks length, allowed characters, and common OS reserved names.

        Args:
            filename_str: The filename string to validate.

        Returns:
            True if the filename is considered valid and safe for storage, False otherwise.
        """
        # Check actual length of the filename string (not the padded field size)
        if not (1 <= len(filename_str) <= MAX_ACTUAL_FILENAME_LENGTH):
            logger.debug(f"Filename validation failed for '{filename_str}': Length ({len(filename_str)}) is out of allowed range (1-{MAX_ACTUAL_FILENAME_LENGTH}).")
            return False
        
        # Disallow path traversal characters (slashes, backslashes, '..') and null bytes within the actual filename
        if '/' in filename_str or '\\' in filename_str or '..' in filename_str or '\0' in filename_str:
            logger.debug(f"Filename validation failed for '{filename_str}': Contains path traversal sequence or null characters.")
            return False
        
        # Regex for generally safe filename characters:
        # Allows alphanumeric, dots, underscores, hyphens, and spaces.
        # This can be made stricter or more lenient based on specific server OS and policies.
        if not re.match(r"^[a-zA-Z0-9._\-\s]+$", filename_str):
            logger.debug(f"Filename validation failed for '{filename_str}': Contains disallowed characters (does not match regex '^[a-zA-Z0-9._\\-\\s]+$').")
            return False
        
        # Check for names that are problematic on some operating systems (e.g., Windows reserved names like CON, PRN)
        # Comparison is case-insensitive for these reserved names.
        # We check the base name of the file (without extension) against reserved names.
        base_filename_no_ext = os.path.splitext(filename_str)[0].upper() # Get name part, uppercase
        reserved_os_names = {"CON", "PRN", "AUX", "NUL"} | \
                            {f"COM{i}" for i in range(1,10)} | \
                            {f"LPT{i}" for i in range(1,10)}
        if base_filename_no_ext in reserved_os_names:
             logger.debug(f"Filename validation failed for '{filename_str}': Base name '{base_filename_no_ext}' is a reserved OS name.")
             return False
        
        return True # If all checks pass, filename is considered valid


    def _handle_send_file(self, sock: socket.socket, client: Client, payload: bytes):
        """
        Handles a file transfer packet (Code 1028) from a client.
        Manages multi-packet reassembly, decryption, CRC calculation, and storage.
        Client object is already resolved by ID from request header.

        Payload Structure:
          uint32_t encrypted_size;    // Size of 'content[]' in this specific packet
          uint32_t original_size;     // Total original (decrypted) file size
          uint16_t packet_number;     // Current packet number (1-based)
          uint16_t total_packets;     // Total number of packets for this entire file
          char     filename[255];     // Null-terminated, zero-padded filename field
          uint8_t  content[];         // Encrypted file chunk for this packet
        """
        
        # Size of the metadata part of the payload (fields before the actual file content)
        metadata_header_size = 4 + 4 + 2 + 2 + MAX_FILENAME_FIELD_SIZE 
        if len(payload) < metadata_header_size: # Payload must be at least this large
            raise ProtocolError(f"SendFile Request (1028): Payload is too short for file metadata part ({len(payload)} bytes). Minimum expected: {metadata_header_size}.")

        # Unpack metadata fields from the payload (all are little-endian)
        encrypted_packet_content_size = struct.unpack("<I", payload[0:4])[0]
        original_file_size = struct.unpack("<I", payload[4:8])[0]
        packet_number = struct.unpack("<H", payload[8:10])[0]
        total_packets = struct.unpack("<H", payload[10:12])[0]
        filename_bytes_padded = payload[12 : 12 + MAX_FILENAME_FIELD_SIZE] # Extract the 255-byte filename field
        
        # --- Input Validations for File Transfer Metadata ---
        if not (encrypted_packet_content_size > 0 and encrypted_packet_content_size <= MAX_PAYLOAD_READ_LIMIT - metadata_header_size): # Ensure content size is reasonable
            raise ProtocolError(f"SendFile: Invalid encrypted_packet_content_size ({encrypted_packet_content_size}). Must be > 0 and within payload limits.")
        if not (original_file_size >= 0 and original_file_size <= MAX_ORIGINAL_FILE_SIZE): # original_file_size can be 0 for empty file
             raise ProtocolError(f"SendFile: Invalid original_file_size ({original_file_size}). Must be >= 0 and <= {MAX_ORIGINAL_FILE_SIZE}.")
        if not (total_packets > 0): # Must be at least one packet
            raise ProtocolError(f"SendFile: Invalid total_packets ({total_packets}). Must be > 0.")
        if not (1 <= packet_number <= total_packets): # Packet number must be within valid range
            raise ProtocolError(f"SendFile: Invalid packet_number ({packet_number}). Must be between 1 and total_packets ({total_packets}).")
        
        # Parse and validate the filename string from its padded field
        try:
            # Filename is null-terminated within the MAX_FILENAME_FIELD_SIZE byte field
            filename_str = filename_bytes_padded.split(b'\0', 1)[0].decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError("SendFile: Filename field in payload is not valid UTF-8.")

        if not self._is_valid_filename_for_storage(filename_str): # Uses MAX_ACTUAL_FILENAME_LENGTH internally
            # If filename is invalid, we cannot proceed with this file transfer.
            raise FileError(f"SendFile: Invalid or unsafe filename received: '{filename_str}'. Transfer aborted for this file.")

        # Extract the actual encrypted content for this packet from the payload
        actual_encrypted_content_in_payload = payload[metadata_header_size:]
        if len(actual_encrypted_content_in_payload) != encrypted_packet_content_size: # Verify declared size matches actual
            raise ProtocolError(f"SendFile: Mismatch for file '{filename_str}'. Declared encrypted content size in packet ({encrypted_packet_content_size}) does not match actual received content size ({len(actual_encrypted_content_in_payload)}).")

        current_aes_key = client.get_aes_key() # Get the current AES session key for this client
        if not current_aes_key:
            # This state implies a protocol violation by the client (e.g., attempting to send a file
            # before completing the public key exchange or a successful reconnect to get an AES key).
            raise ClientError(f"SendFile: Client '{client.name}' has no active AES key for file decryption. This is a critical protocol violation.")
        
        logger.info(f"Client '{client.name}': Receiving file '{filename_str}', Packet {packet_number}/{total_packets} (EncSizeInPkt:{encrypted_packet_content_size}, OrigFileSize:{original_file_size}).")

        # --- Multi-Packet Reassembly Logic ---
        with client.lock: # Ensure thread-safe access to this specific client's partial_files dictionary
            # Initialize or retrieve partial file reassembly state for this filename
            if packet_number == 1: # This is the first packet for this file (or a new attempt for this file)
                if filename_str in client.partial_files: # If restarting a transfer for an existing partial file
                    logger.warning(f"Client '{client.name}': Receiving packet 1 for file '{filename_str}', but partial reassembly data already exists. Overwriting previous state and restarting transfer for this file.")
                # Create a new entry for this file transfer
                client.partial_files[filename_str] = {
                    "total_packets": total_packets,
                    "received_chunks": {}, # Store encrypted chunks here, map: packet_number -> chunk_bytes
                    "original_size": original_file_size,
                    "timestamp": time.monotonic() # Track activity for stale cleanup
                }
            
            file_state = client.partial_files.get(filename_str) # Get the current reassembly state for this file
            
            # Consistency checks if this is not the first packet:
            # Ensure total_packets and original_size match what was declared in packet 1.
            if not file_state or \
               (packet_number > 1 and (file_state["total_packets"] != total_packets or file_state["original_size"] != original_file_size)):
                logger.error(f"Client '{client.name}': Inconsistent file transfer metadata for ongoing transfer of '{filename_str}'. Expected TotalPkts:{file_state.get('total_packets') if file_state else 'N/A'}/OrigSize:{file_state.get('original_size') if file_state else 'N/A'}, but current packet declares TotalPkts:{total_packets}/OrigSize:{original_file_size}. Aborting this file transfer attempt.")
                if file_state : client.clear_partial_file(filename_str) # Clean up the inconsistent state from memory
                self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Send a generic error to the client
                return # Stop processing this request
            
            if packet_number in file_state["received_chunks"]: # Check for duplicate packets
                logger.warning(f"Client '{client.name}': Received duplicate packet number {packet_number} for file '{filename_str}'. Overwriting previous chunk for this packet number.")
            
            # Store the received encrypted chunk for this packet number
            file_state["received_chunks"][packet_number] = actual_encrypted_content_in_payload
            file_state["timestamp"] = time.monotonic() # Update timestamp on receiving any packet for this file

            # --- Check if all packets for the current file have been received ---
            if len(file_state["received_chunks"]) == total_packets:
                logger.info(f"Client '{client.name}': All {total_packets} packets for file '{filename_str}' have been received. Proceeding to reassemble and decrypt...")
                
                # Reassemble all encrypted chunks in the correct packet order
                full_encrypted_data = b''
                try:
                    for i in range(1, total_packets + 1): # Iterate from packet 1 to total_packets
                        full_encrypted_data += file_state["received_chunks"][i] # Append chunk
                except KeyError: # Should not happen if len check above is correct and all packets stored
                    logger.critical(f"INTERNAL SERVER LOGIC ERROR: A packet is missing during reassembly of '{filename_str}' for client '{client.name}' despite count match. This indicates a flaw in reassembly logic.")
                    client.clear_partial_file(filename_str) # Cleanup partial state
                    self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Send generic error
                    return

                try:
                    # Decrypt the fully reassembled encrypted data
                    # AES-CBC mode, IV is all zeros (as per simplified spec), PKCS7 padding
                    cipher_aes = AES.new(current_aes_key, AES.MODE_CBC, iv=b'\0' * 16)
                    decrypted_data = unpad(cipher_aes.decrypt(full_encrypted_data), AES.block_size)

                    # Verify that the size of the decrypted data matches the original_file_size from metadata
                    if len(decrypted_data) != original_file_size:
                        raise FileError(f"Decrypted data size for file '{filename_str}' ({len(decrypted_data)}) does not match the declared original file size ({original_file_size}). File may be corrupted or there was a protocol error.")

                    # Calculate CRC32 checksum on the fully decrypted data
                    calculated_crc_val = self._calculate_crc(decrypted_data)
                    
                    # Atomically save the decrypted file to server storage:
                    # 1. Write to a temporary file.
                    # 2. If successful, rename the temporary file to the final destination path.
                    # This prevents leaving partially written/corrupted files if the server crashes mid-write.
                    temp_file_id = uuid.uuid4() # Generate a unique ID for the temporary filename
                    temp_save_path = os.path.join(FILE_STORAGE_DIR, f"{filename_str}.{temp_file_id}.tmp_EncryptedBackup")
                    final_save_path = os.path.join(FILE_STORAGE_DIR, filename_str) # Final path using the original filename
                    
                    try:
                        with open(temp_save_path, 'wb') as f_temp: # Write decrypted data to temp file
                            f_temp.write(decrypted_data)
                        os.rename(temp_save_path, final_save_path) # Atomically rename (on POSIX if same filesystem)
                        logger.info(f"Client '{client.name}': File '{filename_str}' (Original Size: {original_file_size} bytes) successfully decrypted and saved to storage path: '{final_save_path}'.")
                    except OSError as e_os_save: # Catch errors during file write or rename
                        raise FileError(f"Failed to save decrypted file '{filename_str}' to server storage: {e_os_save}") from e_os_save
                    
                    # Persist file information to the database (initially marked as not verified by client)
                    self._save_file_info_to_db(client.id, filename_str, final_save_path, False) # Verified=False
                    
                    # Send Response Code 1603 (File Received + CRC Information)
                    # Payload: client_id[16], file_size (TOTAL ENCRYPTED size of all chunks)[4], filename[255 (padded)], crc[4]
                    response_payload = client.id + \
                                       struct.pack("<I", len(full_encrypted_data)) + \
                                       filename_bytes_padded + \
                                       struct.pack("<I", calculated_crc_val)
                    self._send_response(sock, RESP_FILE_CRC, response_payload)
                    logger.info(f"Client '{client.name}': Sent CRC ({calculated_crc_val}) for file '{filename_str}'. Now awaiting client's CRC verification response.")

                except (ValueError, FileError, ProtocolError) as e: # ValueError can come from unpad() or struct issues
                    logger.error(f"Client '{client.name}': Error occurred during decryption or final processing of fully received file '{filename_str}': {e}")
                    if 'temp_save_path' in locals() and os.path.exists(temp_save_path): # Ensure cleanup of temp file on error
                        try: os.remove(temp_save_path)
                        except OSError as e_rm_tmp: logger.error(f"Failed to remove temporary file '{temp_save_path}' after error: {e_rm_tmp}")
                    self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Send a generic error to the client
                except Exception as e_final_processing: # Catch-all for other unexpected errors during this stage
                     logger.critical(f"Client '{client.name}': Unexpected critical error during final processing of file '{filename_str}': {e_final_processing}", exc_info=True)
                     if 'temp_save_path' in locals() and os.path.exists(temp_save_path): os.remove(temp_save_path) # Cleanup
                     self._send_response(sock, RESP_GENERIC_SERVER_ERROR)
                finally:
                    # Whether processing was successful or failed, clear the partial file reassembly state from memory for this file
                    client.clear_partial_file(filename_str)
            # If not all packets for the file have been received yet, the server implicitly waits for more packets.
            # The specification does not require an ACK from the server for each individual file packet received.

    def _handle_crc_ok(self, sock: socket.socket, client: Client, payload: bytes):
        """
        Handles client's confirmation that CRC matches (Code 1029).
        Client object is already resolved.
        Payload: char filename[255]; (null-terminated, padded)
        """
        filename_field_protocol_len = 255 # Expected length of the filename field in the protocol
        if len(payload) != filename_field_protocol_len:
            raise ProtocolError(f"CRC OK Request (1029): Invalid payload size. Expected {filename_field_protocol_len} bytes, got {len(payload)}.")
        
        try:
            # Parse filename from payload
            filename_str = self._parse_string_from_payload(payload, filename_field_protocol_len, MAX_ACTUAL_FILENAME_LENGTH, "Filename")
        except ProtocolError as e_parse: # Error during parsing of the filename
            logger.error(f"Client '{client.name}': CRC OK request error - {e_parse}")
            self._send_response(sock, RESP_GENERIC_SERVER_ERROR) # Send generic error if filename parsing fails
            return

        logger.info(f"Client '{client.name}' confirmed CRC OK for file '{filename_str}'. File transfer is now successfully completed and verified.")
        # Determine the path where the file was saved (as done in _handle_send_file)
        final_save_path = os.path.join(FILE_STORAGE_DIR, filename_str)
        # Update the file's record in the database to mark it as verified
        self._save_file_info_to_db(client.id, filename_str, final_save_path, True) # Verified=True
        
        # Send Response 1604 (General ACK)
        # Payload: client_id[16] (client's own ID)
        self._send_response(sock, RESP_ACK, client.id)


    def _handle_crc_invalid_retry(self, sock: socket.socket, client: Client, payload: bytes):
        """
        Handles client's report that CRC does not match and they will retry (Code 1030).
        Client object is already resolved.
        Payload: char filename[255]; (null-terminated, padded)
        """
        filename_field_protocol_len = 255
        if len(payload) != filename_field_protocol_len:
            raise ProtocolError(f"CRC Invalid Retry Request (1030): Invalid payload size. Expected {filename_field_protocol_len}, got {len(payload)}.")
        
        try:
            filename_str = self._parse_string_from_payload(payload, filename_field_protocol_len, MAX_ACTUAL_FILENAME_LENGTH, "Filename")
        except ProtocolError as e_parse:
            logger.error(f"Client '{client.name}': CRC Invalid Retry request error - {e_parse}")
            self._send_response(sock, RESP_GENERIC_SERVER_ERROR)
            return
            
        logger.warning(f"Client '{client.name}' reported CRC invalid for file '{filename_str}'. Client will attempt to retry sending the entire file.")
        # Server-Side Action:
        # The file on disk (if it was saved from the previous attempt) is currently marked as unverified in the DB.
        # The client is expected to re-initiate the entire file transfer sequence (REQ_SEND_FILE from packet 1).
        # The server's in-memory partial file reassembly state for this filename (if any) was cleared
        # when the RESP_FILE_CRC was sent after the previous attempt.
        # If the file exists on disk from the failed attempt, it will be overwritten when the new transfer attempt succeeds.
        # Ensure the database record reflects the file is not verified.
        final_save_path = os.path.join(FILE_STORAGE_DIR, filename_str) # Path remains relevant for DB record
        self._save_file_info_to_db(client.id, filename_str, final_save_path, False) # Ensure Verified=False
        
        # Send Response 1604 (General ACK)
        self._send_response(sock, RESP_ACK, client.id)


    def _handle_crc_failed_abort(self, sock: socket.socket, client: Client, payload: bytes):
        """
        Handles client's report of final CRC failure and aborting transfer (Code 1031).
        Client object is already resolved.
        Payload: char filename[255]; (null-terminated, padded)
        """
        filename_field_protocol_len = 255
        if len(payload) != filename_field_protocol_len:
            raise ProtocolError(f"CRC Failed Abort Request (1031): Invalid payload size. Expected {filename_field_protocol_len}, got {len(payload)}.")
        
        try:
            filename_str = self._parse_string_from_payload(payload, filename_field_protocol_len, MAX_ACTUAL_FILENAME_LENGTH, "Filename")
        except ProtocolError as e_parse:
            logger.error(f"Client '{client.name}': CRC Failed Abort request error - {e_parse}")
            self._send_response(sock, RESP_GENERIC_SERVER_ERROR)
            return

        logger.error(f"Client '{client.name}' aborted transfer for file '{filename_str}' due to final CRC mismatch. Server will delete its copy of this file.")
        final_save_path = os.path.join(FILE_STORAGE_DIR, filename_str) # Path to the file on server
        
        try: # Attempt to remove the corrupted/aborted file from server storage
            if os.path.exists(final_save_path):
                os.remove(final_save_path)
                logger.info(f"Successfully removed aborted file from server storage: {final_save_path}")
            else:
                # This might happen if the file save failed previously or was already cleaned up.
                logger.warning(f"Aborted file '{final_save_path}' was not found on server for deletion (Client: '{client.name}'). It might have failed saving earlier.")
        except OSError as e_os_remove: # Catch errors during file deletion
            logger.error(f"Error occurred while attempting to remove aborted file '{final_save_path}' from storage: {e_os_remove}")
            
        # Update Database: The file is confirmed as not verified.
        # Depending on specific requirements, one might choose to delete the file record from the database entirely,
        # or simply ensure its 'Verified' status is False. The specification implies keeping a record, so update Verified status.
        self._save_file_info_to_db(client.id, filename_str, final_save_path, False) # Ensure Verified=False
        
        # Send Response 1604 (General ACK)
        self._send_response(sock, RESP_ACK, client.id)


    def _calculate_crc(self, data: bytes) -> int:
        """
        Calculates a CRC32 checksum compatible with the Linux 'cksum' command.
        This involves processing data bytes and then processing the length of the data.

        Args:
            data: The input bytes for which to calculate the CRC.

        Returns:
            The 32-bit CRC value.
        """
        crc = 0 # Initialize CRC to 0
        # Process each byte of the input data
        for byte_val in data:
            # Standard CRC32 polynomial algorithm step using a lookup table
            # XOR current CRC's top byte with current data byte to get table index
            # XOR table value with CRC shifted left by 8 bits
            # Ensure result remains a 32-bit unsigned integer
            crc = (self._CRC32_TABLE[(crc >> 24) ^ byte_val] ^ (crc << 8)) & 0xFFFFFFFF 
        
        length = len(data) # Get the length of the data
        # Now, incorporate the length of the data into the CRC calculation, byte by byte
        while length: 
            # Process each byte of the length value
            crc = (self._CRC32_TABLE[(crc >> 24) ^ (length & 0xFF)] ^ (crc << 8)) & 0xFFFFFFFF
            length >>= 8 # Shift length to get next byte
            
        # The final CRC value is the one's complement of the accumulated CRC
        return (~crc) & 0xFFFFFFFF 


# --- Main Execution Guard ---
if __name__ == "__main__":
    # Display a startup banner for the server console
    print("=====================================================================")
    print(f"      Secure Encrypted File Backup Server - Version {SERVER_VERSION}      ")
    print(f"      Process ID: {os.getpid()}                                     ")
    print("=====================================================================")
    
    # Perform basic pre-flight checks before attempting to start the server
    if sys.version_info < (3, 7): # PyCryptodome generally works better with Python 3.7+
        print("Warning: Python 3.7 or newer is recommended for optimal server performance and security library compatibility.", file=sys.stderr)

    try:
        # Quick check to ensure PyCryptodome is available and basic operations work
        _ = RSA.generate(1024, randfunc=get_random_bytes) # Test RSA key generation
        _ = AES.new(get_random_bytes(AES_KEY_SIZE_BYTES), AES.MODE_CBC, iv=get_random_bytes(16)) # Test AES cipher creation
        logger.info("PyCryptodome library check passed: Basic crypto operations are available.")
    except Exception as e_crypto_check:
        print(f"CRITICAL FAILURE: PyCryptodome library is not installed correctly or is non-functional: {e_crypto_check}", file=sys.stderr)
        print("Please ensure PyCryptodome is properly installed (e.g., via 'pip install pycryptodomex'). Server cannot start.", file=sys.stderr)
        sys.exit(1) # Exit if essential crypto library is missing/broken

    # Instantiate the server
    server_instance = BackupServer()
    try:
        server_instance.start() # This method now contains the main accept loop
        
        # The main thread (this __main__ block) will now primarily wait for the server
        # to be shut down (e.g., by a signal). The server's accept loop and client handling
        # occur in other threads.
        while server_instance.running and not server_instance.shutdown_event.is_set():
            time.sleep(1) # Keep the main thread alive, periodically checking server status
            
    except KeyboardInterrupt: # This should now be primarily handled by the SIGINT signal handler
        logger.info("KeyboardInterrupt detected in main execution block. Server stop should have been triggered by signal handler.")
    except SystemExit as e_sys_exit: # If startup checks (e.g., _load_clients_from_db, _perform_startup_checks) decided to exit
         logger.critical(f"Server startup process was aborted: {e_sys_exit}")
    except Exception as e_main_fatal: # Catch-all for any other unexpected fatal errors during server setup or main loop
        logger.critical(f"Server encountered a fatal unhandled exception in main execution: {e_main_fatal}", exc_info=True)
    finally:
        # Ensure server stop sequence is robustly called, even if start() failed or loop exited unexpectedly
        if server_instance.running or not server_instance.shutdown_event.is_set(): # If not already fully stopped
            logger.info("Ensuring server shutdown is called from __main__ 'finally' block...")
            server_instance.stop() # Attempt to stop the server if it's still considered running
        
        logger.info("Server application has completed its full termination sequence.")
        print("Server shutdown process complete. Exiting.")