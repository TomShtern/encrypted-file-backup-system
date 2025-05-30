"""
File management operations
Handles file storage, retrieval, and metadata management
"""

import os
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

class FileManager:
    """Manages file storage and metadata"""

    def __init__(self, storage_path: str = "storage"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True, parents=True)

        # Metadata file to track stored files
        self.metadata_file = self.storage_path / "metadata.json"
        self.metadata = self.load_metadata()

        # Create a lock for thread-safe operations
        import threading
        self._lock = threading.Lock()

    def load_metadata(self) -> Dict:
        """Load file metadata from disk"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        return {"files": {}}

    def save_metadata(self):
        """Save file metadata to disk"""
        try:
            with self._lock:
                with open(self.metadata_file, 'w') as f:
                    json.dump(self.metadata, f, indent=2)
        except IOError as e:
            print(f"Failed to save metadata: {e}")

    def store_file(self, filename: str, data: bytes, user_id: str) -> bool:
        """Store file data and update metadata"""
        try:
            # Create user directory if it doesn't exist
            user_dir = self.storage_path / user_id
            user_dir.mkdir(exist_ok=True)

            # Generate unique filename to avoid conflicts
            file_path = user_dir / filename
            counter = 1
            while file_path.exists():
                name, ext = os.path.splitext(filename)
                file_path = user_dir / f"{name}_{counter}{ext}"
                counter += 1

            # Write file data
            with open(file_path, 'wb') as f:
                f.write(data)

            # Calculate file hash for integrity
            file_hash = hashlib.sha256(data).hexdigest()

            # Update metadata
            file_id = str(file_path.relative_to(self.storage_path))
            self.metadata["files"][file_id] = {
                "original_name": filename,
                "user_id": user_id,
                "size": len(data),
                "hash": file_hash,
                "stored_at": datetime.now().isoformat(),
                "path": str(file_path.relative_to(self.storage_path))
            }

            self.save_metadata()
            return True

        except Exception as e:
            print(f"Error storing file {filename}: {e}")
            return False

    def retrieve_file(self, filename: str, user_id: str) -> Optional[bytes]:
        """Retrieve file data"""
        try:
            # Find file in metadata
            file_info = None
            for file_id, info in self.metadata["files"].items():
                if (info["original_name"] == filename and
                    info["user_id"] == user_id):
                    file_info = info
                    break

            if not file_info:
                return None

            # Read file data
            file_path = self.storage_path / file_info["path"]
            if not file_path.exists():
                return None

            with open(file_path, 'rb') as f:
                data = f.read()

            # Verify integrity
            file_hash = hashlib.sha256(data).hexdigest()
            if file_hash != file_info["hash"]:
                print(f"File integrity check failed for {filename}")
                return None

            return data

        except Exception as e:
            print(f"Error retrieving file {filename}: {e}")
            return None

    def list_files(self, user_id: str) -> List[Dict]:
        """List files for a specific user"""
        files = []

        for file_id, info in self.metadata["files"].items():
            if info["user_id"] == user_id:
                files.append({
                    "name": info["original_name"],
                    "size": info["size"],
                    "stored_at": info["stored_at"]
                })

        return files

    def delete_file(self, filename: str, user_id: str) -> bool:
        """Delete a file"""
        try:
            # Find and remove file
            file_to_remove = None
            for file_id, info in self.metadata["files"].items():
                if (info["original_name"] == filename and
                    info["user_id"] == user_id):
                    file_to_remove = file_id

                    # Delete physical file
                    file_path = self.storage_path / info["path"]
                    if file_path.exists():
                        file_path.unlink()

                    break

            if file_to_remove:
                del self.metadata["files"][file_to_remove]
                self.save_metadata()
                return True

            return False

        except Exception as e:
            print(f"Error deleting file {filename}: {e}")
            return False
