import hashlib
import json
from datetime import datetime

class BlockchainUtils:
    @staticmethod
    def calculate_file_hash(file_stream):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        # Read file in chunks to avoid memory issues
        for byte_block in iter(lambda: file_stream.read(4096), b""):
            sha256_hash.update(byte_block)
        
        # Reset file pointer to beginning
        file_stream.seek(0)
        return sha256_hash.hexdigest()

    @staticmethod
    def generate_block(index, previous_hash, timestamp, data):
        """Generate a block hash based on content"""
        block_content = f"{index}{previous_hash}{timestamp}{json.dumps(data, sort_keys=True)}"
        return hashlib.sha256(block_content.encode()).hexdigest()
