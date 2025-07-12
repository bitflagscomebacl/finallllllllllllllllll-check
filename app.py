import os
import time
import hmac
import hashlib
import base64
import threading
from typing import Dict

from fastapi import FastAPI, Header, Depends, HTTPException, status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- Configuration & In-Memory Store ---

# Load secrets from environment variables.
# In a real Render environment, these will be set in the dashboard.
# For local dev, you can use a .env file.
ENCRYPTION_KEY = os.getenv("ENCRYPTION_SECRET", "0" * 32).encode("utf-8")
SIGNATURE_KEY = os.getenv("SIGNATURE_SECRET", "1" * 32).encode("utf-8")
VALID_API_KEYS_STR = os.getenv("VALID_API_KEYS", "")

# AES-GCM constants. Must match the .NET client.
AES_NONCE_BYTES = 12
AES_TAG_BYTES = 16

# In-memory store for API keys and their usage counts.
# This approach avoids a database, as requested.
class KeyStore:
    def __init__(self, valid_keys_str: str):
        # Using a lock for thread-safe operations on the dictionary
        self._lock = threading.Lock()
        
        # Load valid keys and initialize their usage counts.
        # Example: Each key starts with 5 uses.
        self.key_uses: Dict[str, int] = {
            key.strip(): 5 for key in valid_keys_str.split(',') if key.strip()
        }
        self.valid_keys = set(self.key_uses.keys())
        print(f"KeyStore initialized. Loaded {len(self.valid_keys)} keys.")

    def is_valid(self, key: str) -> bool:
        with self._lock:
            return key in self.valid_keys

    def get_remaining_uses(self, key: str) -> int:
        with self._lock:
            return self.key_uses.get(key, 0)

    def redeem(self, key: str) -> bool:
        with self._lock:
            if self.key_uses.get(key, 0) > 0:
                self.key_uses[key] -= 1
                return True
            return False

# Initialize the store at application startup
key_store = KeyStore(VALID_API_KEYS_STR)

# Initialize FastAPI App
app = FastAPI(docs_url=None, redoc_url=None) # Disable docs for security


# --- Security Dependency ---

async def verify_request(
    x_api_key: str = Header(...),
    x_signature: str = Header(...),
    x_timestamp: str = Header(...),
):
    """
    This dependency performs all security checks.
    It's run before every protected endpoint.
    """
    # 1. Timestamp Validation (prevents replay attacks)
    try:
        client_timestamp = int(x_timestamp)
        current_timestamp = int(time.time())
        if abs(current_timestamp - client_timestamp) > 30:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Invalid request"
            )
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid request"
        )

    # 2. Decrypt the API Key
    try:
        encrypted_data = base64.b64decode(x_api_key)
        
        # Extract nonce, ciphertext, and tag from the payload
        nonce = encrypted_data[:AES_NONCE_BYTES]
        ciphertext = encrypted_data[AES_NONCE_BYTES:-AES_TAG_BYTES]
        tag = encrypted_data[-AES_TAG_BYTES:]
        
        aesgcm = AESGCM(ENCRYPTION_KEY)
        decrypted_raw_key = aesgcm.decrypt(nonce, ciphertext, tag).decode("utf-8")
        
    except (InvalidTag, ValueError, IndexError):
        # Catches decryption errors, base64 errors, or malformed data
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid request"
        )

    # 3. HMAC Signature Verification (prevents tampering)
    message_to_sign = (x_timestamp + decrypted_raw_key).encode("utf-8")
    expected_signature = hmac.new(
        SIGNATURE_KEY, message_to_sign, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid request"
        )
        
    # 4. Key Existence Check
    if not key_store.is_valid(decrypted_raw_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid request"
        )
        
    # If all checks pass, return the decrypted key for the endpoint to use
    return decrypted_raw_key


# --- API Endpoints ---

@app.get("/")
async def root():
    # A simple, unprotected health check endpoint
    return {"status": "ok"}


@app.get("/check_key")
async def check_key(api_key: str = Depends(verify_request)):
    """
    Checks if a key is valid. The real work is done in `verify_request`.
    """
    remaining = key_store.get_remaining_uses(api_key)
    return {"valid": True, "remaining_uses": remaining}


@app.post("/redeem_key")
async def redeem_key(api_key: str = Depends(verify_request)):
    """
    Redeems a single use of a key.
    """
    if key_store.redeem(api_key):
        remaining = key_store.get_remaining_uses(api_key)
        return {"redeemed": True, "remaining_uses": remaining}
    else:
        # This case handles if the key runs out of uses between checks
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Key has no uses left"
        )
