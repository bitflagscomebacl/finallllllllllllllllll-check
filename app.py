import os
import time
import hmac
import hashlib
import base64
import threading
from typing import Dict

from fastapi import FastAPI, Header, Depends, HTTPException, status
# New imports for AES-CBC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --- Configuration & In-Memory Store ---

# Load secrets from environment variables.
# For AES-256, the key MUST be 32 bytes.
ENCRYPTION_KEY = os.getenv("ENCRYPTION_SECRET", "this-is-a-secure-32-byte-key!!").encode("utf-8")
SIGNATURE_KEY = os.getenv("SIGNATURE_SECRET", "this-is-my-hmac-signature-secret").encode("utf-8")
VALID_API_KEYS_STR = os.getenv("VALID_API_KEYS", "key-alpha-123,key-beta-456,key-gamma-789")

# AES-CBC and HMAC constants. Must match the .NET client.
AES_IV_BYTES = 16
HMAC_SHA256_BYTES = 32

# In-memory store (no changes here)
class KeyStore:
    def __init__(self, valid_keys_str: str):
        self._lock = threading.Lock()
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

key_store = KeyStore(VALID_API_KEYS_STR)
app = FastAPI(docs_url=None, redoc_url=None)

# --- REVISED Security Dependency ---

async def verify_request(
    x_api_key: str = Header(...),
    x_signature: str = Header(...),
    x_timestamp: str = Header(...),
):
    """
    Performs all security checks. Now handles Encrypt-then-MAC (AES-CBC + HMAC).
    """
    # 1. Timestamp Validation (no change)
    try:
        client_timestamp = int(x_timestamp)
        if abs(time.time() - client_timestamp) > 30:
            raise HTTPException(status_code=403, detail="Invalid request")
    except (ValueError, TypeError):
        raise HTTPException(status_code=403, detail="Invalid request")

    # 2. Decrypt the API Key (REVISED for Encrypt-then-MAC)
    try:
        encrypted_payload = base64.b64decode(x_api_key)

        # Extract IV, ciphertext, and HMAC tag from the payload
        iv = encrypted_payload[:AES_IV_BYTES]
        hmac_tag = encrypted_payload[-HMAC_SHA256_BYTES:]
        ciphertext = encrypted_payload[AES_IV_BYTES:-HMAC_SHA256_BYTES]

        # A. First, VERIFY the HMAC tag. This prevents padding oracle attacks.
        # We authenticate the IV + Ciphertext.
        # The .NET client used the ENCRYPTION_KEY for this HMAC, so we do too.
        expected_tag = hmac.new(ENCRYPTION_KEY, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, hmac_tag):
            raise InvalidSignature("HMAC validation of encrypted payload failed.")

        # B. If HMAC is valid, then DECRYPT
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # C. Unpad the result
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_raw_key = (unpadder.update(decrypted_padded) + unpadder.finalize()).decode("utf-8")

    except Exception: # Catch any crypto, b64, or slicing error with a generic response
        raise HTTPException(status_code=403, detail="Invalid request")

    # 3. Request Signature Verification (no change in logic, uses the separate SIGNATURE_KEY)
    message_to_sign = (x_timestamp + decrypted_raw_key).encode("utf-8")
    expected_signature = hmac.new(SIGNATURE_KEY, message_to_sign, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, x_signature):
        raise HTTPException(status_code=403, detail="Invalid request")

    # 4. Key Existence Check (no change)
    if not key_store.is_valid(decrypted_raw_key):
        raise HTTPException(status_code=403, detail="Invalid request")

    return decrypted_raw_key


# --- API Endpoints (no changes) ---

@app.get("/")
async def root():
    return {"status": "ok"}

@app.get("/check_key")
async def check_key(api_key: str = Depends(verify_request)):
    remaining = key_store.get_remaining_uses(api_key)
    return {"valid": True, "remaining_uses": remaining}

@app.post("/redeem_key")
async def redeem_key(api_key: str = Depends(verify_request)):
    if key_store.redeem(api_key):
        remaining = key_store.get_remaining_uses(api_key)
        return {"redeemed": True, "remaining_uses": remaining}
    else:
        raise HTTPException(status_code=403, detail="Key has no uses left")
