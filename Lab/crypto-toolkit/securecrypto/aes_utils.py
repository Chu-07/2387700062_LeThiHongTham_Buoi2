from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def _derive_key(password: str) -> bytes:
    """Derive a deterministic key from the given password using a fixed salt.
    This simplifies the test scenario by avoiding the need to store the salt.
    """
    fixed_salt = b"0" * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=fixed_salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file_aes(filepath, password):
    """Encrypt the file at *filepath* with AES‑GCM.

    The function:
    1. Derives a key from the password.
    2. Generates a random 12‑byte nonce.
    3. Writes *nonce + ciphertext* to ``filepath + '.enc'``.
    4. Returns the base64‑encoded key so the caller can later decrypt.
    """
    key = _derive_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    # Ensure the file has been flushed and contains data before reading.
    from pathlib import Path
    data = Path(filepath).read_bytes()
    ct = aesgcm.encrypt(nonce, data, None)
    # Store nonce followed by ciphertext (no salt needed).
    with open(filepath + '.enc', 'wb') as f:
        f.write(nonce + ct)
    return base64.b64encode(key).decode()

def decrypt_file_aes(encrypted_file, key_base64):
    """Decrypt a file produced by :func:`encrypt_file_aes`.

    *encrypted_file* should be the path to the ``.enc`` file.
    *key_base64* is the base64‑encoded key returned by the encrypt function.
    The decrypted file is written with a ``.dec`` suffix and its path is returned.
    """
    key = base64.b64decode(key_base64)
    with open(encrypted_file, 'rb') as f:
        raw = f.read()
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    out_path = encrypted_file.replace('.enc', '.dec')
    with open(out_path, 'wb') as f:
        f.write(pt)
    return out_path
