import base64
from hashlib import sha256, sha512
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from argon2 import PasswordHasher
import os



def hash_sha256(text: str):
    return sha256(text.encode()).hexdigest()

def hash_sha512(text: str):
    return sha512(text.encode()).hexdigest()




argon2_hasher = PasswordHasher()

def argon2_hash(password: str):
    return argon2_hasher.hash(password)

def argon2_verify(hashed: str, password: str):
    try:
        return argon2_hasher.verify(hashed, password)
    except Exception:
        return False




def aes_encrypt(message: str):
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    return {
        "key": base64.b64encode(key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext[:-16]).decode(),
        "tag": base64.b64encode(ciphertext[-16:]).decode(),
    }


def aes_decrypt(key_b64, nonce_b64, ciphertext_b64, tag_b64):
    key = base64.b64decode(key_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)

    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return decrypted.decode()




def chacha_encrypt(message: str):
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)

    ciphertext = chacha.encrypt(nonce, message.encode(), None)

    return {
        "key": base64.b64encode(key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext[:-16]).decode(),
        "tag": base64.b64encode(ciphertext[-16:]).decode(),
    }


def chacha_decrypt(key_b64, nonce_b64, ciphertext_b64, tag_b64):
    key = base64.b64decode(key_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)

    chacha = ChaCha20Poly1305(key)
    decrypted = chacha.decrypt(nonce, ciphertext + tag, None)
    return decrypted.decode()




def rsa_generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "private_key": private_pem.decode(),
        "public_key": public_pem.decode()
    }


def rsa_encrypt(public_key_pem: str, message: str):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(private_key_pem: str, ciphertext_b64: str):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    ciphertext = base64.b64decode(ciphertext_b64)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return plaintext.decode()


def rsa_sign(private_key_pem: str, message: str):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )

    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode()


def rsa_verify(public_key_pem: str, message: str, signature_b64: str):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False