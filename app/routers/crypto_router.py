from fastapi import APIRouter
from pydantic import BaseModel
from app.services.crypto_service import aes_encrypt, aes_decrypt
from app.services.crypto_service import (
    hash_sha256, hash_sha512,
    argon2_hash, argon2_verify,
    chacha_encrypt, chacha_decrypt,
    rsa_generate_keys, rsa_encrypt, rsa_decrypt,
    rsa_sign, rsa_verify
) 

router = APIRouter()

class EncryptRequest(BaseModel):
    message: str

class DecryptRequest(BaseModel):
    key: str
    nonce: str
    ciphertext: str
    tag: str

@router.post("/encrypt/aes")
def encrypt_aes(request: EncryptRequest):
    return aes_encrypt(request.message)

@router.post("/decrypt/aes")
def decrypt_aes(request: DecryptRequest):
    plaintext = aes_decrypt(
        request.key,
        request.nonce,
        request.ciphertext,
        request.tag
    )
    return {"plaintext": plaintext}

class TextRequest(BaseModel):
    text: str

class PasswordVerifyRequest(BaseModel):
    hashed: str
    password: str

class AESDecryptRequest(BaseModel):
    key: str
    nonce: str
    ciphertext: str
    tag: str

class ChaChaDecryptRequest(AESDecryptRequest):
    pass

class RSAEncryptRequest(BaseModel):
    public_key: str
    message: str

class RSADecryptRequest(BaseModel):
    private_key: str
    ciphertext: str

class RSASignRequest(BaseModel):
    private_key: str
    message: str

class RSAVerifyRequest(BaseModel):
    public_key: str
    message: str
    signature: str

# ------------------ ENDPOINTS ------------------

# HASHES
@router.post("/hash/sha256")
def sha256_hash(req: TextRequest):
    return {"hash": hash_sha256(req.text)}

@router.post("/hash/sha512")
def sha512_hash(req: TextRequest):
    return {"hash": hash_sha512(req.text)}

# ARGON2
@router.post("/argon2/hash")
def argon2_hash_endpoint(req: TextRequest):
    return {"hash": argon2_hash(req.text)}

@router.post("/argon2/verify")
def argon2_verify_endpoint(req: PasswordVerifyRequest):
    return {"valid": argon2_verify(req.hashed, req.password)}

# AES
@router.post("/aes/encrypt")
def aes_encrypt_endpoint(req: TextRequest):
    return aes_encrypt(req.text)

@router.post("/aes/decrypt")
def aes_decrypt_endpoint(req: AESDecryptRequest):
    return {"plaintext": aes_decrypt(req.key, req.nonce, req.ciphertext, req.tag)}

# CHACHA20
@router.post("/chacha/encrypt")
def chacha_encrypt_endpoint(req: TextRequest):
    return chacha_encrypt(req.text)

@router.post("/chacha/decrypt")
def chacha_decrypt_endpoint(req: ChaChaDecryptRequest):
    return {"plaintext": chacha_decrypt(req.key, req.nonce, req.ciphertext, req.tag)}

# RSA
@router.get("/rsa/generate_keys")
def generate_keys():
    return rsa_generate_keys()

@router.post("/rsa/encrypt")
def rsa_encrypt_endpoint(req: RSAEncryptRequest):
    return {"ciphertext": rsa_encrypt(req.public_key, req.message)}

@router.post("/rsa/decrypt")
def rsa_decrypt_endpoint(req: RSADecryptRequest):
    return {"plaintext": rsa_decrypt(req.private_key, req.ciphertext)}

@router.post("/rsa/sign")
def rsa_sign_endpoint(req: RSASignRequest):
    return {"signature": rsa_sign(req.private_key, req.message)}

@router.post("/rsa/verify")
def rsa_verify_endpoint(req: RSAVerifyRequest):
    return {"valid": rsa_verify(req.public_key, req.message, req.signature)}