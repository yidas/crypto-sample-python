from Crypto.Cipher import AES 
import base64 
import os 

def aesGcmEncrypt(plaintext: str, secretKey: str, iv: str=None) -> bytes: 
    secretKey = secretKey.encode()
    iv = iv.encode() if iv else os.urandom(12) 
    aesCipher = AES.new(secretKey, AES.MODE_GCM, iv) 
    cipherBody, authTag = aesCipher.encrypt_and_digest(plaintext.encode()) 
    cipherGCM = cipherBody + authTag 
    return cipherGCM

def aesGcmDecrypt(cipherRawWithTag: bytes, secretKey: str, iv: str, authTag: bytes=None) -> str: 
    ciphertext = cipherRawWithTag[0:-16] 
    authTag = authTag if authTag else cipherRawWithTag[-16:]
    aesCipher = AES.new(secretKey.encode(), AES.MODE_GCM, iv.encode()) 
    # decryptedText = aesCipher.decrypt(ciphertext).decode() 
    decryptedText = aesCipher.decrypt_and_verify(ciphertext, authTag).decode()
    return decryptedText


plaintext = "message to be encrypted 中文"
# 256 bits (32 bytes) Key => AES-256-GCM
key = "12345678901234567890123456789012"
iv = "123456789012"

cipherGCM = aesGcmEncrypt(plaintext, key, iv)
cipherGcmB64Text = base64.b64encode(cipherGCM).decode()
decryptedText = aesGcmDecrypt(base64.b64decode(cipherGcmB64Text.encode()), key, iv)

print("plaintext: {} | key: {} | cipherB64: {} decryptedText: {}".format(plaintext, key, cipherGcmB64Text, decryptedText))


