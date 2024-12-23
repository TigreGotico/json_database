import json
import zlib
from binascii import hexlify
from binascii import unhexlify
from json_database.exceptions import EncryptionKeyError, DecryptionKeyError

try:
    # pycryptodomex
    from Cryptodome.Cipher import AES
except ImportError:
    # pycrypto + pycryptodome
    try:
        from Crypto.Cipher import AES
    except:
        AES = None


def encrypt(key, text, nonce=None):
    if AES is None:
        raise ImportError("run pip install pycryptodomex")
    if not isinstance(text, bytes):
        text = bytes(text, encoding="utf-8")
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return ciphertext, tag, cipher.nonce


def decrypt(key, ciphertext, tag, nonce):
    if AES is None:
        raise ImportError("run pip install pycryptodomex")
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    text = data.decode(encoding="utf-8")
    return text


def encrypt_as_json(key, data):
    if isinstance(data, dict):
        data = json.dumps(data)
    if len(key) > 16:
        key = key[0:16]
    ciphertext = encrypt_bin(key, data)
    nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]
    return json.dumps({"ciphertext": hexlify(ciphertext).decode('utf-8'),
                       "tag": hexlify(tag).decode('utf-8'),
                       "nonce": hexlify(nonce).decode('utf-8')})


def decrypt_from_json(key, data):
    if isinstance(data, str):
        data = json.loads(data)
    if len(key) > 16:
        key = key[0:16]
    ciphertext = unhexlify(data["ciphertext"])
    if data.get("tag") is None:  # web crypto
        ciphertext, tag = ciphertext[:-16], ciphertext[-16:]
    else:
        tag = unhexlify(data["tag"])
    nonce = unhexlify(data["nonce"])
    try:
        return decrypt(key, ciphertext, tag, nonce)
    except:
        raise DecryptionKeyError


def encrypt_bin(key, data):
    if len(key) > 16:
        key = key[0:16]
    try:
        data = compress_payload(data)
        ciphertext, tag, nonce = encrypt(key, data)
    except:
        raise EncryptionKeyError
    return nonce + ciphertext + tag


def decrypt_bin(key, ciphertext):
    if len(key) > 16:
        key = key[0:16]

    nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]

    try:
        if not isinstance(key, bytes):
            key = bytes(key, encoding="utf-8")
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return decompress_payload(data)
    except:
        raise DecryptionKeyError


def compress_payload(text):
    # Compressing text
    if isinstance(text, str):
        decompressed = text.encode("utf-8")
    else:
        decompressed = text
    return zlib.compress(decompressed)


def decompress_payload(compressed):
    # Decompressing text
    if isinstance(compressed, str):
        # assume hex
        compressed = unhexlify(compressed)
    return zlib.decompress(compressed)

