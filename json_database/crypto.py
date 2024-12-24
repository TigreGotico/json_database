import json
import zlib
from binascii import hexlify
from binascii import unhexlify

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
    text = compress_payload(text)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return ciphertext, tag, cipher.nonce


def decrypt(key, ciphertext, tag, nonce) -> str:
    if AES is None:
        raise ImportError("run pip install pycryptodomex")
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    text = decompress_payload(data).decode(encoding="utf-8")
    return text


def encrypt_as_json(key, data):
    if isinstance(data, dict):
        data = json.dumps(data)
    if len(key) > 16:
        key = key[0:16]
    ciphertext, tag, nonce = encrypt(key, data)
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
    return decrypt(key, ciphertext, tag, nonce)


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
