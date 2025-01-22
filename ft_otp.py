import hmac
import hashlib
import struct
import binascii
import time
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def generate_hotp(secret, counter):
    try:
        key = binascii.unhexlify(secret)
        counter_bytes = struct.pack('>Q', counter)
        h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = h[-1] & 0xf
        binary = struct.unpack('>L', h[offset:offset+4])[0] & 0x7fffffff
        return str(binary)[-6:].zfill(6)
    except binascii.Error:
        print("Error: Invalid hexadecimal character")
        return None
