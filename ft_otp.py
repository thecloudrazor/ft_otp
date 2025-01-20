import sys
import argparse
import hmac
import hashlib
import struct
from cryptography.fernet import Fernet
import binascii
import time
from ft_otp_bonus import create_window


def generate_key():
    return Fernet.generate_key()


def encrypt_key(key_data):
    encryption_key = generate_key()
    f = Fernet(encryption_key)
    encrypted_data = f.encrypt(key_data.encode())
    
    with open('ft_otp.key', 'wb') as f:
        f.write(encryption_key + b'\n' + encrypted_data)
    return True


def decrypt_key(key_file):
    with open(key_file, 'rb') as f:
        encryption_key = f.readline().strip()
        encrypted_data = f.readline().strip()
    
    f = Fernet(encryption_key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()


def generate_hotp(secret, counter):
    key = binascii.unhexlify(secret)
    counter_bytes = struct.pack('>Q', counter)
    h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0xf
    binary = struct.unpack('>L', h[offset:offset+4])[0] & 0x7fffffff
    return str(binary)[-6:].zfill(6)


def check_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate", help="Generate a new OTP key")
    parser.add_argument("-k", "--key", help="Use an existing OTP key")
    parser.add_argument("-G", "--gui", help="Run the GUI")
    return parser.parse_args()


def main():
    args = check_arg()
    
    if args.generate:
        try:
            with open(args.generate, 'r') as f:
                key_data = f.read().strip()
            
            if len(key_data) < 64 or not all(c in '0123456789ABCDEFabcdef' for c in key_data):
                print("./ft_otp: error: key must be 64 hexadecimal characters.")
                sys.exit(1)
            
            if encrypt_key(key_data):
                print("Key was successfully saved in ft_otp.key.")
            
        except FileNotFoundError:
            print(f"Error: {args.generate} file not found.")
            sys.exit(1)

    elif args.key:
        try:
            secret = decrypt_key(args.key)
            counter = int(time.time() // 30)
            password = generate_hotp(secret, counter)
            print(password)
            
        except FileNotFoundError:
            print(f"Error: {args.key} file not found.")
            sys.exit(1)
    elif args.gui:
        create_window(args.gui)
    else:
        print("Usage: ./ft_otp [-g key_file] or [-k ft_otp.key]")
        sys.exit(1)


if __name__ == "__main__":
    main()
