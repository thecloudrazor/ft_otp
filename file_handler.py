from cryptography.fernet import Fernet
from global_variables import current_key, current_timer, password_label
import binascii
from ft_otp import generate_key

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
