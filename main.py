import sys
import argparse
from gui import create_window
from file_handler import encrypt_key, decrypt_key
from ft_otp import generate_hotp
import time
from global_variables import current_key, current_timer, password_label, result_label, window


def check_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate", help="Generate a new OTP key")
    parser.add_argument("-k", "--key", help="Use an existing OTP key")
    parser.add_argument("-G", "--gui", help="Run the GUI")
    return parser.parse_args()

def printPassword(args):
    secret = decrypt_key(args.key)
    counter = int(time.time() // 30)
    password = generate_hotp(secret, counter)
    print(password)
    return password

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
            printPassword(args)
        except FileNotFoundError:
            print(f"Error: {args.key} file not found.")
            sys.exit(1)
    elif args.gui:
        create_window()
    else:
        print("Usage: ./ft_otp [-g key_file] or [-k ft_otp.key]")
        sys.exit(1)

if __name__ == "__main__":
    main()
