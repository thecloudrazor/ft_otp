import sys
import argparse
import hmac
import hashlib
import struct
from cryptography.fernet import Fernet
import binascii
import time
import tkinter as tk 
from tkinter import filedialog, messagebox
import qrcode
from PIL import Image, ImageTk

# Global değişkenleri en başta tanımla
password = ""
result_label = None
password_label = None

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
    try:
        key = binascii.unhexlify(secret)
        counter_bytes = struct.pack('>Q', counter)
        h = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = h[-1] & 0xf
        binary = struct.unpack('>L', h[offset:offset+4])[0] & 0x7fffffff
        return str(binary)[-6:].zfill(6)
    except binascii.Error:
        print("Hata: Geçersiz hexadecimal karakter dizisi")
        return None

def timer(window, count=30):
    global password_label, result_label
    count_label = tk.Label(window, text=str(count), font=('Arial', 30))
    count_label.place(x=365, y=200)
    
    if count > 0:
        window.after(1000, lambda: count_label.destroy())
        window.after(1000, lambda: timer(window, count - 1))
    else:
        window.after(1000, lambda: count_label.destroy())
        # Sayaç sıfırlandığında yeni OTP ve QR kod oluştur
        entry_widget = window.children['!entry']
        key = entry_widget.get()
        if len(key) == 64 and all(c in '0123456789ABCDEFabcdef' for c in key):
            counter = int(time.time() // 30)
            new_password = generate_hotp(key, counter)
            if new_password:
                password_label.config(text=new_password, font=('Arial', 10))
                # Yeni QR kod oluştur
                qr = qrcode.QRCode(version=1, box_size=5, border=5)
                qr.add_data(new_password)
                qr.make(fit=True)
                qr_image = qr.make_image(fill_color="black", back_color="white")
                qr_photo = ImageTk.PhotoImage(qr_image)
                window.qr_label.configure(image=qr_photo)
                window.qr_label.image = qr_photo
        window.after(1000, lambda: timer(window, 30))

def create_window(gui):
    global result_label, password_label
    window = tk.Tk()
    window.title("OTP Üreteci")
    window.geometry("500x500")  # Pencereyi büyüttüm QR kod için

    def generate_qr(otp):
        qr = qrcode.QRCode(version=1, box_size=5, border=5)
        qr.add_data(otp)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        # QR kodu TK için uygun formata dönüştür
        qr_photo = ImageTk.PhotoImage(qr_image)
        # Eğer önceden QR kod label'ı varsa, güncelle
        if hasattr(window, 'qr_label'):
            window.qr_label.configure(image=qr_photo)
            window.qr_label.image = qr_photo
        else:
            window.qr_label = tk.Label(window, image=qr_photo)
            window.qr_label.image = qr_photo
            window.qr_label.place(x=200, y=250)

    def generate_otp():
        key = entry.get()
        if len(key) == 64 and all(c in '0123456789ABCDEFabcdef' for c in key):
            counter = int(time.time() // 30)
            password = generate_hotp(key, counter)
            if password:
                password_label.config(text=password, font=('Arial', 10))
                generate_qr(password)  # QR kod oluştur
                timer(window)  # Sayacı başlat
        else:
            result_label.config(text="Hata: 64 karakterli hexadecimal bir anahtar giriniz")
            password_label.config(text="")

    # OTP ve sayaç için label'lar
    result_label = tk.Label(window, text="", font=('Arial', 12))
    result_label.place(x=200, y=50)
    
    password_label = tk.Label(window, text="", font=('Arial', 10))
    password_label.place(x=366, y=170)

    # Giriş alanları ve butonlar
    tk.Label(window, text="Hexadecimal Anahtarı Giriniz", font=('Arial', 10)).place(x=50, y=130)
    entry = tk.Entry(window, font=('Arial', 15))
    entry.place(x=50, y=150)
    
    generate_button = tk.Button(window, text="Üret", command=generate_otp)
    generate_button.place(x=50, y=180)
    
    file_button = tk.Button(window, text="Dosyadan Anahtar Seç", command=SelectFile)
    file_button.place(x=50, y=210)

    window.mainloop()

def SelectFile():
    global result_label, password_label, password  # Tüm global değişkenleri belirt
    file_path = tk.filedialog.askopenfilename(title="Dosya Seç")
    if file_path:
        try:
            with open(file_path, 'r') as f:
                key_data = f.read().strip()
            
            if len(key_data) == 64 and all(c in '0123456789ABCDEFabcdef' for c in key_data):
                if encrypt_key(key_data):
                    tk.messagebox.showinfo("Başarılı", "Anahtar başarıyla ft_otp.key dosyasına kaydedildi.")
                    counter = int(time.time() // 30)
                    password = generate_hotp(key_data, counter)
                    if password:
                        password_label.config(text=password, font=('Arial', 10))
                    else:
                        tk.messagebox.showerror("Hata", "OTP üretilirken bir hata oluştu.")
            else:
                tk.messagebox.showerror("Hata", "Dosya içeriği 64 hexadecimal karakter olmalıdır.")
        
        except FileNotFoundError:
            tk.messagebox.showerror("Hata", f"{file_path} dosyası bulunamadı.")
        except UnicodeDecodeError:
            tk.messagebox.showerror("Hata", "Dosya içeriği okunamadı. Metin dosyası olduğundan emin olun.")
        except Exception as e:
            tk.messagebox.showerror("Hata", f"Beklenmeyen bir hata oluştu: {str(e)}")

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
        create_window(args.gui)
    else:
        print("Usage: ./ft_otp [-g key_file] or [-k ft_otp.key]")
        sys.exit(1)


if __name__ == "__main__":
    main()
