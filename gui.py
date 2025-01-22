import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import ImageTk, Image
from file_handler import encrypt_key, decrypt_key
from ft_otp import generate_hotp
import time
import qrcode
from global_variables import current_key, current_timer, password_label, result_label, window

def create_window():
    global result_label, password_label, window
    window = tk.Tk()
    window.title("OTP Generator")
    window.geometry("500x250")
    window.resizable(False, False)

    def generate_otp():
        global current_key, current_timer
        key = entry.get()
        
        # Eğer aynı anahtar ise hiçbir şey yapma
        if key == current_key:
            return
        
        # Farklı anahtar ise mevcut timer'ı iptal et
        if current_timer:
            window.after_cancel(current_timer)
        
        if len(key) == 64 and all(c in '0123456789ABCDEFabcdef' for c in key):
            current_key = key  # Yeni anahtarı kaydet
            counter = int(time.time() // 30)
            password = generate_hotp(key, counter)
            if password:
                password_label.config(text=password, font=('Arial', 10))
                generate_qr(password)
                timer(window)
        else:
            result_label.config(text="Error: Please enter a 64-character hexadecimal key")
            password_label.config(text="")
            current_key = None

    # OTP ve sayaç için label'lar
    result_label = tk.Label(window, text="", font=('Arial', 12))
    result_label.place(x=200, y=50)
    
    password_label = tk.Label(window, text="", font=('Arial', 10))
    password_label.place(x=366, y=170)

    # Giriş alanları ve butonlar
    print("Enter Hexadecimal Key")
    entry = tk.Entry(window, font=('Arial', 15))
    entry.place(x=50, y=70)
    
    generate_button = tk.Button(window, text="Generate", command=generate_otp, width=10)
    generate_button.place(x=70, y=110)
    
    file_button = tk.Button(window, text="Select File", command=SelectFile, width=10)
    file_button.place(x=170, y=110)

    window.mainloop()

def SelectFile():
    global result_label, password_label, password, current_timer, current_key, window
    file_path = tk.filedialog.askopenfilename(title="Select File")
    if file_path:
        try:
            with open(file_path, 'r') as f:
                key_data = f.read().strip()
            
            if len(key_data) == 64 and all(c in '0123456789ABCDEFabcdef' for c in key_data):
                # Eğer aynı anahtar seçildiyse işlem yapma
                if key_data == current_key:
                    return
                    
                # Mevcut timer'ı iptal et ve sayaç etiketini temizle
                if current_timer:
                    window.after_cancel(current_timer)
                    for widget in window.winfo_children():
                        if isinstance(widget, tk.Label) and widget.cget("text").isdigit():
                            widget.destroy()
                
                if encrypt_key(key_data):
                    current_key = key_data
                    tk.messagebox.showinfo("Success", "Key successfully saved to ft_otp.key file.")
                    counter = int(time.time() // 30)
                    password = generate_hotp(key_data, counter)
                    if password:
                        password_label.config(text=password, font=('Arial', 10))
                        generate_qr(password)
                        timer(window, 30)  # Sayacı 30'dan başlat
                    else:
                        tk.messagebox.showerror("Error", "An error occurred while generating OTP.")
            else:
                tk.messagebox.showerror("Error", "File content must be 64 hexadecimal characters.")
                current_key = None
        
        except FileNotFoundError:
            tk.messagebox.showerror("Error", f"File {file_path} not found.")
        except UnicodeDecodeError:
            tk.messagebox.showerror("Error", "Could not read file content. Make sure it's a text file.")
        except Exception as e:
            tk.messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")

def generate_qr(otp):
    qr = qrcode.QRCode(version=1, box_size=5, border=5)
    qr.add_data(otp)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_photo = ImageTk.PhotoImage(qr_image)
    if hasattr(window, 'qr_label'):
        window.qr_label.configure(image=qr_photo)
        window.qr_label.image = qr_photo
    else:
        window.qr_label = tk.Label(window, image=qr_photo)
        window.qr_label.image = qr_photo
        window.qr_label.place(x=313, y=10)

def timer(window, count=30):
    global password_label, result_label, current_timer
    count_label = tk.Label(window, text=str(count), font=('Arial', 30))
    count_label.place(x=365, y=200)
    
    if count > 0:
        current_timer = window.after(1000, lambda: count_label.destroy())
        current_timer = window.after(1000, lambda: timer(window, count - 1))
    else:
        window.after(1000, lambda: count_label.destroy())
        entry_widget = window.children['!entry']
        key = entry_widget.get()
        if len(key) == 64 and all(c in '0123456789ABCDEFabcdef' for c in key):
            counter = int(time.time() // 30)
            new_password = generate_hotp(key, counter)
            if new_password:
                password_label.config(text=new_password, font=('Arial', 10))
                generate_qr(new_password)
                timer(window)
        current_timer = window.after(1000, lambda: timer(window, 30))
