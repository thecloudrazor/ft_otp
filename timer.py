import tkinter as tk
import time
from ft_otp import generate_hotp
from gui import generate_qr

def timer(window, count=30, current_timer=None, current_key=None, password_label=None):
    count_label = tk.Label(window, text=str(count), font=('Arial', 30))
    count_label.place(x=365, y=200)
    
    if count > 0:
        current_timer = window.after(1000, lambda: count_label.destroy())
        current_timer = window.after(1000, lambda: timer(window, count - 1))
    else:
        window.after(1000, lambda: count_label.destroy())
        if current_key:
            counter = int(time.time() // 30)
            new_password = generate_hotp(current_key, counter)
            if new_password:
                password_label.config(text=new_password, font=('Arial', 10))
                generate_qr(new_password)
                timer(window)
