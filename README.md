# OTP Generator (ft_otp)

This project is a tool that allows users to securely generate OTP (One Time Password). It can work with both command-line interface and graphical user interface (GUI). This tool generates OTPs that can be especially used for two-factor authentication (2FA).

## Getting Started

You can follow these steps to start using this project:

```bash
git clone https://github.com/whymami/ft_otp.git && cd ft_otp
```

### Installing Dependencies

You can run the following command to install project requirements:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate New Key

```bash
python main.py -g <path>
```

This command will take a key from the file you provided and save it encrypted to ft_otp.key file.

### 2. Generate OTP

To print the password using an existing OTP key:

```bash
python main.py -k <key_file>
```

### 3. GUI Usage

To run the project in GUI mode:

```bash
python main.py -G gui
```

In the GUI, users can:
- Enter OTP keys
- Select key from file
- View OTP
- Generate QR code

## Features

- **HOTP (HMAC-Based One-Time Password)**: Allows users to generate OTP with hexadecimal keys.
- **GUI (Tkinter)**: Provides GUI support for easy use.
- **QR Code Generation**: Creates a QR code associated with OTP.
- **Key Encryption**: Keys can be encrypted and stored securely.
- **Command Line Support**: OTP can also be generated from command line instead of GUI.

## File Structure

```
ft_otp/
├── gui.py              # GUI interface
├── file_handler.py     # Key encryption and decryption operations
├── otp.py              # OTP generation functions
├── global_variables.py # Global variables
├── main.py             # Main program file
├── requirements.txt    # Required Python libraries
├── ft_otp.key         # Encrypted OTP keys
└── README.md          # Project description (this file)
```