import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import Blowfish, DES3
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os
import datetime
import re
import codecs

# ---------- Settings ----------
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# ---------- Derived Key ----------
def derive_key(password, salt, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ---------- Algorithms ----------
def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def sha256_encrypt(text):
    return hashlib.sha256(text.encode()).hexdigest()

def sha1_encrypt(text):
    return hashlib.sha1(text.encode()).hexdigest()

def md5_encrypt(text):
    return hashlib.md5(text.encode()).hexdigest()

def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(text):
    return base64.b64decode(text.encode()).decode()

def hex_encrypt(text):
    return text.encode().hex()

def hex_decrypt(text):
    return bytes.fromhex(text).decode()

def caesar_encrypt(text, shift=3):
    result = ''
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) + shift - offset) % 26 + offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

def rot13_encrypt(text):
    return codecs.encode(text, 'rot_13')

def rot13_decrypt(text):
    return codecs.encode(text, 'rot_13')

def fernet_encrypt(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def fernet_decrypt(text, key):
    f = Fernet(key)
    return f.decrypt(text.encode()).decode()

def blowfish_encrypt(text, key):
    cipher = Blowfish.new(key[:16].ljust(16, b'\0'), Blowfish.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(text.encode(), Blowfish.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def blowfish_decrypt(text, key):
    raw = base64.b64decode(text)
    iv = raw[:8]
    cipher = Blowfish.new(key[:16].ljust(16, b'\0'), Blowfish.MODE_CBC, iv)
    return unpad(cipher.decrypt(raw[8:]), Blowfish.block_size).decode()

def triple_des_encrypt(text, key):
    cipher = DES3.new(key[:24].ljust(24, b'\0'), DES3.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(text.encode(), DES3.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def triple_des_decrypt(text, key):
    raw = base64.b64decode(text)
    iv = raw[:8]
    cipher = DES3.new(key[:24].ljust(24, b'\0'), DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(raw[8:]), DES3.block_size).decode()

# ---------- Password Strength ----------
def check_password_strength(password):
    if len(password) < 6:
        return "Weak"
    elif re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"\d", password):
        return "Strong"
    elif len(password) < 8:
        return "Medium"
    else:
        return "Medium"

# ---------- Encryption ----------
def encrypt():
    text = input_text.get("0.0", "end").strip()
    password = key_entry.get().strip()
    encryption_type = encryption_type_var.get()

    if not text or not password:
        messagebox.showwarning("Warning", "Enter text and key.")
        return

    strength_label.configure(text=f"Password strength: {check_password_strength(password)}")
    log_activity("Encryption performed")

    try:
        output_text.delete("0.0", "end")

        if encryption_type == "AES":
            salt = os.urandom(16)
            iv = os.urandom(16)
            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encrypted = cipher.encryptor().update(text.encode()) + cipher.encryptor().finalize()
            output_text.delete("0.0", "end")
            output_text.insert("end", base64.b64encode(salt + iv + encrypted).decode())
        elif encryption_type == "XOR":
            output_text.insert("end", xor_encrypt_decrypt(text, password))
        elif encryption_type == "SHA-256":
            output_text.insert("end", sha256_encrypt(text))
        elif encryption_type == "SHA-1":
            output_text.insert("end", sha1_encrypt(text))
        elif encryption_type == "MD5":
            output_text.insert("end", md5_encrypt(text))
        elif encryption_type == "Base64":
            output_text.insert("end", base64_encrypt(text))
        elif encryption_type == "Hex":
            output_text.insert("end", hex_encrypt(text))
        elif encryption_type == "Caesar":
            output_text.insert("end", caesar_encrypt(text))
        elif encryption_type == "ROT13":
            output_text.insert("end", rot13_encrypt(text))
        elif encryption_type == "Fernet":
            key = Fernet.generate_key()
            output_text.insert("end", fernet_encrypt(text, key))
        elif encryption_type == "Blowfish":
            output_text.insert("end", blowfish_encrypt(text, password.encode()))
        elif encryption_type == "TripleDES":
            output_text.insert("end", triple_des_encrypt(text, password.encode()))
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------- Decryption ----------
def decrypt():
    data = input_text.get("0.0", "end").strip()
    password = key_entry.get().strip()
    encryption_type = encryption_type_var.get()

    if not data or not password:
        messagebox.showwarning("Warning", "Enter text and key.")
        return

    log_activity("Decryption performed")

    try:
        output_text.delete("0.0", "end")

        if encryption_type == "AES":
            decoded = base64.b64decode(data)
            salt, iv, encrypted = decoded[:16], decoded[16:32], decoded[32:]
            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decrypted = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()
            output_text.insert("end", decrypted.decode())
        elif encryption_type == "XOR":
            output_text.insert("end", xor_encrypt_decrypt(data, password))
        elif encryption_type in ["SHA-256", "SHA-1", "MD5"]:
            output_text.insert("end", "Hash algorithms are one-way.")
        elif encryption_type == "Base64":
            output_text.insert("end", base64_decrypt(data))
        elif encryption_type == "Hex":
            output_text.insert("end", hex_decrypt(data))
        elif encryption_type == "Caesar":
            output_text.insert("end", caesar_decrypt(data))
        elif encryption_type == "ROT13":
            output_text.insert("end", rot13_decrypt(data))
        elif encryption_type == "Blowfish":
            output_text.insert("end", blowfish_decrypt(data, password.encode()))
        elif encryption_type == "TripleDES":
            output_text.insert("end", triple_des_decrypt(data, password.encode()))
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------- GUI Elements ----------
def toggle_theme():
    current = ctk.get_appearance_mode()
    ctk.set_appearance_mode("Light" if current == "Dark" else "Dark")

def copy_output():
    app.clipboard_clear()
    app.clipboard_append(output_text.get("0.0", "end").strip())
    messagebox.showinfo("Copied", "Output text copied.")
    log_activity("Output copied")

def clear_fields():
    key_entry.delete(0, "end")
    input_text.delete("0.0", "end")
    output_text.delete("0.0", "end")
    log_activity("Fields cleared")

def save_to_file():
    content = output_text.get("0.0", "end").strip()
    if content:
        filename = f"encrypted_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"File {filename} saved.")
        log_activity("Output saved")

def log_activity(msg):
    log_box.configure(state="normal")
    log_box.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
    log_box.configure(state="disabled")
    log_box.see("end")

# ---------- Create GUI ----------
app = ctk.CTk()
app.title("💎 Synchro Security | Cryptography")
app.geometry("800x900")
app.iconbitmap("logo.ico")
ctk.CTkLabel(app, text="💎 Synchro Security | Cryptography", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=15)

key_entry = ctk.CTkEntry(app, placeholder_text="🔑 Encryption Key", width=600)
key_entry.pack(pady=10)

input_text = ctk.CTkTextbox(app, height=180, width=700)
input_text.pack(pady=10)

strength_label = ctk.CTkLabel(app, text="Password strength: Weak")
strength_label.pack(pady=5)

button_frame = ctk.CTkFrame(app)
button_frame.pack(pady=10)

ctk.CTkButton(button_frame, text="🔒 Encrypt", command=encrypt).grid(row=0, column=0, padx=10)
ctk.CTkButton(button_frame, text="🔓 Decrypt", command=decrypt).grid(row=0, column=1, padx=10)
ctk.CTkButton(button_frame, text="🌓 Toggle Theme", command=toggle_theme).grid(row=0, column=2, padx=10)
ctk.CTkButton(button_frame, text="📋 Copy Output", command=copy_output).grid(row=0, column=3, padx=10)
ctk.CTkButton(button_frame, text="🗑 Clear", command=clear_fields).grid(row=0, column=4, padx=10)
ctk.CTkButton(button_frame, text="💾 Save", command=save_to_file).grid(row=0, column=5, padx=10)

output_text = ctk.CTkTextbox(app, height=180, width=700)
output_text.pack(pady=10)

log_box = ctk.CTkTextbox(app, height=5, width=700, state="disabled")
log_box.pack(pady=10)

app.mainloop()
