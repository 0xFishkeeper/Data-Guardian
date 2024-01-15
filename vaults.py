import tkinter as tk
from tkinter import filedialog, messagebox
import os
from keygen import symmetric_encrypt, symmetric_decrypt

def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = symmetric_encrypt(file_data, key)
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)
        messagebox.showinfo("Encryption", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_file(encrypted_file_path, key):
    try:
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = symmetric_decrypt(encrypted_data, key)
        decrypted_file_path = encrypted_file_path.replace('.enc', '')
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        messagebox.showinfo("Decryption", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def browse_vault_file():
    return filedialog.askopenfilename()

