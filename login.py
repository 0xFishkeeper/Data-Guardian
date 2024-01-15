import base64
import json
import re
import sys
import tkinter as tk
import file_operations
import keygen
import requests
from PIL import Image, ImageTk
from tkinter import messagebox, scrolledtext
import vaults

global symmetric_key_file_path_encrypted


def create_account(username_entry, password_entry):
    username = username_entry.get()
    pw = password_entry.get()
    strength, feedback = check_strength(pw)
    if strength == 'Strong':
        confirm(username, pw)  # Pass the username and password to the confirm function
        messagebox.showinfo("Account Creation", "Account created successfully!")

    else:
        # Show feedback
        messagebox.showerror("Weak Password", "\n".join(feedback))


def check_strength(pw):
    length_error = len(pw) < 10
    uppercase_error = not any(char.isupper() for char in pw)
    lowercase_error = not any(char.islower() for char in pw)
    digit_error = not any(char.isdigit() for char in pw)
    symbol_error = not re.search("[@_!#$%^&*()<>?/|}{~:]", pw)
    strength = ''
    error_severity = {
        'length_error': 25,
        'uppercase_error': 15,
        'lowercase_error': 15,
        'digit_error': 15,
        'symbol_error': 50,
        'common_error': 50
    }
    # Fetch the list of common passwords
    passwords_file_url = ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common'
                          '-Credentials/10-million-password-list-top-1000000.txt')
    common_passwords = fetch_file_contents(passwords_file_url)

    common_error = common_passwords and is_password_common(pw, common_passwords)
    # Calculate error severity
    error_severity_score = []
    feedback = []
    if length_error:
        feedback.append('Length should be at least 10 characters')
        error_severity_score.append(error_severity['length_error'])
    if uppercase_error:
        feedback.append('Use at least one uppercase letter')
        error_severity_score.append(error_severity['uppercase_error'])
    if lowercase_error:
        feedback.append('Use at least one lowercase letter')
        error_severity_score.append(error_severity['lowercase_error'])
    if digit_error:
        feedback.append('Use at least one digit')
        error_severity_score.append(error_severity['digit_error'])
    if symbol_error:
        feedback.append('Use at least one special character')
        error_severity_score.append(error_severity['symbol_error'])
    if common_error:
        feedback.append('This is a common password and should not be used.')
        error_severity_score.append(error_severity['common_error'])

    # Error score
    error_severity_equation = sum(error_severity_score)

    if 101 > error_severity_equation >= 75:
        strength = 'Weak'  # Weak
        print(f'Password strength: Weak')

    if 75 > error_severity_equation >= 25:
        strength = 'Medium'  # Medium
        print(f'Password strength: Medium')

    if error_severity_equation < 25:
        strength = 'Strong'  # Strong
        print(f'Password strength: Strong')

    return strength, feedback


def verify_user_credentials(username_entry, password_entry):
    # This function is the authentication function, it verifies the three factors of authentication the user provides
    # The symmetric key to decrypt the credentials in shadow.txt is encrypted with the public key
    # The program uses the private key to decrypt the symmetric key
    # The symmetric key is used to encrypt and decrypt files and to access shadow.enc
    # The hashed username and password is compared to the decrypted shadow.txt
    # If they match then login is permitted
    # The keys provide a layer of security by limiting access to shadow.enc.

    # Get file location
    symmetric_key_file_path_encrypted = symmetric_key_path_var.get()
    # Read file
    symmetric_key_encrypted = file_operations.read_symmetric_key_from_file(symmetric_key_file_path_encrypted)
    if not isinstance(symmetric_key_encrypted, bytes):
        messagebox.showerror("Error", "Symmetric key is not in the correct format")
        return

    if symmetric_key_encrypted is None:
        messagebox.showerror("Error", "Failed to read symmetric key from file")
        return

    # Get username and password
    username = username_entry.get()
    pw = password_entry.get()

    # Get location of private key
    private_key_file_path = private_key_path_var.get()
    if private_key_file_path is None:
        messagebox.showerror("Error", "No private key file selected")
        return

    # Read file of private key
    private_key = file_operations.read_private_key_from_file(private_key_file_path)

    if private_key is None:
        messagebox.showerror("Error", "Failed to read private key from file")
        return
    # Returns decrypted symmetric key
    decrypted_symmetric_key = keygen.asymmetric_decrypt(symmetric_key_encrypted, private_key)
    print(f"Type of decrypted symmetric key: {type(decrypted_symmetric_key)}")
    if decrypted_symmetric_key is None:
        messagebox.showerror("Error", "Failed to decrypt credentials")
        print(f'Failure3')
    else:
        print(f'Success2')
    # Decrypts shadow.enc with symmetric key
    decrypted_credentials = keygen.decrypt_credentials(decrypted_symmetric_key)

    # Hash the provided username and password
    hashed_username = keygen.hash_username(username)
    print(f'{hashed_username}')
    hpw = keygen.hash_password(pw)
    print(f'{hpw}')
    # Compare the hashed username and password with the stored ones
    stored_hashed_username = base64.b64decode(decrypted_credentials['encoded_username_hash'])
    print(f'{stored_hashed_username}')
    stored_hashed_password = base64.b64decode(decrypted_credentials['encoded_password_hash'])
    print(f'{stored_hashed_password}')
    if hashed_username == stored_hashed_username and keygen.verify_password(pw, stored_hashed_password):
        messagebox.showinfo("Login", "Success")
        print(f'Success_one')
        clear_window(window=main_window)
        show_vault_interface(decrypted_symmetric_key)
    else:
        messagebox.showerror("Login Failed", "Incorrect Username or Password")
        print("Success")


def fetch_file_contents(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.splitlines()  # Returns a list of lines in the file
    else:
        print("Failed to retrieve file:", response.status_code)
        return None


def is_password_common(pw, password_list):
    return pw in password_list


def confirm(username, pw):
    response = messagebox.askyesno("Confirm", f"Username: {username} Password: {pw}")
    if response:
        print("User clicked Yes.")
        hashed_username = keygen.hash_username(username)
        hpw = keygen.hash_password(pw)
        private_key, public_key = keygen.generate_asymmetric_key_pair()
        file_operations.save_keys_to_file(private_key, public_key)
        mfa_data = show_confirm_account(hashed_username, hpw, public_key)
        prepare_data_store_login(hashed_username, hpw, public_key, private_key, mfa_data)

    else:
        print("User clicked No.")
        return


def show_confirm_account(hashed_username, hpw, public_key):
    mfa_response = messagebox.askyesno("Confirm", 'Confirm account creation')
    if mfa_response:
        # Generate a symmetric key
        symmetric_key = keygen.generate_symmetric_key()
        # Encrypt the symmetric key with the RSA public key
        encrypted_symmetric_key = keygen.asymmetric_encrypt(symmetric_key, public_key)
        encrypted_key_filename = "encrypted_symmetric_key.txt"
        file_operations.save_encrypted_symmetric_key_to_file(encrypted_symmetric_key, encrypted_key_filename)
        return {'encrypted_symmetric_key': encrypted_symmetric_key}
    else:
        show_main_window()


def prepare_data_store_login(hashed_username, hpw, public_key, private_key, mfa_data):
    # Decrypt the symmetric key with the RSA private key
    encrypted_symmetric_key = mfa_data['encrypted_symmetric_key']
    symmetric_key = keygen.asymmetric_decrypt(encrypted_symmetric_key, private_key)

    # Prepare credential data
    credential_data = {
        'encoded_username_hash': base64.b64encode(hashed_username).decode('utf-8'),
        'encoded_password_hash': base64.b64encode(hpw).decode('utf-8')
    }

    # Serialize credential data
    serialized_data = json.dumps(credential_data).encode('utf-8')

    # Encrypt the serialized data using the symmetric key
    encrypted_data = keygen.symmetric_encrypt(serialized_data, symmetric_key)

    # Save the encrypted data to a file
    keygen.save_to_file(encrypted_data, 'shadow.txt')


def show_login_view():
    clear_window(main_window)
    main_window.title("Login")
    image_path = "images/logo.png"
    original_image = Image.open(image_path)

    resized_image = original_image.resize((200, 200))

    photo = ImageTk.PhotoImage(resized_image)

    image_label = tk.Label(main_window, image=photo, bg='#daeaeb')
    image_label.image = photo

    image_label.pack()

    username_label = tk.Label(main_window, text="Username:", bg='#daeaeb')
    username_label.pack()
    username_entry = tk.Entry(main_window)
    username_entry.pack()

    password_label = tk.Label(main_window, text="Password:", bg='#daeaeb')
    password_label.pack()
    password_entry = tk.Entry(main_window, show="*")
    password_entry.pack(pady=5)

    browse_button = tk.Button(main_window, text="Browse Encrypted Symmetric Key",
                              command=lambda: file_operations.browse_file(symmetric_key_path_var))
    browse_button.pack(padx=10, pady=2)

    private_key_browse_button = tk.Button(main_window, text="Browse Private Key",
                                          command=lambda: file_operations.browse_file(private_key_path_var))
    private_key_browse_button.pack(padx=5, pady=5)

    login_button = tk.Button(main_window, text="Login",
                             command=lambda: verify_user_credentials(username_entry, password_entry))
    login_button.pack(padx=10, pady=2)

    back_button = tk.Button(main_window, text="Previous", command=show_main_window)
    back_button.pack()


def terms_of_use():
    # Create a new Tkinter window
    terms_window = tk.Tk()
    terms_window.title("Terms of Use")

    terms_text = (
        "\nWelcome to Data Guardian!\n"
        "Please carefully read and accept the Terms of Use outlined below:\n\n"
        "1. Acceptance of Terms\n"
        "   Any use of Data Guardian binds the user to these terms of use.\n\n"
        "2. Use of the Application\n"
        "   a. Data Guardian is designed solely for lawful purposes. You agree to use this application only for legal and authorized activities.\n"
        "   b. You are solely responsible for all activities conducted through your use of the application.\n"
        "   c. You must not compromise the security of the application or attempt unauthorized access to the application, its data, or its systems.\n\n"
        "3. Limitation of Liability\n"
        "  Data Guardian is not liable for "
        "  any direct, indirect, incidental, special, consequential, or exemplary damages, \n  including but not limited to, damages for loss of profits, goodwill,\n  use, data, or other intangible losses, resulting from the use or inability to use the application.\n"
    )

    terms_label = tk.Label(terms_window, text=terms_text, justify=tk.LEFT)
    terms_label.pack(padx=10, pady=10)

    # Display the terms of use agreement

    def on_agree():
        terms_window.destroy()

    def on_disagree():
        messagebox.showwarning("Terms of Use", "You must agree to the terms of use to use this encryption tool.")
        terms_window.destroy()
        # Exit or take appropriate action
        print("Exiting the application.")
        sys.exit()

    agree_button = tk.Button(terms_window, text="I Agree", command=on_agree)
    agree_button.pack(side=tk.LEFT, padx=10, pady=10)

    disagree_button = tk.Button(terms_window, text="I Disagree", command=on_disagree)
    disagree_button.pack(side=tk.RIGHT, padx=10, pady=10)

    terms_window.mainloop()


def clear_window(window):
    for widget in window.winfo_children():
        widget.pack_forget()


def show_readme():
    readme_window = tk.Toplevel(main_window)
    readme_window.title("README - Data Guardian")
    readme_window.geometry("1200x800")

    readme_text = """
Overview
Data Guardian is a robust encryption tool designed to safeguard your data using both symmetric (single key) and asymmetric encryption (private and public keys).
By using Data Guardian, you can ensure the security of your sensitive data with state-of-the-art encryption technology.
After creating an account, you will gain access to a personal vault for encrypting and decrypting files.
Credentials are securely stored locally in the program's main directory. The user is responsible for managing the private key, once it is created this key should be removed from the main directory and stored securely.   
The overall security of the system heavily relies on the confidentiality of your private key. It is crucial to keep this key secure and private.

Accessing the Vault
To access your vault, you need to provide your private key, encrypted symmetric key, and your login credentials (username and password).
Once access is granted, you can encrypt and decrypt files as needed.
The encryption and decryption processes utilize the symmetric key, which is automatically decrypted during login and remains vulnerable only during the program's usage.


Security Layers 

Username and Password: The first layer of security is your username and password. These credentials 
are hashed using the Blowfish encryption algorithm (Bcrypt) and securely stored in the shadow.txt file.

Encryption Keys: Upon account creation, three essential keys are generated and stored in the Data_Guardian directory folder: 

Symmetric Key: Used for encrypting and decrypting your files. Public Key: Used to encrypt the symmetric key for 
secure storage. 

Private Key: The only key that can decrypt the symmetric key, and other data encrypted by the public.


WARNING
Storage Caution: Avoid storing the private key on the same computer as the application to mitigate the risk of unauthorized access in case of a security breach.
Loss of Access: Losing access to your private key or symmetric key means permanent inaccessibility to your data. It is vital to take necessary precautions.

Recommendations
External Storage: For enhanced security, consider saving your keys to an external USB drive, hard drive, or other storage media.
Key Copies: Evaluate the advantages and risks of creating multiple copies of your private and symmetric keys.

"""

    readme_scrolled_text = scrolledtext.ScrolledText(readme_window, wrap=tk.WORD)
    readme_scrolled_text.tag_configure('left', justify='left')
    readme_scrolled_text.insert(tk.INSERT, readme_text, 'left')
    readme_scrolled_text.config(state='disabled')
    readme_scrolled_text.pack(expand=True, fill='both')

    close_button = tk.Button(readme_window, text="Close", command=readme_window.destroy)
    close_button.pack(pady=10)



def show_create_account_view():
    clear_window(main_window)
    main_window.title("Create Account")
    messagebox.showinfo("WARNING", "WARNING: Previous keys will be overwritten upon new account creation.  \n"
                                   "Make sure to move shadow.txt, encrypted_symmetric_key.txt, private_key.pem, public_key.pem out of the home directory if they exist."

                        )
    image_path = "images/logo.png"
    original_image = Image.open(image_path)

    resized_image = original_image.resize((200, 200))

    photo = ImageTk.PhotoImage(resized_image)

    image_label = tk.Label(main_window, image=photo, bg='#daeaeb')
    image_label.image = photo

    image_label.pack()

    username_label = tk.Label(main_window, text="Enter Username:", bg='#daeaeb')
    username_label.pack()
    username_entry = tk.Entry(main_window)
    username_entry.pack()

    # Create and place the password label and entry
    password_label = tk.Label(main_window, text="Enter Password:", bg='#daeaeb')
    password_label.pack()
    password_entry = tk.Entry(main_window, show="*")
    password_entry.pack()

    create_new_account_button = tk.Button(main_window, text="Create account",
                                          command=lambda: create_account(username_entry, password_entry))
    create_new_account_button.pack(padx=5, pady=5)

    back_button = tk.Button(main_window, text="Previous", command=show_main_window)
    back_button.pack()

    print(f'Success')


def show_main_window():
    clear_window(main_window)
    main_window.title("Main Menu")
    image_path = "images/logo.png"
    original_image = Image.open(image_path)

    resized_image = original_image.resize((200, 200))

    photo = ImageTk.PhotoImage(resized_image)

    image_label = tk.Label(main_window, image=photo, bg='#daeaeb')
    image_label.image = photo

    image_label.pack()

    create_account_button = tk.Button(main_window, text="Create account", command=show_create_account_view)
    create_account_button.pack(padx=15, pady=15)

    login_to_account_button = tk.Button(main_window, text="Login", command=show_login_view)
    login_to_account_button.pack(padx=0, pady=0)

    show_help_button = tk.Button(main_window, text="Help", command=show_readme)
    show_help_button.pack(padx=15, pady=15)


def show_vault_interface(decrypted_symmetric_key):
    clear_window(main_window)
    main_window.title("Vault")

    image_path = "images/vault.png"
    original_image = Image.open(image_path)
    resized_image = original_image.resize((200, 200))
    photo = ImageTk.PhotoImage(resized_image)
    image_label = tk.Label(main_window, image=photo, bg='#daeaeb')
    image_label.image = photo
    image_label.pack()

    def encrypt_action():
        file_path = vaults.browse_vault_file()
        if file_path:
            vaults.encrypt_file(file_path, decrypted_symmetric_key)

    def decrypt_action():
        file_path = vaults.browse_vault_file()
        if file_path:
            vaults.decrypt_file(file_path, decrypted_symmetric_key)

    encrypt_button = tk.Button(main_window, text="Encrypt File", command=encrypt_action)
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(main_window, text="Decrypt File", command=decrypt_action)
    decrypt_button.pack(pady=10)

    back_button = tk.Button(main_window, text="Previous", command=show_main_window)
    back_button.pack(pady=10)


terms_of_use()

# Create the landing page
main_window = tk.Tk()
main_window.title("Main Menu")
main_window.geometry("500x500")
main_window.configure(bg='#daeaeb')

symmetric_key_path_var = tk.StringVar()
private_key_path_var = tk.StringVar()

if __name__ == "__main__":
    clear_window(main_window)
    show_main_window()
    main_window.mainloop()

show_main_window()
main_window.mainloop()
