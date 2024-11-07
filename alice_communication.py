alice_communication:
import tkinter as tk
from functools import partial
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import os
import time
import hmac

# Read AES key from the file
with open("final_key.txt", "rb") as key_file:
    aes_key = key_file.read(16)


def generate_mac_id_from_key(message, key):
    mac_id = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    return mac_id


# Modify encryption method to include IV and padding
def encrypt_message(message, key):
    start_time = time.time()
    iv = os.urandom(16)  # Generate IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    encryption_time = time.time() - start_time
    print(f"Encryption time for message: {encryption_time:.2f} s")

    return iv + encrypted_message  # Prepend IV to the encrypted message


def encrypt_file(file_path, key):
    start_time = time.time()
    iv = os.urandom(16)  # Generate IV
    with open(file_path, 'rb') as file:
        file_content = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    padded_data = padder.update(file_content) + padder.finalize()
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    encryption_time = time.time() - start_time
    print(f"Encryption time for file: {encryption_time:.2f} s")

    return iv + encrypted_content


def send_message_to_bob(data, key, message_listbox):
    server_address = ('172.16.25.37', 12345)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    mac_id = generate_mac_id_from_key(data, key)
    timestamp = time.ctime()

    if os.path.isfile(data):
        # Handle file sending
        encrypted_file = encrypt_file(data, key)

        client_socket.send(b"FILE:")  # Send "FILE:" protocol header
        client_socket.sendall(encrypted_file)

        print("File encrypted and sent successfully")
    else:
        # Handle message sending
        message_data = f"\nMAC id: {mac_id}\nTimestamp: {timestamp}\nMessage: {data}"
        message = encrypt_message(message_data, key)

        client_socket.send(b"MSG:")  # Send "MSG:" protocol header
        client_socket.sendall(message)

        print("Message encrypted and sent successfully")
        print(f"Message sent at time :{timestamp}")

        # Display the sent message in the GUI
        message_listbox.insert(tk.END, f"[{timestamp}] You: {data}")

    client_socket.close()


def send_message(message_entry, aes_key, message_listbox):
    message = message_entry.get()
    if message:
        # Handle regular message sending
        send_message_to_bob(message, aes_key, message_listbox)
        message_entry.delete(0, tk.END)


def create_gui(aes_key):
    root = tk.Tk()
    root.title("Secure Message Transfer System")

    message_frame = tk.Frame(root)
    message_frame.pack(side=tk.BOTTOM, fill=tk.X)

    message_entry = tk.Entry(message_frame, font=('Roboto', 12))  # Increase font size for emojis
    message_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5, pady=5)
    message_entry.focus_set()  # Set focus to the entry field

    send_button = tk.Button(message_frame, text="->", command=partial(send_message, message_entry, aes_key))
    send_button.pack(side=tk.RIGHT, padx=5, pady=5)

    message_log_frame = tk.Frame(root)
    message_log_frame.pack(expand=True, fill=tk.BOTH)

    message_log_scrollbar = tk.Scrollbar(message_log_frame)
    message_log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    message_listbox = tk.Listbox(message_log_frame, yscrollcommand=message_log_scrollbar.set, width=50, font=("Segoe UI Emoji", 12))

    message_listbox.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
    message_log_scrollbar.config(command=message_listbox.yview)

    # Function to send message on pressing Enter key
    root.bind('<Return>', lambda event: send_message(message_entry, aes_key, message_listbox))

    root.mainloop()


if _name_ == "_main_":
    create_gui(aes_key)