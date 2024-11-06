from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import os
import time
import uuid

# Read AES key from the file
with open("shared_key.txt", "rb") as key_file:
    aes_key = key_file.read()

with open("average_qber.txt", "r") as qber_file:
    qber = qber_file.read()

try:
    qber = float(qber)
except ValueError:
    print("Error: Invalid QBER value in the file.")
    exit(1)

# Calculate the security percentage
secure = 100 - qber


def encrypt_message(message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_message


def encrypt_file(file_path, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    with open(file_path, 'rb') as file:
        file_content = file.read()
    padded_data = padder.update(file_content) + padder.finalize()
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_content


def send_message_to_bob(data, key):
    server_address = ('localhost', 12345)  # Use the same IP and port as in the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    mac_id = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)])

    if isinstance(data, str):
        timestamp = time.ctime()
        message_data = f"\nMAC id: {mac_id}\nTimestamp: {timestamp}\nMessage: {data}"
        encrypted_message = encrypt_message(message_data, key)
        client_socket.send(encrypted_message)

    elif isinstance(data, bytes):
        message = encrypt_file(data)
        client_socket.send(message)

    client_socket.close()


if __name__ == "__main__":
    print("Your line is ", secure, "% secure")

    while True:
        message_to_bob = input("Send a message/file to Bob: ")
        if message_to_bob.lower() == 'bye':
            print("Sending message to Bob....")
            send_message_to_bob(message_to_bob, aes_key)
            print("Message sent to Bob! Goodbye")
            break

        if os.path.isfile(message_to_bob):
            with open(message_to_bob, 'rb') as file:
                file_data = file.read()
                print("Sending file to Bob...")
                send_message_to_bob(file_data, aes_key)
                print("File sent to Bob.")
        else:
            print("Sending message to Bob...")
            send_message_to_bob(message_to_bob, aes_key)
            print("Message sent to Bob!")
