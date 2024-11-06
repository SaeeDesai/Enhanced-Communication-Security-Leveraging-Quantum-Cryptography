from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
from datetime import datetime

with open("shared_key.txt", "rb") as key_file:
    aes_key = key_file.read()


def decrypt_message(encrypted_message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode().strip()


def decrypt_file(encrypted_content, key, file_path):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    with open(file_path, 'wb') as decrypted_file:
        decrypted_file.write(unpadded_data)



def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)  # Use the IP and port you prefer
    server_socket.bind(server_address)
    server_socket.listen(1)  # Listen for a single connection

    while True:
        print("\n\nWaiting for a connection...")
        client_socket, client_address = server_socket.accept()
        print("Connected to", client_address)

        received_message = client_socket.recv(1024)
        if received_message:
            try:
                decrypted_message = decrypt_message(received_message, aes_key)
                message_lines = decrypted_message.split('\n')
                mac_id = message_lines[0].replace("MAC id: ", "")
                timestamp_str = message_lines[1].replace("Timestamp: ", "")
                message = message_lines[2].replace("Message: ", "")

                received_timestamp = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
                current_time = datetime.now()

                time_window = 30

                time_difference = current_time - received_timestamp

                if time_difference.total_seconds() <= time_window:
                    print("Received message is within the time window.")
                    print("MAC id: ", mac_id)
                    print("Timestamp:", received_timestamp)
                    print("Message from Alice:", message)
                else:
                    print("Received message is outside the time window. Ignoring.")

                if message.lower() == 'bye':
                    print("Alice said 'bye'. End of conversation!")
                    break

            except ValueError as e:
                print("Received a file...")
                file_path = "received_file.txt"
                decrypt_file(received_message, aes_key, file_path)
                print("File saved as 'received_file.txt'.")

            client_socket.close()

    server_socket.close()


if __name__ == "__main__":
    start_server()
