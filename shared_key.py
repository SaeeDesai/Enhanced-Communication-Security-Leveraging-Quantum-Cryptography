from bb84 import final_key, qber

# Convert the shared key to bytes
shared_key_bytes = final_key.encode()

# Pad the key to 32 bytes with null bytes
aes_key = shared_key_bytes[:32]


# Save the shared key to a file or share it securely
with open("shared_key.txt", "wb") as key_file:
    key_file.write(aes_key)

with open("average_qber.txt", "w") as file:
    file.write(f"{qber:.2f}")
