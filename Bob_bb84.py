Bob:

from qiskit import QuantumCircuit, Aer, execute
import numpy as np
import socket
import matplotlib.pyplot as plt
from qiskit.visualization import circuit_drawer
import time


def generate_random_key(length):
    return ''.join(np.random.choice(['0', '1'], length))


# Function to run the BB84 protocol as Bob
def bb84_protocol(client_socket):
    total_bits = 32

    # Generate random bases for Bob
    bob_bases = generate_random_key(total_bits)
    print(f"Bob's bases: {bob_bases}")  # Added print statement

    # Prepare Bob's quantum circuit
    bob_circuit = QuantumCircuit(total_bits, total_bits)

    # Receive Alice's bases
    alice_bases = client_socket.recv(1024).decode()  # Receive Alice's bases
    print(f"Bob received Alice's bases: {alice_bases}")  # Added print statement

    # Send chosen bases to Alice
    client_socket.send(bob_bases.encode())
    print("Bob sent his bases to Alice")  # Added print statement

    # Receive and store classical message from Alice
    alice_message = client_socket.recv(1024).decode()
    alice_parts = alice_message.split(": ")
    alice_bits = alice_parts[-1]
    # print(f"Received Alice's bits: {alice_bits}")  # Added print statement

    # Apply basis encodings to Bob's qubits based on received bits
    for i in range(len(alice_bases)):
        if bob_bases[i] == '1':
            bob_circuit.h(i)
            # If Alice's base is '0', no operation needed
    # visualize_bob_circuit(bob_circuit)
    # visualize_bob_circuit(bob_circuit)
    bob_circuit.measure(range(total_bits), range(total_bits))
    # Measure the qubits
    bob_results = measure_qubits(bob_circuit)
    # print(f"Bob's measurement results: {bob_results}")  # Added print statement

    # Send measurement results to Alice
    bob_results_str = "".join(bob_results)
    client_socket.send(bob_results_str.encode())
    print("Bob sent measurement results to Alice")  # Added print statement

    # alice_results = client_socket.recv(1024).decode()
    # print(f"Alice measurement results:{alice_results}")

    discrepancies = 0
    final_key = ""
    for i in range(total_bits):
        if bob_bases[i] == alice_bases[i]:
            if alice_bits[i] != bob_results_str[i]:
                discrepancies += 1
            else:
                final_key += str(alice_bits[i])
    eavesdropping_probability, secret_key_rate = calculate_security_parameters(total_bits, bob_bases, alice_bases,
                                                                               discrepancies / total_bits)

    return final_key, eavesdropping_probability, secret_key_rate


# Function to visualize Alice's quantum circuit
def visualize_bob_circuit(bob_circuit):
    circuit_drawer(bob_circuit, output='mpl', scale=0.7, plot_barriers=False, vertical_compression="low", style="iqp")
    plt.title("Bob's Quantum Circuit")
    plt.show()


# Function to receive bases from Alice
def exchange_bases(client_socket):
    received_bases = client_socket.recv(1024).decode()
    return received_bases


# Function to simulate noise in the quantum channel
def apply_noise(circuit, noise_model):
    noise_op = noise_model
    circuit.append(noise_op, range(len(circuit)))
    print(f"Noise applied: {noise_op}")


def measure_qubits(circuit):
    backend = Aer.get_backend('qasm_simulator')
    shots = 1024  # Define the number of shots for measurement
    result = execute(circuit, backend=backend, shots=shots).result()
    counts = result.get_counts(0).keys()
    return counts


# Function to calculate security parameters
def calculate_security_parameters(key_length, alice_bases, received_bases, discrepancies):
    matching_bits = 0
    for i in range(key_length):
        if alice_bases[i] == received_bases[i]:
            matching_bits += 1

    if matching_bits == 0:
        error_rate_filtered = 1.0e-10  # Set a small non-zero value for error rate
    else:
        error_rate_filtered = discrepancies / matching_bits

    # Ensure the error rate is within the valid range (0, 1)
    error_rate_filtered = min(max(error_rate_filtered, 1.0e-10), 1 - 1.0e-10)

    eavesdropping_probability = 1 - (1 - error_rate_filtered) ** 2
    secret_key_rate = key_length * (1 - h(error_rate_filtered))

    return eavesdropping_probability, secret_key_rate


def h(x):
    if x == 0 or x == 1:
        return 0
    else:
        return -x * np.log2(x) - (1 - x) * np.log2(1 - x) if 0 < x < 1 else 0


# Main function for Bob
def main():
    # Create a socket and listen for incoming connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Waiting for Alice...")

    # Choose a noise model (optional)
    total_runs = 30  # Number of runs to perform

    accumulated_key = ''
    accumulated_secret_key_rate = 0
    accumulated_eavesdropping_prob = 0

    keys = []
    for _ in range(total_runs):
        client_socket, client_address = server_socket.accept()
        # Run the BB84 protocol as Alice for each iteration
        final_key, eavesdropping_prob, secret_key_rate = bb84_protocol(client_socket)
        keys.append(final_key)
        # Accumulate the keys
        accumulated_key += final_key

        # Accumulate secret key rate and eavesdropping probability
        accumulated_secret_key_rate += secret_key_rate
        accumulated_eavesdropping_prob += eavesdropping_prob

        client_socket.close()

    print(f"Secret key formed by the combination of :{keys}")
    # Calculate average values
    average_secret_key_rate = accumulated_secret_key_rate / total_runs
    average_eavesdropping_prob = accumulated_eavesdropping_prob / total_runs

    # Print or use accumulated_key, average_secret_key_rate, average_eavesdropping_prob
    print("\n")
    print("RESULTS: \n")
    print(f"Accumulated Key: {accumulated_key} ({len(accumulated_key)})")
    print(f"Average Secret Key Rate: {average_secret_key_rate:.2f}")
    print(f"Average Eavesdropping Probability: {average_eavesdropping_prob:.2f}")

    with open("final_key.txt", "wb") as key_file:
        key_file.write(accumulated_key.encode())
    print("Key saved in file")

    server_socket.close()


if _name_ == "_main_":
    start_time = time.time()
    main()
    end_time = time.time()
    time = end_time - start_time
    print(f"Time required: {time:.2f} s")