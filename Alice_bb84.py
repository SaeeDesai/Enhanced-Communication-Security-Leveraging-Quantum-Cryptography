Alice:

import time
from qiskit import QuantumCircuit, Aer, execute
import numpy as np
import socket
import matplotlib.pyplot as plt
from qiskit.visualization import circuit_drawer


def generate_random_key(length):
    return ''.join(np.random.choice(['0', '1'], length))


# Function to run the BB84 protocol as Alice
def bb84_protocol(client_socket, noise_model=None):
    total_bits = 32
    # Generate random bit string and bases for Alice
    alice_bits = generate_random_key(total_bits)
    alice_bases = generate_random_key(total_bits)
    print(f"Alice's bits: {alice_bits}")  # Added print statement
    print(f"Alice's bases: {alice_bases}")  # Added print statement

    # Prepare Alice's quantum circuit
    alice_circuit = QuantumCircuit(total_bits, total_bits)

    # Apply bit and basis encodings to Alice's qubits
    for i in range(total_bits):
        # Apply bit encoding first, regardless of basis
        if alice_bits[i] == '1':
            alice_circuit.x(i)
        # Then apply basis encoding if needed
        if alice_bases[i] == '1':
            alice_circuit.h(i)
    # visualize_alice_circuit(alice_circuit)
    # visualize_alice_circuit(alice_circuit)
    # Exchange bases with Bob over a secure channel
    client_socket.send(alice_bases.encode())  # Send Alice's bases to Bob
    received_bases = client_socket.recv(1024).decode()  # Receive Bob's bases
    print(f"Alice received Bob's bases: {received_bases}")  # Added print statement

    # Simulate noise in the quantum channel if applicable
    if noise_model:
        apply_noise(alice_circuit, noise_model)

    # Generate and send classical message to Bob
    classical_message = f"Alice bits: {alice_bits}"
    client_socket.send(classical_message.encode())
    print("Alice sent her bits to Bob")  # Added print statement

    # Receive Bob's measurement results
    bob_results = client_socket.recv(1024).decode()
    # print(f"Alice received Bob's results: {bob_results}")  # Added print statement
    alice_circuit.measure(range(total_bits), range(total_bits))
    # Measure Alice's qubits
    alice_results = measure_qubits(alice_circuit)
    alice_results_str = "".join(alice_results)
    # print(f"Alice results {alice_results}")
    client_socket.send(alice_results_str.encode())
    # print(f"Alice sent her results to Bob: {alice_results_str}")  # Added print statement

    discrepancies = 0
    final_key = ""
    for i in range(total_bits):
        if alice_bases[i] == received_bases[i]:
            if alice_bits[i] != bob_results[i]:
                discrepancies += 1
            else:
                final_key += str(alice_bits[i])

    eavesdropping_probability, secret_key_rate = calculate_security_parameters(total_bits, alice_bases,
                                                                               received_bases, discrepancies)

    return final_key, eavesdropping_probability, secret_key_rate


# Function to visualize Alice's quantum circuit
def visualize_alice_circuit(alice_circuit):
    circuit_drawer(alice_circuit, output='mpl', scale=0.7, plot_barriers=False, vertical_compression="low", style="iqp")
    plt.title("Alice's Quantum Circuit")
    plt.show()


def measure_qubits(circuit):
    backend = Aer.get_backend('qasm_simulator')
    shots = 1024  # Define the number of shots for measurement
    result = execute(circuit, backend=backend, shots=shots).result()
    counts = result.get_counts(0).keys()
    return counts


# Function to simulate noise in the quantum channel
def apply_noise(circuit, noise_model):
    noise_op = noise_model
    circuit.append(noise_op, range(len(circuit)))
    print(f"Noise applied: {noise_op}")


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


# Main function for Alice
def main():
    # Connect to Bob over a secure socket
    server_address = ('localhost', 12345)

    total_runs = 30  # Number of runs to perform

    accumulated_key = ''
    accumulated_secret_key_rate = 0
    accumulated_eavesdropping_prob = 0
    keys = []
    for _ in range(total_runs):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(server_address)
        # Run the BB84 protocol as Alice for each iteration
        final_key, eavesdropping_prob, secret_key_rate = bb84_protocol(client_socket)
        keys.append(final_key)
        # Accumulate the keys
        accumulated_key += final_key

        # Accumulate secret key rate and eavesdropping probability
        accumulated_secret_key_rate += secret_key_rate
        accumulated_eavesdropping_prob += eavesdropping_prob
        # After each iteration, close the socket
        client_socket.close()

    print(f"Secret key formed by the combination of :{keys}")
    # Calculate average values
    average_secret_key_rate = accumulated_secret_key_rate / total_runs
    average_eavesdropping_prob = accumulated_eavesdropping_prob / total_runs

    # Print or use accumulated_key, average_secret_key_rate, average_eavesdropping_prob
    print("\n")
    print("RESULTS:\n")
    print(f"Accumulated Key: {accumulated_key} ({len(accumulated_key)})")
    print(f"Average Secret Key Rate: {average_secret_key_rate:.2f}")
    print(f"Average Eavesdropping Probability: {average_eavesdropping_prob:.2f}")

    with open("final_key.txt", "wb") as key_file:
        key_file.write(accumulated_key.encode())
    print("Key saved in file")

    client_socket.close()


if _name_ == "_main_":
    start_time = time.time()
    main()
    end_time = time.time()
    time = end_time - start_time
    print(f"Time required: {time:.2f} s")