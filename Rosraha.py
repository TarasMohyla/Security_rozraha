from cryptography.hazmat.primitives.asymmetric import padding
import networkx as nx
import matplotlib.pyplot as plt
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding  # for PKCS7 padding

# Генерація RSA ключів для асиметричного шифрування
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# AES encryption with padding
def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding to the data
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits (16 bytes)
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data


# AES decryption with unpadding
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data and then remove padding
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')


# Encrypt the AES session key with RSA and OAEP padding
def encrypt_session_key(session_key, public_key):
    encrypted_key = public_key.encrypt(
        session_key,
        asym_padding.OAEP(  # Use asym_padding here
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Decrypt the AES session key with RSA and OAEP padding
def decrypt_session_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(  # Use asym_padding here
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


# Генерація симетричного ключа AES
def generate_aes_key():
    return os.urandom(32)


# Візуалізація структури мережі
def visualize_structure(network_data):
    G = nx.Graph()
    for node, connections in network_data.items():
        for connection in connections:
            G.add_edge(node, connection)
    nx.draw(G, with_labels=True, node_color="skyblue", node_size=2000, edge_color="gray", font_size=10,
            font_weight="bold")
    plt.show()


# Перевірка цілісності даних
def verify_integrity(data, checksum):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode('utf-8'))
    calculated_checksum = digest.finalize()
    return calculated_checksum == checksum


# Контрольний приклад
def main():
    # Генерація ключів RSA
    private_key, public_key = generate_rsa_keys()

    # Генерація симетричного ключа AES
    session_key = generate_aes_key()

    # Шифрування симетричного ключа за допомогою публічного ключа RSA
    encrypted_session_key = encrypt_session_key(session_key, public_key)

    # Дешифрування симетричного ключа на стороні отримувача
    decrypted_session_key = decrypt_session_key(encrypted_session_key, private_key)

    # Перевірка, чи ключі збігаються
    assert session_key == decrypted_session_key, "Ключі не збігаються!"

    # Дані для передачі
    data = "network_structure_info"

    # Шифрування даних з використанням AES
    encrypted_data = encrypt_data(data, session_key)

    # Дешифрування даних
    decrypted_data = decrypt_data(encrypted_data, session_key)
    print("Original Data:", data)
    print("Decrypted Data:", decrypted_data)

    # Перевірка цілісності
    checksum = hashes.Hash(hashes.SHA256(), backend=default_backend())
    checksum.update(data.encode('utf-8'))
    original_checksum = checksum.finalize()
    integrity_check = verify_integrity(data, original_checksum)
    print("Integrity Check:", integrity_check)

    # Дані для візуалізації (логічна структура мережі)
    network_data = {
        'Node1': ['Node2', 'Node3'],
        'Node2': ['Node1', 'Node4'],
        'Node3': ['Node1'],
        'Node4': ['Node2', 'Node5'],
        'Node5': ['Node4']
    }

    # Візуалізація мережі
    visualize_structure(network_data)


# Запуск основної функції
if __name__ == "__main__":
    main()
