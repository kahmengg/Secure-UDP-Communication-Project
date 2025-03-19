import socket
import hashlib
import random
from Crypto.Cipher import ARC4
import secrets
def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()

def encrypt(key, plaintext):
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)

def decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    return cipher.decrypt(ciphertext)

def main():
    host = '127.0.0.1'
    port = 12345

    password = input("Enter password: ")
    hashed_pw = hash_password(password)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.sendto(b"Bob", (host, port))
    print("Sent connection request to host")
    
    # Step 2
    data, address = client_socket.recvfrom(2048)
    print(f"Step 2: A → B: E(H(PW), p, g, ga mod p): {data}")
    
    # Handle wrong password exception
    try:
        decrypted_message = decrypt(hashed_pw.encode(), data)
        p, g, ga = map(int, decrypted_message.decode().split(','))
    except (UnicodeDecodeError, ValueError) as e:
        print("The password might be incorrect.")
        client_socket.sendto(b"Incorrect Password", (host, port))
        client_socket.close()
        return

    b = random.randint(1, p - 1)
    gb = pow(g, b, p)
    message = f"{gb}"
    encrypted_message = encrypt(hashed_pw.encode(), message.encode())
    client_socket.sendto(encrypted_message, (host, port))
    print(f"Step 3: B → A: E(H(PW), gb mod p): {encrypted_message}")
    
    shared_key = pow(ga, b, p)
    K = hash_password(str(shared_key))
    print(f"Calculated shared key: K={K}")

    data, address = client_socket.recvfrom(2048)
    
    decrypted_message = decrypt(K.encode(), data).decode()
    NA = int(decrypted_message)
    print(f"Step 4: A → B: E(K, NA): {data}")
    
    print(f"Received nonce NA from host: NA={NA}")

    NA1 = NA + 1
    NB = secrets.randbits(64)
    message = f"{NA1},{NB}"
    encrypted_message = encrypt(K.encode(), message.encode())
    client_socket.sendto(encrypted_message, (host, port))
    
    print(f"Step 5: B → A: E(K, NA+1, NB): {encrypted_message}")
    print(f"Sent NA+1 and NB to host: NA+1={NA1}, NB={NB}")
    
    data, address = client_socket.recvfrom(2048)
    decrypted_message = decrypt(K.encode(), data).decode()
    print(f"Step 6: A → B: E(K, NB+1), handshake complete: {data}")
    if decrypted_message == "Login Failed":
        print("Login failed.")
        return

    if int(decrypted_message) != NB + 1:
        print("Nonce mismatch. Connection failed.")
        return

    print("Secure connection established.")

    while True:
        message = input("Client: ")
        if message == "exit":
            encrypted_message = encrypt(K.encode(), message.encode())
            client_socket.sendto(encrypted_message, (host, port))
            client_socket.sendto(encrypt(K.encode(), b"exit"), (host, port))
            print("Connection terminated by client.")
            break
        message_to_send = f"{message}{hash_password(K + message + K)}"
        encrypted_message = encrypt(K.encode(), message_to_send.encode())
        client_socket.sendto(encrypted_message, (host, port))

        data, address = client_socket.recvfrom(2048)
        decrypted_message = decrypt(K.encode(), data).decode()
        
        # If host types exit 
        if decrypted_message == "exit":
            print("Connection terminated by host.")
            break

        # Step 2 : Bob Receive cipher text
        message, hash_received = decrypted_message[:-40], decrypted_message[-40:]
        hash_calculated = hash_password(K + message + K)
        if hash_received == hash_calculated:
            print(f"Host: {message}")
        else:
            print("Hash mismatch. Message rejected.")
    client_socket.close()
if __name__ == "__main__":
    main()
