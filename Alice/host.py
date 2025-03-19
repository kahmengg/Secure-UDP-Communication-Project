import socket
import hashlib
import random
import secrets
from Crypto.Cipher import ARC4

def read_params():
    with open("setup.txt","r") as file:
        p = int(file.readline().strip())
        g = int(file.readline().strip())
        hashed_pass = file.readline().strip()

    return p, g, hashed_pass

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()

def encrypt(key,plaintext):
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)

def decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    return cipher.decrypt(ciphertext)

def main():
    p, g, hash_pwd = read_params()
    host = '127.0.0.1'
    port = 12345

    # Create Socket

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))

    print("Host is running and waiting for connection..")

    while True:


        data, address = server_socket.recvfrom(2048)

        if data.decode(errors='ignore')  == "Bob":
            
            # Step 2: A → B: E(H(PW), p, g, ga mod p)
            a = random.randint(1, p - 1)
            ga = pow(g, a, p)
            message = f"{p},{g},{ga}"
            encrypted_message = encrypt(hash_pwd.encode(), message.encode())
            server_socket.sendto(encrypted_message, address)
            print(f"Step 2: A → B: E(H(PW), p, g, ga mod p): {encrypted_message}")

            # Step 3: B → A: E(H(PW), gb mod p)
            data, address = server_socket.recvfrom(2048)
            if data == b"Incorrect Password":
                print("Bob reported an incorrect password. Terminating connection.")
                break
            decrypted_message = decrypt(hash_pwd.encode(), data)
            gb = int(decrypted_message.decode())
            shared_key = pow(gb, a, p)
            K = hash_password(str(shared_key))
            print(f"Step 3: B → A: E(H(PW), gb mod p): {data}")
            print(f"Calculated shared key: K={K}")

            # Step 4: A → B: E(K, NA)
            NA = secrets.randbits(64)
            message = f"{NA}"
            encrypted_message = encrypt(K.encode(), message.encode())
            server_socket.sendto(encrypted_message, address)
            print(f"Step 4: A → B: E(K, NA): {encrypted_message}")
            print(f"Sent nonce NA to client: NA={NA}")
            
            # Step 5: B → A: E(K, NA+1, NB)
            data, address = server_socket.recvfrom(2048)
            print(f"Step 5: B → A: E(K, NA+1, NB): {data}")
            decrypted_message = decrypt(K.encode(), data).decode()
            NA1, NB = map(int, decrypted_message.split(','))
            if NA1 != NA + 1:
                server_socket.sendto(b"Login Failed", address)
                continue
            print(f"Received NA+1 and NB from client: NA+1={NA1}, NB={NB}")
            
            # Step 6: A → B: E(K, NB+1) or "Login Failed"
            message = f"{NB + 1}"
            encrypted_message = encrypt(K.encode(), message.encode())
            server_socket.sendto(encrypted_message, address)
            print(f"Step 6: A → B: E(K, NB+1), handshake complete: {encrypted_message}")
            
            # Start secure communication
            while True:
                data, address = server_socket.recvfrom(2048)
                decrypted_message = decrypt(K.encode(), data).decode()
                if decrypted_message == "exit":
                    print("Connection terminated by client.")
                    server_socket.sendto(encrypt(K.encode(), b"exit"), address)
                    break

                # Step 2: Alice receive cipher 
                message, hash_received = decrypted_message[:-40], decrypted_message[-40:]
                hash_calculated = hash_password(K + message + K)
                if hash_received == hash_calculated:
                    print(f"Client: {message}")
                    reply = input("Host: ")
                    
                    if reply == "exit":
                        encrypted_message = encrypt(K.encode(), reply.encode())
                        server_socket.sendto(encrypted_message, address)
                        server_socket.sendto(encrypt(K.encode(), b"exit"), address)
                        print("Connection terminated by Host.")
                        break
                    message_to_send = f"{reply}{hash_password(K + reply + K)}"
                    encrypted_message = encrypt(K.encode(), message_to_send.encode())
                    server_socket.sendto(encrypted_message, address)
                else:
                    print("Hash mismatch. Message rejected.")
            break  # Exit the outer loop
    server_socket.close() 
         
                    
if __name__ == "__main__":
    main()