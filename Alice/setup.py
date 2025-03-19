import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import random


def generate_diffie_hellman_params():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    return p, g

def hash(password):
    return hashlib.sha1(password.encode()).hexdigest()

def main(): 
    password = "pass123"

    p , g = generate_diffie_hellman_params()
    hashed_password = hash(password)
    with open("Alice/setup.txt", "w") as file:
        file.write(f"{p}\n{g}\n{hashed_password}")


if __name__ == "__main__":
    main()