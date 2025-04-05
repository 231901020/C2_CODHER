from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_text(plain_text):
    return cipher_suite.encrypt(plain_text.encode()).decode()

def decrypt_text(cipher_text):
    return cipher_suite.decrypt(cipher_text.encode()).decode()
