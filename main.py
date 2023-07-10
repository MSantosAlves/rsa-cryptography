from aes import AES
from rsa import RSA
from file import FileHandler

aes = AES()

plaintext = "Two One Nine Two"
password = "Thats my Kung Fu"

ciphertext = aes.encrypt(plaintext, password)
message = aes.decrypt(ciphertext, password)

print(f"Message: {message}")

rsa = RSA("test.txt")
filehandler = FileHandler("test.txt")
file_bytes = filehandler.read()

e, n, d = rsa.generate_key_pair()
cipher = rsa.encrypt(e, n)
message = rsa.decrypt(d, n)
signature = rsa.sign_message(d, n)
is_valid = rsa.check_signature(e, n)

print(f"Check Signature: {is_valid}")