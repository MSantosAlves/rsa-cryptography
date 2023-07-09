from aes import AES
from rsa import RSA

aes = AES()
rsa = RSA()

message = "Two One Nine Two"
password = "Thats my Kung Fu"

e, n, d = rsa.generate_key_pair()

print(f"Message (integer): {rsa.__string_to_int__(message)}")
print(f"Public exponent (e): {e}")
print(f"Public modulus (n): {n}")
print(f"Private exponent (d): {d}")

ciphernumber = rsa.encrypt(message, e, n)
print(f"Cipher: {ciphernumber}")

message = rsa.decrypt(ciphernumber, d, n)
print(f"Decripted message: {message}")

signed_message = rsa.sign_message(message, d, n)
print(f"Signed message: {signed_message}")
original_message = rsa.check_signature(signed_message, e, n)
print(f"Check signature result: {original_message}")