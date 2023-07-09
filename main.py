from aes import AES
from rsa import RSA

aes = AES()
rsa = RSA()

message = "Two One Nine Two"
encoded_message = [ord(c) for c in message]
password = "Thats my Kung Fu"

e, n, d = rsa.generate_key_pair()

print(f"e: {e}, n: {n}, d: {d}")
print(f"encoded_message: {encoded_message}")
cipher = rsa.encrypt(message, e, n)
print(f"cipher: {cipher}")
decipher = rsa.decrypt(cipher, d, n)
print(f"decipher: {decipher}")

signed_message = rsa.sign_message(message, d, n)
print(f"signed_message: {signed_message}")
original_message_encoded = rsa.check_signature(signed_message, e, n)
print(f"original_message_encoded: {original_message_encoded}")

#decrypted_text = rsa.decrypt(ciphertext, 103, 143)




#print(ciphertext, pub_key, priv_key, n)

#ciphertext = aes.encrypt(plaintext, password)
#print("Ciphertext:", ciphertext)
#
#decrypted = aes.decrypt(ciphertext, password)
#print("Decrypted :", decrypted)
#
#text = aes.hex_to_text(decrypted)
#print("Text      :", text)