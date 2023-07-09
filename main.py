from aes import AES
from rsa import RSA

aes = AES()
rsa = RSA()

plaintext = "Two One"
password = "Thats my Kung Fu"

ciphertext, e, d, n, phi = rsa.encrypt(plaintext)
#signed_message = rsa.sign_message(ciphertext, d, n)

#print(rsa.check_signature(ciphertext, signed_message, e, n))

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