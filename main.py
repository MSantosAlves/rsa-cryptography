from aes import AES

aes = AES()

plaintext = "Two One Nine Two"
password = "Thats my Kung Fu"

# hex_str = "0xAD4"
# hex_int = int(hex_str, 16)
# print(hex(hex_int))

ciphertext = aes.encrypt(plaintext, password)
print(ciphertext)