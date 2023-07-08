from aes import AES

aes = AES()

plaintext = "Two One Nine TwoTwo One Nine Two"
password = "Thats my Kung Fu"

ciphertext = aes.encrypt(plaintext, password)
print("Ciphertext:", ciphertext)

decrypted = aes.decrypt(ciphertext, password)
print("Decrypted :", decrypted)

text = aes.hex_to_text(decrypted)
print("Text      :", text)