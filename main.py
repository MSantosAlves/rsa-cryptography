from aes import AES

aes = AES()

plaintext = "This is a test message and it will be used for tests purposes."

bs = aes.encrypt(plaintext)