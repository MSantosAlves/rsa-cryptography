import math
import random
import base64

class RSA:

    def __generate_prime_numbers__(self):
        p = random.getrandbits(11)
        q = random.getrandbits(11)
        
        while not self.__is_prime__(p):
            p = random.getrandbits(11)

        while not self.__is_prime__(q):
            q = random.getrandbits(11)

        return p, q

    # Implementation credit: https://gist.github.com/Ayrx/5884790
    def  __miller_rabin__(self, n, k):
        if n == 2:
            return True
        
        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def __is_prime__(self, n):
        return self.__miller_rabin__(n, 64)

    def __egcd__(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.__egcd__(b % a, a)
            return (g, x - (b // a) * y, y)

    def __mod_inv__(self, e, phi):
        g, x, y = self.__egcd__(e, phi)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % phi
 
    
    def __totient_function__(self, p, q):
        return (p-1) * (q-1)

    def generate_key_pair(self):
        # Prime numbers
        p, q = self.__generate_prime_numbers__()

        n = p * q

        # Numbers of coprimes of n
        phi = self.__totient_function__(p, q)

        # Forcing e (Public key) to be 65537
        e = 65537

        # Private key
        d = self.__mod_inv__(e, phi)

        return e, n, d

    def encrypt(self, m, e, n):
        encoded_message = [ord(c) for c in m]

        cipher_message = encoded_message

        for i in range(len(encoded_message)):
            cipher_message[i] = (encoded_message[i] ** e) % n
            
        return cipher_message
       
    def decrypt(self, c, d, n):
        cipher_message = c

        encoded_message = cipher_message

        for i in range(len(cipher_message)):
            encoded_message[i] = (cipher_message[i] ** d) % n

        return encoded_message

    def sign_message(self, m, d, n):
        encoded_message = [ord(c) for c in m]

        signed_message = encoded_message

        for i in range(len(encoded_message)):
            signed_message[i] = (encoded_message[i] ** d) % n
        
        return signed_message

    def check_signature(self, s, e, n):
        signed_message = s
        original_message = signed_message

        for i in range(len(signed_message)):
            original_message[i] = (signed_message[i] ** e) % n
        
        return original_message