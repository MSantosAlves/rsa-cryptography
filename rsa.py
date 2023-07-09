import math
import random
import base64

class RSA:

    def __generate_prime_numbers__(self):
        p = random.getrandbits(1024)
        q = random.getrandbits(1024)
        
        while not self.__is_prime__(p):
            p = random.getrandbits(1024)

        while not self.__is_prime__(q):
            q = random.getrandbits(1024)

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

    def __string_to_int__(self, s):
        return int.from_bytes(s.encode(), byteorder='little')

    def __int_to_string__(self, i):
        length = math.ceil(i.bit_length() / 8)
        return i.to_bytes(length, byteorder='little').decode()

    def encrypt(self, m, e, n):
        m = self.__string_to_int__(m)
        return pow(m, e, n)
       
    def decrypt(self, c, d, n):
        m = pow(c, d, n)
        return self.__int_to_string__(m)

    def sign_message(self, m, d, n):
        s = self.__string_to_int__(m)
        return pow(s, d, n)

    def check_signature(self, s, e, n):
        m = pow(s, e, n)
        return self.__int_to_string__(m) 
        