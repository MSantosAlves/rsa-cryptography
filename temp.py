   def __break_string_into_lines__(self, text, n = 64):
        nb_of_lines = math.ceil(len(text) / n)
        text_size = len(text)
        lines = []
        for i in range(0, nb_of_lines):
            start = i * n
            end = start + n if start + n < text_size else text_size
            lines.append(text[start:end])
        
        return "\n".join(lines)

    def __int_to_base64__(self, i):
        return base64.b64encode(i.to_bytes((i.bit_length() + 7) // 8, 'big')).decode('utf8')

# RSA public Key file (PKCS#1) - https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/asn1-key-structures-in-der-and-pem/#rsa-public-key-file-pkcs-1
    #
    # RSAPublicKey ::= SEQUENCE {
    #   modulus   INTEGER,  -- n
    #   publicExponentINTEGER   -- e
    # }
    #
    def __create_pubic_key_pem_file__(self, n, e):
       
        base64_n = self.__int_to_base64__(n)
        base64_e = self.__int_to_base64__(e)
        
        encoded_key = f"{n}{e}"
        pem_public_key  = f"-----BEGIN PUBLIC KEY-----\n"
        pem_public_key += self.__break_string_into_lines__(encoded_key)
        pem_public_key += f"\n-----END PUBLIC KEY-----"

        with open("public.pem", "w") as f:
            f.write(pem_public_key)

    # RSA private Key file (PKCS#1) - https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/asn1-key-structures-in-der-and-pem/#rsa-private-key-file-pkcs-1
    #
    # RSAPrivateKey ::= SEQUENCE {
    #   version   Version,
    #   modulus   INTEGER,  -- n
    #   publicExponentINTEGER,  -- e
    #   privateExponent   INTEGER,  -- d
    #   prime1INTEGER,  -- p
    #   prime2INTEGER,  -- q
    #   exponent1 INTEGER,  -- d mod (p-1)
    #   exponent2 INTEGER,  -- d mod (q-1)
    #   coefficient   INTEGER,  -- (inverse of q) mod p
    #   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    # }
    #
    def __create_private_key_pem_file__(self, n, e, d, p, q):
        base64_p = self.__int_to_base64__(p)
        base64_q = self.__int_to_base64__(q)
        base64_e = self.__int_to_base64__(e)
        base64_n = self.__int_to_base64__(n)
        base64_d = self.__int_to_base64__(d)
        encoded_key = f"{n}{e}{d}{p}{q}"
        
        pem_private_key  = f"-----BEGIN PRIVATE KEY-----\n"
        pem_private_key += self.__break_string_into_lines__(encoded_key)
        pem_private_key += f"\n-----END PRIVATE KEY-----"

        with open("private.pem", "w") as f:
            f.write(pem_private_key)