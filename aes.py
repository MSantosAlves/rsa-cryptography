import math
import random
import numpy as np

class AES:

    def __init__(self):
        self.sbox = self.__initialize_aes_sbox__()
        self.key = self.__generate_random_key__()
        self.rcon = self.__initialize_aes_rcon__()

    # From the wikipedia definition
    # See (https://en.wikipedia.org/wiki/Rijndael_S-box) for more details
    def __initialize_aes_sbox__(self):
        ROTL8 = lambda x, shift: (x << shift) | (x >> (8 - shift))
        sbox = [0] * 256
        p = q = 1
        while True:
            # multiply p by 3 
            p = p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)
            p = p & 255
            # divide q by 3 (equals multiplication by 0xf6)
            q ^= q << 1
            q ^= q << 2
            q ^= q << 4
            q ^= (0x09 if q & 0x80 else 0)
            q = q & 255
            # compute the affine transformation
            xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4)
            sbox[p] = (xformed ^ 0x63) & 255
            if p == 1:
                break
        sbox[0] = 0x63
        sbox = [hex(x) for x in sbox]
        sbox = np.array(sbox).reshape(16, 16)
        return sbox

    def __generate_random_key__(self):
        key_block = []
        key = bytearray(random.SystemRandom().randint(0, 255) for _ in range(16))
        key = [hex(x) for x in key]
        key = np.array(key).reshape(4, 4)
        return key
    def __set_key__(self, key):
        self.key = key

    def __generate_key_from_password__(self, password):
        key_block = []
        key = bytearray((ord(c) for c in password))
        key = [hex(x) for x in key]
        key = np.array(key).reshape(4, 4)
        return key

    # AES Round Constants
    def __initialize_aes_rcon__(self):
        rcon = []
        row = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        rcon.append(row)
        row = [0] * 10
        for i in range(3):
            rcon.append(row)

        return np.array(rcon)

    def __get_matrix_colum__(self, matrix, col):
        return [row[col] for row in matrix]

    # AES Key Expansion
    def __key_schedule__(self):

        keys = np.array(([self.key] * 11))
        
        for i in range(1, 11):
            # Build RotWord
            last_key = keys[i-1]
            rot_word = [last_key[1][3], last_key[2][3], last_key[3][3], last_key[0][3]]

            # SubBytes in RotWord
            for j in range(4):
                tmp = int(rot_word[j], 16)
                row = tmp // 0x10
                col = tmp % 0x10
                rot_word[j] = self.sbox[row][col]

            rcon = [hex(x) for x in self.__get_matrix_colum__(self.rcon, i-1)]

            # Calculate new first column
            first_col = self.__get_matrix_colum__(last_key, 0)
            curr_col = self.__arr_xor__(first_col, rot_word)
            curr_col = self.__arr_xor__(curr_col, rcon)

            round_key = np.array([curr_col])

            for l in range(1, 4):
                col = self.__get_matrix_colum__(last_key, l)
                new_col = self.__arr_xor__(col, round_key[l-1])
                round_key = np.append(round_key, [new_col], axis=0)

            round_key = np.array(round_key.reshape(4, 4)).transpose(1, 0)
            keys[i] = round_key

        return keys

    # Matrix XOR bitwise operation
    def __matrix_column_xor__(self, m1, m2):
        rows_len = len(m1)
        cols_len = len(m1[0])
        
        for i in range(rows_len):
            for j in range(cols_len):
                a = int(m1[i][j], 16)
                b = int(m2[i][j], 16)
                m1[i][j] = hex(a ^ b)
        return np.array(m1).transpose(1, 0)

    def __arr_xor__(self, arr1, arr2):
        for i in range(len(arr1)):
            a = int(arr1[i], 16)
            b = int(arr2[i], 16)
            arr1[i] = hex(a ^ b)
        return arr1

    # AES AddRoundKey transformation
    def __add_round_key__(self, state, round_key):
        state = self.__matrix_column_xor__(state, round_key)
        return state

    # AES SubBytes transformation
    def __sub_bytes__(self, state):
        for i in range(4):
            for j in range(4):
                tmp = int(state[i][j], 16)
                row = tmp // 0x10
                col = tmp % 0x10
                state[i][j] = self.sbox[row][col]
        return state

    # AES ShiftRows transformation
    def __shift_rows__(self, state):
        for i in range(1, 4):
            state[i] = np.concatenate((state[i][i:], state[i][:i]))
        return state

    
    def __galois_multiplication__(self, a, b):
        # Multiplication in the AES field GF(2^8)
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1
        p = p if p <= 256 else p - 256
        return p

    # AES MixColumns transformation
    def __mix_columns__(self, state):
        # The AES mix_columns matrix
        mix_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

        # Perform the matrix multiplication
        result_state = np.array([[0] * 4 for _ in range(4)])
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    a = mix_matrix[i][k]
                    b = int(state[k][j], 16)
                    result_state[i][j] = result_state[i][j] ^ self.__galois_multiplication__(a, b)
        
        result_state = [hex(x) for x in result_state.flatten()]
        result_state = np.array(result_state).reshape(4, 4)
        return result_state

    def __plaintext_to_blocks__(self, plaintext, nb_of_blocks):
        blocks = []
        text_len = len(plaintext)
        start = end = 0

        for i in range(0, nb_of_blocks):
            start = end
            end = start + 16 if start + 16 <= text_len else text_len
            block_text = plaintext[start:end]
            block = []
            for j in range(4):
                k = j * 4
                chars_list = list((block_text[k:k + 4]))
                hex_bytes = [hex(ord(x)) for x in chars_list]
                block.append(hex_bytes)

            blocks.append(block)
        return np.array(blocks)

    # AES encryption
    def encrypt(self, plaintext, key = None):
        if key is not None:
            key = self.__generate_key_from_password__(key)
            self.__set_key__(key)

        # self.__set_key__([
        #     ['0x2b', '0x28', '0xab', '0x09'],
        #     ['0x7e', '0xae', '0xf7', '0xcf'],
        #     ['0x15', '0xd2', '0x15', '0x4f'],	
        #     ['0x16', '0xa6', '0x88', '0x3c']
        # ])

        # self.__set_key__([
        #     ['0x00', '0x00', '0x00', '0x00'],
        #     ['0x00', '0x00', '0x00', '0x00'],
        #     ['0x00', '0x00', '0x00', '0x00'],	
        #     ['0x00', '0x00', '0x00', '0x00']
        # ])

        nb_of_blocks = math.ceil(len(plaintext) / 16)
        blocks = self.__plaintext_to_blocks__(plaintext, nb_of_blocks)

        round_keys = self.__key_schedule__()

        print(round_keys)

        for i in range(0, nb_of_blocks):
            state = blocks[i]
            round_key = round_keys[i]
            
            # Initial round
            state = self.__add_round_key__(state, round_key)

            # Main rounds
            for j in range(1, 2):
                state = self.__sub_bytes__(state)
                state = self.__shift_rows__(state)
                state = self.__mix_columns__(state)
                state = self.__add_round_key__(state, round_keys[j])
                # print(state)
            # Final round
            # block = sub_bytes(block)
            # block = shift_rows(block)
            # block = add_round_key(block, round_keys[-1])

        # Convert state to a flat list
        # ciphertext = [state[i][j] for i in range(4) for j in range(4)]
        # return bytes(ciphertext)

    # AES decryption
    def decrypt(ciphertext, key):
        state = [[ciphertext[i + j] for j in range(0, 16, 4)] for i in range(0, 16, 4)]
        round_keys = expand_key(key)

        # Initial round
        state = add_round_key(state, round_keys[-1])

        # Main rounds
        for i in range(9, 0, -1):
            state = shift_rows(state, inverse=True)
            state = sub_bytes(state, inverse=True)
            state = add_round_key(state, round_keys[i])
            state = mix_columns(state, inverse=True)

        # Final round
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, inverse=True)
        state = add_round_key(state, round_keys[0])

        # Convert state to a flat list
        plaintext = [state[i][j] for i in range(4) for j in range(4)]
        return bytes(plaintext)
