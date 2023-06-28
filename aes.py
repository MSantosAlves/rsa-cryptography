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

      return bytes(sbox)

  def __generate_random_key__(self):
      key = bytes(random.SystemRandom().randint(0, 255) for _ in range(16))
      return key

  # AES Round Constants
  def __initialize_aes_rcon__(self):
    rcon = []
    row = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36] 
    rcon.append(row)
    row = [0] * 10
    for i in range(3):
      rcon.append(row)
    
    return rcon

  # AES SubBytes transformation
  def sub_bytes(state):
      for i in range(4):
          for j in range(4):
              row = state[i][j] // 0x10
              col = state[i][j] % 0x10
              state[i][j] = S_BOX[row * 16 + col]
      return state

  # AES ShiftRows transformation
  def shift_rows(state):
      for i in range(1, 4):
          state[i] = state[i][i:] + state[i][:i]
      return state

  # AES MixColumns transformation
  def mix_columns(state):
      for i in range(4):
          s0 = state[0][i]
          s1 = state[1][i]
          s2 = state[2][i]
          s3 = state[3][i]
          state[0][i] = (2 * s0) ^ (3 * s1) ^ s2 ^ s3
          state[1][i] = s0 ^ (2 * s1) ^ (3 * s2) ^ s3
          state[2][i] = s0 ^ s1 ^ (2 * s2) ^ (3 * s3)
          state[3][i] = (3 * s0) ^ s1 ^ s2 ^ (2 * s3)
      return state

  # AES AddRoundKey transformation
  def add_round_key(state, round_key):
      for i in range(4):
          for j in range(4):
              state[i][j] ^= round_key[i][j]
      return state

  # AES Key Expansion
  def __key_schedule__(self):
    return [self.key] * 11

  def plaintext_to_blocks(self, plaintext, nb_of_blocks):
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
            hex_bytes = [x.encode().hex() for x in chars_list]
            block.append(hex_bytes)
            
          blocks.append(block)
      return blocks

  # AES encryption
  def encrypt(self, plaintext):
      nb_of_blocks = math.ceil(len(plaintext) / 16)
      blocks = self.plaintext_to_blocks(plaintext, nb_of_blocks)

      round_keys = self.__key_schedule__()

      for i in range(len(round_keys)):
        print(round_keys[i].hex())
      return

      # Initial round
      block = add_round_key(block, round_keys[0])

      # Main rounds
      for i in range(1, 10):
          block = sub_bytes(block)
          block = shift_rows(block)
          block = mix_columns(block)
          block = add_round_key(block, round_keys[i])

      # Final round
      block = sub_bytes(block)
      block = shift_rows(block)
      block = add_round_key(block, round_keys[-1])

      # Convert state to a flat list
      ciphertext = [state[i][j] for i in range(4) for j in range(4)]
      return bytes(ciphertext)

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