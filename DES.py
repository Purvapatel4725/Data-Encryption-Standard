import binascii
import sys
import os
# Initial permutation table
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final permutation table (inverse of IP)
FP_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Permuted choice 1 (PC1) table
PC1_TABLE = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted choice 2 (PC2) table
PC2_TABLE = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Expansion table
EXPANSION_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S-boxes (S1 to S8) 
S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]


# Left shift table
LEFT_SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Permutation (P) table
P_TABLE = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]


# Helper function to convert hex to binary
def hex_to_bin(hex_string):
    return bin(int(hex_string, 16))[2:].zfill(64)

# Helper function to convert binary to hex
def bin_to_hex(bin_string):
    return hex(int(bin_string, 2))[2:].upper().zfill(16)

# Helper function to convert decimal to binary
def dec_to_bin(decimal_string):
    return bin(int(decimal_string))[2:].zfill(64)

# Convert text to binary (ensures 64-bit blocks)
def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text).ljust((len(text) + 7) // 8 * 8 * 8, '0')

# Convert binary back to text
def bin_to_text(binary_data):
    text = ''.join(chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8))
    return text

# Apply the initial permutation
def initial_permutation(block):
    return ''.join([block[i - 1] for i in IP_TABLE])

# Apply the final permutation
def final_permutation(block):
    return ''.join([block[i - 1] for i in FP_TABLE])

# Key scheduling to generate 16 round keys
def key_schedule(key_64bit):
    # Apply PC-1 to get the 56-bit key
    permuted_key = ''.join([key_64bit[i - 1] for i in PC1_TABLE])
    # Split into left (C) and right (D) halves
    left, right = permuted_key[:28], permuted_key[28:]

    round_keys = []
    for round_number in range(16):
        # Perform left shifts
        left = left_shift(left, LEFT_SHIFT_TABLE[round_number])
        right = left_shift(right, LEFT_SHIFT_TABLE[round_number])
        combined_key = left + right
        # Apply PC-2 to get the round key
        round_key = ''.join([combined_key[i - 1] for i in PC2_TABLE])
        round_keys.append(round_key)

    return round_keys

# Left shift function for key scheduling
def left_shift(bits, shift_count):
    return bits[shift_count:] + bits[:shift_count]

# DES round function (Feistel structure)
def feistel_function(right_half, round_key):
    expanded_right = ''.join([right_half[i - 1] for i in EXPANSION_TABLE])  # Apply expansion
    xored = xor(expanded_right, round_key)  # XOR with the round key

    sbox_output = ''
    for i in range(8):
        sbox_input = xored[i * 6:(i + 1) * 6]
        row = int(sbox_input[0] + sbox_input[5], 2)  # Row is determined by the outer bits
        col = int(sbox_input[1:5], 2)  # Column is determined by the middle 4 bits
        sbox_value = S_BOXES[i][row][col]
        sbox_output += format(sbox_value, '04b')  # Convert the S-box output to binary

    return ''.join([sbox_output[i - 1] for i in P_TABLE])  # Apply permutation P

# XOR two binary strings
def xor(bin1, bin2):
    return ''.join(['0' if b1 == b2 else '1' for b1, b2 in zip(bin1, bin2)])

# Encrypt a single 64-bit block
def des_encrypt_block(block, round_keys):
    block = initial_permutation(block)  # Apply initial permutation
    left, right = block[:32], block[32:]

    for i in range(16):
        new_right = xor(left, feistel_function(right, round_keys[i]))
        left = right
        right = new_right

    combined = right + left  # Swap halves after the 16 rounds
    return final_permutation(combined)  # Apply final permutation

# Decrypt a single 64-bit block (same as encryption but with reversed round keys)
def des_decrypt_block(block, round_keys):
    block = initial_permutation(block)  # Apply initial permutation
    left, right = block[:32], block[32:]

    for i in range(15, -1, -1):  # Reverse order of round keys for decryption
        new_right = xor(left, feistel_function(right, round_keys[i]))
        left = right
        right = new_right

    combined = right + left  # Swap halves
    return final_permutation(combined)  # Apply final permutation

# Pad the text to ensure it fits into 64-bit blocks
def pad_text(text):
    padding_length = 8 - (len(text) % 8)
    return text + (chr(padding_length) * padding_length)

# Unpad the decrypted text to get the original message
def unpad_text(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

# DES encryption on a file
def des_encrypt_file(key, input_file, output_file):
    key_64bit = hex_to_bin(key) if len(key) == 16 else dec_to_bin(key)
    round_keys = key_schedule(key_64bit)  # Generate round keys

    with open(input_file, 'r') as f:
        plaintext = f.read()

    padded_plaintext = pad_text(plaintext)
    binary_plaintext = text_to_bin(padded_plaintext)

    cipher_binary = ''
    for i in range(0, len(binary_plaintext), 64):
        block = binary_plaintext[i:i + 64]
        cipher_binary += des_encrypt_block(block, round_keys)

    cipher_hex = bin_to_hex(cipher_binary)

    with open(output_file, 'w') as f:
        f.write(cipher_hex)

    print(f"Encryption complete. Ciphertext written to {output_file}")

# DES decryption on a file
def des_decrypt_file(key, input_file, output_file):
    key_64bit = hex_to_bin(key) if len(key) == 16 else dec_to_bin(key)
    round_keys = key_schedule(key_64bit)  # Generate round keys

    with open(input_file, 'r') as f:
        cipher_hex = f.read().strip()

    cipher_binary = hex_to_bin(cipher_hex)  # Convert hex to binary

    decrypted_binary = ''
    for i in range(0, len(cipher_binary), 64):
        block = cipher_binary[i:i + 64]
        decrypted_binary += des_decrypt_block(block, round_keys)

    decrypted_text = bin_to_text(decrypted_binary)
    unpadded_text = unpad_text(decrypted_text)

    with open(output_file, 'w') as f:
        f.write(unpadded_text)

    print(f"Decryption complete. Plaintext written to {output_file}")


def get_mode():
    while True:
        print("\nSelect Operation:")
        print("1. Encrypt")
        print("2. Decrypt")
        mode = input("Please choose an option (1 or 2): ").strip()
        if mode in ['1', '2']:
            return mode
        print("Invalid input. Please enter '1' for Encrypt or '2' for Decrypt.")

def get_key_format():
    while True:
        print("\nSelect Key Format:")
        print("1. Hexadecimal")
        print("2. Decimal")
        key_format = input("Please choose an option (1 or 2): ").strip()
        if key_format in ['1', '2']:
            return key_format
        print("Invalid input. Please enter '1' for Hexadecimal or '2' for Decimal.")

def get_key(key_format):
    while True:
        key = input(f"\nEnter 64-bit {'hexadecimal' if key_format == '1' else 'decimal'} key: ").strip()
        if len(key) == 16 and key_format == '1':  # 16 hex digits for 64 bits
            return key
        elif len(key) == 20 and key_format == '2':  # 64-bit decimal key should have 20 digits max
            return key
        print("Invalid key length. Please enter a valid 64-bit key.")

def list_files():
    print("\nAvailable files in the current directory:")
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    for index, file in enumerate(files, start=1):
        print(f"{index}. {file}")
    return files

def get_file_names():
    files = list_files()
    print("\nEnter the number of the file you want to use, or type the full file name:")
    choice = input("Your choice: ").strip()
    
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        input_file = files[int(choice) - 1]
    else:
        input_file = choice  # User entered a file name

    output_file = input("Enter output file name: ").strip()
    return input_file, output_file

# Main function
if __name__ == '__main__':
    mode = get_mode()
    key_format = get_key_format()
    key = get_key(key_format)
    input_file, output_file = get_file_names()

    if mode == '1':
        des_encrypt_file(key, input_file, output_file)
    elif mode == '2':
        des_decrypt_file(key, input_file, output_file)

    print("\nOperation completed successfully.")
