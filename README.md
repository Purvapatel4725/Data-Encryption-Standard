# Data-Encryption-Standard

This repository contains a Python implementation of the **Data Encryption Standard (DES)** algorithm, designed to encrypt and decrypt files using a 64-bit key. The DES algorithm operates on 64-bit blocks of data and uses a symmetric key encryption method. This tool allows you to encrypt plaintext files and decrypt ciphertext files securely.

## Features
- Encryption and decryption of files using DES.
- Accepts 64-bit keys in both hexadecimal and decimal formats.
- Text padding and unpadding for proper 64-bit block alignment.
- Key scheduling and round function implementation based on DES standards.
- Supports both encryption and decryption modes.

## Installation
1. Clone the repository to your local machine:
    ```bash
    git clone https://github.com/your-username/DES-Encryption-Utility.git
    cd Data-Encryption-Standard
    ```

2. Install the required dependencies:
    The code requires no external dependencies beyond Python's standard libraries. However, ensure you have Python 3.x installed.

## Usage
1. Run the `des_encrypt_file()` or `des_decrypt_file()` function as required through the command-line interface.
2. The tool operates on text files, so ensure your input files are readable plaintext files.

### Encryption
To encrypt a file, run:
```bash
python des_utility.py
```
You will be prompted to:
- Choose the operation: Encryption or Decryption
- Select the key format (Hexadecimal or Decimal)
- Enter a valid 64-bit key
- Provide the input and output file names

### Decryption
To decrypt a file, run the same command:
```bash
python des_utility.py
```
This time, choose the decryption option, and the rest of the process follows similarly.

## Options
### Key Formats
- **Hexadecimal (16 characters)**: A hexadecimal string that represents the 64-bit key. Example: `A1B2C3D4E5F6G789`
- **Decimal (20 digits)**: A 64-bit decimal key with a maximum of 20 digits. Example: `12345678901234567890`

### File Input and Output
The script will list all the files available in the current directory. You can either select a file by its number or manually enter the file name.

## Helper Functions
The tool includes several helper functions to handle various parts of the DES process:
- **hex_to_bin**: Converts a hexadecimal string to binary.
- **bin_to_hex**: Converts binary to hexadecimal.
- **dec_to_bin**: Converts a decimal string to binary.
- **text_to_bin**: Converts a text string to binary, ensuring proper block size.
- **bin_to_text**: Converts binary data back into text.
- **initial_permutation**: Applies the initial permutation to the 64-bit block.
- **final_permutation**: Applies the final permutation after all DES rounds.
- **key_schedule**: Generates 16 round keys from the initial key.
- **feistel_function**: The round function used in DES, including expansion, XOR, and S-box operations.
- **xor**: XORs two binary strings.
- **pad_text**: Adds padding to ensure the text length is a multiple of 8 bytes.
- **unpad_text**: Removes padding from decrypted text.

## Example
Here is an example workflow for using the tool:

1. You have a plaintext file named `message.txt` and a 64-bit hexadecimal key `A1B2C3D4E5F6A7B8`.
2. Run the script and select "Encrypt" as the operation.
3. Enter the key format as `Hexadecimal`, and provide the key `A1B2C3D4E5F6A7B8`.
4. Choose the input file as `message.txt` and provide an output file name such as `cipher.txt`.
5. The file will be encrypted, and the result will be saved in `cipher.txt`.

To decrypt:
1. Select "Decrypt" as the operation.
2. Provide the same key used for encryption.
3. Input the encrypted file `cipher.txt` and provide an output file name, such as `decrypted_message.txt`.

The decrypted file should match the original plaintext.

## License
This project is licensed under the MIT License. You are free to use, modify, and distribute this code, but the author holds no responsibility for illegal or unethical usage.

---

Feel free to adjust the license section if you prefer a different licensing model! Let me know if you need more specific details added.
