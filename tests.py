import ctypes

# Load the shared library
rijndael = ctypes.CDLL('./rijndael.so')

# Define the required C functions
expand_key = rijndael.expand_key
expand_key.restype = ctypes.POINTER(ctypes.c_ubyte * 176)

# Define the required C function for encryption
encrypt = rijndael.aes_encrypt_block
encrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte * 176), ctypes.POINTER(
    ctypes.c_ubyte * 16)]

# Define a function to print the key


def print_expanded_key(expanded_key):
    print("Expanded Key:")
    for i in range(176):
        print(hex(expanded_key.contents[i]), end=' ')
        if (i + 1) % 16 == 0:
            print()


# Define test parameters
plaintexts = [
    b'\x32\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x07\x34']
keys = [b'\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C']

# Test with different plaintexts and keys
for key in keys:
    print("Key:")
    print(key)
    expanded_key = expand_key(key)
    print_expanded_key(expanded_key)

    for plaintext in plaintexts:
        # Pad the plaintext if necessary
        padded_plaintext = plaintext.ljust(16, b'\0')

        # Define the plaintext as a ctypes array
        plaintext_array = (ctypes.c_ubyte * 16)()
        for i in range(16):
            plaintext_array[i] = padded_plaintext[i]

        # Call the C function to encrypt the plaintext
        ciphertext = encrypt(expanded_key, plaintext_array)

    # Call the C function to encrypt the plaintext
        ciphertext_ptr = encrypt(expanded_key, plaintext_array)

        # Interpret the pointer as a byte array
        ciphertext_bytes = ctypes.cast(
            ciphertext_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents

        # Print the plaintext and ciphertext
        print("Plaintext:")
        for byte in padded_plaintext:
            print(hex(byte), end=' ')
        print("\nCiphertext:")
        for byte in ciphertext_bytes:
            print(hex(byte), end=' ')
        print()

        # Validate the ciphertext (assertion)
        expected_ciphertext = b'\x10\xca\x9b\xc6\xa3\xc8\x62\xae\x2d\x32\x55\x81\x9d\x87\x1f\x98'
        hex_expected_ciphertext = bytearray(expected_ciphertext)
        # ' '.join(
        # [hex(byte) for byte in expected_ciphertext])
        print("Expected Ciphertext:")
        print(expected_ciphertext)
        if (ciphertext_bytes == hex_expected_ciphertext):
            print("Assertion Passed: Ciphertext matches expected value ")
            print()
        else:
            print("Assertion Failed: Ciphertext does not match expected value")
            print()
