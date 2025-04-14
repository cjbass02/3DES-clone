import sys
NUM_ROUNDS = 4


def rotate_left(value, shift, bits):
    """Rotate 'value' left by 'shift' positions over 'bits' bits."""
    return ((value << shift) & ((1 << bits) - 1)) | (value >> (bits - shift))

def permute(block, table, block_size):
    """
    Permute the bits of 'block' (of length block_size) using the provided table.
    The table entries are 1-indexed positions.
    """
    bits = format(block, '0{}b'.format(block_size))
    permuted = ''.join(bits[i - 1] for i in table)
    return int(permuted, 2)

def initial_permutation(block):
    """
    A simple initial permutation: reverse the order of the 64 bits.
    (This is only for demonstration and is self-inverse.)
    """
    bits = format(block, '064b')
    reversed_bits = bits[::-1]
    return int(reversed_bits, 2)

def final_permutation(block):
    """
    The final permutation is the inverse of the initial permutation.
    (Reversing the bits again restores the original order.)
    """
    bits = format(block, '064b')
    reversed_bits = bits[::-1]
    return int(reversed_bits, 2)

# --- S-box and P-box Definitions ---

# Define a simple 4-bit S-box.
# This S-box maps 4-bit inputs (0-15) to 4-bit outputs.
S_BOX = [14, 4, 13, 1,
         2, 15, 11, 8,
         3, 10, 6, 12,
         5, 9, 0, 7]

# 32-bit P-box
P_BOX = [16, 7, 20, 21,
         29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2, 8, 24, 14,
         32, 27, 3, 9,
         19, 13, 30, 6,
         22, 11, 4, 25]


def generate_round_keys(key):
    """
    Generate a 32-bit round key for each round.
    We rotate the 64-bit key by (i*7)%64 and take the lower 32 bits.
    """
    round_keys = []
    for i in range(NUM_ROUNDS):
        rotated = rotate_left(key, (i * 7) % 64, 64)
        round_key = rotated & 0xFFFFFFFF  # extract lower 32 bits
        round_keys.append(round_key)
    return round_keys


def f_function(R, round_key):
    """
    The round function operates on a 32-bit input R.
    1. XOR R with a 32-bit round key.
    2. Split the result into eight 4-bit chunks.
    3. Substitute each 4-bit nibble using the S-box.
    4. Recombine the eight 4-bit outputs into a 32-bit word.
    5. Permute the 32 bits using the P-box.
    """
    # Key mixing
    x = R ^ round_key

    # S-box substitution:
    s_output = 0
    for i in range(8):
        # Extract 4 bits; start from the left (most significant nibble)
        shift = (7 - i) * 4
        nibble = (x >> shift) & 0xF
        substituted = S_BOX[nibble]
        s_output = (s_output << 4) | substituted

    # Apply P-box permutation on the 32-bit s_output
    p_output = permute(s_output, P_BOX, 32)
    return p_output

# --- Encryption and Decryption (Feistel Structure) ---

def encrypt(plaintext, key):
    """
    Encrypt a 64-bit plaintext using a 64-bit key.
    Steps:
      1. Apply an initial permutation.
      2. Split the block into left (L) and right (R) 32-bit halves.
      3. For each round, compute:
             temp = R
             R = L XOR f_function(R, round_key)
             L = temp
      4. Combine the halves in swapped order.
      5. Apply a final permutation.
    """
    # Initial permutation
    block = initial_permutation(plaintext)
    
    # Split into 32-bit halves
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF
    
    # Generate round keys
    round_keys = generate_round_keys(key)
    
    # Feistel rounds
    for rk in round_keys:
        temp = R
        R = L ^ f_function(R, rk)
        L = temp
    
    # Combine halves in swapped order (this swap is conventional for Feistel ciphers)
    combined = (R << 32) | L
    
    # Final permutation
    ciphertext = final_permutation(combined)
    return ciphertext

def decrypt(ciphertext, key):
    # Apply the same initial permutation as in encryption.
    block = initial_permutation(ciphertext)
    # Recall: Encryption did combined = (R << 32) | L, so:
    R = (block >> 32) & 0xFFFFFFFF  # This is R_n
    L = block & 0xFFFFFFFF          # This is L_n

    round_keys = generate_round_keys(key)

    # Decryption: process rounds in reverse order.
    for rk in reversed(round_keys):
        new_R = L                  # R_{i-1} = L_i
        new_L = R ^ f_function(L, rk)  # L_{i-1} = R_i XOR f(L_i, K_i)
        R, L = new_R, new_L

    # Now (L, R) should be (L_0, R_0) as originally split.
    combined = (L << 32) | R
    plaintext = final_permutation(combined)
    return plaintext

def run_tests():
    test_cases = [
        (0xFEDCBA9876543210, 0x0F1571C947D9E859),
        (0x0123456789ABCDEF, 0xFEDCBA9876543210),
        (0xAABBCCDDEEFF0011, 0x1122334455667788)
    ]
    
    for pt, key in test_cases:
        print("\nTest Plaintext:  {:016X}".format(pt))
        print("Test Key:        {:016X}".format(key))
        ct = encrypt(pt, key)
        print("Ciphertext:      {:016X}".format(ct))
        decrypted = decrypt(ct, key)
        print("Decrypted:       {:016X}".format(decrypted))
        if decrypted == pt:
            print("Test Passed!")
        else:
            print("Test Failed!")

def main():
    print("Select an option:")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Run Test")
    choice = input("Enter choice: ").strip()
    
    if choice == "1":
        plaintext_str = input("Enter 64-bit plaintext in hex (e.g., 0123456789ABCDEF): ").strip()
        key_str = input("Enter 64-bit key in hex (e.g., 0F1571C947D9E859): ").strip()
        try:
            plaintext = int(plaintext_str, 16)
            key = int(key_str, 16)
        except ValueError:
            print("Invalid hexadecimal input.")
            sys.exit(1)
        ciphertext = encrypt(plaintext, key)
        print("Ciphertext: {:016X}".format(ciphertext))
        
    elif choice == "2":
        ciphertext_str = input("Enter 64-bit ciphertext in hex: ").strip()
        key_str = input("Enter 64-bit key in hex: ").strip()
        try:
            ciphertext = int(ciphertext_str, 16)
            key = int(key_str, 16)
        except ValueError:
            print("Invalid hexadecimal input.")
            sys.exit(1)
        plaintext = decrypt(ciphertext, key)
        print("Plaintext: {:016X}".format(plaintext))
        
    elif choice == "3":
        run_tests()
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
