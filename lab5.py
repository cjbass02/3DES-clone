import struct

#FLK Hash (Functional Lightweight Keys)

# Initial hash values
H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Round constants 
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01
]

def right_rotate(value, shift):
    return (value >> shift) | (value << (32 - shift)) & 0xFFFFFFFF

def hash_function(message):
    # Pre-processing
    message = bytearray(message, 'ascii')
    original_length = len(message) * 8
    #Mark beginning of padding (end of message)
    message.append(0x80)
    # pad to multiple of 512
    while (len(message) * 8) % 512 != 448:
        message.append(0)
    message += struct.pack('>Q', original_length)

    # Process message into 512-bit chunks
    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start:chunk_start + 64]
        w = list(struct.unpack('>16L', chunk)) + [0] * 48

        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w  [i - 7] + s1) & 0xFFFFFFFF
        #set all vars equal to starting values
        h_state = H.copy()
        a, b, c, d, e, f, g, h = h_state

    # 10 rounds
    for i in range(10): 
        s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        #choice function makes a choice bit array in to show which bit to take between the original hash value and s1
        ch = (e & f) ^ (~e & g)
        temp1 = (h + s1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF
        h_state[0] = (h_state[0] + a) & 0xFFFFFFFF
        h_state[1] = (h_state[1] + b) & 0xFFFFFFFF
        h_state[2] = (h_state[2] + c) & 0xFFFFFFFF
        h_state[3] = (h_state[3] + d) & 0xFFFFFFFF
        h_state[4] = (h_state[4] + e) & 0xFFFFFFFF
        h_state[5] = (h_state[5] + f) & 0xFFFFFFFF
        h_state[6] = (h_state[6] + g) & 0xFFFFFFFF
        h_state[7] = (h_state[7] + h) & 0xFFFFFFFF

    return ''.join(f'{x:08x}' for x in h_state)

if __name__ == "__main__":
    messages = [
        "Hello, world!",
        "Information Security",
        "Information Security",
        "Information Security!",
    ]

    for msg in messages:
        print(f"Message: {msg}")
        print(f"Hash: {hash_function(msg)}\n")