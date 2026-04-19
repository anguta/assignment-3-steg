from bitstring import BitArray

def bytes_to_bits(data):
    result = []
    for b in BitArray(bytes=data).bin:
        result.append(int(b))
    return result

def bits_to_bytes(bits):
    while len(bits) % 8:
        bits.append(0)
    return BitArray(bin=''.join(str(b) for b in bits)).bytes

def encode(P, M, S, L, C):
    if not C:
        C = [L]

    p = bytes_to_bits(P)
    m = bytes_to_bits(M)
    message_header = [int(b) for b in format(len(m), '032b')] + m

    if len(message_header) > (len(p) - S) // max(C):
        raise ValueError("use a larger file or smaller message")

    result = list(p)
    bit_position = S

    for i, bit in enumerate(message_header):
        val = i % len(C)
        L = C[val]
        bit_position += L
        if bit_position >= len(result):
            raise ValueError("use a larger file or smaller message")
        result[bit_position] = bit

    return bits_to_bytes(result)

def decode(stego, S, L, C):
    if not C:
        C = [L]

    bits = bytes_to_bits(stego)
    result = []
    bit_position = S

    for i in range(32):
        val = i % len(C)
        L = C[val]
        bit_position += L
        if bit_position >= len(bits):
            raise ValueError("double check S, L and C values")
        result.append(bits[bit_position])

    binary_string = ''
    for b in result:
        binary_string += str(b)
    m_len = int(binary_string, 2)

    for i in range(32, 32 + m_len):
        val = i % len(C)
        L = C[val]
        bit_position += L
        if bit_position >= len(bits):
            raise ValueError("double check S, L and C values")
        result.append(bits[bit_position])

    return bits_to_bytes(result[32:])