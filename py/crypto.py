from collections import namedtuple


def xor(b1, b2):
    """xor takes two byte buffers and returns their XOR combination,
    b2 can be shorter in length than b1, if so b2 will repeat"""
    l = len(b1)
    if len(b2) > l:
        raise ValueError("Xor does not accept b2 longer than b1, "
                         "args len(b1)=%d, len(b2)=%d" % (len(b1), len(b2)))
    out = bytearray(l)
    b2Index = 0
    for i in range(0, l):
        out[i] = b1[i] ^ b2[b2Index]
        b2Index += 1
        if b2Index == len(b2):
            b2Index = 0
    return out

# Source http://www.data-compression.com/english.html
letter_frequency = {
    "a": 0.0651738,
    "b": 0.0124248,
    "c": 0.0217339,
    "d": 0.0349835,
    "e": 0.1041442,
    "f": 0.0197881,
    "g": 0.0158610,
    "h": 0.0492888,
    "i": 0.0558094,
    "j": 0.0009033,
    "k": 0.0050529,
    "l": 0.0331490,
    "m": 0.0202124,
    "n": 0.0564513,
    "o": 0.0596302,
    "p": 0.0137645,
    "q": 0.0008606,
    "r": 0.0497563,
    "s": 0.0515760,
    "t": 0.0729357,
    "u": 0.0225134,
    "v": 0.0082903,
    "w": 0.0171272,
    "x": 0.0013692,
    "y": 0.0145984,
    "z": 0.0007836,
    " ": 0.1918182,
}

Result = namedtuple("Result", ["plaintext", "cipher", "score"])


def bruteforce_xor(b_in):
    """bruteforce_xor searches for a single character XOR cypher that yields
    the most likely plaintext by trying all possible single character
    ciphers"""
    top_result = Result("", bytes(1), 0)
    for i in range(0, 128):
        cipher = bytes([i])
        try:
            plaintext = xor(b_in, cipher).decode("ascii")
        except UnicodeDecodeError:
            continue
        score = score_plaintext(plaintext)
        if score > top_result.score:
            top_result = Result(
                plaintext=plaintext,
                cipher=cipher,
                score=score_plaintext(plaintext)
            )
    return top_result


def score_plaintext(s):
    """score_plaintext scores a string for confidence that is plaintext,
    the higher the score, the higher the confidence"""
    return sum([letter_frequency.get(c, 0) for c in s])


def break_repeating_key_xor(b):
    keysize, distance = determine_keysize(b)
    print("Likely keysize %d has normalised hamming distance of %f\n" %
         (keysize, distance))

    # break data into keysize blocks of len keysize
    blocks = [b[i*keysize:(i+1)*keysize] for i in range(0, keysize)]

    # transpose blocks so each block is composed of ciphertext encrypted with
    # the same key of the cipher
    transposed = []
    for i in range(keysize):
        block = bytearray(keysize)
        for j in range(keysize):
            block[j] = blocks[j][i]
        transposed.append(block)

    # bruteforce each cipher character using the block of ciphertext
    # encrypted by that cipher character
    cipher = bytes()
    for block in transposed:
        cipher += bruteforce_xor(block).cipher
    return xor(b, cipher)


def determine_keysize(b):
    """ determine_keysize determines the likely keysize of an encryption cypher
    given the encrypted data b. It also returns normalised difference of the
    blocks of size keysize, this can be considered a sort of confidence, the
    lower the better"""
    shortest_distance = 1000.0
    likely_keysize = -1
    for keysize in range(2, 41):
        distance = hamming_distance(
            b[:keysize],
            b[keysize:keysize*2],
            b[keysize*2:keysize*3],
            b[keysize*3:keysize*4])
        normalised_distance = distance / keysize
        if normalised_distance < shortest_distance:
            shortest_distance = normalised_distance
            likely_keysize = keysize
    return likely_keysize, shortest_distance


def hamming_distance(*bs):
    if len(bs) < 2:
        raise ValueError("hamming_distance called with only " +
                         "%d args, requires at least 2" % len(bs))

    total = 0.0
    num_iter = 0.0
    for i in range(0, len(bs)):
        for j in range(i+1, len(bs)):
            dist = hamming_distance_impl(bs[i], bs[j])
            #print("%d %d has distance of %d\n" % (i, j, dist))
            total += dist
            num_iter += 1
    total /= num_iter  # normalise
    return total


def hamming_distance_impl(b1, b2):
    if len(b1) != len(b2):
        raise ValueError("hamming_distance_impl called with different " +
                         "length buffers len(b1)=%d, len(b2)=%d" %
                         (len(b1), len(b2)))

    total = 0
    for i in range(0, len(b1)):
        # xor args, thus val represents the number of bits set
        val = b1[i] ^ b2[i]

        # increment total by one and clear a bit
        while val != 0:
            total += 1
            val &= val-1

    return total
