
def xor(b1, b2):
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
