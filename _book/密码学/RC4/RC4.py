from binascii import*
def KSA(key):
    keyLength = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keyLength]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S,Len):
    i = 0
    j = 0
    keystream = []
    for _ in range(Len):
        i = (i+1)%256
        j = (j+S[i]) %256
        S[i],S[j] = S[j],S[i]
        k = S[(S[i]+S[j])%256]
        keystream.append(k)
    return keystream

def Xor(plaintext,keystream):
    c = ''
    for i in range(len(plaintext)):
        c += chr(ord(plaintext[i]) ^ keystream[i])
    return c

def RC4(key,plaintext):
    key = [ord(c) for c in key]
    S = KSA(key)
    keystream = PRGA(S,len(plaintext))
    c = Xor(plaintext,keystream)
    return str2byte(c).decode()

def str2byte(c):
    re = b''
    for i in c:
        re += b'%02x'%ord(i)
    return re
def byte2str(c):
    re = ''
    for i in c:
        re += chr(i)
    return re

if __name__ == '__main__':
    choice = 1
    key ='Key'
    if choice == 0:
        plaintext = 'Plaintext'
        c = RC4(key,plaintext)
        print('密文====>'+c)
    elif choice ==1:
        c = b'bbf316e8d940af0ad3'
        c = byte2str(unhexlify(c))
        m = RC4(key,c)
        print('明文====>'+unhexlify(m).decode())


