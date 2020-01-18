
import struct
import sys
import operator

block_size = 16
key_size = 32

class Twofish:
    
    def __init__(self, key=None):
        """Twofish."""

        if key:
            self.key_func(key)


    def key_func(self, key):
        """Init."""
        
        keyLength = len(key)
        if keyLength not in [16, 24, 32]:
            
            #raise KeyError, "key 16, 24 ya da 32 byte olmali."
            if len(key)<16:
                while len(key)%16!=0:
                    key+="."
            elif len(key)>16 and len(key)<24:
                while len(key)%24!=0:
                    key+="."
            else:
                while len(key)%32!=0:
                    key+="."
            keyLength=len(key)
        if keyLength % 4:
            raise KeyError, "key 4'un kati degil"
        if keyLength > 32:
            raise KeyError, "keyLength > 32"
        
        self.context = TWI()
        
        key_32 = [0] * 32
        i = 0
        while key:
            key_32[i] = struct.unpack("<L", key[0:4])[0]
            key = key[4:]
            i += 1

        key_func(self.context, key_32, keyLength)

        
    def decrypt(self, block):
        """Bloklari cozer"""
        
        if len(block) % 16:
            raise ValueError, "blok size 16'nin katlari olmali."
        plaintext = ''
        
        while block:
            a, b, c, d = struct.unpack("<4L", block[:16])
            temp = [a, b, c, d]
            decrypt(self.context, temp)
            plaintext += struct.pack("<4L", *temp)
            block = block[16:]
            
        return plaintext

        
    def encrypt(self, block):
        """Bloklari sifreler"""

        if len(block) % 16:
            raise ValueError, "blok size 16'nin katlari olmali."

        ciphertext = ''
        
        while block:
            a, b, c, d = struct.unpack("<4L", block[0:16])
            temp = [a, b, c, d]
            encrypt(self.context, temp)
            ciphertext += struct.pack("<4L", *temp)
            block = block[16:]
            
        return ciphertext


WORD_BIGENDIAN = 0
if sys.byteorder == 'big':
    WORD_BIGENDIAN = 1

def rotateright32(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)

def rotateleft32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def byte_swap(x):
    return ((x & 0xff) << 24) | (((x >> 8) & 0xff) << 16) | \
           (((x >> 16) & 0xff) << 8) | ((x >> 24) & 0xff)

class TWI:
    def __init__(self):
        self.k_len = 0 # word32
        self.l_key = [0]*40 # word32
        self.s_key = [0]*4 # word32
        self.qt_generate = 0 # word32
        self.q_tab = [[0]*256, [0]*256] # byte
        self.mt_genrt = 0 # word32
        self.m_tab = [[0]*256, [0]*256, [0]*256, [0]*256] # word32
        self.mk_tab = [[0]*256, [0]*256, [0]*256, [0]*256] # word32

def byte(x, n):
    return (x >> (8 * n)) & 0xff

tab_5b = [0, 90, 180, 238]
tab_ef = [0, 238, 180, 90]
rotr4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]
qt0 = [[8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
       [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5]]
qt1 = [[14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
       [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8]]
qt2 = [[11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
       [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15]]
qt3 = [[13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
       [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10]]

def qp(n, x): # word32, byte
    n %= 0x100000000
    x %= 0x100
    a0 = x >> 4;
    b0 = x & 15;
    a1 = a0 ^ b0;
    b1 = rotr4[b0] ^ ashx[a0];
    a2 = qt0[n][a1];
    b2 = qt1[n][b1];
    a3 = a2 ^ b2;
    b3 = rotr4[b2] ^ ashx[a2];
    a4 = qt2[n][a3];
    b4 = qt3[n][b3];
    return (b4 << 4) | a4;

def generate_qtab(gkey):
    for i in xrange(256):
        gkey.q_tab[0][i] = qp(0, i)
        gkey.q_tab[1][i] = qp(1, i)
        
def generate_mtab(gkey):
    for i in xrange(256):
        f01 = gkey.q_tab[1][i]
        f01 = gkey.q_tab[1][i];
        f5b = ((f01) ^ ((f01) >> 2) ^ tab_5b[(f01) & 3]);
        fef = ((f01) ^ ((f01) >> 1) ^ ((f01) >> 2) ^ tab_ef[(f01) & 3]);
        gkey.m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
        gkey.m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);

        f01 = gkey.q_tab[0][i];
        f5b = ((f01) ^ ((f01) >> 2) ^ tab_5b[(f01) & 3]);
        fef = ((f01) ^ ((f01) >> 1) ^ ((f01) >> 2) ^ tab_ef[(f01) & 3]);
        gkey.m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
        gkey.m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);

def generate_mk_tab(gkey, key):
    if gkey.k_len == 2:
        for i in xrange(256):
            by = i % 0x100
            gkey.mk_tab[0][i] = gkey.m_tab[0][gkey.q_tab[0][gkey.q_tab[0][by] ^ byte(key[1],0)] ^ byte(key[0],0)];
            gkey.mk_tab[1][i] = gkey.m_tab[1][gkey.q_tab[0][gkey.q_tab[1][by] ^ byte(key[1],1)] ^ byte(key[0],1)];
            gkey.mk_tab[2][i] = gkey.m_tab[2][gkey.q_tab[1][gkey.q_tab[0][by] ^ byte(key[1],2)] ^ byte(key[0],2)];
            gkey.mk_tab[3][i] = gkey.m_tab[3][gkey.q_tab[1][gkey.q_tab[1][by] ^ byte(key[1],3)] ^ byte(key[0],3)];
    if gkey.k_len == 3:
        for i in xrange(256):
            by = i % 0x100
            gkey.mk_tab[0][i] = gkey.m_tab[0][gkey.q_tab[0][gkey.q_tab[0][gkey.q_tab[1][by] ^ byte(key[2], 0)] ^ byte(key[1], 0)] ^ byte(key[0], 0)];
            gkey.mk_tab[1][i] = gkey.m_tab[1][gkey.q_tab[0][gkey.q_tab[1][gkey.q_tab[1][by] ^ byte(key[2], 1)] ^ byte(key[1], 1)] ^ byte(key[0], 1)];
            gkey.mk_tab[2][i] = gkey.m_tab[2][gkey.q_tab[1][gkey.q_tab[0][gkey.q_tab[0][by] ^ byte(key[2], 2)] ^ byte(key[1], 2)] ^ byte(key[0], 2)];
            gkey.mk_tab[3][i] = gkey.m_tab[3][gkey.q_tab[1][gkey.q_tab[1][gkey.q_tab[0][by] ^ byte(key[2], 3)] ^ byte(key[1], 3)] ^ byte(key[0], 3)];
    if gkey.k_len == 4:
        for i in xrange(256):
            by = i % 0x100
            gkey.mk_tab[0][i] = gkey.m_tab[0][gkey.q_tab[0][gkey.q_tab[0][gkey.q_tab[1][gkey.q_tab[1][by] ^ byte(key[3], 0)] ^ byte(key[2], 0)] ^ byte(key[1], 0)] ^ byte(key[0], 0)];
            gkey.mk_tab[1][i] = gkey.m_tab[1][gkey.q_tab[0][gkey.q_tab[1][gkey.q_tab[1][gkey.q_tab[0][by] ^ byte(key[3], 1)] ^ byte(key[2], 1)] ^ byte(key[1], 1)] ^ byte(key[0], 1)];
            gkey.mk_tab[2][i] = gkey.m_tab[2][gkey.q_tab[1][gkey.q_tab[0][gkey.q_tab[0][gkey.q_tab[0][by] ^ byte(key[3], 2)] ^ byte(key[2], 2)] ^ byte(key[1], 2)] ^ byte(key[0], 2)];
            gkey.mk_tab[3][i] = gkey.m_tab[3][gkey.q_tab[1][gkey.q_tab[1][gkey.q_tab[0][gkey.q_tab[1][by] ^ byte(key[3], 3)] ^ byte(key[2], 3)] ^ byte(key[1], 3)] ^ byte(key[0], 3)];


def h_function(gkey, x, key): 
    b0 = byte(x, 0);
    b1 = byte(x, 1);
    b2 = byte(x, 2);
    b3 = byte(x, 3);
    if gkey.k_len >= 4:
        b0 = gkey.q_tab[1][b0] ^ byte(key[3], 0);
        b1 = gkey.q_tab[0][b1] ^ byte(key[3], 1);
        b2 = gkey.q_tab[0][b2] ^ byte(key[3], 2);
        b3 = gkey.q_tab[1][b3] ^ byte(key[3], 3);
    if gkey.k_len >= 3:
        b0 = gkey.q_tab[1][b0] ^ byte(key[2], 0);
        b1 = gkey.q_tab[1][b1] ^ byte(key[2], 1);
        b2 = gkey.q_tab[0][b2] ^ byte(key[2], 2);
        b3 = gkey.q_tab[0][b3] ^ byte(key[2], 3);
    if gkey.k_len >= 2:
        b0 = gkey.q_tab[0][gkey.q_tab[0][b0] ^ byte(key[1], 0)] ^ byte(key[0], 0);
        b1 = gkey.q_tab[0][gkey.q_tab[1][b1] ^ byte(key[1], 1)] ^ byte(key[0], 1);
        b2 = gkey.q_tab[1][gkey.q_tab[0][b2] ^ byte(key[1], 2)] ^ byte(key[0], 2);
        b3 = gkey.q_tab[1][gkey.q_tab[1][b3] ^ byte(key[1], 3)] ^ byte(key[0], 3);      
    return gkey.m_tab[0][b0] ^ gkey.m_tab[1][b1] ^ gkey.m_tab[2][b2] ^ gkey.m_tab[3][b3];   

def mds_rem(p0, p1):
    i, t, u = 0, 0, 0
    for i in xrange(8):
        t = p1 >> 24
        p1 = ((p1 << 8) & 0xffffffff) | (p0 >> 24)
        p0 = (p0 << 8) & 0xffffffff
        u = (t << 1) & 0xffffffff
        if t & 0x80:
            u ^= 0x0000014d
        p1 ^= t ^ ((u << 16) & 0xffffffff)
        u ^= (t >> 1)
        if t & 0x01:
            u ^= 0x0000014d >> 1
        p1 ^= ((u << 24) & 0xffffffff) | ((u << 8) & 0xffffffff)
    return p1

def key_func(gkey, in_key, keyLength):
    gkey.qt_generate = 0
    if not gkey.qt_generate:
        generate_qtab(gkey)
        gkey.qt_generate = 1
    gkey.mt_genrt = 0
    if not gkey.mt_genrt:
        generate_mtab(gkey)
        gkey.mt_genrt = 1
    gkey.k_len = (keyLength * 8) / 64

    a = 0
    b = 0
    me_key = [0,0,0,0]
    mo_key = [0,0,0,0]
    for i in xrange(gkey.k_len):
        if WORD_BIGENDIAN:
            a = byte_swap(in_key[i + 1])
            me_key[i] = a            
            b = byte_swap(in_key[i + i + 1])
        else:
            a = in_key[i + i]
            me_key[i] = a            
            b = in_key[i + i + 1]
        mo_key[i] = b
        gkey.s_key[gkey.k_len - i - 1] = mds_rem(a, b);
    for i in xrange(0, 40, 2):
        a = (0x01010101 * i) % 0x100000000;
        b = (a + 0x01010101) % 0x100000000;
        a = h_function(gkey, a, me_key);
        b = rotateleft32(h_function(gkey, b, mo_key), 8);
        gkey.l_key[i] = (a + b) % 0x100000000;
        gkey.l_key[i + 1] = rotateleft32((a + 2 * b) % 0x100000000, 9);
    generate_mk_tab(gkey, gkey.s_key)

def encrypt(gkey, in_blok):
    blok = [0, 0, 0, 0]

    if WORD_BIGENDIAN:
        blok[0] = byte_swap(in_blok[0]) ^ gkey.l_key[0];
        blok[1] = byte_swap(in_blok[1]) ^ gkey.l_key[1];
        blok[2] = byte_swap(in_blok[2]) ^ gkey.l_key[2];
        blok[3] = byte_swap(in_blok[3]) ^ gkey.l_key[3];
    else:
        blok[0] = in_blok[0] ^ gkey.l_key[0];
        blok[1] = in_blok[1] ^ gkey.l_key[1];
        blok[2] = in_blok[2] ^ gkey.l_key[2];
        blok[3] = in_blok[3] ^ gkey.l_key[3];        

    for i in xrange(8):
        t1 = ( gkey.mk_tab[0][byte(blok[1],3)] ^ gkey.mk_tab[1][byte(blok[1],0)] ^ gkey.mk_tab[2][byte(blok[1],1)] ^ gkey.mk_tab[3][byte(blok[1],2)] ); 
        t0 = ( gkey.mk_tab[0][byte(blok[0],0)] ^ gkey.mk_tab[1][byte(blok[0],1)] ^ gkey.mk_tab[2][byte(blok[0],2)] ^ gkey.mk_tab[3][byte(blok[0],3)] );
        
        blok[2] = rotateright32(blok[2] ^ ((t0 + t1 + gkey.l_key[4 * (i) + 8]) % 0x100000000), 1);
        blok[3] = rotateleft32(blok[3], 1) ^ ((t0 + 2 * t1 + gkey.l_key[4 * (i) + 9]) % 0x100000000);

        t1 = ( gkey.mk_tab[0][byte(blok[3],3)] ^ gkey.mk_tab[1][byte(blok[3],0)] ^ gkey.mk_tab[2][byte(blok[3],1)] ^ gkey.mk_tab[3][byte(blok[3],2)] ); 
        t0 = ( gkey.mk_tab[0][byte(blok[2],0)] ^ gkey.mk_tab[1][byte(blok[2],1)] ^ gkey.mk_tab[2][byte(blok[2],2)] ^ gkey.mk_tab[3][byte(blok[2],3)] );
        
        blok[0] = rotateright32(blok[0] ^ ((t0 + t1 + gkey.l_key[4 * (i) + 10]) % 0x100000000), 1);
        blok[1] = rotateleft32(blok[1], 1) ^ ((t0 + 2 * t1 + gkey.l_key[4 * (i) + 11]) % 0x100000000);         

    if WORD_BIGENDIAN:
        in_blok[0] = byte_swap(blok[2] ^ gkey.l_key[4]);
        in_blok[1] = byte_swap(blok[3] ^ gkey.l_key[5]);
        in_blok[2] = byte_swap(blok[0] ^ gkey.l_key[6]);
        in_blok[3] = byte_swap(blok[1] ^ gkey.l_key[7]);
    else:
        in_blok[0] = blok[2] ^ gkey.l_key[4];
        in_blok[1] = blok[3] ^ gkey.l_key[5];
        in_blok[2] = blok[0] ^ gkey.l_key[6];
        in_blok[3] = blok[1] ^ gkey.l_key[7];
        
    return

def decrypt(gkey, in_blok):
    blok = [0, 0, 0, 0]
    
    if WORD_BIGENDIAN:
        blok[0] = byte_swap(in_blok[0]) ^ gkey.l_key[4];
        blok[1] = byte_swap(in_blok[1]) ^ gkey.l_key[5];
        blok[2] = byte_swap(in_blok[2]) ^ gkey.l_key[6];
        blok[3] = byte_swap(in_blok[3]) ^ gkey.l_key[7];
    else:
        blok[0] = in_blok[0] ^ gkey.l_key[4];
        blok[1] = in_blok[1] ^ gkey.l_key[5];
        blok[2] = in_blok[2] ^ gkey.l_key[6];
        blok[3] = in_blok[3] ^ gkey.l_key[7];    

    for i in xrange(7, -1, -1):
        t1 = ( gkey.mk_tab[0][byte(blok[1],3)] ^ gkey.mk_tab[1][byte(blok[1],0)] ^ gkey.mk_tab[2][byte(blok[1],1)] ^ gkey.mk_tab[3][byte(blok[1],2)] )
        t0 = ( gkey.mk_tab[0][byte(blok[0],0)] ^ gkey.mk_tab[1][byte(blok[0],1)] ^ gkey.mk_tab[2][byte(blok[0],2)] ^ gkey.mk_tab[3][byte(blok[0],3)] )

        blok[2] = rotateleft32(blok[2], 1) ^ ((t0 + t1 + gkey.l_key[4 * (i) + 10]) % 0x100000000)
        blok[3] = rotateright32(blok[3] ^ ((t0 + 2 * t1 + gkey.l_key[4 * (i) + 11]) % 0x100000000), 1)

        t1 = ( gkey.mk_tab[0][byte(blok[3],3)] ^ gkey.mk_tab[1][byte(blok[3],0)] ^ gkey.mk_tab[2][byte(blok[3],1)] ^ gkey.mk_tab[3][byte(blok[3],2)] )
        t0 = ( gkey.mk_tab[0][byte(blok[2],0)] ^ gkey.mk_tab[1][byte(blok[2],1)] ^ gkey.mk_tab[2][byte(blok[2],2)] ^ gkey.mk_tab[3][byte(blok[2],3)] )

        blok[0] = rotateleft32(blok[0], 1) ^ ((t0 + t1 + gkey.l_key[4 * (i) + 8]) % 0x100000000)
        blok[1] = rotateright32(blok[1] ^ ((t0 + 2 * t1 + gkey.l_key[4 * (i) + 9]) % 0x100000000), 1)        

    if WORD_BIGENDIAN:
        in_blok[0] = byte_swap(blok[2] ^ gkey.l_key[0]);
        in_blok[1] = byte_swap(blok[3] ^ gkey.l_key[1]);
        in_blok[2] = byte_swap(blok[0] ^ gkey.l_key[2]);
        in_blok[3] = byte_swap(blok[1] ^ gkey.l_key[3]);
    else:
        in_blok[0] = blok[2] ^ gkey.l_key[0];
        in_blok[1] = blok[3] ^ gkey.l_key[1];
        in_blok[2] = blok[0] ^ gkey.l_key[2];
        in_blok[3] = blok[1] ^ gkey.l_key[3];
    return

class TwofishCBC:
    """
    Sifre blogu(cipherblock) zincirleme (CBC) Twofish calisma modu.
    """
    def __init__(self, key, init_vec=0):
        """
        sifreleme icin kullanilacak anahtari ayarlayin ve istege bagli olarak bir baslatma vektoru belirtin.
        """
        self.twofish = Twofish()
        self.twofish.key_func(key)
        self.state = init_vec

    def encrypt(self, plaintext):
        """
        Twofish CBC kullanarak verilen stringi sifreleme islemi.
        """
        if len(plaintext) % 16:
            #raise RuntimeError("Twofish ciphertext uzunlugu 16'nin katlari olmalidir.")
            while len(plaintext)%16!=0:
                plaintext+="."
        ciphertext = ""
        while len(plaintext) >= 16:
            block = self.twofish.encrypt(self._xor_block(plaintext[0:16], self.state))
            ciphertext += block
            plaintext = plaintext[16:]
            self.state = block
        return ciphertext

    def decrypt(self, ciphertext):
        """    
        Twofish CBC kullanarak verilen stringin sifresini cozme islemi.
        """
        if len(ciphertext) % 16:
            raise RuntimeError("Twofish ciphertext uzunlugu 16'nin kati olmalidir.")
        plaintext = ""
        while len(ciphertext) >= 16:
            block = ciphertext[0:16]
            plaintext += self._xor_block(self.twofish.decrypt(block), self.state)
            ciphertext = ciphertext[16:]
            self.state = block
        return plaintext

    @staticmethod
    def _xor_block(text1, text2):
        """
        Iki rastgele(keyfi) uzunluktaki veri bloklarinin bit xor'unu dondur
        """
        return "".join(
                       map(
                           lambda c1, c2: chr(operator.xor(ord(c1), ord(c2))),
                           text1,
                           text2
                           )
                       )



#test_Key = "Kripto fonksiyonlarini test etme islemi"
__testivc = "Initialization V"

test_Key=raw_input("Key:")
plaint=raw_input("Msg:")
cip=TwofishCBC(test_Key,__testivc).encrypt(plaint)
print "Encrypted: "
print "".join("{:02x}".format(ord(c)) for c in TwofishCBC(test_Key,__testivc).encrypt(plaint))
print "Decrypted:"
print TwofishCBC(test_Key,__testivc).decrypt(cip)
