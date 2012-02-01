/********************************************/
/**** lookup3-based hash for public keys ****/
/********************************************/

/*
 Original source:

 http://www.burtleburtle.net/bob/c/lookup3.c
 lookup3.c, by Bob Jenkins, May 2006, Public Domain.

 I've ripped out just the bits that I needed and made a small custom
 hash function for mapping fixed-length 32-byte keys to 32-bit hashes
 according to the author's instructions.  There's nothing novel here.

*/

#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

#define mix(a,b,c) { \
    a -= c;  a ^= rot(c, 4);  c += b; \
    b -= a;  b ^= rot(a, 6);  a += c; \
    c -= b;  c ^= rot(b, 8);  b += a; \
    a -= c;  a ^= rot(c,16);  c += b; \
    b -= a;  b ^= rot(a,19);  a += c; \
    c -= b;  c ^= rot(b, 4);  b += a; \
}

#define final(a,b,c) { \
    c ^= b; c -= rot(b,14); \
    a ^= c; a -= rot(c,11); \
    b ^= a; b -= rot(a,25); \
    c ^= b; c -= rot(b,16); \
    a ^= c; a -= rot(c,4);  \
    b ^= a; b -= rot(a,14); \
    c ^= b; c -= rot(b,24); \
}

static uint32_t pubkey_lookup3(const uint32_t* pubkey, uint32_t salt) {
    uint32_t a, b, c;

    a = b = c = salt;
    a += pubkey[0];
    b += pubkey[1];
    c += pubkey[2];
    mix(a,b,c);
    a += pubkey[3];
    b += pubkey[4];
    c += pubkey[5];
    mix(a,b,c);
    a += pubkey[6];
    b += pubkey[7];
    final(a,b,c);
    return c;
}
