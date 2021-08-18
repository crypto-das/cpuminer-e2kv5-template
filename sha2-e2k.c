#include <stdint.h>
#include <e2kintrin.h>

#define ROTR(x, n)      __builtin_e2k_qpsrcw(x, n)
#define SHIFTR(x, n)    __builtin_e2k_qpsrlw(x, n)

#define Ch(x, y, z)     __builtin_e2k_qplog(0xCA, x, y, z)
#define Maj(x, y, z)    __builtin_e2k_qplog(0xE8, x, y, z)

#define S0(x)           __builtin_e2k_qplog(0x96, ROTR(x, 2), ROTR(x, 13), ROTR(x, 22))
#define S1(x)           __builtin_e2k_qplog(0x96, ROTR(x, 6), ROTR(x, 11), ROTR(x, 25))
#define s0(x)           __builtin_e2k_qplog(0x96, ROTR(x, 7), ROTR(x, 18), SHIFTR(x, 3))
#define s1(x)           __builtin_e2k_qplog(0x96, ROTR(x, 17), ROTR(x, 19), SHIFTR(x, 10))

#define EXTEND_W(i)     W[i] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(W[i - 16], W[i - 7]), __builtin_e2k_qpaddw(s0(W[i - 15]), s1(W[i - 2])))
#define EXTEND_S(i)     S[i] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(S[i - 16], S[i - 7]), __builtin_e2k_qpaddw(s0(S[i - 15]), s1(S[i - 2])))

#define RND(a, b, c, d, e, f, g, h, k) \
	{ \
		t0 = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(h, k), __builtin_e2k_qpaddw(S1(e), Ch(e, f, g))); \
		t1 = __builtin_e2k_qpaddw(S0(a), Maj(a, b, c)); \
		d = __builtin_e2k_qpaddw(d, t0); \
		h  = __builtin_e2k_qpaddw(t0, t1); \
	}

#define RNDr(S_, W_, i) \
	RND(S_[(64 - i) % 8], S_[(65 - i) % 8], \
	    S_[(66 - i) % 8], S_[(67 - i) % 8], \
	    S_[(68 - i) % 8], S_[(69 - i) % 8], \
	    S_[(70 - i) % 8], S_[(71 - i) % 8], \
	    __builtin_e2k_qpaddw(W_[i], sha256_k[i]))

static const uint32_t sha256_k_as_words[4 * 64]  __attribute__((aligned(16))) = {
	0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98, 
    0x71374491, 0x71374491, 0x71374491, 0x71374491, 
    0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 
    0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5,
	0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b, 
    0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1, 
    0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4, 
    0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5,
	0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98, 
    0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01, 
    0x243185be, 0x243185be, 0x243185be, 0x243185be, 
    0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3,
	0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74, 
    0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 
    0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 
    0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174,
	0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 
    0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786, 
    0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 
    0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc,
	0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 
    0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 
    0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 
    0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da,
	0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152, 
    0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d, 
    0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8, 
    0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7,
	0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 
    0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147, 
    0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351, 
    0x14292967, 0x14292967, 0x14292967, 0x14292967,
	0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85, 
    0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 
    0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 
    0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13,
	0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354, 
    0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb, 
    0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 
    0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85,
	0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 
    0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b, 
    0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 
    0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3,
	0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819, 
    0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624, 
    0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585, 
    0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070,
	0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116, 
    0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08, 
    0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c, 
    0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5,
	0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 
    0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 
    0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 
    0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3,
	0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee, 
    0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f, 
    0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814, 
    0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208,
	0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa, 
    0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 
    0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 
    0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2
};
#define sha256_k ((__v2di *) sha256_k_as_words)

static const uint32_t sha256d_hash1_as_words[4 * 16] __attribute__((aligned(16))) = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x80000000, 0x80000000, 0x80000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 
    0x00000100, 0x00000100, 0x00000100, 0x00000100
};
#define sha256d_hash1 ((__v2di *) sha256d_hash1_as_words)

static const uint32_t sha256_h_as_words[4 * 8] __attribute__((aligned(16))) = {
	0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 
    0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 
    0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 
    0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a,
	0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 
    0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 
    0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 
    0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 
};
#define sha256_h ((__v2di *) sha256_h_as_words)


int sha256_use_4way()
{
    return 0;
}

void sha256_init_4way(uint32_t *state)
{
    (void) state;
}

void sha256_transform_4way(uint32_t *state, const uint32_t *block, int swap)
{
    (void) state;
    (void) block;
    (void) swap;
}

void sha256d_ms_4way(__v2di * restrict hash,  __v2di * restrict W, const __v2di * restrict midstate, const __v2di * restrict prehash)
{
    __v2di S[64];
	__v2di t0, t1;
    
	S[18] = W[18];
	S[19] = W[19];
	S[20] = W[20];
	S[22] = W[22];
	S[23] = W[23];
	S[24] = W[24];
	S[30] = W[30];
	S[31] = W[31];

	W[18] = __builtin_e2k_qpaddw(W[18], s0(W[3]));
	W[19] = __builtin_e2k_qpaddw(W[19], W[3]);
	W[20] = __builtin_e2k_qpaddw(W[20], s1(W[18]));
	W[21] = s1(W[19]);
	W[22] = __builtin_e2k_qpaddw(W[22], s1(W[20]));
	W[23] = __builtin_e2k_qpaddw(W[23], s1(W[21]));
	W[24] = __builtin_e2k_qpaddw(W[24], s1(W[22]));
	W[25] = __builtin_e2k_qpaddw(s1(W[23]), W[18]);
	W[26] = __builtin_e2k_qpaddw(s1(W[24]), W[19]);
	W[27] = __builtin_e2k_qpaddw(s1(W[25]), W[20]);
	W[28] = __builtin_e2k_qpaddw(s1(W[26]), W[21]);
	W[29] = __builtin_e2k_qpaddw(s1(W[27]), W[22]);
	W[30] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(W[30], W[23]), s1(W[28]));
	W[31] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(W[31], W[24]), s1(W[29]));
    EXTEND_W(32);
    EXTEND_W(33);
    EXTEND_W(34);
    EXTEND_W(35);
    EXTEND_W(36);
    EXTEND_W(37);
    EXTEND_W(38);
    EXTEND_W(39);
    EXTEND_W(40);
    EXTEND_W(41);
    EXTEND_W(42);
    EXTEND_W(43);
    EXTEND_W(44);
    EXTEND_W(45);
    EXTEND_W(46);
    EXTEND_W(47);
    EXTEND_W(48);
    EXTEND_W(49);
    EXTEND_W(50);
    EXTEND_W(51);
    EXTEND_W(52);
    EXTEND_W(53);
    EXTEND_W(54);
    EXTEND_W(55);
    EXTEND_W(56);
    EXTEND_W(57);
    EXTEND_W(58);
    EXTEND_W(59);
    EXTEND_W(60);
    EXTEND_W(61);
    EXTEND_W(62);
    EXTEND_W(63);
    
    S[0] = prehash[0];
    S[1] = prehash[1];
    S[2] = prehash[2];
    S[3] = prehash[3];
    S[4] = prehash[4];
    S[5] = prehash[5];
    S[6] = prehash[6];
    S[7] = prehash[7];
    
    RNDr(S, W,  3);
	RNDr(S, W,  4);
	RNDr(S, W,  5);
	RNDr(S, W,  6);
	RNDr(S, W,  7);
	RNDr(S, W,  8);
	RNDr(S, W,  9);
	RNDr(S, W, 10);
	RNDr(S, W, 11);
	RNDr(S, W, 12);
	RNDr(S, W, 13);
	RNDr(S, W, 14);
	RNDr(S, W, 15);
	RNDr(S, W, 16);
	RNDr(S, W, 17);
	RNDr(S, W, 18);
	RNDr(S, W, 19);
	RNDr(S, W, 20);
	RNDr(S, W, 21);
	RNDr(S, W, 22);
	RNDr(S, W, 23);
	RNDr(S, W, 24);
	RNDr(S, W, 25);
	RNDr(S, W, 26);
	RNDr(S, W, 27);
	RNDr(S, W, 28);
	RNDr(S, W, 29);
	RNDr(S, W, 30);
	RNDr(S, W, 31);
	RNDr(S, W, 32);
	RNDr(S, W, 33);
	RNDr(S, W, 34);
	RNDr(S, W, 35);
	RNDr(S, W, 36);
	RNDr(S, W, 37);
	RNDr(S, W, 38);
	RNDr(S, W, 39);
	RNDr(S, W, 40);
	RNDr(S, W, 41);
	RNDr(S, W, 42);
	RNDr(S, W, 43);
	RNDr(S, W, 44);
	RNDr(S, W, 45);
	RNDr(S, W, 46);
	RNDr(S, W, 47);
	RNDr(S, W, 48);
	RNDr(S, W, 49);
	RNDr(S, W, 50);
	RNDr(S, W, 51);
	RNDr(S, W, 52);
	RNDr(S, W, 53);
	RNDr(S, W, 54);
	RNDr(S, W, 55);
	RNDr(S, W, 56);
	RNDr(S, W, 57);
	RNDr(S, W, 58);
	RNDr(S, W, 59);
	RNDr(S, W, 60);
	RNDr(S, W, 61);
	RNDr(S, W, 62);
	RNDr(S, W, 63);
    
    S[0] = __builtin_e2k_qpaddw(S[0], midstate[0]);
    S[1] = __builtin_e2k_qpaddw(S[1], midstate[1]);
    S[2] = __builtin_e2k_qpaddw(S[2], midstate[2]);
    S[3] = __builtin_e2k_qpaddw(S[3], midstate[3]);
    S[4] = __builtin_e2k_qpaddw(S[4], midstate[4]);
    S[5] = __builtin_e2k_qpaddw(S[5], midstate[5]);
    S[6] = __builtin_e2k_qpaddw(S[6], midstate[6]);
    S[7] = __builtin_e2k_qpaddw(S[7], midstate[7]);
    
    W[18] = S[18];
	W[19] = S[19];
	W[20] = S[20];
	W[22] = S[22];
	W[23] = S[23];
	W[24] = S[24];
	W[30] = S[30];
	W[31] = S[31];
    
    S[ 8] = sha256d_hash1[ 8];
    S[ 9] = sha256d_hash1[ 9];
    S[10] = sha256d_hash1[10];
    S[11] = sha256d_hash1[11];
    S[12] = sha256d_hash1[12];
    S[13] = sha256d_hash1[13];
    S[14] = sha256d_hash1[14];
    S[15] = sha256d_hash1[15];
    
    S[16] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(sha256d_hash1[14]), sha256d_hash1[ 9]), __builtin_e2k_qpaddw(s0(S[ 1]), S[ 0]));
	S[17] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(sha256d_hash1[15]), sha256d_hash1[10]), __builtin_e2k_qpaddw(s0(S[ 2]), S[ 1]));
	S[18] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[16]), sha256d_hash1[11]), __builtin_e2k_qpaddw(s0(S[ 3]), S[ 2]));
	S[19] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[17]), sha256d_hash1[12]), __builtin_e2k_qpaddw(s0(S[ 4]), S[ 3]));
	S[20] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[18]), sha256d_hash1[13]), __builtin_e2k_qpaddw(s0(S[ 5]), S[ 4]));
	S[21] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[19]), sha256d_hash1[14]), __builtin_e2k_qpaddw(s0(S[ 6]), S[ 5]));
	S[22] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[20]), sha256d_hash1[15]), __builtin_e2k_qpaddw(s0(S[ 7]), S[ 6]));
	S[23] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[21]), S[16]), __builtin_e2k_qpaddw(s0(sha256d_hash1[ 8]), S[ 7]));
	S[24] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[22]), S[17]), __builtin_e2k_qpaddw(s0(sha256d_hash1[ 9]), sha256d_hash1[ 8]));
	S[25] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[23]), S[18]), __builtin_e2k_qpaddw(s0(sha256d_hash1[10]), sha256d_hash1[ 9]));
	S[26] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[24]), S[19]), __builtin_e2k_qpaddw(s0(sha256d_hash1[11]), sha256d_hash1[10]));
	S[27] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[25]), S[20]), __builtin_e2k_qpaddw(s0(sha256d_hash1[12]), sha256d_hash1[11]));
	S[28] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[26]), S[21]), __builtin_e2k_qpaddw(s0(sha256d_hash1[13]), sha256d_hash1[12]));
	S[29] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[27]), S[22]), __builtin_e2k_qpaddw(s0(sha256d_hash1[14]), sha256d_hash1[13]));
	S[30] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[28]), S[23]), __builtin_e2k_qpaddw(s0(sha256d_hash1[15]), sha256d_hash1[14]));
	S[31] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(s1(S[29]), S[24]), __builtin_e2k_qpaddw(s0(S[16])            , sha256d_hash1[15]));
	
    
    EXTEND_S(32);
    EXTEND_S(33);
    EXTEND_S(34);
    EXTEND_S(35);
    EXTEND_S(36);
    EXTEND_S(37);
    EXTEND_S(38);
    EXTEND_S(39);
    EXTEND_S(40);
    EXTEND_S(41);
    EXTEND_S(42);
    EXTEND_S(43);
    EXTEND_S(44);
    EXTEND_S(45);
    EXTEND_S(46);
    EXTEND_S(47);
    EXTEND_S(48);
    EXTEND_S(49);
    EXTEND_S(50);
    EXTEND_S(51);
    EXTEND_S(52);
    EXTEND_S(53);
    EXTEND_S(54);
    EXTEND_S(55);
    EXTEND_S(56);
    EXTEND_S(57);
    EXTEND_S(58);
    EXTEND_S(59);
    EXTEND_S(60);
    
    hash[0] = sha256_h[0];
    hash[1] = sha256_h[1];
    hash[2] = sha256_h[2];
    hash[3] = sha256_h[3];
    hash[4] = sha256_h[4];
    hash[5] = sha256_h[5];
    hash[6] = sha256_h[6];
    hash[7] = sha256_h[7];

	RNDr(hash, S,  0);
	RNDr(hash, S,  1);
	RNDr(hash, S,  2);
	RNDr(hash, S,  3);
	RNDr(hash, S,  4);
	RNDr(hash, S,  5);
	RNDr(hash, S,  6);
	RNDr(hash, S,  7);
	RNDr(hash, S,  8);
	RNDr(hash, S,  9);
	RNDr(hash, S, 10);
	RNDr(hash, S, 11);
	RNDr(hash, S, 12);
	RNDr(hash, S, 13);
	RNDr(hash, S, 14);
	RNDr(hash, S, 15);
	RNDr(hash, S, 16);
	RNDr(hash, S, 17);
	RNDr(hash, S, 18);
	RNDr(hash, S, 19);
	RNDr(hash, S, 20);
	RNDr(hash, S, 21);
	RNDr(hash, S, 22);
	RNDr(hash, S, 23);
	RNDr(hash, S, 24);
	RNDr(hash, S, 25);
	RNDr(hash, S, 26);
	RNDr(hash, S, 27);
	RNDr(hash, S, 28);
	RNDr(hash, S, 29);
	RNDr(hash, S, 30);
	RNDr(hash, S, 31);
	RNDr(hash, S, 32);
	RNDr(hash, S, 33);
	RNDr(hash, S, 34);
	RNDr(hash, S, 35);
	RNDr(hash, S, 36);
	RNDr(hash, S, 37);
	RNDr(hash, S, 38);
	RNDr(hash, S, 39);
	RNDr(hash, S, 40);
	RNDr(hash, S, 41);
	RNDr(hash, S, 42);
	RNDr(hash, S, 43);
	RNDr(hash, S, 44);
	RNDr(hash, S, 45);
	RNDr(hash, S, 46);
	RNDr(hash, S, 47);
	RNDr(hash, S, 48);
	RNDr(hash, S, 49);
	RNDr(hash, S, 50);
	RNDr(hash, S, 51);
	RNDr(hash, S, 52);
	RNDr(hash, S, 53);
	RNDr(hash, S, 54);
	RNDr(hash, S, 55);
	RNDr(hash, S, 56);
    
    hash[2] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(__builtin_e2k_qpaddw(hash[2], hash[6]), __builtin_e2k_qpaddw(S1(hash[3]), Ch(hash[3], hash[4], hash[5]))), __builtin_e2k_qpaddw(S[57], sha256_k[57]));
	hash[1] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(__builtin_e2k_qpaddw(hash[1], hash[5]), __builtin_e2k_qpaddw(S1(hash[2]), Ch(hash[2], hash[3], hash[4]))), __builtin_e2k_qpaddw(S[58], sha256_k[58]));
	hash[0] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(__builtin_e2k_qpaddw(hash[0], hash[4]), __builtin_e2k_qpaddw(S1(hash[1]), Ch(hash[1], hash[2], hash[3]))), __builtin_e2k_qpaddw(S[59], sha256_k[59]));
	hash[7] = __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(__builtin_e2k_qpaddw(hash[7], hash[3]), __builtin_e2k_qpaddw(S1(hash[0]), Ch(hash[0], hash[1], hash[2]))), __builtin_e2k_qpaddw(__builtin_e2k_qpaddw(S[60], sha256_k[60]), sha256_h[7]));
}
