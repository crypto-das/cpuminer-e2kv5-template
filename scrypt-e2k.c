#include <e2kintrin.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>



void sha256_init(uint32_t *state);
void sha256_transform(uint32_t *state, const uint32_t *block, int swap);

static inline uint32_t swab32(uint32_t v)
{
	return __builtin_bswap32(v);
}


static const uint32_t keypad[12] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};
static const uint32_t finalblk[16] = {
	0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static inline void HMAC_SHA256_80_init(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	memcpy(pad, key + 16, 16);
	memcpy(pad + 4, keypad, 48);
	sha256_transform(tstate, pad, 0);
	memcpy(ihash, tstate, 32);

	sha256_init(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform(ostate, pad, 0);

	sha256_init(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	sha256_transform(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
	uint32_t istate[8], ostate2[8];
	uint32_t ibuf[16], obuf[16];
	int i, j;

	memcpy(istate, tstate, 32);
	sha256_transform(istate, salt, 0);
	
	memcpy(ibuf, salt + 16, 16);
	memcpy(ibuf + 5, innerpad, 44);
	memcpy(obuf + 8, outerpad, 32);

	for (i = 0; i < 4; i++) {
		memcpy(obuf, istate, 32);
		ibuf[4] = i + 1;
		sha256_transform(obuf, ibuf, 0);

		memcpy(ostate2, ostate, 32);
		sha256_transform(ostate2, obuf, 0);
		for (j = 0; j < 8; j++)
			output[8 * i + j] = swab32(ostate2[j]);
	}
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate,
	const uint32_t *salt, uint32_t *output)
{
	uint32_t buf[16];
	int i;
	
	sha256_transform(tstate, salt, 1);
	sha256_transform(tstate, salt + 16, 1);
	sha256_transform(tstate, finalblk, 0);
	memcpy(buf, tstate, 32);
	memcpy(buf + 8, outerpad, 32);

	sha256_transform(ostate, buf, 0);
	for (i = 0; i < 8; i++)
		output[i] = swab32(ostate[i]);
}



static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00+x12, 7);	
        x09 ^= R(x05+x01, 7);
		x14 ^= R(x10+x06, 7);	
        x03 ^= R(x15+x11, 7);
		
		x08 ^= R(x04+x00, 9);	
        x13 ^= R(x09+x05, 9);
		x02 ^= R(x14+x10, 9);	
        x07 ^= R(x03+x15, 9);
		
		x12 ^= R(x08+x04,13);	
        x01 ^= R(x13+x09,13);
		x06 ^= R(x02+x14,13);	
        x11 ^= R(x07+x03,13);
		
		x00 ^= R(x12+x08,18);	
        x05 ^= R(x01+x13,18);
		x10 ^= R(x06+x02,18);	
        x15 ^= R(x11+x07,18);
		
		/* Operate on rows. */
		x01 ^= R(x00+x03, 7);	
        x06 ^= R(x05+x04, 7);
		x11 ^= R(x10+x09, 7);	
        x12 ^= R(x15+x14, 7);
		
		x02 ^= R(x01+x00, 9);	
        x07 ^= R(x06+x05, 9);
		x08 ^= R(x11+x10, 9);	
        x13 ^= R(x12+x15, 9);
		
		x03 ^= R(x02+x01,13);	
        x04 ^= R(x07+x06,13);
		x09 ^= R(x08+x11,13);	
        x14 ^= R(x13+x12,13);
		
		x00 ^= R(x03+x02,18);	
        x05 ^= R(x04+x07,18);
		x10 ^= R(x09+x08,18);	
        x15 ^= R(x14+x13,18);
#undef R
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

static inline void scrypt_core(uint32_t *X, uint32_t *V, int N)
{
	uint32_t i, j, k;
	
	for (i = 0; i < N; i++) {
		memcpy(&V[i * 32], X, 32 * 4);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < N; i++) {
		j = 32 * (X[16] & (N - 1));
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
}

#define ROTL(x, n)      __builtin_e2k_qpsrcw(x, 32 - n)
#define XOR(x, y)       __builtin_e2k_qpxor(x, y)
#define AND(x, y)       __builtin_e2k_qpand(x, y)
#define ADD(x, y)       __builtin_e2k_qpaddw(x, y)

#define SALSA_DOUBLEROUND \
		x04 = XOR(x04, ROTL(ADD(x00, x12), 7)); \
        x09 = XOR(x09, ROTL(ADD(x05, x01), 7)); \
		x14 = XOR(x14, ROTL(ADD(x10, x06), 7)); \
        x03 = XOR(x03, ROTL(ADD(x15, x11), 7)); \
		x08 = XOR(x08, ROTL(ADD(x04, x00), 9)); \
        x13 = XOR(x13, ROTL(ADD(x09, x05), 9)); \
		x02 = XOR(x02, ROTL(ADD(x14, x10), 9)); \
        x07 = XOR(x07, ROTL(ADD(x03, x15), 9)); \
		x12 = XOR(x12, ROTL(ADD(x08, x04),13)); \
        x01 = XOR(x01, ROTL(ADD(x13, x09),13)); \
		x06 = XOR(x06, ROTL(ADD(x02, x14),13)); \
        x11 = XOR(x11, ROTL(ADD(x07, x03),13)); \
		x00 = XOR(x00, ROTL(ADD(x12, x08),18)); \
        x05 = XOR(x05, ROTL(ADD(x01, x13),18)); \
		x10 = XOR(x10, ROTL(ADD(x06, x02),18)); \
        x15 = XOR(x15, ROTL(ADD(x11, x07),18)); \
		x01 = XOR(x01, ROTL(ADD(x00, x03), 7)); \
        x06 = XOR(x06, ROTL(ADD(x05, x04), 7)); \
		x11 = XOR(x11, ROTL(ADD(x10, x09), 7)); \
        x12 = XOR(x12, ROTL(ADD(x15, x14), 7)); \
		x02 = XOR(x02, ROTL(ADD(x01, x00), 9)); \
        x07 = XOR(x07, ROTL(ADD(x06, x05), 9)); \
		x08 = XOR(x08, ROTL(ADD(x11, x10), 9)); \
        x13 = XOR(x13, ROTL(ADD(x12, x15), 9)); \
		x03 = XOR(x03, ROTL(ADD(x02, x01),13)); \
        x04 = XOR(x04, ROTL(ADD(x07, x06),13)); \
		x09 = XOR(x09, ROTL(ADD(x08, x11),13)); \
        x14 = XOR(x14, ROTL(ADD(x13, x12),13)); \
		x00 = XOR(x00, ROTL(ADD(x03, x02),18)); \
        x05 = XOR(x05, ROTL(ADD(x04, x07),18)); \
		x10 = XOR(x10, ROTL(ADD(x09, x08),18)); \
        x15 = XOR(x15, ROTL(ADD(x14, x13),18));

#define XOR_SALSA8_EL4WAY(B, Bx) \
{ \
    __v2di x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15; \
    \
	x00 = (B[ 0] = XOR(B[ 0], Bx[ 0])); \
	x01 = (B[ 1] = XOR(B[ 1], Bx[ 1])); \
	x02 = (B[ 2] = XOR(B[ 2], Bx[ 2])); \
	x03 = (B[ 3] = XOR(B[ 3], Bx[ 3])); \
	x04 = (B[ 4] = XOR(B[ 4], Bx[ 4])); \
	x05 = (B[ 5] = XOR(B[ 5], Bx[ 5])); \
	x06 = (B[ 6] = XOR(B[ 6], Bx[ 6])); \
	x07 = (B[ 7] = XOR(B[ 7], Bx[ 7])); \
	x08 = (B[ 8] = XOR(B[ 8], Bx[ 8])); \
	x09 = (B[ 9] = XOR(B[ 9], Bx[ 9])); \
	x10 = (B[10] = XOR(B[10], Bx[10])); \
	x11 = (B[11] = XOR(B[11], Bx[11])); \
	x12 = (B[12] = XOR(B[12], Bx[12])); \
	x13 = (B[13] = XOR(B[13], Bx[13])); \
	x14 = (B[14] = XOR(B[14], Bx[14])); \
	x15 = (B[15] = XOR(B[15], Bx[15])); \
    \
    SALSA_DOUBLEROUND \
    SALSA_DOUBLEROUND \
    SALSA_DOUBLEROUND \
    SALSA_DOUBLEROUND \
    \
	B[ 0] = ADD(B[ 0], x00); \
	B[ 1] = ADD(B[ 1], x01); \
	B[ 2] = ADD(B[ 2], x02); \
	B[ 3] = ADD(B[ 3], x03); \
	B[ 4] = ADD(B[ 4], x04); \
	B[ 5] = ADD(B[ 5], x05); \
	B[ 6] = ADD(B[ 6], x06); \
	B[ 7] = ADD(B[ 7], x07); \
	B[ 8] = ADD(B[ 8], x08); \
	B[ 9] = ADD(B[ 9], x09); \
	B[10] = ADD(B[10], x10); \
	B[11] = ADD(B[11], x11); \
	B[12] = ADD(B[12], x12); \
	B[13] = ADD(B[13], x13); \
	B[14] = ADD(B[14], x14); \
	B[15] = ADD(B[15], x15); \
}

#define SALSA_PACK(input, output) \
{ \
    __v2di tmp[32]; \
    tmp[ 0] = __builtin_e2k_qppermb(input[ 8], input[ 0], words_02_perm); \
    tmp[ 1] = __builtin_e2k_qppermb(input[ 8], input[ 0], words_13_perm); \
    tmp[ 2] = __builtin_e2k_qppermb(input[ 9], input[ 1], words_02_perm); \
    tmp[ 3] = __builtin_e2k_qppermb(input[ 9], input[ 1], words_13_perm); \
    tmp[ 4] = __builtin_e2k_qppermb(input[10], input[ 2], words_02_perm); \
    tmp[ 5] = __builtin_e2k_qppermb(input[10], input[ 2], words_13_perm); \
    tmp[ 6] = __builtin_e2k_qppermb(input[11], input[ 3], words_02_perm); \
    tmp[ 7] = __builtin_e2k_qppermb(input[11], input[ 3], words_13_perm); \
    tmp[ 8] = __builtin_e2k_qppermb(input[24], input[16], words_02_perm); \
    tmp[ 9] = __builtin_e2k_qppermb(input[24], input[16], words_13_perm); \
    tmp[10] = __builtin_e2k_qppermb(input[25], input[17], words_02_perm); \
    tmp[11] = __builtin_e2k_qppermb(input[25], input[17], words_13_perm); \
    tmp[12] = __builtin_e2k_qppermb(input[26], input[18], words_02_perm); \
    tmp[13] = __builtin_e2k_qppermb(input[26], input[18], words_13_perm); \
    tmp[14] = __builtin_e2k_qppermb(input[27], input[19], words_02_perm); \
    tmp[15] = __builtin_e2k_qppermb(input[27], input[19], words_13_perm); \
    \
    tmp[16] = __builtin_e2k_qppermb(input[12], input[ 4], words_02_perm); \
    tmp[17] = __builtin_e2k_qppermb(input[12], input[ 4], words_13_perm); \
    tmp[18] = __builtin_e2k_qppermb(input[13], input[ 5], words_02_perm); \
    tmp[19] = __builtin_e2k_qppermb(input[13], input[ 5], words_13_perm); \
    tmp[20] = __builtin_e2k_qppermb(input[14], input[ 6], words_02_perm); \
    tmp[21] = __builtin_e2k_qppermb(input[14], input[ 6], words_13_perm); \
    tmp[22] = __builtin_e2k_qppermb(input[15], input[ 7], words_02_perm); \
    tmp[23] = __builtin_e2k_qppermb(input[15], input[ 7], words_13_perm); \
    tmp[24] = __builtin_e2k_qppermb(input[28], input[20], words_02_perm); \
    tmp[25] = __builtin_e2k_qppermb(input[28], input[20], words_13_perm); \
    tmp[26] = __builtin_e2k_qppermb(input[29], input[21], words_02_perm); \
    tmp[27] = __builtin_e2k_qppermb(input[29], input[21], words_13_perm); \
    tmp[28] = __builtin_e2k_qppermb(input[30], input[22], words_02_perm); \
    tmp[29] = __builtin_e2k_qppermb(input[30], input[22], words_13_perm); \
    tmp[30] = __builtin_e2k_qppermb(input[31], input[23], words_02_perm); \
    tmp[31] = __builtin_e2k_qppermb(input[31], input[23], words_13_perm); \
    \
    output[ 0] = __builtin_e2k_qppermb(tmp[ 8], tmp[ 0], words_02_perm); \
    output[ 1] = __builtin_e2k_qppermb(tmp[ 9], tmp[ 1], words_02_perm); \
    output[ 2] = __builtin_e2k_qppermb(tmp[ 8], tmp[ 0], words_13_perm); \
    output[ 3] = __builtin_e2k_qppermb(tmp[ 9], tmp[ 1], words_13_perm); \
    output[ 4] = __builtin_e2k_qppermb(tmp[10], tmp[ 2], words_02_perm); \
    output[ 5] = __builtin_e2k_qppermb(tmp[11], tmp[ 3], words_02_perm); \
    output[ 6] = __builtin_e2k_qppermb(tmp[10], tmp[ 2], words_13_perm); \
    output[ 7] = __builtin_e2k_qppermb(tmp[11], tmp[ 3], words_13_perm); \
    output[ 8] = __builtin_e2k_qppermb(tmp[12], tmp[ 4], words_02_perm); \
    output[ 9] = __builtin_e2k_qppermb(tmp[13], tmp[ 5], words_02_perm); \
    output[10] = __builtin_e2k_qppermb(tmp[12], tmp[ 4], words_13_perm); \
    output[11] = __builtin_e2k_qppermb(tmp[13], tmp[ 5], words_13_perm); \
    output[12] = __builtin_e2k_qppermb(tmp[14], tmp[ 6], words_02_perm); \
    output[13] = __builtin_e2k_qppermb(tmp[15], tmp[ 7], words_02_perm); \
    output[14] = __builtin_e2k_qppermb(tmp[14], tmp[ 6], words_13_perm); \
    output[15] = __builtin_e2k_qppermb(tmp[15], tmp[ 7], words_13_perm); \
    \
    output[16] = __builtin_e2k_qppermb(tmp[24], tmp[16], words_02_perm); \
    output[17] = __builtin_e2k_qppermb(tmp[25], tmp[17], words_02_perm); \
    output[18] = __builtin_e2k_qppermb(tmp[24], tmp[16], words_13_perm); \
    output[19] = __builtin_e2k_qppermb(tmp[25], tmp[17], words_13_perm); \
    output[20] = __builtin_e2k_qppermb(tmp[26], tmp[18], words_02_perm); \
    output[21] = __builtin_e2k_qppermb(tmp[27], tmp[19], words_02_perm); \
    output[22] = __builtin_e2k_qppermb(tmp[26], tmp[18], words_13_perm); \
    output[23] = __builtin_e2k_qppermb(tmp[27], tmp[19], words_13_perm); \
    output[24] = __builtin_e2k_qppermb(tmp[28], tmp[20], words_02_perm); \
    output[25] = __builtin_e2k_qppermb(tmp[29], tmp[21], words_02_perm); \
    output[26] = __builtin_e2k_qppermb(tmp[28], tmp[20], words_13_perm); \
    output[27] = __builtin_e2k_qppermb(tmp[29], tmp[21], words_13_perm); \
    output[28] = __builtin_e2k_qppermb(tmp[30], tmp[22], words_02_perm); \
    output[29] = __builtin_e2k_qppermb(tmp[31], tmp[23], words_02_perm); \
    output[30] = __builtin_e2k_qppermb(tmp[30], tmp[22], words_13_perm); \
    output[31] = __builtin_e2k_qppermb(tmp[31], tmp[23], words_13_perm); \
}

#define SALSA_UNPACK(input, output) \
{ \
    __v2di tmp[32]; \
    tmp[ 0] = __builtin_e2k_qppermb(input[ 1], input[ 0], words_02_perm); \
    tmp[ 1] = __builtin_e2k_qppermb(input[ 1], input[ 0], words_13_perm); \
    tmp[ 2] = __builtin_e2k_qppermb(input[ 3], input[ 2], words_02_perm); \
    tmp[ 3] = __builtin_e2k_qppermb(input[ 3], input[ 2], words_13_perm); \
    tmp[ 4] = __builtin_e2k_qppermb(input[ 5], input[ 4], words_02_perm); \
    tmp[ 5] = __builtin_e2k_qppermb(input[ 5], input[ 4], words_13_perm); \
    tmp[ 6] = __builtin_e2k_qppermb(input[ 7], input[ 6], words_02_perm); \
    tmp[ 7] = __builtin_e2k_qppermb(input[ 7], input[ 6], words_13_perm); \
    tmp[ 8] = __builtin_e2k_qppermb(input[ 9], input[ 8], words_02_perm); \
    tmp[ 9] = __builtin_e2k_qppermb(input[ 9], input[ 8], words_13_perm); \
    tmp[10] = __builtin_e2k_qppermb(input[11], input[10], words_02_perm); \
    tmp[11] = __builtin_e2k_qppermb(input[11], input[10], words_13_perm); \
    tmp[12] = __builtin_e2k_qppermb(input[13], input[12], words_02_perm); \
    tmp[13] = __builtin_e2k_qppermb(input[13], input[12], words_13_perm); \
    tmp[14] = __builtin_e2k_qppermb(input[15], input[14], words_02_perm); \
    tmp[15] = __builtin_e2k_qppermb(input[15], input[14], words_13_perm); \
    \
    tmp[16] = __builtin_e2k_qppermb(input[17], input[16], words_02_perm); \
    tmp[17] = __builtin_e2k_qppermb(input[17], input[16], words_13_perm); \
    tmp[18] = __builtin_e2k_qppermb(input[19], input[18], words_02_perm); \
    tmp[19] = __builtin_e2k_qppermb(input[19], input[18], words_13_perm); \
    tmp[20] = __builtin_e2k_qppermb(input[21], input[20], words_02_perm); \
    tmp[21] = __builtin_e2k_qppermb(input[21], input[20], words_13_perm); \
    tmp[22] = __builtin_e2k_qppermb(input[23], input[22], words_02_perm); \
    tmp[23] = __builtin_e2k_qppermb(input[23], input[22], words_13_perm); \
    tmp[24] = __builtin_e2k_qppermb(input[25], input[24], words_02_perm); \
    tmp[25] = __builtin_e2k_qppermb(input[25], input[24], words_13_perm); \
    tmp[26] = __builtin_e2k_qppermb(input[27], input[26], words_02_perm); \
    tmp[27] = __builtin_e2k_qppermb(input[27], input[26], words_13_perm); \
    tmp[28] = __builtin_e2k_qppermb(input[29], input[28], words_02_perm); \
    tmp[29] = __builtin_e2k_qppermb(input[29], input[28], words_13_perm); \
    tmp[30] = __builtin_e2k_qppermb(input[31], input[30], words_02_perm); \
    tmp[31] = __builtin_e2k_qppermb(input[31], input[30], words_13_perm); \
    \
    output[ 0] = __builtin_e2k_qppermb(tmp[ 2], tmp[ 0], words_02_perm); \
    output[ 1] = __builtin_e2k_qppermb(tmp[ 6], tmp[ 4], words_02_perm); \
    output[ 2] = __builtin_e2k_qppermb(tmp[10], tmp[ 8], words_02_perm); \
    output[ 3] = __builtin_e2k_qppermb(tmp[14], tmp[12], words_02_perm); \
    output[ 4] = __builtin_e2k_qppermb(tmp[18], tmp[16], words_02_perm); \
    output[ 5] = __builtin_e2k_qppermb(tmp[22], tmp[20], words_02_perm); \
    output[ 6] = __builtin_e2k_qppermb(tmp[26], tmp[24], words_02_perm); \
    output[ 7] = __builtin_e2k_qppermb(tmp[30], tmp[28], words_02_perm); \
    \
    output[ 8] = __builtin_e2k_qppermb(tmp[ 3], tmp[ 1], words_02_perm); \
    output[ 9] = __builtin_e2k_qppermb(tmp[ 7], tmp[ 5], words_02_perm); \
    output[10] = __builtin_e2k_qppermb(tmp[11], tmp[ 9], words_02_perm); \
    output[11] = __builtin_e2k_qppermb(tmp[15], tmp[13], words_02_perm); \
    output[12] = __builtin_e2k_qppermb(tmp[19], tmp[17], words_02_perm); \
    output[13] = __builtin_e2k_qppermb(tmp[23], tmp[21], words_02_perm); \
    output[14] = __builtin_e2k_qppermb(tmp[27], tmp[25], words_02_perm); \
    output[15] = __builtin_e2k_qppermb(tmp[31], tmp[29], words_02_perm); \
    \
    output[16] = __builtin_e2k_qppermb(tmp[ 2], tmp[ 0], words_13_perm); \
    output[17] = __builtin_e2k_qppermb(tmp[ 6], tmp[ 4], words_13_perm); \
    output[18] = __builtin_e2k_qppermb(tmp[10], tmp[ 8], words_13_perm); \
    output[19] = __builtin_e2k_qppermb(tmp[14], tmp[12], words_13_perm); \
    output[20] = __builtin_e2k_qppermb(tmp[18], tmp[16], words_13_perm); \
    output[21] = __builtin_e2k_qppermb(tmp[22], tmp[20], words_13_perm); \
    output[22] = __builtin_e2k_qppermb(tmp[26], tmp[24], words_13_perm); \
    output[23] = __builtin_e2k_qppermb(tmp[30], tmp[28], words_13_perm); \
    \
    output[24] = __builtin_e2k_qppermb(tmp[ 3], tmp[ 1], words_13_perm); \
    output[25] = __builtin_e2k_qppermb(tmp[ 7], tmp[ 5], words_13_perm); \
    output[26] = __builtin_e2k_qppermb(tmp[11], tmp[ 9], words_13_perm); \
    output[27] = __builtin_e2k_qppermb(tmp[15], tmp[13], words_13_perm); \
    output[28] = __builtin_e2k_qppermb(tmp[19], tmp[17], words_13_perm); \
    output[29] = __builtin_e2k_qppermb(tmp[23], tmp[21], words_13_perm); \
    output[30] = __builtin_e2k_qppermb(tmp[27], tmp[25], words_13_perm); \
    output[31] = __builtin_e2k_qppermb(tmp[31], tmp[29], words_13_perm); \
}

#define SALSA_STORE(offset) \
    V[i * 32 + offset + 0] = X[offset + 0]; \
    V[i * 32 + offset + 1] = X[offset + 1]; \
    V[i * 32 + offset + 2] = X[offset + 2]; \
    V[i * 32 + offset + 3] = X[offset + 3]; \
    V[i * 32 + offset + 4] = X[offset + 4]; \
    V[i * 32 + offset + 5] = X[offset + 5]; \
    V[i * 32 + offset + 6] = X[offset + 6]; \
    V[i * 32 + offset + 7] = X[offset + 7];

#define SALSA_LOAD(j, offset) \
    lx[offset + 0] = V[j + offset + 0]; \
    lx[offset + 1] = V[j + offset + 1]; \
    lx[offset + 2] = V[j + offset + 2]; \
    lx[offset + 3] = V[j + offset + 3]; \
    lx[offset + 4] = V[j + offset + 4]; \
    lx[offset + 5] = V[j + offset + 5]; \
    lx[offset + 6] = V[j + offset + 6]; \
    lx[offset + 7] = V[j + offset + 7];

#define SALSA_LOAD_old(j, offset) \
    memcpy(lx + offset, V + j + offset, 128);

static void scrypt_1024_core_1_cycle_el4way(__v2di *X, __v2di *wx, __v2di *V)
{
    register const __v2di words_02_perm  = { 0x0b0a090803020100, 0x1b1a191813121110 };
    register const __v2di words_13_perm  = { 0x0f0e0d0c07060504, 0x1f1e1d1c17161514 };
    
#pragma loop count(1024)
    for (long i = 0; i < 1024; ++i) {
		memcpy(&V[i * 32], X, 128 * 4);
//         SALSA_STORE(0)
//         SALSA_STORE(8)
//         SALSA_STORE(16)
//         SALSA_STORE(24)
        
        XOR_SALSA8_EL4WAY(((__v2di *) &wx[0]), ((__v2di *) &wx[16]));
        XOR_SALSA8_EL4WAY(((__v2di *) &wx[16]), ((__v2di *) &wx[0]));
        
        SALSA_UNPACK(wx, X)
	}
}

static void scrypt_1024_core_2_cycle_el4way(__v2di *X, __v2di *wx, __v2di *V)
{
    __v2di lx[4 * 8];
    register const __v2di words_02_perm  = { 0x0b0a090803020100, 0x1b1a191813121110 };
    register const __v2di words_13_perm  = { 0x0f0e0d0c07060504, 0x1f1e1d1c17161514 };
    register const __v2di addr_mask =      { 0x000003ff000003ff, 0x000003ff000003ff };
    
#pragma loop count(1024)
	for (long i = 0; i < 1024; ++i) {
        __v2di j = __builtin_e2k_qpsllw(AND(wx[16], addr_mask), 5);
        
        uint32_t j0 = ((uint32_t *) &j)[0];
        uint32_t j1 = ((uint32_t *) &j)[1];
        uint32_t j2 = ((uint32_t *) &j)[2];
        uint32_t j3 = ((uint32_t *) &j)[3];
        
        SALSA_LOAD(j0, 0)
        SALSA_LOAD(j1, 8)
        SALSA_LOAD(j2, 16)
        SALSA_LOAD(j3, 24)
        
        SALSA_PACK(lx, X)
        
#pragma unroll(32)
		for (long k = 0; k < 32; ++k) {
			wx[k] = XOR(wx[k], X[k]);
        }
        XOR_SALSA8_EL4WAY(((__v2di *) &wx[0]), ((__v2di *) &wx[16]));
        XOR_SALSA8_EL4WAY(((__v2di *) &wx[16]), ((__v2di *) &wx[0]));
	}
}

static inline void scrypt_1024_core_el4way(__v2di *X, __v2di *V)
{
    register const __v2di words_02_perm  = { 0x0b0a090803020100, 0x1b1a191813121110 };
    register const __v2di words_13_perm  = { 0x0f0e0d0c07060504, 0x1f1e1d1c17161514 };
    
    __v2di wx[4 * 8];
    
    SALSA_PACK(X, wx)
	
#pragma no_inline
	scrypt_1024_core_1_cycle_el4way(X, wx, V);
	
#pragma no_inline
	scrypt_1024_core_2_cycle_el4way(X, wx, V);
	
	SALSA_UNPACK(wx, X)
}


void scrypt_1024_1_1_256_el4way(const uint32_t * restrict input, uint32_t * restrict output, uint32_t * restrict midstate, uint32_t * restrict V, int N)
{
    uint32_t tstate[4 * 8] __attribute__((aligned(16)));
    uint32_t ostate[4 * 8] __attribute__((aligned(16)));
    uint32_t X[4 * 32] __attribute__((aligned(16)));
	//uint32_t W[4 * 32] __attribute__((aligned(128)));
    
	memcpy(tstate +  0, midstate, 32);
	memcpy(tstate +  8, midstate, 32);
	memcpy(tstate + 16, midstate, 32);
	memcpy(tstate + 24, midstate, 32);
    
	HMAC_SHA256_80_init(input +  0, tstate +  0, ostate +  0);
	HMAC_SHA256_80_init(input + 20, tstate +  8, ostate +  8);
	HMAC_SHA256_80_init(input + 40, tstate + 16, ostate + 16);
	HMAC_SHA256_80_init(input + 60, tstate + 24, ostate + 24);
    
	PBKDF2_SHA256_80_128(tstate +  0, ostate +  0, input +  0, X +  0);
	PBKDF2_SHA256_80_128(tstate +  8, ostate +  8, input + 20, X + 32);
	PBKDF2_SHA256_80_128(tstate + 16, ostate + 16, input + 40, X + 64);
	PBKDF2_SHA256_80_128(tstate + 24, ostate + 24, input + 60, X + 96);
    
#if 1
    scrypt_1024_core_el4way((__v2di *) X, (__v2di *) V);
#else
    scrypt_core(X + 00, V, N);
    scrypt_core(X + 32, V, N);
    scrypt_core(X + 64, V, N);
    scrypt_core(X + 96, V, N);
#endif
#if 0    
    for (i = 0; i < 32; i++)
        for (k = 0; k < 4; k++)
            W[4 * i + k] = X[k * 32 + i];
        
    for (i = 0; i < 32; i++)
        for (k = 0; k < 4; k++)
            X[k * 32 + i] = W[4 * i + k];
#endif
    
	PBKDF2_SHA256_128_32(tstate +  0, ostate +  0, X +  0, output +  0);
	PBKDF2_SHA256_128_32(tstate +  8, ostate +  8, X + 32, output +  8);
	PBKDF2_SHA256_128_32(tstate + 16, ostate + 16, X + 64, output + 16);
	PBKDF2_SHA256_128_32(tstate + 24, ostate + 24, X + 96, output + 24);
}
