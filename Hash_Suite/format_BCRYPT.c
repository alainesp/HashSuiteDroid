// This file is part of Hash Suite password cracker,
// Copyright (c) 2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

// Binary salt type, also keeps the number of rounds and hash sub-type.
typedef struct {
	uint32_t salt[4];
	uint32_t rounds;
	uint32_t sign_extension_bug;
} BF_salt;

// Same charset, different order -- can't use the common.c table here.
unsigned char BF_atoi64[0x80] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 0, 1,
	54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 64, 64, 64, 64, 64,
	64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 64, 64, 64, 64, 64,
	64, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 64, 64, 64, 64, 64
};

#define PLAINTEXT_LENGTH	27//63
#define BINARY_SIZE			6*sizeof(uint32_t)
#define SALT_SIZE			sizeof(BF_salt)

PRIVATE int bcrypt_line_is_valid(char* user_name, char* ciphertext, char* unused, char* unused1)
{
	if (user_name && ciphertext)
	{
		// Check prefix
		if (strncmp(ciphertext, "$2a$", 4) && strncmp(ciphertext, "$2b$", 4) && strncmp(ciphertext, "$2x$", 4) && strncmp(ciphertext, "$2y$", 4))
			return FALSE;

		// Rounds
		if (ciphertext[4] < '0' || ciphertext[4] > '9') return FALSE;
		if (ciphertext[5] < '0' || ciphertext[5] > '9') return FALSE;
		if (ciphertext[6] != '$') return FALSE;

		if (atoi(ciphertext + 4) > 31) return FALSE;

		// Salt and binary are base-64 encoded
		if (valid_base64_string(ciphertext + 7, 53))
		{
			if (BF_atoi64[ciphertext[59]] & 0x3) return FALSE;
			if (BF_atoi64[ciphertext[28]] & 0xF) return FALSE;

			return TRUE;
		}
	}
	return FALSE;
}
PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* ciphertext, char* unused, char* unused1)
{
	if (bcrypt_line_is_valid(user_name, ciphertext, NULL, NULL))
	{
		// Insert hash and account
		return insert_hash_account1(param, user_name, ciphertext, BCRYPT_INDEX);
	}

	return -1;
}

#ifdef HS_TESTING
PUBLIC
#else
PRIVATE
#endif
void BF_decode(uint32_t *dst, const char *src, int size)
{
	unsigned char *dptr = (unsigned char *)dst;
	unsigned char *end = dptr + size;
	unsigned char *sptr = (unsigned char *)src;
	uint32_t c1, c2, c3, c4;

	do {
		c1 = BF_atoi64[*sptr++];
		c2 = BF_atoi64[*sptr++];
		*dptr++ = (c1 << 2) | ((c2 & 0x30) >> 4);
		if (dptr >= end) break;

		c3 = BF_atoi64[*sptr++];
		*dptr++ = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2);
		if (dptr >= end) break;

		c4 = BF_atoi64[*sptr++];
		*dptr++ = ((c3 & 0x03) << 6) | c4;
	} while (dptr < end);
}

PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt_void)
{
	uint32_t* bin = (uint32_t*)binary;
	BF_salt* salt = (BF_salt*)salt_void;

	// Get the salt part
	BF_decode(salt->salt, ciphertext + 7, 16);
	swap_endianness_array(salt->salt, 4);

	salt->rounds = 1u << atoi(ciphertext + 4);
	salt->sign_extension_bug = (ciphertext[2] == 'x');

	// Get the binary part
	bin[5] = 0;
	BF_decode(binary, ciphertext + 29, 23);
	swap_endianness_array(bin, 6);
	bin[5] &= 0xFFFFFF00;

	return bin[0];
}
PRIVATE unsigned char BF_itoa64[64 + 1] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
PRIVATE void BF_encode(unsigned char *dst, const uint32_t* src, int size)
{
	const unsigned char *sptr = (const unsigned char *)src;
	const unsigned char *end = sptr + size;
	unsigned char *dptr = (unsigned char *)dst;
	uint32_t c1, c2;

	do {
		c1 = *sptr++;
		*dptr++ = BF_itoa64[c1 >> 2];
		c1 = (c1 & 0x03) << 4;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 4;
		*dptr++ = BF_itoa64[c1];
		c1 = (c2 & 0x0f) << 2;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 6;
		*dptr++ = BF_itoa64[c1];
		*dptr++ = BF_itoa64[c2 & 0x3f];
	} while (sptr < end);
}
PRIVATE void binary2hex(const void* binary, const BF_salt* salt, unsigned char* ciphertext)
{
	uint32_t tmp[6];

	int exponent = 0;
	for (int rounds = salt->rounds; rounds > 1; rounds >>= 1, exponent++);

	sprintf((char*)ciphertext, "$2%s$%02i$", salt->sign_extension_bug ? "x" : "y", exponent);

	memcpy(tmp, salt->salt, 4 * sizeof(uint32_t));
	swap_endianness_array(tmp, 4);
	BF_encode(ciphertext + 7, tmp, 16);

	/* This has to be bug-compatible with the original implementation, so
	* only encode 23 of the 24 bytes. :-) */
	memcpy(tmp, binary, 6 * sizeof(uint32_t));
	swap_endianness_array(tmp, 6);
	BF_encode(&ciphertext[7 + 22], tmp, 23);
	ciphertext[7 + 22 + 31] = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct {
	uint32_t S[4][0x100];
	uint32_t P[18];
} BF_ctx;

// Magic IV for 64 Blowfish encryptions that we do at the end.
// The string is "OrpheanBeholderScryDoubt" on big-endian.
PRIVATE uint32_t BF_magic_w[6] = { 0x4F727068, 0x65616E42, 0x65686F6C, 0x64657253, 0x63727944, 0x6F756274 };

// P-box and S-box tables initialized with digits of Pi.
PUBLIC BF_ctx BF_init_state = {
	{
		{
			0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
			0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
			0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
			0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
			0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
			0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
			0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
			0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
			0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
			0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
			0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
			0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
			0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
			0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
			0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
			0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
			0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
			0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
			0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
			0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
			0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
			0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
			0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
			0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
			0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
			0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
			0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
			0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
			0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
			0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
			0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
			0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
			0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
			0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
			0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
			0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
			0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
			0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
			0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
			0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
			0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
			0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
			0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
			0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
			0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
			0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
			0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
			0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
			0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
			0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
			0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
			0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
			0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
			0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
			0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
			0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
			0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
			0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
			0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
			0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
			0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
			0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
			0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
			0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a
		}, {
			0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
			0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
			0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
			0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
			0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
			0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
			0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
			0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
			0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
			0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
			0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
			0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
			0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
			0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
			0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
			0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
			0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
			0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
			0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
			0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
			0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
			0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
			0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
			0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
			0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
			0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
			0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
			0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
			0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
			0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
			0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
			0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
			0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
			0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
			0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
			0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
			0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
			0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
			0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
			0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
			0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
			0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
			0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
			0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
			0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
			0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
			0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
			0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
			0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
			0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
			0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
			0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
			0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
			0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
			0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
			0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
			0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
			0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
			0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
			0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
			0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
			0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
			0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
			0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7
		}, {
			0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
			0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
			0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
			0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
			0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
			0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
			0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
			0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
			0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
			0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
			0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
			0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
			0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
			0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
			0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
			0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
			0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
			0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
			0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
			0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
			0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
			0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
			0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
			0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
			0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
			0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
			0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
			0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
			0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
			0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
			0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
			0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
			0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
			0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
			0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
			0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
			0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
			0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
			0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
			0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
			0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
			0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
			0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
			0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
			0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
			0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
			0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
			0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
			0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
			0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
			0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
			0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
			0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
			0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
			0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
			0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
			0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
			0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
			0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
			0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
			0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
			0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
			0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
			0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0
		}, {
			0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
			0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
			0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
			0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
			0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
			0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
			0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
			0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
			0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
			0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
			0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
			0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
			0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
			0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
			0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
			0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
			0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
			0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
			0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
			0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
			0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
			0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
			0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
			0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
			0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
			0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
			0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
			0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
			0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
			0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
			0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
			0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
			0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
			0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
			0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
			0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
			0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
			0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
			0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
			0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
			0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
			0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
			0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
			0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
			0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
			0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
			0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
			0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
			0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
			0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
			0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
			0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
			0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
			0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
			0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
			0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
			0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
			0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
			0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
			0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
			0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
			0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
			0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
			0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
		}
	}, {
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
		0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
		0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
		0x9216d5d9, 0x8979fb1b
	}
};

PRIVATE void blowfish_set_key(uint32_t* buffer, uint32_t* subkeys, uint32_t* expanded_key, int simd_width, int sign_extension_bug, uint32_t NUM_KEYS)
{
	unsigned char key[MAX_KEY_LENGHT_SMALL];
	for (int simd_index = 0; simd_index < simd_width; simd_index++)
	{
		utf8_coalesc2utf8_key(buffer, key, NUM_KEYS, simd_index);

		const char* ptr = key;
		for (int i = 0; i < 18; i++)
		{
			uint32_t tmp = 0;
			for (int j = 0; j < 4; j++)
			{
				tmp <<= 8;
				if (sign_extension_bug)
					tmp |= (int)(signed char)*ptr;
				else
					tmp |= (unsigned char)*ptr;

				if (!*ptr) ptr = key; else ptr++;
			}

			expanded_key[i*simd_width+simd_index] = tmp;
			subkeys[i*simd_width+simd_index] = BF_init_state.P[i] ^ tmp;
		}
	}
}

#define BYTE_0(word)	((word & 0xFF))
#define BYTE_1(word)	((word >> 8 ) & 0xFF)
#define BYTE_2(word)	((word >> 16) & 0xFF)
#define BYTE_3(word)	((word >> 24))

#ifdef __ANDROID__
	#define BF_IN_PARALLEL	1
#else
	#define BF_IN_PARALLEL	3
#endif

#define NT_NUM_KEYS BF_IN_PARALLEL

#if (BF_IN_PARALLEL == 1)
// Encrypt one block
#define BF_ENCRYPT \
	L ^= subkeys[0 ]; \
	R ^= subkeys[1 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[2 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[3 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[4 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[5 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[6 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[7 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[9 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[10] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[11] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[12] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[13] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[14] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[15] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[16] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	tmp_swap = R;\
	R = L;\
	L = tmp_swap ^ subkeys[17];

// More expensive funtion: the one to optimize
#define blowfish_body blowfish_body_c_code
PRIVATE void blowfish_body_c_code(uint32_t* subkeys, uint32_t* sboxs)
{
	uint32_t L = 0, R = 0, tmp_swap;
	for (int i = 0; i < 18; i += 2)
	{
		BF_ENCRYPT;
		subkeys[i  ] = L;
		subkeys[i+1] = R;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		BF_ENCRYPT;
		sboxs[i  ] = L;
		sboxs[i+1] = R;
	}
}

PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	unsigned char key[MAX_KEY_LENGHT_SMALL];
	uint32_t* buffer = (uint32_t*)malloc(8*NT_NUM_KEYS* sizeof(uint32_t) + (4 * 256 + 18 + 18 + 6) * sizeof(uint32_t)*BF_IN_PARALLEL);
	memset(buffer, 0, 8*NT_NUM_KEYS*sizeof(uint32_t));

	uint32_t* sboxs   = buffer + 8 * NT_NUM_KEYS;
	uint32_t* subkeys = sboxs + 4 * 256 * BF_IN_PARALLEL;
	uint32_t* expanded_key = subkeys + 18* BF_IN_PARALLEL;
	uint32_t* crypt_result = expanded_key + 18* BF_IN_PARALLEL;

	while(continue_attack && param->gen(buffer, NT_NUM_KEYS, param->thread_id))
	{
		BF_salt* salt = (BF_salt*)salts_values;
		// For all salts
		for(uint32_t current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++, salt++)
		{
			uint32_t L, R, tmp_swap;

			blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
			for (int i = 0; i < NT_NUM_KEYS; i++)
				memcpy(sboxs+i*sizeof(BF_init_state.S)/4, BF_init_state.S, sizeof(BF_init_state.S));

			L = R = 0;
			for (int i = 0; i < 18; i+=2)
			{
				L ^= salt->salt[(i & 2)];
				R ^= salt->salt[(i & 2) + 1];
				BF_ENCRYPT;
				subkeys[i  ] = L;
				subkeys[i+1] = R;
			}
			for (int i = 0; i < 256*4; i+=2)
			{
				L ^= salt->salt[(i + 2) & 3];
				R ^= salt->salt[(i + 3) & 3];
				BF_ENCRYPT;
				sboxs[i  ] = L;
				sboxs[i+1] = R;
			}

			// Expensive key schedule
			for (uint32_t round = 0; round < salt->rounds; round++)
			{
				// Key part
				for (int i = 0; i < 18; i++)
					subkeys[i] ^= expanded_key[i];

				blowfish_body(subkeys, sboxs);

				// Salt part
				for (int i = 0; i < 18; i ++)
					subkeys[i] ^= salt->salt[i&3];

				blowfish_body(subkeys, sboxs);
			}

			// Final part: Encrypt
			for (int i = 0; i < 6; i += 2)
			{
				L = BF_magic_w[i];
				R = BF_magic_w[i+1];

				for (int j = 0; j < 64; j++)
				{
					BF_ENCRYPT;
				}

				crypt_result[i  ] = L;
				crypt_result[i+1] = R;
			}
			/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
			crypt_result[5] &= 0xFFFFFF00;

			for (int k = 0; k < NT_NUM_KEYS; k++)
			{
				// Search for a match
				uint32_t hash_index = salt_index[current_salt_index];

				// Partial match
				while (hash_index != NO_ELEM)
				{
					// Total match
					if (!memcmp(crypt_result, ((uint32_t*)binary_values) + hash_index * 6, BINARY_SIZE))
						password_was_found(hash_index, utf8_coalesc2utf8_key(buffer, key, NT_NUM_KEYS, k));

					hash_index = same_salt_next[hash_index];
				}
			}
		}

		report_keys_processed(NT_NUM_KEYS);
	}

	free(buffer);
	finish_thread();
}
#elif (BF_IN_PARALLEL == 2)
// Encrypt one block
#define BF_ENCRYPT \
	L0 ^= subkeys[0 ]; \
	L1 ^= subkeys[1 ]; \
	R0 ^= subkeys[2 ] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[3 ] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[4 ] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[5 ] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[6 ] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[7 ] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[9 ] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[10] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[11] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[12] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[13] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[14] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[15] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[16] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[17] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[18] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[19] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[20] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[21] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[22] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[23] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[24] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[25] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[26] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[27] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[28] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[29] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	R0 ^= subkeys[30] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[31] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	L0 ^= subkeys[32] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[33] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	ts0 = R0;\
	ts1 = R1;\
	R0 = L0;\
	R1 = L1;\
	L0 = ts0 ^ subkeys[34];\
	L1 = ts1 ^ subkeys[35];

// More expensive funtion: the one to optimize
void blowfish_body_asm_x64(uint32_t* subkeys, uint32_t* Sboxs);
//#define blowfish_body blowfish_body_asm_x64
#define blowfish_body blowfish_body_c_code
PRIVATE void blowfish_body_c_code(uint32_t* subkeys, uint32_t* sboxs)
{
	uint32_t L0 = 0, R0 = 0, ts0, L1 = 0, R1 = 0, ts1;
	for (int i = 0; i < 18; i += 2)
	{
		BF_ENCRYPT;

		subkeys[(i  )*BF_IN_PARALLEL  ] = L0;
		subkeys[(i+1)*BF_IN_PARALLEL  ] = R0;
		subkeys[(i  )*BF_IN_PARALLEL+1] = L1;
		subkeys[(i+1)*BF_IN_PARALLEL+1] = R1;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		BF_ENCRYPT;

		sboxs[i       ] = L0;
		sboxs[i+1     ] = R0;
		sboxs[i  +1024] = L1;
		sboxs[i+1+1024] = R1;
	}
}

PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	unsigned char key[MAX_KEY_LENGHT_SMALL];
	uint32_t* buffer = (uint32_t*)malloc(8 * NT_NUM_KEYS* sizeof(uint32_t)+(4 * 256 + 18 + 18 + 6) * sizeof(uint32_t)*BF_IN_PARALLEL);
	memset(buffer, 0, 8*NT_NUM_KEYS*sizeof(uint32_t));

	uint32_t* sboxs   = buffer + 8 * NT_NUM_KEYS;
	uint32_t* subkeys = sboxs + 4 * 256 * BF_IN_PARALLEL;
	uint32_t* expanded_key = subkeys + 18* BF_IN_PARALLEL;
	uint32_t* crypt_result = expanded_key + 18* BF_IN_PARALLEL;

	while(continue_attack && param->gen(buffer, NT_NUM_KEYS, param->thread_id))
	{
		BF_salt* salt = (BF_salt*)salts_values;
		// For all salts
		for(uint32_t current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++, salt++)
		{
			uint32_t L0, R0, ts0, L1, R1, ts1;

			blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
			for (int i = 0; i < NT_NUM_KEYS; i++)
				memcpy(sboxs+i*sizeof(BF_init_state.S)/4, BF_init_state.S, sizeof(BF_init_state.S));

			L0 = R0 = L1 = R1 = 0;
			for (int i = 0; i < 18; i+=2)
			{
				L0 ^= salt->salt[(i & 2)];
				R0 ^= salt->salt[(i & 2) + 1];
				L1 ^= salt->salt[(i & 2)];
				R1 ^= salt->salt[(i & 2) + 1];
				BF_ENCRYPT;
				subkeys[(i  )*BF_IN_PARALLEL  ] = L0;
				subkeys[(i+1)*BF_IN_PARALLEL  ] = R0;
				subkeys[(i  )*BF_IN_PARALLEL+1] = L1;
				subkeys[(i+1)*BF_IN_PARALLEL+1] = R1;
			}
			for (int i = 0; i < 256*4; i+=2)
			{
				L0 ^= salt->salt[(i + 2) & 3];
				R0 ^= salt->salt[(i + 3) & 3];
				L1 ^= salt->salt[(i + 2) & 3];
				R1 ^= salt->salt[(i + 3) & 3];
				BF_ENCRYPT;
				sboxs[i       ] = L0;
				sboxs[i+1     ] = R0;
				sboxs[i  +1024] = L1;
				sboxs[i+1+1024] = R1;
			}

			// Expensive key schedule
			for (uint32_t round = 0; round < salt->rounds; round++)
			{
				// Key part
				for (int i = 0; i < 18*BF_IN_PARALLEL; i++)
					subkeys[i] ^= expanded_key[i];

				blowfish_body(subkeys, sboxs);

				// Salt part
				for (int i = 0; i < 18*BF_IN_PARALLEL; i++)
					subkeys[i] ^= salt->salt[(i/BF_IN_PARALLEL)&3];

				blowfish_body(subkeys, sboxs);
			}

			// Final part: Encrypt
			for (int i = 0; i < 6; i += 2)
			{
				L0 = L1 = BF_magic_w[i];
				R0 = R1 = BF_magic_w[i+1];

				for (int j = 0; j < 64; j++)
				{
					BF_ENCRYPT;
				}

				crypt_result[i    ] = L0;
				crypt_result[i+1  ] = R0;
				crypt_result[i  +6] = L1;
				crypt_result[i+1+6] = R1;
			}
			
			for (int k = 0; k < NT_NUM_KEYS; k++)
			{
				/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
				crypt_result[5+k*6] &= 0xFFFFFF00;

				// Search for a match
				uint32_t hash_index = salt_index[current_salt_index];

				// Partial match
				while (hash_index != NO_ELEM)
				{
					// Total match
					if (!memcmp(crypt_result+k*6, ((uint32_t*)binary_values) + hash_index * 6, BINARY_SIZE))
						password_was_found(hash_index, utf8_coalesc2utf8_key(buffer, key, NT_NUM_KEYS, k));

					hash_index = same_salt_next[hash_index];
				}
			}
		}

		report_keys_processed(NT_NUM_KEYS);
	}

	free(buffer);
	finish_thread();
}
#elif (BF_IN_PARALLEL == 3)
// Encrypt one block
#define BF_ENCRYPT \
	L0 ^= subkeys[0 ]; \
	L1 ^= subkeys[1 ]; \
	L2 ^= subkeys[2 ]; \
	R0 ^= subkeys[3 ] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[4 ] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[5 ] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[6 ] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[7 ] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[9 ] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[10] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[11] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[12] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[13] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[14] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[15] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[16] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[17] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[18] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[19] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[20] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[21] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[22] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[23] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[24] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[25] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[26] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[27] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[28] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[29] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[30] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[31] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[32] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[33] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[34] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[35] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[36] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[37] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[38] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[39] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[40] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[41] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[42] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[43] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[44] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	R0 ^= subkeys[45] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[46] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[47] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	L0 ^= subkeys[48] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[49] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[50] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	ts0 = R0;\
	ts1 = R1;\
	ts2 = R2;\
	R0 = L0;\
	R1 = L1;\
	R2 = L2;\
	L0 = ts0 ^ subkeys[51];\
	L1 = ts1 ^ subkeys[52];\
	L2 = ts2 ^ subkeys[53];

// More expensive funtion: the one to optimize
#ifdef _M_X64
	void blowfish_body_asm_x64(uint32_t* subkeys, uint32_t* Sboxs);
	#define blowfish_body blowfish_body_asm_x64
#else
	#define blowfish_body blowfish_body_c_code
PRIVATE void blowfish_body_c_code(uint32_t* subkeys, uint32_t* sboxs)
{
	uint32_t L0 = 0, R0 = 0, L1 = 0, R1 = 0, L2 = 0, R2 = 0;
	uint32_t ts0, ts1, ts2;
	for (int i = 0; i < 18; i += 2)
	{
		BF_ENCRYPT;

		subkeys[(i  )*BF_IN_PARALLEL  ] = L0;
		subkeys[(i+1)*BF_IN_PARALLEL  ] = R0;
		subkeys[(i  )*BF_IN_PARALLEL+1] = L1;
		subkeys[(i+1)*BF_IN_PARALLEL+1] = R1;
		subkeys[(i  )*BF_IN_PARALLEL+2] = L2;
		subkeys[(i+1)*BF_IN_PARALLEL+2] = R2;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		BF_ENCRYPT;

		sboxs[i       ] = L0;
		sboxs[i+1     ] = R0;
		sboxs[i  +1024] = L1;
		sboxs[i+1+1024] = R1;
		sboxs[i  +2048] = L2;
		sboxs[i+1+2048] = R2;
	}
}
#endif

PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	unsigned char key[MAX_KEY_LENGHT_SMALL];
	uint32_t* buffer = (uint32_t*)malloc(8 * NT_NUM_KEYS* sizeof(uint32_t)+(4 * 256 + 18 + 18 + 6) * sizeof(uint32_t)*BF_IN_PARALLEL);
	memset(buffer, 0, 8*NT_NUM_KEYS*sizeof(uint32_t));

	uint32_t* sboxs   = buffer + 8 * NT_NUM_KEYS;
	uint32_t* subkeys = sboxs + 4 * 256 * BF_IN_PARALLEL;
	uint32_t* expanded_key = subkeys + 18* BF_IN_PARALLEL;
	uint32_t* crypt_result = expanded_key + 18* BF_IN_PARALLEL;

	while(continue_attack && param->gen(buffer, NT_NUM_KEYS, param->thread_id))
	{
		BF_salt* salt = (BF_salt*)salts_values;
		// For all salts
		for(uint32_t current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++, salt++)
		{
			uint32_t L0, R0, ts0, L1, R1, ts1, L2, R2, ts2;

			blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
			for (int i = 0; i < NT_NUM_KEYS; i++)
				memcpy(sboxs+i*sizeof(BF_init_state.S)/4, BF_init_state.S, sizeof(BF_init_state.S));

			L0 = R0 = L1 = R1 = L2 = R2 = 0;
			for (int i = 0; i < 18; i+=2)
			{
				L0 ^= salt->salt[(i & 2)];
				R0 ^= salt->salt[(i & 2) + 1];
				L1 ^= salt->salt[(i & 2)];
				R1 ^= salt->salt[(i & 2) + 1];
				L2 ^= salt->salt[(i & 2)];
				R2 ^= salt->salt[(i & 2) + 1];
				BF_ENCRYPT;
				subkeys[(i  )*BF_IN_PARALLEL  ] = L0;
				subkeys[(i+1)*BF_IN_PARALLEL  ] = R0;
				subkeys[(i  )*BF_IN_PARALLEL+1] = L1;
				subkeys[(i+1)*BF_IN_PARALLEL+1] = R1;
				subkeys[(i  )*BF_IN_PARALLEL+2] = L2;
				subkeys[(i+1)*BF_IN_PARALLEL+2] = R2;
			}
			for (int i = 0; i < 256*4; i+=2)
			{
				L0 ^= salt->salt[(i + 2) & 3];
				R0 ^= salt->salt[(i + 3) & 3];
				L1 ^= salt->salt[(i + 2) & 3];
				R1 ^= salt->salt[(i + 3) & 3];
				L2 ^= salt->salt[(i + 2) & 3];
				R2 ^= salt->salt[(i + 3) & 3];
				BF_ENCRYPT;
				sboxs[i       ] = L0;
				sboxs[i+1     ] = R0;
				sboxs[i  +1024] = L1;
				sboxs[i+1+1024] = R1;
				sboxs[i  +2048] = L2;
				sboxs[i+1+2048] = R2;
			}

			// Expensive key schedule
			for (uint32_t round = 0; round < salt->rounds; round++)
			{
				// Key part
				for (int i = 0; i < 18*BF_IN_PARALLEL; i++)
					subkeys[i] ^= expanded_key[i];

				blowfish_body(subkeys, sboxs);

				// Salt part
				for (int i = 0; i < 18*BF_IN_PARALLEL; i ++)
					subkeys[i] ^= salt->salt[(i/BF_IN_PARALLEL)&3];

				blowfish_body(subkeys, sboxs);
			}

			// Final part: Encrypt
			for (int i = 0; i < 6; i += 2)
			{
				L0 = L1 = L2 = BF_magic_w[i];
				R0 = R1 = R2 = BF_magic_w[i+1];

				for (int j = 0; j < 64; j++)
				{
					BF_ENCRYPT;
				}

				crypt_result[i     ] = L0;
				crypt_result[i+1   ] = R0;
				crypt_result[i  + 6] = L1;
				crypt_result[i+1+ 6] = R1;
				crypt_result[i  +12] = L2;
				crypt_result[i+1+12] = R2;
			}
			
			for (int k = 0; k < NT_NUM_KEYS; k++)
			{
				/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
				crypt_result[5+k*6] &= 0xFFFFFF00;

				// Search for a match
				uint32_t hash_index = salt_index[current_salt_index];

				// Partial match
				while (hash_index != NO_ELEM)
				{
					// Total match
					if (!memcmp(crypt_result+k*6, ((uint32_t*)binary_values) + hash_index * 6, BINARY_SIZE))
						password_was_found(hash_index, utf8_coalesc2utf8_key(buffer, key, NT_NUM_KEYS, k));

					hash_index = same_salt_next[hash_index];
				}
			}
		}

		report_keys_processed(NT_NUM_KEYS);
	}

	free(buffer);
	finish_thread();
}
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BMI
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _M_X64

#undef BF_IN_PARALLEL
#undef NT_NUM_KEYS
#undef BF_ENCRYPT

#define BF_IN_PARALLEL	4
#define NT_NUM_KEYS		BF_IN_PARALLEL
// Encrypt one block
#define BF_ENCRYPT \
	L0 ^= subkeys[0 ]; \
	L1 ^= subkeys[1 ]; \
	L2 ^= subkeys[2 ]; \
	L3 ^= subkeys[3 ]; \
	R0 ^= subkeys[4 ] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[5 ] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[6 ] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[7 ] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[9 ] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[10] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[11] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[12] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[13] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[14] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[15] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[16] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[17] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[18] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[19] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[20] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[21] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[22] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[23] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[24] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[25] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[26] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[27] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[28] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[29] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[30] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[31] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[32] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[33] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[34] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[35] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[36] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[37] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[38] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[39] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[40] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[41] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[42] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[43] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[44] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[45] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[46] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[47] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[48] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[49] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[50] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[51] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[52] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[53] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[54] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[55] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[56] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[57] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[58] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[59] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	R0 ^= subkeys[60] ^ (((sboxs[BYTE_3(L0)+0   ] + sboxs[BYTE_2(L0)+256+0   ]) ^ sboxs[BYTE_1(L0)+512+0   ]) + sboxs[BYTE_0(L0)+768+0   ]);\
	R1 ^= subkeys[61] ^ (((sboxs[BYTE_3(L1)+1024] + sboxs[BYTE_2(L1)+256+1024]) ^ sboxs[BYTE_1(L1)+512+1024]) + sboxs[BYTE_0(L1)+768+1024]);\
	R2 ^= subkeys[62] ^ (((sboxs[BYTE_3(L2)+2048] + sboxs[BYTE_2(L2)+256+2048]) ^ sboxs[BYTE_1(L2)+512+2048]) + sboxs[BYTE_0(L2)+768+2048]);\
	R3 ^= subkeys[63] ^ (((sboxs[BYTE_3(L3)+3072] + sboxs[BYTE_2(L3)+256+3072]) ^ sboxs[BYTE_1(L3)+512+3072]) + sboxs[BYTE_0(L3)+768+3072]);\
	L0 ^= subkeys[64] ^ (((sboxs[BYTE_3(R0)+0   ] + sboxs[BYTE_2(R0)+256+0   ]) ^ sboxs[BYTE_1(R0)+512+0   ]) + sboxs[BYTE_0(R0)+768+0   ]);\
	L1 ^= subkeys[65] ^ (((sboxs[BYTE_3(R1)+1024] + sboxs[BYTE_2(R1)+256+1024]) ^ sboxs[BYTE_1(R1)+512+1024]) + sboxs[BYTE_0(R1)+768+1024]);\
	L2 ^= subkeys[66] ^ (((sboxs[BYTE_3(R2)+2048] + sboxs[BYTE_2(R2)+256+2048]) ^ sboxs[BYTE_1(R2)+512+2048]) + sboxs[BYTE_0(R2)+768+2048]);\
	L3 ^= subkeys[67] ^ (((sboxs[BYTE_3(R3)+3072] + sboxs[BYTE_2(R3)+256+3072]) ^ sboxs[BYTE_1(R3)+512+3072]) + sboxs[BYTE_0(R3)+768+3072]);\
	ts0 = R0;\
	ts1 = R1;\
	ts2 = R2;\
	ts3 = R3;\
	R0 = L0;\
	R1 = L1;\
	R2 = L2;\
	R3 = L3;\
	L0 = ts0 ^ subkeys[68];\
	L1 = ts1 ^ subkeys[69];\
	L2 = ts2 ^ subkeys[70];\
	L3 = ts3 ^ subkeys[71];

// More expensive funtion: the one to optimize
void blowfish_body_asm_bmi(uint32_t* Sboxs, uint32_t* subkeys);
//PRIVATE void blowfish_body_asm_bmi(uint32_t* sboxs, uint32_t* subkeys)
//{
//	uint32_t L0 = 0, R0 = 0, L1 = 0, R1 = 0, L2 = 0, R2 = 0, L3 = 0, R3 = 0;
//	uint32_t ts0, ts1, ts2, ts3;
//	for (int i = 0; i < 18; i += 2)
//	{
//		BF_ENCRYPT;
//
//		subkeys[(i  )*BF_IN_PARALLEL  ] = L0;
//		subkeys[(i+1)*BF_IN_PARALLEL  ] = R0;
//		subkeys[(i  )*BF_IN_PARALLEL+1] = L1;
//		subkeys[(i+1)*BF_IN_PARALLEL+1] = R1;
//		subkeys[(i  )*BF_IN_PARALLEL+2] = L2;
//		subkeys[(i+1)*BF_IN_PARALLEL+2] = R2;
//		subkeys[(i  )*BF_IN_PARALLEL+3] = L3;
//		subkeys[(i+1)*BF_IN_PARALLEL+3] = R3;
//	}
//	for (int i = 0; i < 256 * 4; i += 2)
//	{
//		BF_ENCRYPT;
//
//		sboxs[i       ] = L0;
//		sboxs[i+1     ] = R0;
//		sboxs[i  +1024] = L1;
//		sboxs[i+1+1024] = R1;
//		sboxs[i  +2048] = L2;
//		sboxs[i+1+2048] = R2;
//		sboxs[i  +3072] = L3;
//		sboxs[i+1+3072] = R3;
//	}
//}

PRIVATE void crypt_utf8_coalesc_protocol_bmi(CryptParam* param)
{
	unsigned char key[MAX_KEY_LENGHT_SMALL];
	uint32_t* buffer = (uint32_t*)malloc(8 * NT_NUM_KEYS* sizeof(uint32_t)+(4 * 256 + 18 + 18 + 6) * sizeof(uint32_t)*BF_IN_PARALLEL);
	memset(buffer, 0, 8*NT_NUM_KEYS*sizeof(uint32_t));

	uint32_t* sboxs   = buffer + 8 * NT_NUM_KEYS;
	uint32_t* subkeys = sboxs + 4 * 256 * BF_IN_PARALLEL;
	uint32_t* expanded_key = subkeys + 18* BF_IN_PARALLEL;
	uint32_t* crypt_result = expanded_key + 18* BF_IN_PARALLEL;

	while(continue_attack && param->gen(buffer, NT_NUM_KEYS, param->thread_id))
	{
		BF_salt* salt = (BF_salt*)salts_values;
		// For all salts
		for(uint32_t current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++, salt++)
		{
			uint32_t L0, R0, ts0, L1, R1, ts1, L2, R2, ts2, L3, R3, ts3;

			blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
			for (int i = 0; i < NT_NUM_KEYS; i++)
				memcpy(sboxs+i*sizeof(BF_init_state.S)/4, BF_init_state.S, sizeof(BF_init_state.S));

			L0 = R0 = L1 = R1 = L2 = R2 = L3 = R3 = 0;
			for (int i = 0; i < 18; i+=2)
			{
				L0 ^= salt->salt[(i & 2)];
				R0 ^= salt->salt[(i & 2) + 1];
				L1 ^= salt->salt[(i & 2)];
				R1 ^= salt->salt[(i & 2) + 1];
				L2 ^= salt->salt[(i & 2)];
				R2 ^= salt->salt[(i & 2) + 1];
				L3 ^= salt->salt[(i & 2)];
				R3 ^= salt->salt[(i & 2) + 1];
				BF_ENCRYPT;
				subkeys[(i  )*BF_IN_PARALLEL  ] = L0;
				subkeys[(i+1)*BF_IN_PARALLEL  ] = R0;
				subkeys[(i  )*BF_IN_PARALLEL+1] = L1;
				subkeys[(i+1)*BF_IN_PARALLEL+1] = R1;
				subkeys[(i  )*BF_IN_PARALLEL+2] = L2;
				subkeys[(i+1)*BF_IN_PARALLEL+2] = R2;
				subkeys[(i  )*BF_IN_PARALLEL+3] = L3;
				subkeys[(i+1)*BF_IN_PARALLEL+3] = R3;
			}
			for (int i = 0; i < 256*4; i+=2)
			{
				L0 ^= salt->salt[(i + 2) & 3];
				R0 ^= salt->salt[(i + 3) & 3];
				L1 ^= salt->salt[(i + 2) & 3];
				R1 ^= salt->salt[(i + 3) & 3];
				L2 ^= salt->salt[(i + 2) & 3];
				R2 ^= salt->salt[(i + 3) & 3];
				L3 ^= salt->salt[(i + 2) & 3];
				R3 ^= salt->salt[(i + 3) & 3];
				BF_ENCRYPT;
				sboxs[i       ] = L0;
				sboxs[i+1     ] = R0;
				sboxs[i  +1024] = L1;
				sboxs[i+1+1024] = R1;
				sboxs[i  +2048] = L2;
				sboxs[i+1+2048] = R2;
				sboxs[i  +3072] = L3;
				sboxs[i+1+3072] = R3;
			}

			// Expensive key schedule
			for (uint32_t round = 0; round < salt->rounds; round++)
			{
				// Key part
				for (int i = 0; i < 18*BF_IN_PARALLEL; i++)
					subkeys[i] ^= expanded_key[i];

				blowfish_body_asm_bmi(sboxs, subkeys);

				// Salt part
				for (int i = 0; i < 18*BF_IN_PARALLEL; i ++)
					subkeys[i] ^= salt->salt[(i/BF_IN_PARALLEL)&3];

				blowfish_body_asm_bmi(sboxs, subkeys);
			}

			// Final part: Encrypt
			for (int i = 0; i < 6; i += 2)
			{
				L0 = L1 = L2 = L3 = BF_magic_w[i];
				R0 = R1 = R2 = R3 = BF_magic_w[i+1];

				for (int j = 0; j < 64; j++)
				{
					BF_ENCRYPT;
				}

				crypt_result[i     ] = L0;
				crypt_result[i+1   ] = R0;
				crypt_result[i  + 6] = L1;
				crypt_result[i+1+ 6] = R1;
				crypt_result[i  +12] = L2;
				crypt_result[i+1+12] = R2;
				crypt_result[i  +18] = L3;
				crypt_result[i+1+18] = R3;
			}
			
			for (int k = 0; k < NT_NUM_KEYS; k++)
			{
				/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
				crypt_result[5+k*6] &= 0xFFFFFF00;

				// Search for a match
				uint32_t hash_index = salt_index[current_salt_index];

				// Partial match
				while (hash_index != NO_ELEM)
				{
					// Total match
					if (!memcmp(crypt_result+k*6, ((uint32_t*)binary_values) + hash_index * 6, BINARY_SIZE))
						password_was_found(hash_index, utf8_coalesc2utf8_key(buffer, key, NT_NUM_KEYS, k));

					hash_index = same_salt_next[hash_index];
				}
			}
		}

		report_keys_processed(NT_NUM_KEYS);
	}

	free(buffer);
	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT

//#define BF_USE_LOCAL_MEMORY
//#define BF_USE_LOCAL_MEMORY_COALESCED
//#define BF_USE_GLOBAL_MEMORY
//#define BF_USE_REGISTER_MEMORY
//#define BF_REGISTER_WORKGROUP	32

#define KERNEL_INDEX_BLOWFISH_SET_KEY		0
#define KERNEL_INDEX_BF_BODY_SALT			1
#define KERNEL_INDEX_BF_BODY_LOOP			2
#define KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE	3
#ifdef BF_USE_REGISTER_MEMORY
	#define KERNEL_INDEX_BF_BODY_XOR_KEY	4
	#define KERNEL_INDEX_BF_BODY_XOR_SALT	5
#endif

#define INDEX_SBOXS			0
#define INDEX_SUBKEY		1024
#define INDEX_EXPANDED_KEY	1042
#define CRYPT_RESULT		1060

PRIVATE void ocl_work_body(OpenCL_Param* param, int num_keys_filled, void* buffer, ocl_get_key* get_key)
{
	int64_t total_ks = 0;
	int64_t processed_ks = 0;
	int num_keys_reported = 0;
	BF_salt* salt = (BF_salt*)salts_values;
	size_t bf_body_workgroup = param->param0;
	size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_filled, param->max_work_group_size);

	for (cl_uint current_salt_index = 0; current_salt_index < num_diff_salts; current_salt_index++)
		total_ks += (salt[current_salt_index].rounds * 2 + 1);

	for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++, salt++)
	{
		pclSetKernelArg(param->kernels[KERNEL_INDEX_BLOWFISH_SET_KEY], 2, sizeof(salt->sign_extension_bug), (void*)&salt->sign_extension_bug);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BLOWFISH_SET_KEY], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_SALT], 2, sizeof(current_salt_index), (void*)&current_salt_index);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_SALT], 1, NULL, &num_work_items, &bf_body_workgroup, 0, NULL, NULL);
		processed_ks++;

		// Expensive key setup
#ifdef BF_USE_REGISTER_MEMORY
		size_t reg_num_work_items = num_work_items*bf_body_workgroup;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_XOR_SALT], 2, sizeof(current_salt_index), (void*)&current_salt_index);
#else
		cl_uint num_iters = param->param1;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 2, sizeof(current_salt_index), (void*)&current_salt_index);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 3, sizeof(num_iters), (void*)&num_iters);
#endif
		for (cl_uint k = 0; continue_attack && k < salt->rounds; k+=num_iters)
		{
			//int64_t init = get_milliseconds();
#ifdef BF_USE_REGISTER_MEMORY
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_XOR_KEY], 1, NULL, &num_work_items    , &bf_body_workgroup, 0, NULL, NULL);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_LOOP   ], 1, NULL, &reg_num_work_items, &bf_body_workgroup, 0, NULL, NULL);

			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_XOR_SALT], 1, NULL, &num_work_items    , &bf_body_workgroup, 0, NULL, NULL);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_LOOP    ], 1, NULL, &reg_num_work_items, &bf_body_workgroup, 0, NULL, NULL);
#else
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 1, NULL, &num_work_items, &bf_body_workgroup, 0, NULL, NULL);
#endif
			// Report keys processed from time to time to maintain good Rate
			pclFinish(param->queue);
			//hs_log(HS_LOG_DEBUG, "Test Suite", "Time Loop: %ims", get_milliseconds()-init);

			processed_ks += 2*num_iters;
			int num_keys_reported_add = (int)(num_keys_filled*processed_ks / total_ks) - num_keys_reported;
			if (num_keys_reported_add > 0)
			{
				num_keys_reported += num_keys_reported_add;
				report_keys_processed(num_keys_reported_add);
			}
		}

		if (continue_attack)
		{
			// Search for a match-----------------------------------------------------------------------------------------------------------------------------------------------------
			cl_uint hash_index = salt_index[current_salt_index];
			// Partial match
			while (hash_index != NO_ELEM && continue_attack)
			{
				// Compare results
				pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE], 3, sizeof(hash_index), (void*)&hash_index);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

				// Find matches
				cl_uint num_found;
				pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

				// GPU found some passwords
				if (num_found)
					ocl_common_process_found(param, &num_found, get_key, buffer, num_work_items, num_keys_filled);

				hash_index = same_salt_next[hash_index];
			}
		}
	}

	if (continue_attack)
	{
		num_keys_filled -= num_keys_reported;
		if (num_keys_filled > 0)
			report_keys_processed(num_keys_filled);
	}
	else
		report_keys_processed(-num_keys_reported);
}

PRIVATE const int MultiplyDeBruijnBitPosition2[32] =
{
	0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
	31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
};
PRIVATE int log2_of_power2(uint32_t v)
{
	return MultiplyDeBruijnBitPosition2[(uint32_t)(v * 0x077CB531U) >> 27];
}

PRIVATE char* ocl_gen_kernels(GPUDevice* gpu, oclKernel2Common* ocl_kernel_provider, OpenCL_Param* param, int multiplier)
{
	// Because bug in HS implementation or Intel OpenCL driver
	char backup_vendor = gpu->vendor;
	if(gpu->vendor == OCL_VENDOR_INTEL)
		gpu->vendor = OCL_VENDOR_AMD;

	assert(multiplier > 0);
	// Generate code
	char* source = malloc(64 * 1024 * (size_t)multiplier);
	source[0] = 0;
	// Header definitions
	//if(num_passwords_loaded > 1 )
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");

	//Initial values
	if (multiplier==1)// Normal
		sprintf(source+strlen(source),
			// First is the keys
			"#define INDEX_SBOXS		8\n"
			"#define INDEX_SUBKEY		1032\n"
			"#define INDEX_EXPANDED_KEY	1050\n");
	else// Rules
		sprintf(source+strlen(source),
			"#define INDEX_SBOXS		0\n"
			"#define INDEX_SUBKEY		1024\n"
			"#define INDEX_EXPANDED_KEY	1042\n");

	// Workgroup size calculation
	if (gpu->vendor == OCL_VENDOR_INTEL)
	{//#ifdef BF_USE_GLOBAL_MEMORY
		param->param0 = (int)gpu->lm_work_group_size;
	}//#endif
	else
	{//#ifdef BF_USE_LOCAL_MEMORY
		param->param0 = __min((int)gpu->max_work_group_size, (int)(gpu->local_memory_size/1024/sizeof(cl_uint)));
		param->param0 = floor_power_2(param->param0);
		sprintf(source + strlen(source), "#define BF_BODY_WORKGROUP %i\n", param->param0);
	}//#endif
#ifdef BF_USE_REGISTER_MEMORY
	 param->param0 = BF_REGISTER_WORKGROUP;
#endif

sprintf(source+strlen(source),"#define GET_DATA(STATE,index) data_ptr[(STATE+index)*%uu]\n", param->NUM_KEYS_OPENCL);

	// Constants
	sprintf(source + strlen(source), "__constant uint bf_init_subkeys[]={");
	for (uint32_t i = 0; i < 18; i++)
		sprintf(source + strlen(source), "%s0x%x", i ? "," : "", BF_init_state.P[i]);
	sprintf(source + strlen(source), "};\n");

	sprintf(source + strlen(source), "__constant uint bf_init_sboxs[]={");
	for (uint32_t i = 0; i < 1024; i++)
		sprintf(source + strlen(source), "%s0x%x", i ? "," : "", BF_init_state.S[i/256][i%256]);
	sprintf(source + strlen(source), "};\n");

	ocl_kernel_provider->gen_kernel(source, param->NUM_KEYS_OPENCL);

	// Begin code generation
	sprintf(source+strlen(source),
	"__kernel void blowfish_set_key(__global uint* current_data,__global uint* keys, uint sign_extension_bug)"
	"{"
		"uint idx=get_global_id(0);"
		"__global uint* data_ptr = current_data+get_global_id(0);"

		// Convert the key
		"uint len=keys[7u*%uu+idx]>>4u;"
		"if(len>27u)return;"
		"for(uint i=0,ptr=0;i<18;i++)"
		"{"
			"uint tmp=0,val;"
			"for(uint j=0;j<4;j++)"
			"{"
				"tmp<<=8u;"
				"if(ptr==len){"
					"val=0;"
					"ptr=0;"
				"}else{"
					"val=(keys[ptr/4*%uu+idx]>>(8*(ptr&3)))&0xff;"
					"ptr++;"
				"}"
				"if(sign_extension_bug){"
					"tmp|=(int)(char)val;"
				"}else{"
					"tmp|=val;"
				"}"
			"}"

			"GET_DATA(INDEX_EXPANDED_KEY,i)=tmp;"
			"GET_DATA(INDEX_SUBKEY,i)=tmp^bf_init_subkeys[i];"
		"}"

		"for(uint i=0;i<1024;i++)"
			"GET_DATA(INDEX_SBOXS,i)=bf_init_sboxs[i];"
	"}", param->NUM_KEYS_OPENCL*multiplier, param->NUM_KEYS_OPENCL*multiplier);

	// Encrypt macro
	int shifts = log2_of_power2(param->NUM_KEYS_OPENCL);
	sprintf(source + strlen(source), "\n"
		"#define BF_ENCRYPT_GLOBAL "
		"L^=subkey0;");
	for (int i = 1; i <= 16; i++)
	{
		char* R = (i & 1) ? "R" : "L";
		char* L = (i & 1) ? "L" : "R";
		sprintf(source + strlen(source),
			"%s ^= subkey%i ^ (((sboxs0[(%s & 0xff000000)   %s            %iu] + sboxs1[(%s & 0xff0000)     %s             %iu]) ^ sboxs2[(%s & 0xff00)      %s            %iu]) + sboxs3[(%s & 0xff)<<%iu]);"
			, R         , i             , L, (shifts>24)?"<<":">>", abs(24-shifts)      , L, (shifts>16)?"<<":">>", abs(16-shifts)        , L, (shifts>8)?"<<":">>", abs(8-shifts)        , L       , shifts);
	}
	sprintf(source + strlen(source),
		"tmp_swap=R;"
		"R=L;"
		"L=tmp_swap^subkey17;\n");

	if (gpu->vendor != OCL_VENDOR_INTEL)
	{//#ifdef BF_USE_LOCAL_MEMORY
	// Encrypt macro
	int shiftsl = log2_of_power2(param->param0);
	sprintf(source + strlen(source),
		"#define BF_ENCRYPT_LOCAL "
		"L^=subkey0;");
	for (int i = 1; i <= 16; i++)
	{
		char* R = (i & 1) ? "R" : "L";
		char* L = (i & 1) ? "L" : "R";
		if (gpu->vendor == OCL_VENDOR_NVIDIA)//#ifdef BF_USE_LOCAL_MEMORY_COALESCED
			sprintf(source + strlen(source),
				"%s ^= subkey%i ^ (((sboxs0[(%s & 0xff000000) >> %i] + sboxs1[(%s & 0xff0000) >> %i]) ^ sboxs2[(%s & 0xff00) >> %i]) + sboxs3[(%s & 0xff)*BF_BODY_WORKGROUP]);"
				, R         , i             , L              , 24-shiftsl     , L            , 16-shiftsl      , L          , 8-shiftsl       , L);
/*#else*/else
			sprintf(source + strlen(source),
				"%s ^= subkey%i ^ (((sboxs0[%s >> 24u] + sboxs1[(%s >> 16u) & 0xff]) ^ sboxs2[(%s >> 8u) & 0xff]) + sboxs3[%s & 0xff]);"
				, R         , i            , L                  , L                          , L                          , L);
//#endif
	}
	sprintf(source + strlen(source),
		"tmp_swap=R;"
		"R=L;"
		"L=tmp_swap^subkey17;\n");

	// Kernels using encrypt macro
	sprintf(source+strlen(source),
	"__attribute__((reqd_work_group_size(%i, 1, 1))) __kernel void bf_body_salt(__global uint* current_data,__global uint* salt, uint salt_index)"
	"{"
		"__global uint* data_ptr = current_data+get_global_id(0);"
		
		// Load sboxs into local memory
		"uint lid=get_local_id(0);"
		"local uint sboxs[BF_BODY_WORKGROUP*1024];", param->param0);
	if (gpu->vendor == OCL_VENDOR_NVIDIA)//#ifdef BF_USE_LOCAL_MEMORY_COALESCED
		sprintf(source+strlen(source),
		"local uint* sboxs0 = sboxs+lid;"
		"local uint* sboxs1 = sboxs+lid+256*BF_BODY_WORKGROUP;"
		"local uint* sboxs2 = sboxs+lid+512*BF_BODY_WORKGROUP;"
		"local uint* sboxs3 = sboxs+lid+768*BF_BODY_WORKGROUP;"

		"for (uint i = 0; i < 1024; i++)"
			"sboxs0[i*BF_BODY_WORKGROUP]=GET_DATA(INDEX_SBOXS,i);");
/*#else*/else
			sprintf(source+strlen(source),
		"local uint* sboxs0 = sboxs+lid*1024;"
		"local uint* sboxs1 = sboxs0+256;"
		"local uint* sboxs2 = sboxs1+256;"
		"local uint* sboxs3 = sboxs2+256;"

		"for (uint i = 0; i < 1024; i++)"
			"sboxs0[i]=GET_DATA(INDEX_SBOXS,i);");
//#endif
	sprintf(source+strlen(source),
		"uint L, R, tmp_swap;"
		// Load salt
		"uint salt0=salt[6*salt_index+0];"
		"uint salt1=salt[6*salt_index+1];"
		"uint salt2=salt[6*salt_index+2];"
		"uint salt3=salt[6*salt_index+3];"

		"L = R = 0;");
		// Load subkey
	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), "uint subkey%i = GET_DATA(INDEX_SUBKEY,%i);", i, i);
	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
			"L ^= salt%i;"
			"R ^= salt%i;"
			"BF_ENCRYPT_LOCAL;"
			"subkey%i = L;"
			"subkey%i = R;"
			// Save subkey
			"GET_DATA(INDEX_SUBKEY,%i)=L;"
			"GET_DATA(INDEX_SUBKEY,%i)=R;", i & 2, (i & 2) + 1, i, i + 1, i, i + 1);
	// Change sboxs
	sprintf(source+strlen(source),
		"for (uint i = 0; i < 1024; i+=4)"
		"{"
			"L ^= salt2;"
			"R ^= salt3;"
			"BF_ENCRYPT_LOCAL;"
			"sboxs0[ i   %s]=L;"
			"sboxs0[(i+1)%s]=R;"

			"GET_DATA(INDEX_SBOXS,i  ) = L;"
			"GET_DATA(INDEX_SBOXS,i+1) = R;"

			"L ^= salt0;"
			"R ^= salt1;"
			"BF_ENCRYPT_LOCAL;"
			"sboxs0[(i+2)%s]=L;"
			"sboxs0[(i+3)%s]=R;"

			"GET_DATA(INDEX_SBOXS,i+2) = L;"
			"GET_DATA(INDEX_SBOXS,i+3) = R;"
		"}"
	"}", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP":"", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP":"", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP":"", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP":"");
	}
	else
	{//#else
	// Kernels using encrypt macro
	sprintf(source+strlen(source),
	"__kernel void bf_body_salt(__global uint* current_data,__global uint* salt, uint salt_index)"
	"{"
		"__global uint* data_ptr = current_data+get_global_id(0);"
		"__global uint* sboxs0 = data_ptr+(INDEX_SBOXS)*%uu;"
		"__global uint* sboxs1 = data_ptr+(INDEX_SBOXS+256)*%uu;"
		"__global uint* sboxs2 = data_ptr+(INDEX_SBOXS+512)*%uu;"
		"__global uint* sboxs3 = data_ptr+(INDEX_SBOXS+768)*%uu;"		
		"uint L, R, tmp_swap;"
		// Load salt
		"uint salt0=salt[6*salt_index+0];"
		"uint salt1=salt[6*salt_index+1];"
		"uint salt2=salt[6*salt_index+2];"
		"uint salt3=salt[6*salt_index+3];"

		"L = R = 0;", param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL);
		// Load subkey
	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), "uint subkey%i = GET_DATA(INDEX_SUBKEY,%i);", i, i);
	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
			"L ^= salt%i;"
			"R ^= salt%i;"
			"BF_ENCRYPT_GLOBAL;"
			"subkey%i = L;"
			"subkey%i = R;"
			// Save subkey
			"GET_DATA(INDEX_SUBKEY,%i)=L;"
			"GET_DATA(INDEX_SUBKEY,%i)=R;", i & 2, (i & 2) + 1, i, i + 1, i, i + 1);
	// Change sboxs
	sprintf(source+strlen(source),
		"for (uint i = 0; i < 1024; i+=4)"
		"{"
			"L ^= salt2;"
			"R ^= salt3;"
			"BF_ENCRYPT_GLOBAL;"
			"GET_DATA(INDEX_SBOXS,i  ) = L;"
			"GET_DATA(INDEX_SBOXS,i+1) = R;"

			"L ^= salt0;"
			"R ^= salt1;"
			"BF_ENCRYPT_GLOBAL;"
			"GET_DATA(INDEX_SBOXS,i+2) = L;"
			"GET_DATA(INDEX_SBOXS,i+3) = R;"
		"}"
	"}");
	}//#endif

	if(gpu->vendor != OCL_VENDOR_INTEL)
	{//#ifdef BF_USE_LOCAL_MEMORY
	sprintf(source + strlen(source),
	"\n__attribute__((reqd_work_group_size(%i, 1, 1))) __kernel void bf_body_loop(__global uint* current_data,__global uint* salt,uint salt_index, uint num_iter)"
	"{"
		"__global uint* data_ptr = current_data+get_global_id(0);"
		"uint L, R, tmp_swap;"

		// Load sboxs into local memory
		"uint lid=get_local_id(0);"
		"local uint sboxs[BF_BODY_WORKGROUP*1024];", param->param0);

	if(gpu->vendor == OCL_VENDOR_NVIDIA)//#ifdef BF_USE_LOCAL_MEMORY_COALESCED
		sprintf(source + strlen(source),
		"local uint* sboxs0 = sboxs+lid;"
		"local uint* sboxs1 = sboxs+lid+256*BF_BODY_WORKGROUP;"
		"local uint* sboxs2 = sboxs+lid+512*BF_BODY_WORKGROUP;"
		"local uint* sboxs3 = sboxs+lid+768*BF_BODY_WORKGROUP;"

		"for (uint i = 0; i < 1024; i++)"
			"sboxs0[i*BF_BODY_WORKGROUP]=GET_DATA(INDEX_SBOXS,i);");
/*#else*/else
			sprintf(source + strlen(source),
		"local uint* sboxs0 = sboxs+lid*1024;"
		"local uint* sboxs1 = sboxs0+256;"
		"local uint* sboxs2 = sboxs1+256;"
		"local uint* sboxs3 = sboxs2+256;"

		"for (uint i = 0; i < 1024; i++)"
			"sboxs0[i]=GET_DATA(INDEX_SBOXS,i);");
//#endif
		// Load salt
	sprintf(source + strlen(source),
		"uint salt0=salt[6*salt_index+0];"
		"uint salt1=salt[6*salt_index+1];"
		"uint salt2=salt[6*salt_index+2];"
		"uint salt3=salt[6*salt_index+3];");

		// Load subkey and expanded_key
	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), 
		"uint subkey%i = GET_DATA(INDEX_SUBKEY,%i);"
		"uint expkey%i = GET_DATA(INDEX_EXPANDED_KEY,%i);", i, i, i, i);

	sprintf(source + strlen(source),
		"for(uint j=0;j<num_iter;j++)"
		"{"
			"L = R = 0;");
	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), "subkey%i ^= expkey%i;", i, i);

	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
			"BF_ENCRYPT_LOCAL;"
			"subkey%i=L;"
			"subkey%i=R;", i, i + 1);
	// Change sboxs
	sprintf(source + strlen(source),
			"for (uint i = 0; i < 1024; i+=2)"
			"{"
				"BF_ENCRYPT_LOCAL;"
				"sboxs0[ i   %s]=L;"
				"sboxs0[(i+1)%s]=R;"
			"}"
			"L = R = 0;", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP" : "", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP" : "");

	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), "subkey%i ^= salt%i;", i, i & 3);

	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
			"BF_ENCRYPT_LOCAL;"
			"subkey%i=L;"
			"subkey%i=R;", i, i + 1);
	// Change sboxs
	sprintf(source + strlen(source),
			"for (uint i = 0; i < 1024; i+=2)"
			"{"
				"BF_ENCRYPT_LOCAL;"
				"sboxs0[ i   %s]=L;"
				"sboxs0[(i+1)%s]=R;"
			"}"
		"}", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP" : "", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP" : "");
	// Save subkey
	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), "GET_DATA(INDEX_SUBKEY,%i)=subkey%i;", i, i);
	// Save sboxs
	sprintf(source + strlen(source),
		"for (uint i = 0; i < 1024; i++)"
			"GET_DATA(INDEX_SBOXS,i)=sboxs0[i%s];"
	"}", (gpu->vendor == OCL_VENDOR_NVIDIA) ? "*BF_BODY_WORKGROUP" : "");
	}
	else
	{//#endif
//#ifdef BF_USE_GLOBAL_MEMORY
	sprintf(source + strlen(source),
	"\n__kernel void bf_body_loop(__global uint* current_data,__global uint* salt,uint salt_index, uint num_iter)"
	"{"
		"__global uint* data_ptr = current_data+get_global_id(0);"
		"__global uint* sboxs0 = data_ptr+(INDEX_SBOXS)*%uu;"
		"__global uint* sboxs1 = data_ptr+(INDEX_SBOXS+256)*%uu;"
		"__global uint* sboxs2 = data_ptr+(INDEX_SBOXS+512)*%uu;"
		"__global uint* sboxs3 = data_ptr+(INDEX_SBOXS+768)*%uu;"

		"uint L, R, tmp_swap;"

		// Load salt
		"uint salt0=salt[6*salt_index+0];"
		"uint salt1=salt[6*salt_index+1];"
		"uint salt2=salt[6*salt_index+2];"
		"uint salt3=salt[6*salt_index+3];"

		// Load subkey
		"uint subkey0  = GET_DATA(INDEX_SUBKEY,0 );"
		"uint subkey1  = GET_DATA(INDEX_SUBKEY,1 );"
		"uint subkey2  = GET_DATA(INDEX_SUBKEY,2 );"
		"uint subkey3  = GET_DATA(INDEX_SUBKEY,3 );"
		"uint subkey4  = GET_DATA(INDEX_SUBKEY,4 );"
		"uint subkey5  = GET_DATA(INDEX_SUBKEY,5 );"
		"uint subkey6  = GET_DATA(INDEX_SUBKEY,6 );"
		"uint subkey7  = GET_DATA(INDEX_SUBKEY,7 );"
		"uint subkey8  = GET_DATA(INDEX_SUBKEY,8 );"
		"uint subkey9  = GET_DATA(INDEX_SUBKEY,9 );"
		"uint subkey10 = GET_DATA(INDEX_SUBKEY,10);"
		"uint subkey11 = GET_DATA(INDEX_SUBKEY,11);"
		"uint subkey12 = GET_DATA(INDEX_SUBKEY,12);"
		"uint subkey13 = GET_DATA(INDEX_SUBKEY,13);"
		"uint subkey14 = GET_DATA(INDEX_SUBKEY,14);"
		"uint subkey15 = GET_DATA(INDEX_SUBKEY,15);"
		"uint subkey16 = GET_DATA(INDEX_SUBKEY,16);"
		"uint subkey17 = GET_DATA(INDEX_SUBKEY,17);"

		// Prefetch sboxs
		"/*for (uint i = 0; i < 1024; i++)"
			"prefetch(sboxs0+i*%uu, 1u);*/"

		"for(uint j=0;j<num_iter;j++)"
		"{"
			"subkey0  ^= GET_DATA(INDEX_EXPANDED_KEY,0 );"
			"subkey1  ^= GET_DATA(INDEX_EXPANDED_KEY,1 );"
			"subkey2  ^= GET_DATA(INDEX_EXPANDED_KEY,2 );"
			"subkey3  ^= GET_DATA(INDEX_EXPANDED_KEY,3 );"
			"subkey4  ^= GET_DATA(INDEX_EXPANDED_KEY,4 );"
			"subkey5  ^= GET_DATA(INDEX_EXPANDED_KEY,5 );"
			"subkey6  ^= GET_DATA(INDEX_EXPANDED_KEY,6 );"
			"subkey7  ^= GET_DATA(INDEX_EXPANDED_KEY,7 );"
			"subkey8  ^= GET_DATA(INDEX_EXPANDED_KEY,8 );"
			"subkey9  ^= GET_DATA(INDEX_EXPANDED_KEY,9 );"
			"subkey10 ^= GET_DATA(INDEX_EXPANDED_KEY,10);"
			"subkey11 ^= GET_DATA(INDEX_EXPANDED_KEY,11);"
			"subkey12 ^= GET_DATA(INDEX_EXPANDED_KEY,12);"
			"subkey13 ^= GET_DATA(INDEX_EXPANDED_KEY,13);"
			"subkey14 ^= GET_DATA(INDEX_EXPANDED_KEY,14);"
			"subkey15 ^= GET_DATA(INDEX_EXPANDED_KEY,15);"
			"subkey16 ^= GET_DATA(INDEX_EXPANDED_KEY,16);"
			"subkey17 ^= GET_DATA(INDEX_EXPANDED_KEY,17);"

			"L = R = 0;", param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL);
	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
			"BF_ENCRYPT_GLOBAL;"
			"subkey%i = L;"
			"subkey%i = R;", i, i + 1);
	// Change sboxs
	sprintf(source + strlen(source),
			"for (uint i = 0; i < 1024; i+=2)"
			"{"
				"BF_ENCRYPT_GLOBAL;"
				// Save sboxs
				"GET_DATA(INDEX_SBOXS,i  )=L;"
				"GET_DATA(INDEX_SBOXS,i+1)=R;"
			"}"

			"subkey0  ^= salt0;"
			"subkey1  ^= salt1;"
			"subkey2  ^= salt2;"
			"subkey3  ^= salt3;"
			"subkey4  ^= salt0;"
			"subkey5  ^= salt1;"
			"subkey6  ^= salt2;"
			"subkey7  ^= salt3;"
			"subkey8  ^= salt0;"
			"subkey9  ^= salt1;"
			"subkey10 ^= salt2;"
			"subkey11 ^= salt3;"
			"subkey12 ^= salt0;"
			"subkey13 ^= salt1;"
			"subkey14 ^= salt2;"
			"subkey15 ^= salt3;"
			"subkey16 ^= salt0;"
			"subkey17 ^= salt1;"

			"L = R = 0;");
	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
			"BF_ENCRYPT_GLOBAL;"
			"subkey%i = L;"
			"subkey%i = R;", i, i + 1);
	// Change sboxs
	sprintf(source + strlen(source),
			"for (uint i = 0; i < 1024; i+=2)"
			"{"
				"BF_ENCRYPT_GLOBAL;"
				// Save sboxs
				"GET_DATA(INDEX_SBOXS,i  )=L;"
				"GET_DATA(INDEX_SBOXS,i+1)=R;"
			"}"
		"}");

	// Save subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
		"GET_DATA(INDEX_SUBKEY,%i)=subkey%i;"
		"GET_DATA(INDEX_SUBKEY,%i)=subkey%i;", i, i, i + 1, i + 1);

	sprintf(source + strlen(source),"}");
	}
//#endif
#ifdef BF_USE_REGISTER_MEMORY
	sprintf(source + strlen(source),
		"\n__kernel void bf_body_xor_key(__global uint* current_data)"
		"{"
			"__global uint* data_ptr = current_data+get_global_id(0);"

			"for(uint i=0;i<18u;i++)"
				"GET_DATA(INDEX_SUBKEY,i)^=GET_DATA(INDEX_EXPANDED_KEY,i);"
		"}"
		"\n__kernel void bf_body_xor_salt(__global uint* current_data,__global uint* salt,uint salt_index)"
		"{"
			"__global uint* data_ptr = current_data+get_global_id(0);"

			"for(uint i=0;i<18u;i++)"
				"GET_DATA(INDEX_SUBKEY,i)^=salt[6u*salt_index+(i&3u)];"
		"}");
#if (BF_REGISTER_WORKGROUP==64)
	// Encrypt macro
	sprintf(source + strlen(source),
		"\n#define BF_ENCRYPT_REG "
		"L^=subkey[0];");
	for (int i = 1; i <= 16; i++)
	{
		char* R = (i & 1) ? "R" : "L";
		char* L = (i & 1) ? "L" : "R";
		sprintf(source + strlen(source),
			"sb=(%s >> sb_shift) & 0xff;"
			//"sb=amd_bfe(%s, sb_shift, 8u);"
			"sb-=sb_min;"

			// sboxs lookup
			"if(sb<16u){"
				/*"if(sb<8u){"
					"if(sb<4u){"
						"if(sb<2u){"
							"if(sb==0u) sboxs_values[sb_index]=sb0;"
							"else sboxs_values[sb_index]=sb1;"
						"}else{"
							"if(sb==2u) sboxs_values[sb_index]=sb2;"
							"else sboxs_values[sb_index]=sb3;"
						"}"
					"}else{"
						"if(sb<6u){"
							"if(sb==4u) sboxs_values[sb_index]=sb4;"
							"else sboxs_values[sb_index]=sb5;"
						"}else{"
							"if(sb==6u) sboxs_values[sb_index]=sb6;"
							"else sboxs_values[sb_index]=sb7;"
						"}"
					"}"
				"}else{"
					"if(sb<12u){"
						"if(sb<10u){"
							"if(sb==8u) sboxs_values[sb_index]=sb8;"
							"else sboxs_values[sb_index]=sb9;"
						"}else{"
							"if(sb==10u) sboxs_values[sb_index]=sb10;"
							"else sboxs_values[sb_index]=sb11;"
						"}"
					"}else{"
						"if(sb<14u){"
							"if(sb==12u) sboxs_values[sb_index]=sb12;"
							"else sboxs_values[sb_index]=sb13;"
						"}else{"
							"if(sb==14u) sboxs_values[sb_index]=sb14;"
							"else sboxs_values[sb_index]=sb15;"
						"}"
					"}"
				"}"*/
				"switch (sb)"
				"{"
					"case 0u:sboxs_values[sb_index]=sb0;break;"
					"case 1u:sboxs_values[sb_index]=sb1;break;"
					"case 2u:sboxs_values[sb_index]=sb2;break;"
					"case 3u:sboxs_values[sb_index]=sb3;break;"
					"case 4u:sboxs_values[sb_index]=sb4;break;"
					"case 5u:sboxs_values[sb_index]=sb5;break;"
					"case 6u:sboxs_values[sb_index]=sb6;break;"
					"case 7u:sboxs_values[sb_index]=sb7;break;"
					"case 8u:sboxs_values[sb_index]=sb8;break;"
					"case 9u:sboxs_values[sb_index]=sb9;break;"

					"case 10u:sboxs_values[sb_index]=sb10;break;"
					"case 11u:sboxs_values[sb_index]=sb11;break;"
					"case 12u:sboxs_values[sb_index]=sb12;break;"
					"case 13u:sboxs_values[sb_index]=sb13;break;"
					"case 14u:sboxs_values[sb_index]=sb14;break;"
					"case 15u:sboxs_values[sb_index]=sb15;break;"
				"}"
			"}"

			"barrier(CLK_LOCAL_MEM_FENCE);"

			"%s ^= subkey[%i] ^ (((sboxs_values[0] + sboxs_values[1]) ^ sboxs_values[2]) + sboxs_values[3]);"
			, L, R, i);
	}
	sprintf(source + strlen(source),
		"tmp_swap=R;"
		"R=L;"
		"L=tmp_swap^subkey[17];\n"
		
		"#define BF_REG_SET(i,L,R) "
			"if(i==(lid*16+0 )) {sb0 =L;sb1 =R;}"
			"if(i==(lid*16+2 )) {sb2 =L;sb3 =R;}"
			"if(i==(lid*16+4 )) {sb4 =L;sb5 =R;}"
			"if(i==(lid*16+6 )) {sb6 =L;sb7 =R;}"
			"if(i==(lid*16+8 )) {sb8 =L;sb9 =R;}"
			"if(i==(lid*16+10)) {sb10=L;sb11=R;}"
			"if(i==(lid*16+12)) {sb12=L;sb13=R;}"
			"if(i==(lid*16+14)) {sb14=L;sb15=R;}\n"
		);

	sprintf(source + strlen(source),
	"\n__attribute__((reqd_work_group_size(%i, 1, 1))) __kernel void bf_body_loop(__global uint* current_data)"
	"{"
		"__global uint* data_ptr = current_data+get_group_id(0);"
		"uint lid = get_local_id(0);"
		"uint L, R, tmp_swap;"

		"uint sb;"
		"uint sb_index=lid/16;"
		"uint sb_shift=24u-sb_index*8u;"
		"uint sb_min  =lid*16-256*sb_index;"

		// Load sboxs into registers
		"local uint sboxs_values[4];"
		"uint sb0 =GET_DATA(INDEX_SBOXS,lid*16+0 ),sb1 =GET_DATA(INDEX_SBOXS,lid*16+1 ),sb2 =GET_DATA(INDEX_SBOXS,lid*16+2 ),sb3 =GET_DATA(INDEX_SBOXS,lid*16+3 );"
		"uint sb4 =GET_DATA(INDEX_SBOXS,lid*16+4 ),sb5 =GET_DATA(INDEX_SBOXS,lid*16+5 ),sb6 =GET_DATA(INDEX_SBOXS,lid*16+6 ),sb7 =GET_DATA(INDEX_SBOXS,lid*16+7 );"
		"uint sb8 =GET_DATA(INDEX_SBOXS,lid*16+8 ),sb9 =GET_DATA(INDEX_SBOXS,lid*16+9 ),sb10=GET_DATA(INDEX_SBOXS,lid*16+10),sb11=GET_DATA(INDEX_SBOXS,lid*16+11);"
		"uint sb12=GET_DATA(INDEX_SBOXS,lid*16+12),sb13=GET_DATA(INDEX_SBOXS,lid*16+13),sb14=GET_DATA(INDEX_SBOXS,lid*16+14),sb15=GET_DATA(INDEX_SBOXS,lid*16+15);"

		// Load subkey
		"local uint subkey[18];"
		"if(lid<18u)"
			"subkey[lid]=GET_DATA(INDEX_SUBKEY,lid);"
		"barrier(CLK_LOCAL_MEM_FENCE);"

		"L = R = 0;", param->param0);

	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
		"BF_ENCRYPT_REG;"
		"if(lid==0){"
			"subkey[%i]=L;"
			"subkey[%i]=R;"
			// Save subkey
			"GET_DATA(INDEX_SUBKEY,%i)=L;"
			"GET_DATA(INDEX_SUBKEY,%i)=R;}"
		"barrier(CLK_LOCAL_MEM_FENCE);", i, i + 1, i, i + 1);
	// Change sboxs
	sprintf(source + strlen(source),
		"for (uint i = 0; i < 1024; i+=2)"
		"{"
			"BF_ENCRYPT_REG;"
			"BF_REG_SET(i,L,R);"
			// Save sboxs
			"if(lid==0){"
				"GET_DATA(INDEX_SBOXS,i  )=L;"
				"GET_DATA(INDEX_SBOXS,i+1)=R;}"
		"}"
	"}");
#elif (BF_REGISTER_WORKGROUP==32)
	// Encrypt macro
	sprintf(source + strlen(source),
		"\n#define BF_ENCRYPT_REG "
		"L^=subkey[0];");
	for (int i = 1; i <= 16; i++)
	{
		char* R = (i & 1) ? "R" : "L";
		char* L = (i & 1) ? "L" : "R";
		sprintf(source + strlen(source),
			"sb=(%s >> sb_shift) & 0xff;"
			"sb-=sb_min;"

			// sboxs lookup
			"if(sb<32u){"
				"switch (sb)"
				"{"
					"case 0u:sboxs_values[sb_index]=sb0;break;"
					"case 1u:sboxs_values[sb_index]=sb1;break;"
					"case 2u:sboxs_values[sb_index]=sb2;break;"
					"case 3u:sboxs_values[sb_index]=sb3;break;"
					"case 4u:sboxs_values[sb_index]=sb4;break;"
					"case 5u:sboxs_values[sb_index]=sb5;break;"
					"case 6u:sboxs_values[sb_index]=sb6;break;"
					"case 7u:sboxs_values[sb_index]=sb7;break;"
					"case 8u:sboxs_values[sb_index]=sb8;break;"
					"case 9u:sboxs_values[sb_index]=sb9;break;"

					"case 10u:sboxs_values[sb_index]=sb10;break;"
					"case 11u:sboxs_values[sb_index]=sb11;break;"
					"case 12u:sboxs_values[sb_index]=sb12;break;"
					"case 13u:sboxs_values[sb_index]=sb13;break;"
					"case 14u:sboxs_values[sb_index]=sb14;break;"
					"case 15u:sboxs_values[sb_index]=sb15;break;"
					"case 16u:sboxs_values[sb_index]=sb16;break;"
					"case 17u:sboxs_values[sb_index]=sb17;break;"
					"case 18u:sboxs_values[sb_index]=sb18;break;"
					"case 19u:sboxs_values[sb_index]=sb19;break;"

					"case 20u:sboxs_values[sb_index]=sb20;break;"
					"case 21u:sboxs_values[sb_index]=sb21;break;"
					"case 22u:sboxs_values[sb_index]=sb22;break;"
					"case 23u:sboxs_values[sb_index]=sb23;break;"
					"case 24u:sboxs_values[sb_index]=sb24;break;"
					"case 25u:sboxs_values[sb_index]=sb25;break;"
					"case 26u:sboxs_values[sb_index]=sb26;break;"
					"case 27u:sboxs_values[sb_index]=sb27;break;"
					"case 28u:sboxs_values[sb_index]=sb28;break;"
					"case 29u:sboxs_values[sb_index]=sb29;break;"

					"case 30u:sboxs_values[sb_index]=sb30;break;"
					"case 31u:sboxs_values[sb_index]=sb31;break;"
				"}"
			"}"

			"barrier(CLK_LOCAL_MEM_FENCE);"

			"%s ^= subkey[%i] ^ (((sboxs_values[0] + sboxs_values[1]) ^ sboxs_values[2]) + sboxs_values[3]);"
			, L, R, i);
	}
	sprintf(source + strlen(source),
		"tmp_swap=R;"
		"R=L;"
		"L=tmp_swap^subkey[17];\n"
		
		"#define BF_REG_SET(i,L,R) "
			"if(i==(lid*32+0 )) {sb0 =L;sb1 =R;}"
			"if(i==(lid*32+2 )) {sb2 =L;sb3 =R;}"
			"if(i==(lid*32+4 )) {sb4 =L;sb5 =R;}"
			"if(i==(lid*32+6 )) {sb6 =L;sb7 =R;}"
			"if(i==(lid*32+8 )) {sb8 =L;sb9 =R;}"
			"if(i==(lid*32+10)) {sb10=L;sb11=R;}"
			"if(i==(lid*32+12)) {sb12=L;sb13=R;}"
			"if(i==(lid*32+14)) {sb14=L;sb15=R;}"

			"if(i==(lid*32+16)) {sb16=L;sb17=R;}"
			"if(i==(lid*32+18)) {sb18=L;sb19=R;}"
			"if(i==(lid*32+20)) {sb20=L;sb21=R;}"
			"if(i==(lid*32+22)) {sb22=L;sb23=R;}"
			"if(i==(lid*32+24)) {sb24=L;sb25=R;}"
			"if(i==(lid*32+26)) {sb26=L;sb27=R;}"
			"if(i==(lid*32+28)) {sb28=L;sb29=R;}"
			"if(i==(lid*32+30)) {sb30=L;sb31=R;}\n"
		);

	sprintf(source + strlen(source),
	"\n__attribute__((reqd_work_group_size(%i, 1, 1))) __kernel void bf_body_loop(__global uint* current_data)"
	"{"
		"__global uint* data_ptr = current_data+get_group_id(0);"
		"uint lid = get_local_id(0);"
		"uint L, R, tmp_swap;"

		"uint sb;"
		"uint sb_index=lid/8;"
		"uint sb_shift=24u-sb_index*8u;"
		"uint sb_min  =lid*32-256*sb_index;"

		// Load sboxs into registers
		"local uint sboxs_values[4];"
		"uint sb0 =GET_DATA(INDEX_SBOXS,lid*32+0 ),sb1 =GET_DATA(INDEX_SBOXS,lid*32+1 ),sb2 =GET_DATA(INDEX_SBOXS,lid*32+2 ),sb3 =GET_DATA(INDEX_SBOXS,lid*32+3 );"
		"uint sb4 =GET_DATA(INDEX_SBOXS,lid*32+4 ),sb5 =GET_DATA(INDEX_SBOXS,lid*32+5 ),sb6 =GET_DATA(INDEX_SBOXS,lid*32+6 ),sb7 =GET_DATA(INDEX_SBOXS,lid*32+7 );"
		"uint sb8 =GET_DATA(INDEX_SBOXS,lid*32+8 ),sb9 =GET_DATA(INDEX_SBOXS,lid*32+9 ),sb10=GET_DATA(INDEX_SBOXS,lid*32+10),sb11=GET_DATA(INDEX_SBOXS,lid*32+11);"
		"uint sb12=GET_DATA(INDEX_SBOXS,lid*32+12),sb13=GET_DATA(INDEX_SBOXS,lid*32+13),sb14=GET_DATA(INDEX_SBOXS,lid*32+14),sb15=GET_DATA(INDEX_SBOXS,lid*32+15);"
		"uint sb16=GET_DATA(INDEX_SBOXS,lid*32+16),sb17=GET_DATA(INDEX_SBOXS,lid*32+17),sb18=GET_DATA(INDEX_SBOXS,lid*32+18),sb19=GET_DATA(INDEX_SBOXS,lid*32+19);"
		"uint sb20=GET_DATA(INDEX_SBOXS,lid*32+20),sb21=GET_DATA(INDEX_SBOXS,lid*32+21),sb22=GET_DATA(INDEX_SBOXS,lid*32+22),sb23=GET_DATA(INDEX_SBOXS,lid*32+23);"
		"uint sb24=GET_DATA(INDEX_SBOXS,lid*32+24),sb25=GET_DATA(INDEX_SBOXS,lid*32+25),sb26=GET_DATA(INDEX_SBOXS,lid*32+26),sb27=GET_DATA(INDEX_SBOXS,lid*32+27);"
		"uint sb28=GET_DATA(INDEX_SBOXS,lid*32+28),sb29=GET_DATA(INDEX_SBOXS,lid*32+29),sb30=GET_DATA(INDEX_SBOXS,lid*32+30),sb31=GET_DATA(INDEX_SBOXS,lid*32+31);"

		// Load subkey
		"local uint subkey[18];"
		"if(lid<18u)"
			"subkey[lid]=GET_DATA(INDEX_SUBKEY,lid);"
		"barrier(CLK_LOCAL_MEM_FENCE);"

		"L = R = 0;", param->param0);

	// Change subkey
	for (cl_uint i = 0; i < 18; i += 2)
		sprintf(source + strlen(source),
		"BF_ENCRYPT_REG;"
		"if(lid==0){"
			"subkey[%i]=L;"
			"subkey[%i]=R;"
			// Save subkey
			"GET_DATA(INDEX_SUBKEY,%i)=L;"
			"GET_DATA(INDEX_SUBKEY,%i)=R;}"
		"barrier(CLK_LOCAL_MEM_FENCE);", i, i + 1, i, i + 1);
	// Change sboxs
	sprintf(source + strlen(source),
		"for (uint i = 0; i < 1024; i+=2)"
		"{"
			"BF_ENCRYPT_REG;"
			"BF_REG_SET(i,L,R);"
			// Save sboxs
			"if(lid==0){"
				"GET_DATA(INDEX_SBOXS,i  )=L;"
				"GET_DATA(INDEX_SBOXS,i+1)=R;}"
		"}"
	"}");
#endif
#endif

	// Final part: Encrypt
	sprintf(source+strlen(source),
	"\n__kernel void bf_encrypt_and_compare(__global uint* current_data,__global uint* output,const __global uint* binary_values,uint hash_index)"
	"{"
		"uint idx = get_global_id(0);"
		"__global uint* data_ptr = current_data+idx;"
		"__global uint* sboxs0 = data_ptr+(INDEX_SBOXS)*%uu;"
		"__global uint* sboxs1 = data_ptr+(INDEX_SBOXS+256)*%uu;"
		"__global uint* sboxs2 = data_ptr+(INDEX_SBOXS+512)*%uu;"
		"__global uint* sboxs3 = data_ptr+(INDEX_SBOXS+768)*%uu;"		
		"uint L, R, tmp_swap;", param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL);

	for (cl_uint i = 0; i < 18; i++)
		sprintf(source + strlen(source), "uint subkey%i = GET_DATA(INDEX_SUBKEY,%i);", i, i);

	// Encrypt
	sprintf(source + strlen(source), 
		"L = 0x4F727068;"
		"R = 0x65616E42;"
		"for (uint j = 0; j < 64; j++)"
		"{"
			"BF_ENCRYPT_GLOBAL;"
		"}"
		"if(L!=binary_values[6u*hash_index+0] || R!=binary_values[6u*hash_index+1])"
			"return;"

		"L = 0x65686F6C;"
		"R = 0x64657253;"
		"for (uint j = 0; j < 64; j++)"
		"{"
			"BF_ENCRYPT_GLOBAL;"
		"}"
		"if(L!=binary_values[6u*hash_index+2] || R!=binary_values[6u*hash_index+3])"
			"return;"

		"L = 0x63727944;"
		"R = 0x6F756274;"
		"for (uint j = 0; j < 64; j++)"
		"{"
			"BF_ENCRYPT_GLOBAL;"
		"}"
		/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
		"R&=0xFFFFFF00;"
		// Complete match
		"if(L==binary_values[6u*hash_index+4] && R==binary_values[6u*hash_index+5])"
		"{"
			"uint found=atomic_inc(output);"
			"output[2*found+1]=idx;"
			"output[2*found+2]=hash_index;"
		"}"
	"}");

	if(backup_vendor == OCL_VENDOR_INTEL)
		gpu->vendor = OCL_VENDOR_INTEL;
	return source;
}
PRIVATE int ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules)
{
	//      HD_4600        HD_7970        GTX_590       HD_6450    Adreno_330
	//     G_16 L  R	G_64  L    R      R G_64  L      L   G     L G_32 G_16	                           	                 	         
	// 16 -             501	                                 66               (512)
	// 32 -350 360      839 3.94k 1.37k          1.38K       69       57   58 (256)
	// 64 -510 360      877 3.94k 1.35k      608 1.39k  130  57    63 56   58 (128)
	// 128-572 356 65   917 4.05k 1.30k  348 623 1.42K  129  46    66 61   58 (64 )
	// 256-469 349 64  1060 4.09k 1.21k  340 655 1.41k  127        68 55   53 (32 )
	ocl_init_slow_hashes(param, gpu_index, gen, gpu_crypt, ocl_kernel_provider, use_rules, 1024 + 18 + 18 + (use_rules?0:8), BINARY_SIZE, SALT_SIZE, ocl_gen_kernels, ocl_work_body, 128);
	//hs_log(HS_LOG_DEBUG, "Test Suite", "Num Items: %i Workgroup: %i", param->NUM_KEYS_OPENCL, param->param0);

	// Crypt Kernels
	create_kernel(param, KERNEL_INDEX_BLOWFISH_SET_KEY	    , "blowfish_set_key");
	create_kernel(param, KERNEL_INDEX_BF_BODY_SALT		    , "bf_body_salt");
	create_kernel(param, KERNEL_INDEX_BF_BODY_LOOP		    , "bf_body_loop");
	create_kernel(param, KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE, "bf_encrypt_and_compare");
	
	// Set OpenCL kernel params
	int big_buffer_index = use_rules ? GPU_RULE_SLOW_BUFFER : GPU_CURRENT_KEY;
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BLOWFISH_SET_KEY], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BLOWFISH_SET_KEY], 1, sizeof(cl_mem), (void*)&param->mems[use_rules ? GPU_RULE_SLOW_TRANSFORMED_KEYS : big_buffer_index]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_SALT], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_SALT], 1, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);
	// Expensive key setup
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
#ifdef BF_USE_REGISTER_MEMORY
	create_kernel(param, KERNEL_INDEX_BF_BODY_XOR_KEY , "bf_body_xor_key");
	create_kernel(param, KERNEL_INDEX_BF_BODY_XOR_SALT, "bf_body_xor_salt");

	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_XOR_KEY ], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_XOR_SALT], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_XOR_SALT], 1, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);
#else
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 1, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);
#endif

	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_ENCRYPT_AND_COMPARE], 2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);

#ifndef BF_USE_REGISTER_MEMORY
	cl_uint current_salt_index = 0;
	cl_uint num_iters = 1;
	size_t bf_body_workgroup = param->param0;
	size_t num_work_items = param->NUM_KEYS_OPENCL;
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 2, sizeof(current_salt_index), (void*)&current_salt_index);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 3, sizeof(num_iters), (void*)&num_iters);
	pclFinish(param->queue);

	int64_t init = get_milliseconds();

	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_BF_BODY_LOOP], 1, NULL, &num_work_items, &bf_body_workgroup, 0, NULL, NULL);
	pclFinish(param->queue);

	uint64_t duration = get_milliseconds() - init;
	change_value_proportionally(&num_iters, (cl_uint)(duration*3/4));

	//hs_log(HS_LOG_DEBUG, "Bcrypt Loop", "num_iter:%i duration:%i Num Items: %i", num_iters, (int)duration, param->NUM_KEYS_OPENCL);

	cl_uint min_rounds = UINT32_MAX;
	BF_salt* salt = (BF_salt*)salts_values;
	for (uint32_t i = 0; i < num_diff_salts; i++)
		if (min_rounds > salt[i].rounds)
			min_rounds = salt[i].rounds;

	param->param1 = CLIP_RANGE(num_iters, 1, min_rounds);
#endif

	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Encrypt one block
#undef BF_ENCRYPT
#define BF_ENCRYPT \
	L ^= subkeys[0 ]; \
	R ^= subkeys[1 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[2 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[3 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[4 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[5 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[6 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[7 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[9 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[10] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[11] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[12] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[13] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[14] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[15] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[16] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	tmp_swap = R;\
	R = L;\
	L = tmp_swap ^ subkeys[17];
PRIVATE void blowfish_body_c_code_1(uint32_t* subkeys, uint32_t* sboxs)
{
	uint32_t L = 0, R = 0, tmp_swap;
	for (int i = 0; i < 18; i += 2)
	{
		BF_ENCRYPT;
		subkeys[i  ] = L;
		subkeys[i+1] = R;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		BF_ENCRYPT;
		sboxs[i  ] = L;
		sboxs[i+1] = R;
	}
}
PRIVATE void ocl_test_empty()
{
	uint32_t* sboxs = (uint32_t*)malloc((1024 + 18 + 6) * sizeof(uint32_t));
	uint32_t* subkeys = sboxs + 1024;
	uint32_t* crypt_result = subkeys + 18;

	BF_salt* salt = (BF_salt*)salts_values;
	// For all salts
	for(uint32_t current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++, salt++)
	{
		uint32_t L, R, tmp_swap;

		//blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
		memcpy(subkeys, BF_init_state.P, 18 * sizeof(uint32_t));
		memcpy(sboxs, BF_init_state.S, sizeof(BF_init_state.S));

		L = R = 0;
		for (int i = 0; i < 18; i+=2)
		{
			L ^= salt->salt[(i & 2)];
			R ^= salt->salt[(i & 2) + 1];
			BF_ENCRYPT;
			subkeys[i  ] = L;
			subkeys[i+1] = R;
		}
		for (int i = 0; i < 256*4; i+=2)
		{
			L ^= salt->salt[(i + 2) & 3];
			R ^= salt->salt[(i + 3) & 3];
			BF_ENCRYPT;
			sboxs[i  ] = L;
			sboxs[i+1] = R;
		}

		// Expensive key schedule
		for (uint32_t round = 0; round < salt->rounds; round++)
		{
			blowfish_body_c_code_1(subkeys, sboxs);

			// Salt part
			for (int i = 0; i < 18; i ++)
				subkeys[i] ^= salt->salt[i&3];

			blowfish_body_c_code_1(subkeys, sboxs);
		}

		// Final part: Encrypt
		for (int i = 0; i < 6; i += 2)
		{
			L = BF_magic_w[i];
			R = BF_magic_w[i+1];

			for (int j = 0; j < 64; j++)
			{
				BF_ENCRYPT;
			}

			crypt_result[i  ] = L;
			crypt_result[i+1] = R;
		}
		/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
		crypt_result[5] &= 0xFFFFFF00;

		// Search for a match
		uint32_t hash_index = salt_index[current_salt_index];
		// Partial match
		while (hash_index != NO_ELEM)
		{
			// Total match
			if (!memcmp(crypt_result, ((uint32_t*)binary_values) + hash_index * 6, BINARY_SIZE))
				password_was_found(hash_index, "");

			hash_index = same_salt_next[hash_index];
		}
	}

	free(sboxs);
}
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		ocl_test_empty(); 
		current_key_lenght = 1;
		report_keys_processed(1);
	}
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common + CHARSET_INDEX_IN_KERNELS, FALSE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common + PHRASES_INDEX_IN_KERNELS, FALSE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common + UTF8_INDEX_IN_KERNELS, FALSE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern int provider_index;

PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	int i, kernel2common_index;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (i = 0; i < LENGTH(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	return ocl_protocol_common_init(param, gpu_device_index, gen, gpu_crypt, kernels2common + kernel2common_index, TRUE);
}
#endif

Format bcrypt_format = {
	"BCRYPT",
	"Blowfish Crypt.",
	"",
	PLAINTEXT_LENGTH,
	BINARY_SIZE,
	SALT_SIZE,
	10,
	NULL,
	0,
	get_binary,
	binary2hex,
	DEFAULT_VALUE_MAP_INDEX,
	DEFAULT_VALUE_MAP_INDEX,
	bcrypt_line_is_valid,
	add_hash_from_line,
	NULL,
#ifdef _M_X64
	{{CPU_CAP_BMI, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_bmi}, {CPU_CAP_AVX, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
	#endif
#endif

#ifdef HS_OPENCL_SUPPORT
	{{PROTOCOL_CHARSET_OCL_NO_ALIGNED, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
#endif
};
