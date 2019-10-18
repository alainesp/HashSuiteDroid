// This file is part of Hash Suite password cracker,
// Copyright (c) 2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

typedef struct
{
	char          essid[36];
	unsigned char mac1[6];
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];
	unsigned char eapol[256];
	int           eapol_size;
	int           keyver;
	unsigned char keymic[16];
} hccap_t;

typedef struct
{
	uint32_t keymic[4];
	unsigned char prf_buffer[128];
	unsigned char eapol[256+64];
	uint32_t  eapol_blocks;
	int           keyver;
} hccap_bin;

#define PLAINTEXT_LENGTH	27//63
#define BINARY_SIZE			((uint32_t)(sizeof(hccap_bin)))
#define SALT_SIZE			64
#define NT_NUM_KEYS		    64


#define WPA_PREFIX		"$WPAPSK$"
#define WPA_PREFIX_LEN	8
PRIVATE int wpa_line_is_valid(char* hccap, char* unused0, char* unused, char* unused1)
{
	if (hccap && !_strnicmp(hccap, WPA_PREFIX, WPA_PREFIX_LEN))
	{
		hccap += WPA_PREFIX_LEN;
		char* base64 = strchr(hccap, '#');
		uint32_t essid_len = (uint32_t)(base64 - hccap);
		if (base64 && essid_len <= 51 && valid_base64_string(base64 + 1, 475))
		{
			// Check eapol size
			base64 += 110 * 4 + 1;
			uint32_t eapol_size;
			unsigned char* dst = (unsigned char*)&eapol_size;

			dst[0] = (base64_to_num[base64[2]] << 6) | (base64_to_num[base64[3]]);
			base64 += 4;
			dst[1] = (base64_to_num[base64[0]] << 2) | (base64_to_num[base64[1]] >> 4);
			dst[2] = (base64_to_num[base64[1]] << 4) | (base64_to_num[base64[2]] >> 2);
			dst[3] = (base64_to_num[base64[2]] << 6) | (base64_to_num[base64[3]]);

			if (eapol_size > 256)
				return FALSE;

			return TRUE;
		}
	}
	return FALSE;
}
PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* hccap, char* unused0, char* unused, char* unused1)
{
	char essid[64];

	if (hccap && !_strnicmp(hccap, WPA_PREFIX, WPA_PREFIX_LEN))
	{
		hccap += WPA_PREFIX_LEN;
		char* base64 = strchr(hccap, '#');
		uint32_t essid_len = (uint32_t)(base64 - hccap);
		if (base64 && essid_len <= 51 && valid_base64_string(base64 + 1, 475))
		{
			strncpy(essid, hccap, essid_len);
			essid[essid_len] = 0;
			// Insert hash and account
			return insert_hash_account1(param, essid, hccap, WPA_INDEX);
		}
	}

	return -1;
}

PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt_void)
{
	hccap_bin* out_bin = (hccap_bin*)binary;
	unsigned char* salt_essid = (unsigned char*)salt_void;
	
	hccap_t hccap;
	const unsigned char *essid = ciphertext;
	unsigned char *base64 = strrchr(ciphertext, '#');
	unsigned char *dst = ((unsigned char*)(&hccap)) + 36;

	// Copy essid and preprocess
	uint32_t essid_len = (uint32_t)(base64 - ciphertext);
	strncpy(salt_essid, essid, base64 - essid);
	memcpy(salt_essid + essid_len, "\x0\x0\x0\x1\x80", 5);
	memset(salt_essid + essid_len + 5, 0, 60 - (essid_len + 5));
	uint32_t* salt_essid_ptr = (uint32_t*)salt_essid;
	salt_essid_ptr[15] = (64 + essid_len + 4) << 3;
	swap_endianness_array(salt_essid_ptr, 14);
	base64++;

	// Base64 decode
	for (int i = 0; i < 118; i++)
	{
		dst[0] = (base64_to_num[base64[0]] << 2) | (base64_to_num[base64[1]] >> 4);
		dst[1] = (base64_to_num[base64[1]] << 4) | (base64_to_num[base64[2]] >> 2);
		dst[2] = (base64_to_num[base64[2]] << 6) | (base64_to_num[base64[3]]);
		dst += 3;
		base64 += 4;
	}
	dst[0] = (base64_to_num[base64[0]] << 2) | (base64_to_num[base64[1]] >> 4);
	dst[1] = (base64_to_num[base64[1]] << 4) | (base64_to_num[base64[2]] >> 2);

	// Manage binary
	memcpy(out_bin->keymic, hccap.keymic, 16);
	if (hccap.keyver != 1)
		swap_endianness_array(out_bin->keymic, 4);

	// Preproccess salt
	out_bin->keyver = hccap.keyver;
	// eapol
	out_bin->eapol_blocks = 1 + (hccap.eapol_size + 8) / 64;
	memcpy(out_bin->eapol, hccap.eapol, hccap.eapol_size);
	out_bin->eapol[hccap.eapol_size] = 0x80;
	memset(out_bin->eapol + hccap.eapol_size + 1, 0, sizeof(out_bin->eapol) - hccap.eapol_size - 1);
	uint32_t* eapol_ptr = ((uint32_t*)out_bin->eapol);
	if (hccap.keyver != 1)
		swap_endianness_array(eapol_ptr, sizeof(out_bin->eapol) / 4 - 2);

	eapol_ptr[16 * (out_bin->eapol_blocks-1) + ((hccap.keyver == 1) ? 14 : 15)] = (64 + hccap.eapol_size) << 3;

	// prf_512 preprocess----------------------------------------------------
	memcpy(out_bin->prf_buffer, "Pairwise key expansion", 23);

	//insert_mac
	int k = memcmp(hccap.mac1, hccap.mac2, 6);
	if (k > 0) {
		memcpy(out_bin->prf_buffer + 23, hccap.mac2, 6);
		memcpy(out_bin->prf_buffer + 6 + 23, hccap.mac1, 6);
	} else {
		memcpy(out_bin->prf_buffer + 23, hccap.mac1, 6);
		memcpy(out_bin->prf_buffer + 6 + 23, hccap.mac2, 6);
	}
	//insert_nonce
	k = memcmp(hccap.nonce1, hccap.nonce2, 32);
	if (k > 0) {
		memcpy(out_bin->prf_buffer + 12 + 23, hccap.nonce2, 32);
		memcpy(out_bin->prf_buffer + 32 + 12 + 23, hccap.nonce1, 32);
	} else {
		memcpy(out_bin->prf_buffer + 12 + 23, hccap.nonce1, 32);
		memcpy(out_bin->prf_buffer + 32 + 12 + 23, hccap.nonce2, 32);
	}
	out_bin->prf_buffer[99] = 0;
	out_bin->prf_buffer[100] = 0x80;
	memset(out_bin->prf_buffer + 101, 0, sizeof(out_bin->prf_buffer) - 4 - 101);

	uint32_t* prf_buffer_ptr = ((uint32_t*)out_bin->prf_buffer);
	prf_buffer_ptr[16+15] = (64 + 100) << 3;

	swap_endianness_array(prf_buffer_ptr, 104/4);
	//------------------------------------------------------------------------------
	
	return out_bin->keymic[0];
}
PRIVATE void binary2hex(const unsigned char* binary, const void* salt, unsigned char* ciphertext)
{
	uint32_t salt_essid[SALT_SIZE/sizeof(uint32_t)];
	memcpy(salt_essid, salt, SALT_SIZE);

	swap_endianness_array(salt_essid, 14);
	strcpy(ciphertext, (char*)salt_essid);
	strcat(ciphertext, "#");

	hccap_bin out_bin = ((hccap_bin*)binary)[0];
	hccap_t hccap;
	memset(&hccap, 0, sizeof(hccap));

	// Manage binary
	hccap.keyver = out_bin.keyver;
	memcpy(hccap.keymic, out_bin.keymic, 16);

	// eapol
	hccap.eapol_size = (((uint32_t*)out_bin.eapol)[16 * (out_bin.eapol_blocks - 1) + ((hccap.keyver == 1) ? 14 : 15)] >> 3) - 64;
	if (hccap.keyver != 1)
	{
		swap_endianness_array((uint32_t*)hccap.keymic, 4);
		swap_endianness_array((uint32_t*)out_bin.eapol, sizeof(out_bin.eapol) / 4 - 2);
	}
	memcpy(hccap.eapol, out_bin.eapol, hccap.eapol_size);

	swap_endianness_array((uint32_t*)out_bin.prf_buffer, 104 / 4);
	//insert_mac
	memcpy(hccap.mac1, out_bin.prf_buffer + 23, 6);
	memcpy(hccap.mac2, out_bin.prf_buffer + 6 + 23, 6);
	//insert_nonce
	memcpy(hccap.nonce1, out_bin.prf_buffer + 12 + 23, 32);
	memcpy(hccap.nonce2, out_bin.prf_buffer + 32 + 12 + 23, 32);

	// Write hash
	unsigned char* base64 = ciphertext + strlen((char*)ciphertext);
	unsigned char* r_data = ((unsigned char*)&hccap) + 36;
	for (int i = 0; i < 118; i++)
	{
		base64[0] = itoa64[(r_data[0] >> 2)];
		base64[1] = itoa64[((r_data[0] & 0x3) << 4) | (r_data[1] >> 4)];
		base64[2] = itoa64[((r_data[1] & 0xf) << 2) | (r_data[2] >> 6)];
		base64[3] = itoa64[r_data[2] & 0x3f];

		r_data += 3;
		base64 += 4;
	}
	base64[0] = itoa64[(r_data[0] >> 2)];
	base64[1] = itoa64[((r_data[0] & 0x3) << 4) | (r_data[1] >> 4)];
	base64[2] = itoa64[((r_data[1] & 0xf) << 2)];
	base64[3] = 0;
}

void sha1_process_block_simd(uint32_t* state, uint32_t* W, uint32_t simd_with);
void sha1_process_block_hmac_sha1(const uint32_t state[5], uint32_t sha1_hash[5], uint32_t W[16]);
void md5_process_block(uint32_t* state, const uint32_t* block);
void hmac_sha1_init_simd(uint32_t* key, uint32_t* key_lenghts, uint32_t simd_with, uint32_t multiplier, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void convert2be(uint32_t* nt_buffer, uint32_t NUM_KEYS)
{
	for (uint32_t i = 0; i < NUM_KEYS; i++, nt_buffer++)
	{
		// Remove 0x80
		uint32_t len = nt_buffer[7 * NUM_KEYS] >> 3;
		uint32_t _0x80_index = len / 4 * NUM_KEYS;
		((unsigned char*)nt_buffer)[_0x80_index * 4 + (len & 3)] = 0;
		len = (len + 3) / 4;

		for (uint32_t j = 0; j < len; j++)
		{
			SWAP_ENDIANNESS(nt_buffer[j * NUM_KEYS], nt_buffer[j * NUM_KEYS]);
		}
	}
}
#ifndef HS_TESTING
PRIVATE
#endif
void wpa_body_c_code(uint32_t* nt_buffer, uint32_t* essid_block, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W)
{
	uint32_t len = nt_buffer[7 * NT_NUM_KEYS] >> 3;
	len = (len + 3) / 4;

	hmac_sha1_init_simd(nt_buffer, &len, 1, NT_NUM_KEYS, opad_state, ipad_state, W);

	// Begin PBKDF2
	for (uint32_t i = 0; i < 2; i++)
	{
		memcpy(sha1_hash, ipad_state, 5 * sizeof(uint32_t));
		// Process the salt
		memcpy(W, essid_block, 64);
		if (i)
		{
			uint32_t salt_len = (essid_block[15] >> 3) - 64 - 1;
			// Change byte with 1 to 2
			((unsigned char*)W)[(salt_len&(~3u))+3-(salt_len&3u)] = 2;
		}
		sha1_process_block_simd(sha1_hash, W, 1);

		sha1_process_block_hmac_sha1(opad_state, sha1_hash, W);
		// Only copy first 16 bytes, since that is ALL this format uses
		memcpy(crypt_result + i * 5, sha1_hash, 5 * sizeof(uint32_t));

		for (uint32_t k = 1; k < 4096; k++)
		{
			sha1_process_block_hmac_sha1(ipad_state, sha1_hash, W);
			sha1_process_block_hmac_sha1(opad_state, sha1_hash, W);

			// Only XOR first 16 bytes, since that is ALL this format uses
			crypt_result[0+i*5] ^= sha1_hash[0];
			crypt_result[1+i*5] ^= sha1_hash[1];
			crypt_result[2+i*5] ^= sha1_hash[2];
			crypt_result[3+i*5] ^= sha1_hash[3];
			crypt_result[4+i*5] ^= sha1_hash[4];
		}
	}
}
#ifndef HS_TESTING
PRIVATE
#endif
void wpa_postprocess_c_code(hccap_bin* salt, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W)
{
	uint32_t len = 8;
	// prf_512------------------------------------------------------------------
	hmac_sha1_init_simd(crypt_result, &len, 1, 1, opad_state, ipad_state, W);

	// HMAC_Update
	memcpy(crypt_result, ipad_state, 5 * sizeof(uint32_t));
	memcpy(W, salt->prf_buffer, 64);
	sha1_process_block_simd(crypt_result, W, 1);
	memcpy(W, salt->prf_buffer + 64, 64);
	sha1_process_block_simd(crypt_result, W, 1);

	sha1_process_block_hmac_sha1(opad_state, crypt_result, W);
	// end prf_512--------------------------------------------------------------

	if (salt->keyver == 1)// HMAC_MD5
	{
		swap_endianness_array(crypt_result, 4);

		// hmac_md5_init 
		// ipad_state
		for (uint32_t i = 0; i < 4; i++)
			W[i] = crypt_result[i] ^ 0x36363636;
		memset(W + 4, 0x36, (16 - 4)*sizeof(uint32_t));

		ipad_state[0] = INIT_A;
		ipad_state[1] = INIT_B;
		ipad_state[2] = INIT_C;
		ipad_state[3] = INIT_D;
		md5_process_block(ipad_state, W);

		// opad_state
		for (uint32_t i = 0; i < 4; i++)
			W[i] = crypt_result[i] ^ 0x5C5C5C5C;
		memset(W + 4, 0x5C, (16 - 4)*sizeof(uint32_t));

		opad_state[0] = INIT_A;
		opad_state[1] = INIT_B;
		opad_state[2] = INIT_C;
		opad_state[3] = INIT_D;
		md5_process_block(opad_state, W);
	
		// HMAC_Update
		memcpy(crypt_result, ipad_state, 4 * sizeof(uint32_t));
		for (uint32_t i = 0; i < salt->eapol_blocks; i++)
		{
			memcpy(W, salt->eapol+i*64, 64);
			md5_process_block(crypt_result, W);
		}
		memcpy(W, crypt_result, 4 * sizeof(uint32_t));
		W[4] = 0x80;
		memset(W + 5, 0, (14 - 5) * sizeof(uint32_t));
		W[14] = (64 + 16) << 3;
		W[15] = 0;
		memcpy(crypt_result, opad_state, 4 * sizeof(uint32_t));
		md5_process_block(crypt_result, W);
	}
	else// HMAC_SHA1
	{
		len = 4;
		hmac_sha1_init_simd(crypt_result, &len, 1, 1, opad_state, ipad_state, W);
	
		// HMAC_Update
		memcpy(crypt_result, ipad_state, 5 * sizeof(uint32_t));
		for (uint32_t i = 0; i < salt->eapol_blocks; i++)
		{
			memcpy(W, salt->eapol+i*64, 64);
			sha1_process_block_simd(crypt_result, W, 1);
		}

		sha1_process_block_hmac_sha1(opad_state, crypt_result, W);
	}
}

#ifndef _M_X64
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	uint32_t* nt_buffer = (uint32_t*)calloc(17 * NT_NUM_KEYS, sizeof(uint32_t));
	unsigned char* key = (unsigned char*)calloc(PLAINTEXT_LENGTH + 1, sizeof(unsigned char));

	uint32_t crypt_result[10], sha1_hash[5], opad_state[5], ipad_state[5], W[16];

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		convert2be(nt_buffer, NT_NUM_KEYS);

		for(uint32_t i = 0; i < NT_NUM_KEYS; i++)
		{
			uint32_t* essid_block = (uint32_t*)salts_values;

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, essid_block+=SALT_SIZE/4)
			{
				wpa_body_c_code(nt_buffer+i, essid_block, crypt_result, sha1_hash, opad_state, ipad_state, W);

				// Search for a match
				uint32_t index = salt_index[j];

				// Partial match
				while(index != NO_ELEM)
				{
					hccap_bin* bin = ((hccap_bin*)binary_values) + index;
					wpa_postprocess_c_code(bin, crypt_result, sha1_hash, opad_state, ipad_state, W);

					// Total match
					if(!memcmp(crypt_result, bin->keymic, 16))
						password_was_found(index, utf8_be_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));
					
					index = same_salt_next[index];
				}
			}

			report_keys_processed(1);
		}
	}

	free(key);
	free(nt_buffer);
	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "arch_simd.h"

#ifdef HS_X86
// Calculate W in each iteration
void sha1_process_sha1_sse2(const __m128i* state, __m128i* sha1_hash, __m128i* W);

PRIVATE void crypt_utf8_coalesc_protocol_sse2(CryptParam* param)
{
	__m128i* nt_buffer = (__m128i*)_aligned_malloc(17 * 4 * NT_NUM_KEYS, 16);
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_BIG, sizeof(unsigned char));
	__m128i* crypt_result = (__m128i*)_aligned_malloc(sizeof(__m128i)*(10+5+5+5+16), 16);

	__m128i* sha1_hash = crypt_result + 10;
	__m128i* opad_state = sha1_hash + 5;
	__m128i* ipad_state = opad_state + 5;
	__m128i* W = ipad_state + 5;
	__m128i len;

	memset(nt_buffer, 0, 17 * 4 * NT_NUM_KEYS);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		convert2be((uint32_t*)nt_buffer, NT_NUM_KEYS);

		for(uint32_t i = 0; i < NT_NUM_KEYS/4; i++)
		{
			uint32_t* essid_block = (uint32_t*)salts_values;
			len = SSE2_SR(nt_buffer[7 * NT_NUM_KEYS / 4 + i], 3);
			len = SSE2_SR(SSE2_ADD(len, SSE2_CONST(3)), 2);

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, essid_block += SALT_SIZE/4)
			{
				hmac_sha1_init_simd((uint32_t*)(nt_buffer+i), (uint32_t*)(&len), 4, NT_NUM_KEYS/4, (uint32_t*)opad_state, (uint32_t*)ipad_state, (uint32_t*)W);

				// Begin PBKDF2
				for (uint32_t di = 0; di < 2; di++)
				{
					memcpy(sha1_hash, ipad_state, 5 * sizeof(__m128i));
					// Process the salt
					memcpy(W, essid_block, 64);
					if (di)
					{
						uint32_t salt_len = (essid_block[15] >> 3) - 64 - 1;
						// Change byte with 1 to 2
						((unsigned char*)W)[(salt_len&(~3u))+3-(salt_len&3u)] = 2;
					}
					for (uint32_t w_index = 15; w_index < 16; w_index--)
						W[w_index] = SSE2_CONST(((uint32_t*)W)[w_index]);
					sha1_process_block_simd((uint32_t*)sha1_hash, (uint32_t*)W, 4);

					sha1_process_sha1_sse2(opad_state, sha1_hash, W);
					// Copy
					memcpy(crypt_result + di * 5, sha1_hash, 5 * sizeof(__m128i));

					for (uint32_t k = 1; k < 4096; k++)
					{
						sha1_process_sha1_sse2(ipad_state, sha1_hash, W);
						sha1_process_sha1_sse2(opad_state, sha1_hash, W);

						// XOR
						crypt_result[0+di*5] = SSE2_XOR(crypt_result[0+di*5], sha1_hash[0]);
						crypt_result[1+di*5] = SSE2_XOR(crypt_result[1+di*5], sha1_hash[1]);
						crypt_result[2+di*5] = SSE2_XOR(crypt_result[2+di*5], sha1_hash[2]);
						crypt_result[3+di*5] = SSE2_XOR(crypt_result[3+di*5], sha1_hash[3]);
						crypt_result[4+di*5] = SSE2_XOR(crypt_result[4+di*5], sha1_hash[4]);
					}
				}

				// Search for a match
				for (uint32_t k = 0; k < 4; k++)
				{
					uint32_t index = salt_index[j];
					// Partial match
					while(index != NO_ELEM)
					{
						hccap_bin* bin = ((hccap_bin*)binary_values) + index;
						uint32_t result[8];
						for (uint32_t r_index = 0; r_index < 8; r_index++)
							result[r_index] = crypt_result[r_index].m128i_u32[k];
						wpa_postprocess_c_code(bin, result, (uint32_t*)sha1_hash, (uint32_t*)opad_state, (uint32_t*)ipad_state, (uint32_t*)W);

						// Total match
						if(!memcmp(result, bin->keymic, 16))
							password_was_found(index, utf8_be_coalesc2utf8_key((uint32_t*)nt_buffer, key, NT_NUM_KEYS, i*4+k));
					
						index = same_salt_next[index];
					}
				}
			}
			report_keys_processed(4);
		}
	}

	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);
	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// V128 Implementation (AVX and Neon)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void sha1_process_sha1_avx(const void* state, void* sha1_hash, void* W);

#define NT_NUM_KEYS_AVX 256
#define sha1_process_sha1_v128 sha1_process_sha1_avx
#endif

#ifdef HS_ARM
void sha1_process_sha1_neon(const void* state, void* sha1_hash, void* W);

#define NT_NUM_KEYS_AVX 64
#define sha1_process_sha1_v128 sha1_process_sha1_neon
#endif

PRIVATE void crypt_utf8_coalesc_protocol_v128(CryptParam* param)
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc(8 * 4 * NT_NUM_KEYS_AVX, 32);
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_BIG, sizeof(unsigned char));
	uint32_t* crypt_result = (uint32_t*)_aligned_malloc(sizeof(V128_WORD)* 2 * (10 + 5 + 5 + 5 + 16 + 1), 32);

	uint32_t* sha1_hash = crypt_result + 20*4;
	uint32_t* opad_state = sha1_hash + 10*4;
	uint32_t* ipad_state = opad_state + 10*4;
	uint32_t* W = ipad_state + 10*4;
	uint32_t* len = W + 16 * 2 * 4;

	memset(nt_buffer, 0, 8 * 4 * NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		convert2be((uint32_t*)nt_buffer, NT_NUM_KEYS_AVX);

		for(uint32_t i = 0; i < NT_NUM_KEYS_AVX/8; i++)
		{
			uint32_t* essid_block = (uint32_t*)salts_values;
			for (uint32_t j = 0; j < 8; j++)
				len[j] = ((nt_buffer[7 * NT_NUM_KEYS_AVX + 8 * i + j] >> 3) + 3) >> 2;

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, essid_block += SALT_SIZE/4)
			{
				hmac_sha1_init_simd(nt_buffer+i*8  , len  , 4, NT_NUM_KEYS_AVX/4, opad_state    , ipad_state    , W);
				hmac_sha1_init_simd(nt_buffer+i*8+4, len+4, 4, NT_NUM_KEYS_AVX/4, opad_state+5*4, ipad_state+5*4, W);

				// Begin PBKDF2
				for (uint32_t di = 0; di < 2; di++)
				{
					memcpy(sha1_hash, ipad_state, 10 * sizeof(V128_WORD));
					// Process the salt
					memcpy(W, essid_block, 64);
					if (di)
					{
						uint32_t salt_len = (essid_block[15] >> 3) - 64 - 1;
						// Change byte with 1 to 2
						((unsigned char*)W)[(salt_len&(~3u))+3-(salt_len&3u)] = 2;
					}
					for (uint32_t w_index = 15; w_index < 16; w_index--)
					{
						V128_WORD w_value = V128_CONST(W[w_index]);
						((V128_WORD*)W)[w_index+0 ] = w_value;
						((V128_WORD*)W)[w_index+16] = w_value;
					}
					// ipad
					sha1_process_block_simd(sha1_hash    , W     , 4);
					sha1_process_block_simd(sha1_hash+5*4, W+16*4, 4);
					// opad
					sha1_process_sha1_v128(opad_state, sha1_hash, W);
					memcpy(crypt_result + di * 10*4, sha1_hash, 10 * sizeof(V128_WORD));

					V128_WORD* crypt_result_ptr = (V128_WORD*)(crypt_result + di * 10*4);
					for (uint32_t k = 1; k < 4096; k++)
					{
						sha1_process_sha1_v128(ipad_state, sha1_hash, W);
						sha1_process_sha1_v128(opad_state, sha1_hash, W);

						// XOR
						for (uint32_t xor_count = 0; xor_count < 10; xor_count++)
							crypt_result_ptr[xor_count] = V128_XOR(crypt_result_ptr[xor_count], ((V128_WORD*)sha1_hash)[xor_count]);
					}
				}

				for(uint32_t k = 0; k < 8; k++)
				{
					// Search for a match
					uint32_t index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						hccap_bin* bin = ((hccap_bin*)binary_values) + index;
						uint32_t result[8];
						for (uint32_t r_index = 0; r_index < 8; r_index++)
							result[r_index] = crypt_result[(r_index%5 + 10*(r_index/5) + 5*(k/4)) * 4 + (k & 3)];
						wpa_postprocess_c_code(bin, result, sha1_hash, opad_state, ipad_state, W);

						// Total match
						if(!memcmp(result, bin->keymic, 16))
							password_was_found(index, utf8_be_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS_AVX, i*8+k));

						index = same_salt_next[index];
					}
				}
			}
			report_keys_processed(8);
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include <immintrin.h>

#define AVX2_WORD				__m256i
#define AVX2_AND(a,b)			_mm256_and_si256(a,b)
#define AVX2_XOR(a,b)			_mm256_xor_si256(a,b)
#define AVX2_ADD(a,b)			_mm256_add_epi32(a,b)
#define AVX2_SR(a,shift)		_mm256_srli_epi32(a,shift)
#define AVX2_CONST(u32_const)	_mm256_broadcastd_epi32(_mm_set1_epi32(u32_const))

void sha1_process_sha1_avx2(const void* state, void* sha1_hash, void* W);

PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc(8 * 4 * NT_NUM_KEYS_AVX, 32);
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_BIG, sizeof(unsigned char));
	AVX2_WORD* crypt_result = (AVX2_WORD*)_aligned_malloc(sizeof(AVX2_WORD)* 2 * (10 + 5 + 5 + 5 + 16), 32);

	AVX2_WORD* sha1_hash = crypt_result + 20;
	AVX2_WORD* opad_state = sha1_hash + 10;
	AVX2_WORD* ipad_state = opad_state + 10;
	AVX2_WORD* W = ipad_state + 10;
	AVX2_WORD len[2];

	memset(nt_buffer, 0, 8*4*NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		convert2be((uint32_t*)nt_buffer, NT_NUM_KEYS_AVX);

		for(uint32_t i = 0; i < NT_NUM_KEYS_AVX/16; i++)
		{
			uint32_t* essid_block = (uint32_t*)salts_values;
			len[0] = AVX2_SR(((AVX2_WORD*)nt_buffer)[7 * NT_NUM_KEYS_AVX / 8 + 2 * i + 0], 3);
			len[1] = AVX2_SR(((AVX2_WORD*)nt_buffer)[7 * NT_NUM_KEYS_AVX / 8 + 2 * i + 1], 3);
			len[0] = AVX2_SR(AVX2_ADD(len[0], AVX2_CONST(3)), 2);
			len[1] = AVX2_SR(AVX2_ADD(len[1], AVX2_CONST(3)), 2);

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, essid_block += SALT_SIZE/4)
			{
				hmac_sha1_init_simd(nt_buffer+i*16  , (uint32_t*)(len  ), 8, NT_NUM_KEYS_AVX/8, (uint32_t*)(opad_state  ), (uint32_t*)(ipad_state  ), (uint32_t*)W);
				hmac_sha1_init_simd(nt_buffer+i*16+8, (uint32_t*)(len+1), 8, NT_NUM_KEYS_AVX/8, (uint32_t*)(opad_state+5), (uint32_t*)(ipad_state+5), (uint32_t*)W);

				// Begin PBKDF2
				for (uint32_t di = 0; di < 2; di++)
				{
					memcpy(sha1_hash, ipad_state, 10 * sizeof(AVX2_WORD));
					// Process the salt
					memcpy(W, essid_block, 64);
					if (di)
					{
						uint32_t salt_len = (essid_block[15] >> 3) - 64 - 1;
						// Change byte with 1 to 2
						((unsigned char*)W)[(salt_len&(~3u))+3-(salt_len&3u)] = 2;
					}
					for (uint32_t w_index = 15; w_index < 16; w_index--)
					{
						AVX2_WORD w_value = AVX2_CONST(((uint32_t*)W)[w_index]);
						W[w_index+0 ] = w_value;
						W[w_index+16] = w_value;
					}
					// ipad
					sha1_process_block_simd((uint32_t*)(sha1_hash  ), (uint32_t*)(W   ), 8);
					sha1_process_block_simd((uint32_t*)(sha1_hash+5), (uint32_t*)(W+16), 8);
					// opad
					sha1_process_sha1_avx2(opad_state, sha1_hash, W);
					memcpy(crypt_result + di * 10, sha1_hash, 10 * sizeof(AVX2_WORD));

					AVX2_WORD* crypt_result_ptr = crypt_result + di * 10;
					for (uint32_t k = 1; k < 4096; k++)
					{
						sha1_process_sha1_avx2(ipad_state, sha1_hash, W);
						sha1_process_sha1_avx2(opad_state, sha1_hash, W);

						// XOR
						for (uint32_t xor_count = 0; xor_count < 10; xor_count++)
							crypt_result_ptr[xor_count] = AVX2_XOR(crypt_result_ptr[xor_count], sha1_hash[xor_count]);
					}
				}

				for(uint32_t k = 0; k < 16; k++)
				{
					// Search for a match
					uint32_t index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						hccap_bin* bin = ((hccap_bin*)binary_values) + index;
						uint32_t result[8];
						for (uint32_t r_index = 0; r_index < 8; r_index++)
							result[r_index] = crypt_result[r_index%5 + 10*(r_index/5) + 5*(k/8)].m256i_u32[k & 7];
						wpa_postprocess_c_code(bin, result, (uint32_t*)sha1_hash, (uint32_t*)opad_state, (uint32_t*)ipad_state, (uint32_t*)W);

						// Total match
						if(!memcmp(result, bin->keymic, 16))
							password_was_found(index, utf8_be_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS_AVX, i*16+k));

						index = same_salt_next[index];
					}
				}
			}
			report_keys_processed(16);
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT

#define KERNEL_INDEX_DCC2_SHA1_OPAD				0
#define KERNEL_INDEX_DCC2_COMPARE_RESULT		1
#define KERNEL_INDEX_DCC2_SHA1_PAD_MASK			2
#define KERNEL_INDEX_SHA1_PROCESS_SALT			3
#define KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE		4
#define KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC	5

#define KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL	6
#define KERNEL_INDEX_WPA_PRF_BLOCK				7
#define KERNEL_INDEX_WPA_MD5_PAD_MASK			8
#define KERNEL_INDEX_WPA_MD5_EAPOL_BLOCK		9
#define KERNEL_INDEX_WPA_MD5_FINAL				10

#define IPAD_STATE			15
#define OPAD_STATE			20
#define SHA1_HASH			0
#define CRYPT_RESULT		5

#define PRF_IPAD			0
#define PRF_OPAD			5
#define PRF_HASH			10
#define LAST_OPAD_STATE		25


PRIVATE void ocl_work_body(OpenCL_Param* param, int num_keys_filled, void* buffer, ocl_get_key* get_key)
{
	int64_t total_ks = num_diff_salts * 4095 * 2;
	size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_filled, param->max_work_group_size);
	int num_keys_reported = 0;

	// IPAD STATE
	cl_uint state = IPAD_STATE;
	cl_uint flag = 0x36363636;
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, sizeof(state), (void*)&state);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 2, sizeof(flag), (void*)&flag);
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
	pclFinish(param->queue);

	// OPAD STATE
	state = OPAD_STATE;
	flag = 0x5C5C5C5C;
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, sizeof(state), (void*)&state);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 2, sizeof(flag), (void*)&flag);
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++)
	{
		// Change last added char from 1 to 2
		for (uint32_t salt_change = CRYPT_RESULT, processed_calls=0; salt_change < (10+CRYPT_RESULT); salt_change+=5, processed_calls+=4095)
		{
			flag = salt_change - CRYPT_RESULT;
			pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 2, sizeof(current_salt_index), (void*)&current_salt_index);
			pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 3, sizeof(flag), (void*)&flag);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

			// Sha1 Opad
			state = SHA1_HASH;
			flag = OPAD_STATE;
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, sizeof(state), (void*)&state);
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 2, sizeof(flag), (void*)&flag);
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 3, sizeof(salt_change), (void*)&salt_change);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

			// SHA1 cycle
			state = OCL_SLOW_GET_CYCLE_PARAM(param->param0);
			pclSetKernelArg(param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, sizeof(state), (void*)&state);
			pclSetKernelArg(param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 2, sizeof(salt_change), (void*)&salt_change);
			size_t cycle_num_work_items = num_work_items;
#ifndef HS_OCL_REDUCE_REGISTER_USE
			if (OCL_SLOW_GET_KERNEL_INDEX(param->param0) == KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC)
				cycle_num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_work_items / 2, param->max_work_group_size);
#endif
			for (cl_uint k = 0; k < 4095 / state; k++)
			{
				pclEnqueueNDRangeKernel(param->queue, param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, NULL, &cycle_num_work_items, &param->max_work_group_size, 0, NULL, NULL);
				pclFinish(param->queue);
				if (!continue_attack)
					break;

				// Report keys processed from time to time to maintain good Rate
				int64_t processed_ks = current_salt_index * 4095 * 2 + k*state + processed_calls;
				int num_keys_reported_add = (int)(num_keys_filled*processed_ks / total_ks) - num_keys_reported;
				if (num_keys_reported_add > 0)
				{
					num_keys_reported += num_keys_reported_add;
					report_keys_processed(num_keys_reported_add);
				}
			}
			// Last part
			state = OCL_SLOW_GET_CYCLE_PARAM(param->param0) - 1;
			pclSetKernelArg(param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, sizeof(state), (void*)&state);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, NULL, &cycle_num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		}

		// PRF_512--------------------------------------------------------------------------------------------------------------------------------------------------------------
		// IPAD STATE
		state = CRYPT_RESULT;
		cl_uint crypt_len = 8;
		flag = 0x36363636;
		cl_uint crypt_out_index = PRF_IPAD;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 1, sizeof(state), (void*)&state);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 2, sizeof(crypt_len), (void*)&crypt_len);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 3, sizeof(flag), (void*)&flag);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 4, sizeof(crypt_out_index), (void*)&crypt_out_index);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		// OPAD STATE
		flag = 0x5C5C5C5C;
		crypt_out_index = PRF_OPAD;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 3, sizeof(flag), (void*)&flag);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 4, sizeof(crypt_out_index), (void*)&crypt_out_index);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		// Search for a match-----------------------------------------------------------------------------------------------------------------------------------------------------
		cl_uint hash_index = salt_index[current_salt_index];
		// Partial match
		while (hash_index != NO_ELEM && continue_attack)
		{
			hccap_bin* bin = ((hccap_bin*)binary_values) + hash_index;
			// Copy ipad to crypt_result
			crypt_out_index = PRF_HASH;
			cl_mem big_chunk = param->mems[GPU_RULE_SLOW_BUFFER] ? param->mems[GPU_RULE_SLOW_BUFFER] : param->mems[GPU_CURRENT_KEY];
			pclEnqueueCopyBuffer(param->queue, big_chunk, big_chunk, PRF_IPAD*sizeof(cl_uint)*param->NUM_KEYS_OPENCL, PRF_HASH*sizeof(cl_uint)*param->NUM_KEYS_OPENCL, 5 * sizeof(cl_uint)*param->NUM_KEYS_OPENCL, 0, NULL, NULL);

			// PRF-IPAD
			cl_uint prf_index = hash_index*BINARY_SIZE / 4 + 4;
			pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 2, sizeof(prf_index), (void*)&prf_index);
			pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 3, sizeof(crypt_out_index), (void*)&crypt_out_index);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			// repeat
			prf_index += 16;
			pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 2, sizeof(prf_index), (void*)&prf_index);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

			// PRF-OPAD
			state = PRF_OPAD;
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, sizeof(crypt_out_index), (void*)&crypt_out_index);
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 2, sizeof(state), (void*)&state);
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 3, sizeof(crypt_out_index), (void*)&crypt_out_index);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			// end prf_512--------------------------------------------------------------

			if (bin->keyver == 1)// HMAC_MD5
			{
				// OPAD STATE
				flag = 0x5C5C5C5C;
				crypt_out_index = LAST_OPAD_STATE;
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK], 1, sizeof(flag), (void*)&flag);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK], 2, sizeof(crypt_out_index), (void*)&crypt_out_index);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

				// IPAD STATE
				flag = 0x36363636;
				crypt_out_index = PRF_HASH;
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK], 1, sizeof(flag), (void*)&flag);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK], 2, sizeof(crypt_out_index), (void*)&crypt_out_index);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

				// HMAC_Update
				prf_index = hash_index*BINARY_SIZE / 4 + 4 + 32;
				for (cl_uint i = 0; i < bin->eapol_blocks; i++, prf_index+=16)
				{
					pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_EAPOL_BLOCK], 2, sizeof(prf_index), (void*)&prf_index);
					pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_MD5_EAPOL_BLOCK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
				}

				// OPAD end
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_MD5_FINAL], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			}
			else// HMAC_SHA1
			{
				// OPAD STATE
				state = PRF_HASH;
				crypt_len = 4;
				flag = 0x5C5C5C5C;
				crypt_out_index = LAST_OPAD_STATE;
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 1, sizeof(state), (void*)&state);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 2, sizeof(crypt_len), (void*)&crypt_len);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 3, sizeof(flag), (void*)&flag);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 4, sizeof(crypt_out_index), (void*)&crypt_out_index);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

				// IPAD STATE
				flag = 0x36363636;
				crypt_out_index = PRF_HASH;
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 3, sizeof(flag), (void*)&flag);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 4, sizeof(crypt_out_index), (void*)&crypt_out_index);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

				// HMAC_Update
				prf_index = hash_index*BINARY_SIZE / 4 + 4 + 32;
				pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 3, sizeof(crypt_out_index), (void*)&crypt_out_index);
				for (cl_uint i = 0; i < bin->eapol_blocks; i++, prf_index+=16)
				{
					pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 2, sizeof(prf_index), (void*)&prf_index);
					pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
				}

				state = LAST_OPAD_STATE;
				pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, sizeof(crypt_out_index), (void*)&crypt_out_index);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 2, sizeof(state), (void*)&state);
				pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 3, sizeof(crypt_out_index), (void*)&crypt_out_index);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			}

			// Compare results
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 1, sizeof(hash_index), (void*)&hash_index);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

			// Find matches
			cl_uint num_found;
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			pclFinish(param->queue);

			// GPU found some passwords
			if (num_found)
				ocl_common_process_found(param, &num_found, get_key, buffer, num_work_items, num_keys_filled);
					
			hash_index = same_salt_next[hash_index];
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

extern const char* md5_array_body;
extern const char* sha1_array_body;
extern const char* sha1_process_sha1_body;
PRIVATE char* ocl_gen_kernels(GPUDevice* gpu, oclKernel2Common* ocl_kernel_provider, OpenCL_Param* param, int multiplier)
{
	// Generate code
	char* source = malloc(128 * 1024 * multiplier);
	source[0] = 0;
	// Header definitions
	//if(num_passwords_loaded > 1 )
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
#ifdef USE_MAJ_SELECTOR
	switch (MAJ_SELECTOR)
	{
	case 0:
		sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 1:
		sprintf(source + strlen(source), "#define MAJ(b,d,c) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 2:
		sprintf(source + strlen(source), "#define MAJ(c,b,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 3:
		sprintf(source + strlen(source), "#define MAJ(c,d,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 4:
		sprintf(source + strlen(source), "#define MAJ(d,b,c) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 5:
		sprintf(source + strlen(source), "#define MAJ(d,c,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	}
#else
	sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
#endif
	
	//Initial values
	sprintf(source+strlen(source),
"#define INIT_A 0x67452301\n"
"#define INIT_B 0xefcdab89\n"
"#define INIT_C 0x98badcfe\n"
"#define INIT_D 0x10325476\n"
"#define INIT_E 0xC3D2E1F0\n"

"#define SQRT_2 0x5a827999\n"
"#define SQRT_3 0x6ed9eba1\n"
"#define CONST3 0x8F1BBCDC\n"
"#define CONST4 0xCA62C1D6\n"

"#define LOAD_BIG_ENDIAN(x) x=rotate(x,16U);x=((x&0x00FF00FF)<<8U)+((x>>8U)&0x00FF00FF);\n"

"#define IPAD_STATE			15\n"
"#define OPAD_STATE			20\n"
"#define SHA1_HASH			0\n"
"#define PRF_CRYPT_RESULT	10\n"
"#define LAST_OPAD_STATE    25\n"
"#define GET_DATA(STATE,index) current_key[(STATE+index)*%uu+idx]\n"
"#define NUM_KEYS_OPENCL %uu\n"
, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL);

	ocl_kernel_provider->gen_kernel(source, param->NUM_KEYS_OPENCL);

	sprintf(source+strlen(source),
	"\n#define DCC2_R(w0,w1,w2,w3)	W[w0]=rotate((W[w0]^W[w1]^W[w2]^W[w3]),1U)\n"
	"__kernel void dcc2_sha1_pad_mask(__global uint* current_key,uint state,uint flag,__global uint* wpa_key)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"
			// Convert the key into pads
			"uint i,len=wpa_key[7u*%uu+idx]>>4u;"
			"if(len>27u)return;"
			"for(i=0;i<len/4;i++)"
			"{"
				"uint tmp=wpa_key[i*%uu+idx];"
				"LOAD_BIG_ENDIAN(tmp);"
				"W[i]=tmp^flag;"
			"}"

			"uint tmp=wpa_key[i*%uu+idx];"
			"tmp^=0x80u<<(8u*(len&3u));"// Eliminate the final 0x80
			"LOAD_BIG_ENDIAN(tmp);"
			"W[i]=tmp^flag;"

			"for(i++;i<16;i++)"
				"W[i]=flag;"

			"uint A=INIT_A;"
			"uint B=INIT_B;"
			"uint C=INIT_C;"
			"uint D=INIT_D;"
			"uint E=INIT_E;"

			"%s"

			"GET_DATA(state,0)=INIT_A+A;"
			"GET_DATA(state,1)=INIT_B+B;"
			"GET_DATA(state,2)=INIT_C+C;"
			"GET_DATA(state,3)=INIT_D+D;"
			"GET_DATA(state,4)=INIT_E+E;"
	"}", param->NUM_KEYS_OPENCL*multiplier, param->NUM_KEYS_OPENCL*multiplier, param->NUM_KEYS_OPENCL*multiplier, sha1_array_body);

	sprintf(source+strlen(source),
	"\n__kernel void wpa_sha1_pad_mask_final(__global uint* current_key,uint data_in,uint len,uint flag,uint state_out)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"
			// Convert the key into pads
			"for(uint i=0;i<len;i++)"
				"W[i]=GET_DATA(data_in,i)^flag;"

			"for(uint i=len;i<16;i++)"
				"W[i]=flag;"

			"uint A=INIT_A;"
			"uint B=INIT_B;"
			"uint C=INIT_C;"
			"uint D=INIT_D;"
			"uint E=INIT_E;"

			"%s"

			"GET_DATA(state_out,0)=INIT_A+A;"
			"GET_DATA(state_out,1)=INIT_B+B;"
			"GET_DATA(state_out,2)=INIT_C+C;"
			"GET_DATA(state_out,3)=INIT_D+D;"
			"GET_DATA(state_out,4)=INIT_E+E;"
	"}", sha1_array_body);

		

sprintf(source+strlen(source),
	"\n__kernel void wpa_md5_pad_mask(__global uint* current_key,uint flag,uint state_out)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"
			// Convert the key into pads
			"for(uint i=0;i<4;i++)"
			"{"
				"uint tmp=GET_DATA(PRF_CRYPT_RESULT,i);"
				"LOAD_BIG_ENDIAN(tmp);"
				"W[i]=tmp^flag;"
			"}"

			"for(uint i=4;i<16;i++)"
				"W[i]=flag;"

			"uint a=INIT_A;"
			"uint b=INIT_B;"
			"uint c=INIT_C;"
			"uint d=INIT_D;"

			"%s"

			"GET_DATA(state_out,0)=INIT_A+a;"
			"GET_DATA(state_out,1)=INIT_B+b;"
			"GET_DATA(state_out,2)=INIT_C+c;"
			"GET_DATA(state_out,3)=INIT_D+d;"
	"}", md5_array_body);

sprintf(source+strlen(source),
	"\n__kernel void wpa_md5_eapol_block(__global uint* current_key,__global uint* bin,uint eapol_index)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"
			// Convert the key into pads
			"for(uint i=0;i<16;i++)"
				"W[i]=bin[eapol_index+i];"

			"uint a=GET_DATA(PRF_CRYPT_RESULT,0);"
			"uint b=GET_DATA(PRF_CRYPT_RESULT,1);"
			"uint c=GET_DATA(PRF_CRYPT_RESULT,2);"
			"uint d=GET_DATA(PRF_CRYPT_RESULT,3);"

			"%s"

			"GET_DATA(PRF_CRYPT_RESULT,0)+=a;"
			"GET_DATA(PRF_CRYPT_RESULT,1)+=b;"
			"GET_DATA(PRF_CRYPT_RESULT,2)+=c;"
			"GET_DATA(PRF_CRYPT_RESULT,3)+=d;"
	"}", md5_array_body);

sprintf(source+strlen(source),
	"\n__kernel void wpa_md5_final(__global uint* current_key)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"
			// Convert the key into pads
			"for(uint i=0;i<4;i++)"
				"W[i]=GET_DATA(PRF_CRYPT_RESULT,i);"

			"W[4]=0x80;"
			"for(uint i=5;i<14;i++)"
				"W[i]=0;"
			"W[14]=(64u+16u)<<3u;"
			"W[15]=0;"

			"uint a=GET_DATA(LAST_OPAD_STATE,0);"
			"uint b=GET_DATA(LAST_OPAD_STATE,1);"
			"uint c=GET_DATA(LAST_OPAD_STATE,2);"
			"uint d=GET_DATA(LAST_OPAD_STATE,3);"

			"%s"

			"GET_DATA(PRF_CRYPT_RESULT,0)=a+GET_DATA(LAST_OPAD_STATE,0);"
			"GET_DATA(PRF_CRYPT_RESULT,1)=b+GET_DATA(LAST_OPAD_STATE,1);"
			"GET_DATA(PRF_CRYPT_RESULT,2)=c+GET_DATA(LAST_OPAD_STATE,2);"
			"GET_DATA(PRF_CRYPT_RESULT,3)=d+GET_DATA(LAST_OPAD_STATE,3);"
	"}", md5_array_body);

sprintf(source+strlen(source),
	"\n__kernel void wpa_prf_block(__global uint* current_key,__global uint* bin,uint prf_index,uint state)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"
			// Convert the key into pads
			"for(uint i=0;i<16;i++)"
				"W[i]=bin[prf_index+i];"

			"uint A=GET_DATA(state,0);"
			"uint B=GET_DATA(state,1);"
			"uint C=GET_DATA(state,2);"
			"uint D=GET_DATA(state,3);"
			"uint E=GET_DATA(state,4);"

			"%s"

			"GET_DATA(state,0)+=A;"
			"GET_DATA(state,1)+=B;"
			"GET_DATA(state,2)+=C;"
			"GET_DATA(state,3)+=D;"
			"GET_DATA(state,4)+=E;"
	"}", sha1_array_body);

	sprintf(source+strlen(source),
	"\n__kernel void sha1_process_salt(__global uint* current_key,const __global uint* salt_values,uint current_salt_index,uint is_two)"
	"{"
			"uint idx=get_global_id(0);"
			"uint W[16];"

			//memcpy(&sha1_hash, &ipad_state, 5*sizeof(uint32_t));
			"uint A=GET_DATA(IPAD_STATE,0);"
			"uint B=GET_DATA(IPAD_STATE,1);"
			"uint C=GET_DATA(IPAD_STATE,2);"
			"uint D=GET_DATA(IPAD_STATE,3);"
			"uint E=GET_DATA(IPAD_STATE,4);"

			"GET_DATA(SHA1_HASH,0)=A;"
			"GET_DATA(SHA1_HASH,1)=B;"
			"GET_DATA(SHA1_HASH,2)=C;"
			"GET_DATA(SHA1_HASH,3)=D;"
			"GET_DATA(SHA1_HASH,4)=E;"

			// Copy
			"for(uint i=0;i<16;i++)"
				"W[i]=salt_values[16*current_salt_index+i];"

			"if(is_two){"
				"uint salt_len=(W[15]>>3)-64-1;"
				// Change byte with 1 to 2
				"W[salt_len/4]+=1u<<(24-8*(salt_len&3));"
			"}"

			"%s"

			"GET_DATA(SHA1_HASH,0)+=A;"
			"GET_DATA(SHA1_HASH,1)+=B;"
			"GET_DATA(SHA1_HASH,2)+=C;"
			"GET_DATA(SHA1_HASH,3)+=D;"
			"GET_DATA(SHA1_HASH,4)+=E;"
	"}", sha1_array_body);

sprintf(source + strlen(source), "\n#undef DCC2_R\n"
	"#define DCC2_R(w0,w1,w2,w3)	(W ## w0)=rotate((W ## w0)^(W ## w1)^(W ## w2)^(W ## w3),1U)\n"
	"\n__kernel void dcc2_sha1_opad(__global uint* current_key,uint sha1_hash,uint opad_state, uint crypt_result)"
		"{"
				"uint W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;"
				"uint idx=get_global_id(0);"

				"W0=GET_DATA(sha1_hash,0);"
				"W1=GET_DATA(sha1_hash,1);"
				"W2=GET_DATA(sha1_hash,2);"
				"W3=GET_DATA(sha1_hash,3);"
				"W4=GET_DATA(sha1_hash,4);"

				"uint A=GET_DATA(opad_state,0);"
				"uint B=GET_DATA(opad_state,1);"
				"uint C=GET_DATA(opad_state,2);"
				"uint D=GET_DATA(opad_state,3);"
				"uint E=GET_DATA(opad_state,4);"

				"%s"

				"A+=GET_DATA(opad_state,0);"
				"B+=GET_DATA(opad_state,1);"
				"C+=GET_DATA(opad_state,2);"
				"D+=GET_DATA(opad_state,3);"
				"E+=GET_DATA(opad_state,4);"

				"GET_DATA(sha1_hash,0)=A;"
				"GET_DATA(sha1_hash,1)=B;"
				"GET_DATA(sha1_hash,2)=C;"
				"GET_DATA(sha1_hash,3)=D;"
				"GET_DATA(sha1_hash,4)=E;"

				"GET_DATA(crypt_result,0)=A;"
				"GET_DATA(crypt_result,1)=B;"
				"GET_DATA(crypt_result,2)=C;"
				"GET_DATA(crypt_result,3)=D;"
				"GET_DATA(crypt_result,4)=E;"
		"}", sha1_process_sha1_body);

sprintf(source + strlen(source), 
	"\n__kernel void pbkdf2_hmac_sha1_cycle(__global uint* current_key,uint iter_count,uint salt_crypt_result)"
		"{"
				"uint W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;"
				"uint idx=get_global_id(0);"

				"W0=GET_DATA(SHA1_HASH,0);"
				"W1=GET_DATA(SHA1_HASH,1);"
				"W2=GET_DATA(SHA1_HASH,2);"
				"W3=GET_DATA(SHA1_HASH,3);"
				"W4=GET_DATA(SHA1_HASH,4);"

				"uint ipad_state0=GET_DATA(IPAD_STATE,0);"
				"uint ipad_state1=GET_DATA(IPAD_STATE,1);"
				"uint ipad_state2=GET_DATA(IPAD_STATE,2);"
				"uint ipad_state3=GET_DATA(IPAD_STATE,3);"
				"uint ipad_state4=GET_DATA(IPAD_STATE,4);"

				"uint opad_state0=GET_DATA(OPAD_STATE,0);"
				"uint opad_state1=GET_DATA(OPAD_STATE,1);"
				"uint opad_state2=GET_DATA(OPAD_STATE,2);"
				"uint opad_state3=GET_DATA(OPAD_STATE,3);"
				"uint opad_state4=GET_DATA(OPAD_STATE,4);"

				"uint result0=GET_DATA(salt_crypt_result,0);"
				"uint result1=GET_DATA(salt_crypt_result,1);"
				"uint result2=GET_DATA(salt_crypt_result,2);"
				"uint result3=GET_DATA(salt_crypt_result,3);"
				"uint result4=GET_DATA(salt_crypt_result,4);"

				"for(uint i=0;i<iter_count;i++){"

					"uint A=ipad_state0;"
					"uint B=ipad_state1;"
					"uint C=ipad_state2;"
					"uint D=ipad_state3;"
					"uint E=ipad_state4;"

					"%s"

					"W0=ipad_state0+A;"
					"W1=ipad_state1+B;"
					"W2=ipad_state2+C;"
					"W3=ipad_state3+D;"
					"W4=ipad_state4+E;"

					"A=opad_state0;"
					"B=opad_state1;"
					"C=opad_state2;"
					"D=opad_state3;"
					"E=opad_state4;"

					"%s"

					"W0=opad_state0+A;"
					"W1=opad_state1+B;"
					"W2=opad_state2+C;"
					"W3=opad_state3+D;"
					"W4=opad_state4+E;"

					"result0^=W0;"
					"result1^=W1;"
					"result2^=W2;"
					"result3^=W3;"
					"result4^=W4;"
				"}"

				"GET_DATA(SHA1_HASH,0)=W0;"
				"GET_DATA(SHA1_HASH,1)=W1;"
				"GET_DATA(SHA1_HASH,2)=W2;"
				"GET_DATA(SHA1_HASH,3)=W3;"
				"GET_DATA(SHA1_HASH,4)=W4;"

				"GET_DATA(salt_crypt_result,0)=result0;"
				"GET_DATA(salt_crypt_result,1)=result1;"
				"GET_DATA(salt_crypt_result,2)=result2;"
				"GET_DATA(salt_crypt_result,3)=result3;"
				"GET_DATA(salt_crypt_result,4)=result4;"
			"}\n", sha1_process_sha1_body, sha1_process_sha1_body);

#ifndef HS_OCL_REDUCE_REGISTER_USE
sprintf(source + strlen(source), 
	"\n#define  GET_DATA_VEC(STATE,index) vload2((STATE+index)*NUM_KEYS_OPENCL/2+idx,current_key)\n"
	"#define  SET_DATA_VEC(STATE,index,data) vstore2(data,(STATE+index)*NUM_KEYS_OPENCL/2+idx,current_key)\n"
	"__kernel void pbkdf2_hmac_sha1_cycle_vec(__global uint* current_key,uint iter_count,uint salt_crypt_result)"
		"{"
				"uint2 W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;"
				"uint idx=get_global_id(0);"

				"W0=GET_DATA_VEC(SHA1_HASH,0);"
				"W1=GET_DATA_VEC(SHA1_HASH,1);"
				"W2=GET_DATA_VEC(SHA1_HASH,2);"
				"W3=GET_DATA_VEC(SHA1_HASH,3);"
				"W4=GET_DATA_VEC(SHA1_HASH,4);"

				"uint2 ipad_state0=GET_DATA_VEC(IPAD_STATE,0);"
				"uint2 ipad_state1=GET_DATA_VEC(IPAD_STATE,1);"
				"uint2 ipad_state2=GET_DATA_VEC(IPAD_STATE,2);"
				"uint2 ipad_state3=GET_DATA_VEC(IPAD_STATE,3);"
				"uint2 ipad_state4=GET_DATA_VEC(IPAD_STATE,4);"

				"uint2 opad_state0=GET_DATA_VEC(OPAD_STATE,0);"
				"uint2 opad_state1=GET_DATA_VEC(OPAD_STATE,1);"
				"uint2 opad_state2=GET_DATA_VEC(OPAD_STATE,2);"
				"uint2 opad_state3=GET_DATA_VEC(OPAD_STATE,3);"
				"uint2 opad_state4=GET_DATA_VEC(OPAD_STATE,4);"

				"uint2 result0=GET_DATA_VEC(salt_crypt_result,0);"
				"uint2 result1=GET_DATA_VEC(salt_crypt_result,1);"
				"uint2 result2=GET_DATA_VEC(salt_crypt_result,2);"
				"uint2 result3=GET_DATA_VEC(salt_crypt_result,3);"
				"uint2 result4=GET_DATA_VEC(salt_crypt_result,4);"

				"for(uint i=0;i<iter_count;i++){"

					"uint2 A=ipad_state0;"
					"uint2 B=ipad_state1;"
					"uint2 C=ipad_state2;"
					"uint2 D=ipad_state3;"
					"uint2 E=ipad_state4;"

					"%s"

					"W0=ipad_state0+A;"
					"W1=ipad_state1+B;"
					"W2=ipad_state2+C;"
					"W3=ipad_state3+D;"
					"W4=ipad_state4+E;"

					"A=opad_state0;"
					"B=opad_state1;"
					"C=opad_state2;"
					"D=opad_state3;"
					"E=opad_state4;"

					"%s"

					"W0=opad_state0+A;"
					"W1=opad_state1+B;"
					"W2=opad_state2+C;"
					"W3=opad_state3+D;"
					"W4=opad_state4+E;"

					"result0^=W0;"
					"result1^=W1;"
					"result2^=W2;"
					"result3^=W3;"
					"result4^=W4;"
				"}"

				"SET_DATA_VEC(SHA1_HASH,0,W0);"
				"SET_DATA_VEC(SHA1_HASH,1,W1);"
				"SET_DATA_VEC(SHA1_HASH,2,W2);"
				"SET_DATA_VEC(SHA1_HASH,3,W3);"
				"SET_DATA_VEC(SHA1_HASH,4,W4);"

				"SET_DATA_VEC(salt_crypt_result,0,result0);"
				"SET_DATA_VEC(salt_crypt_result,1,result1);"
				"SET_DATA_VEC(salt_crypt_result,2,result2);"
				"SET_DATA_VEC(salt_crypt_result,3,result3);"
				"SET_DATA_VEC(salt_crypt_result,4,result4);"
			"}", sha1_process_sha1_body, sha1_process_sha1_body);
#endif

sprintf(source + strlen(source),
		"\n__kernel void dcc2_compare_result(__global uint* current_key,uint hash_index,__global uint* output,const __global uint* binary_values)"
		"{"
				"uint idx=get_global_id(0);"
				"if(GET_DATA(PRF_CRYPT_RESULT,0)==binary_values[%uu*hash_index+0]&&"
				   "GET_DATA(PRF_CRYPT_RESULT,1)==binary_values[%uu*hash_index+1]&&"
				   "GET_DATA(PRF_CRYPT_RESULT,2)==binary_values[%uu*hash_index+2]&&"
				   "GET_DATA(PRF_CRYPT_RESULT,3)==binary_values[%uu*hash_index+3])"
				"{"
						"uint found=atomic_inc(output);"
						"output[2*found+1]=idx;"
						"output[2*found+2]=hash_index;"
				"}"
		"}", BINARY_SIZE/4, BINARY_SIZE/4, BINARY_SIZE/4, BINARY_SIZE/4);

	return source;
}

PRIVATE int ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules)
{
	// Only one hash
	// For Intel HD 4600 best DIVIDER=1-2
	//  1	4.14K
	//	2	4.15K
	//	4	4.00K
	//	8	3.58K
	//	16	2.95K
	// For AMD HD 7970 best DIVIDER=1-2
	//  1	144K
	//	2	144K
	//	4	142K
	//	8	141K
	//	16	137K
	//	32	131K
	//	64	112K
	// For Nvidia GTX 590 best DIVIDER=1-32
	//  1	32.7K
	//	2	32.8K
	//	4	32.8K
	//	8	32.8K
	//	16	32.8K
	//	32	32.8K
	//	64	31.2K
	//	128	17.7K
	if (!ocl_init_slow_hashes(param, gpu_index, gen, gpu_crypt, ocl_kernel_provider, use_rules, 5 + 5 + 5 + 10 + 5, BINARY_SIZE, SALT_SIZE, ocl_gen_kernels, ocl_work_body, 2))
		return FALSE;

	// Crypt Kernels
	create_kernel(param, KERNEL_INDEX_DCC2_SHA1_PAD_MASK		, "dcc2_sha1_pad_mask");
	create_kernel(param, KERNEL_INDEX_SHA1_PROCESS_SALT			, "sha1_process_salt");
	create_kernel(param, KERNEL_INDEX_DCC2_SHA1_OPAD			, "dcc2_sha1_opad");
	create_kernel(param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE	, "pbkdf2_hmac_sha1_cycle");
#ifndef HS_OCL_REDUCE_REGISTER_USE
	create_kernel(param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC, "pbkdf2_hmac_sha1_cycle_vec");
#endif
	create_kernel(param, KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL	, "wpa_sha1_pad_mask_final");
	create_kernel(param, KERNEL_INDEX_WPA_PRF_BLOCK				, "wpa_prf_block");

	create_kernel(param, KERNEL_INDEX_WPA_MD5_PAD_MASK			, "wpa_md5_pad_mask");
	create_kernel(param, KERNEL_INDEX_WPA_MD5_EAPOL_BLOCK		, "wpa_md5_eapol_block");
	create_kernel(param, KERNEL_INDEX_WPA_MD5_FINAL				, "wpa_md5_final");
	
	create_kernel(param, KERNEL_INDEX_DCC2_COMPARE_RESULT		, "dcc2_compare_result");

	// Set OpenCL kernel params
	uint32_t zero = 0;
	int big_buffer_index = use_rules ? GPU_RULE_SLOW_BUFFER : GPU_CURRENT_KEY;
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 3, sizeof(cl_mem), (void*)&param->mems[use_rules ? GPU_RULE_SLOW_TRANSFORMED_KEYS : big_buffer_index]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 1, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);
	
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD]		   , 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE], 2, sizeof(zero), (void*)&zero);
#ifndef HS_OCL_REDUCE_REGISTER_USE
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC], 2, sizeof(zero), (void*)&zero);
#endif

	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_SHA1_PAD_MASK_FINAL], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_PRF_BLOCK], 1, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_PAD_MASK   ], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_EAPOL_BLOCK], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_EAPOL_BLOCK], 1, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_WPA_MD5_FINAL      ], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 2, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);

	pclFinish(param->queue);

	// Select best params
	ocl_best_workgroup_pbkdf2(param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC);

	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		current_key_lenght = 1;
		report_keys_processed(1);

		cl_uint nt_buffer[8*NT_NUM_KEYS], crypt_result[12], sha1_hash[5], opad_state[5], ipad_state[5], W[16];
		uint32_t* essid_block = (uint32_t*)salts_values;
		memset(nt_buffer, 0, sizeof(nt_buffer));

		// For all salts
		for(uint32_t j = 0; j < num_diff_salts; j++, essid_block+=SALT_SIZE/4)
		{
			wpa_body_c_code(nt_buffer, essid_block, crypt_result, sha1_hash, opad_state, ipad_state, W);

			// Search for a match
			uint32_t index = salt_index[j];

			// Partial match
			while(index != NO_ELEM)
			{
				hccap_bin* bin = ((hccap_bin*)binary_values) + index;
				wpa_postprocess_c_code(bin, crypt_result, sha1_hash, opad_state, ipad_state, W);

				// Total match
				if(!memcmp(crypt_result, bin->keymic, 16))
					password_was_found(index, "");
					
				index = same_salt_next[index];
			}
		}
	}
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_dcc2_crypt, kernels2common + CHARSET_INDEX_IN_KERNELS, FALSE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_dcc2_crypt, kernels2common + PHRASES_INDEX_IN_KERNELS, FALSE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_dcc2_crypt, kernels2common + UTF8_INDEX_IN_KERNELS, FALSE);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern int provider_index;

PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	int i, kernel2common_index;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	return ocl_protocol_common_init(param, gpu_device_index, gen, gpu_dcc2_crypt, kernels2common + kernel2common_index, TRUE);
}
#endif

Format wpa_format = {
	"WPA-PSK",
	"Wi-Fi Protected Access (WPA / WPA2), Pre-shared key (PSK, also known as Personal mode).",
	WPA_PREFIX,
	PLAINTEXT_LENGTH,
	BINARY_SIZE,
	SALT_SIZE,
	9,
	NULL,
	0,
	get_binary,
	binary2hex,
	DEFAULT_VALUE_MAP_INDEX,
	DEFAULT_VALUE_MAP_INDEX,
	wpa_line_is_valid,
	add_hash_from_line,
	NULL,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_v128}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_v128}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
	#endif
#endif

#ifdef HS_OPENCL_SUPPORT
	{{PROTOCOL_CHARSET_OCL_NO_ALIGNED, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
#endif
};
