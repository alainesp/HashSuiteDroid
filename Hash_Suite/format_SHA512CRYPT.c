// This file is part of Hash Suite password cracker,
// Copyright (c) 2020 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

#define BINARY_SIZE				64
#define SALT_SIZE				sizeof(crypt_sha256_salt)
#define MAX_SALT_SIZE			16
#define MAX_KEY_SIZE			27
#define ROUNDS_DEFAULT          5000//Default number of rounds if not explicitly specified.
#define ROUNDS_PREFIX "rounds="

typedef struct {
	uint32_t rounds;
	uint32_t saltlen;
	uint8_t salt[MAX_SALT_SIZE];
} crypt_sha256_salt;


PRIVATE int is_valid(char* user_name, char* ciphertext, char* unused, char* unused1)
{
	if (ciphertext == NULL)
		ciphertext = user_name;

	if (ciphertext)
	{
		if (strncmp(ciphertext, "$6$", 3))
			return FALSE;

		ciphertext += 3;
		if (!strncmp(ciphertext, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1))
		{
			const char* num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
			char* endp;
			if (!strtoul(num, &endp, 10))
				return FALSE;
			if (*endp == '$')
				ciphertext = endp + 1;
			else
				return FALSE;
		}

		char* pos = strchr(ciphertext, '$');
		if (!pos || (pos - ciphertext) < 1 || (pos - ciphertext) > 16)
			return FALSE;

		pos++;
		if (!valid_base64_string(pos, 86))
			return FALSE;

		if (base64_to_num[pos[85]] & 0xFC)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* ciphertext, char* unused, char* unused1)
{
	if (ciphertext == NULL)
	{
		ciphertext = user_name;
		user_name = NULL;
	}

	if (ciphertext)
	{
		if (strncmp(ciphertext, "$6$", 3))
			return -1;

		char* all_ciphertext = ciphertext;

		ciphertext += 3;
		if (!strncmp(ciphertext, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1))
		{
			const char* num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
			char* endp;
			if (!strtoul(num, &endp, 10))
				return -1;
			if (*endp == '$')
				ciphertext = endp + 1;
			else
				return -1;
		}

		char* pos = strchr(ciphertext, '$');
		if (!pos || (pos - ciphertext) < 1 || (pos - ciphertext) > 16)
			return -1;

		pos++;
		if (!valid_base64_string(pos, 86))
			return -1;

		if (base64_to_num[pos[85]] & 0xFC)
			return -1;

		return insert_hash_account1(param, user_name, all_ciphertext, SHA512CRYPT_INDEX);
	}

	return -1;
}
#define TO_BINARY(b1, b2, b3) \
	value = \
		 (uint32_t)base64_to_num[pos[0]] | \
		((uint32_t)base64_to_num[pos[1]] << 6) | \
		((uint32_t)base64_to_num[pos[2]] << 12) | \
		((uint32_t)base64_to_num[pos[3]] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	// Binary
	unsigned char* out = (unsigned char*)binary;
	uint32_t value;

	const char* pos = ciphertext + 3;
	// Salt
	crypt_sha256_salt* out_salt = (crypt_sha256_salt*)salt;
	memset(out_salt, 0, sizeof(crypt_sha256_salt));
	out_salt->rounds = ROUNDS_DEFAULT;
	
	if (!strncmp(pos, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1))
	{
		const char* num = pos + sizeof(ROUNDS_PREFIX) - 1;
		out_salt->rounds = strtoul(num, (char**)(&pos), 10);
		pos++;
	}

	const char* salt_end = strchr(pos, '$');
	out_salt->saltlen = (uint32_t)(salt_end - pos);
	memcpy(out_salt->salt, pos, out_salt->saltlen);
	pos = salt_end + 1;

	TO_BINARY(0, 21, 42);
	TO_BINARY(22, 43, 1);
	TO_BINARY(44, 2, 23);
	TO_BINARY(3, 24, 45);
	TO_BINARY(25, 46, 4);
	TO_BINARY(47, 5, 26);
	TO_BINARY(6, 27, 48);
	TO_BINARY(28, 49, 7);
	TO_BINARY(50, 8, 29);
	TO_BINARY(9, 30, 51);
	TO_BINARY(31, 52, 10);
	TO_BINARY(53, 11, 32);
	TO_BINARY(12, 33, 54);
	TO_BINARY(34, 55, 13);
	TO_BINARY(56, 14, 35);
	TO_BINARY(15, 36, 57);
	TO_BINARY(37, 58, 16);
	TO_BINARY(59, 17, 38);
	TO_BINARY(18, 39, 60);
	TO_BINARY(40, 61, 19);
	TO_BINARY(62, 20, 41);
	out[63] = ((uint32_t)base64_to_num[pos[0]]) | ((uint32_t)base64_to_num[pos[1]] << 6);

	swap_endianness_array64(binary, 8);

	return 0;
}
#define TO_BASE64(b1, b2, b3) \
	value = out[b3] | (out[b2] << 8) | (out[b1] << 16);\
	\
	pos[0] = itoa64[(value    ) & 63];\
	pos[1] = itoa64[(value>>6 ) & 63];\
	pos[2] = itoa64[(value>>12) & 63];\
	pos[3] = itoa64[(value>>18) & 63];\
	pos += 4;
PRIVATE void binary2hex(const void* binary, const uint8_t* salt, unsigned char* ciphertext)
{
	// State
	uint64_t tmp_state[8];
	memcpy(tmp_state, binary, sizeof(tmp_state));
	swap_endianness_array64(tmp_state, 8);
	// Salt
	const crypt_sha256_salt* out_salt = (const crypt_sha256_salt*)salt;

	// Export hash
	if(out_salt->rounds == ROUNDS_DEFAULT)
		sprintf(ciphertext, "%.*s$", out_salt->saltlen, out_salt->salt);
	else
		sprintf(ciphertext, "rounds=%i$%.*s$", out_salt->rounds, out_salt->saltlen, out_salt->salt);
	char* pos = ciphertext + strlen(ciphertext);
	const unsigned char* out = (const unsigned char*)tmp_state;
	uint32_t value;

	TO_BASE64(0, 21, 42);
	TO_BASE64(22, 43, 1);
	TO_BASE64(44, 2, 23);
	TO_BASE64(3, 24, 45);
	TO_BASE64(25, 46, 4);
	TO_BASE64(47, 5, 26);
	TO_BASE64(6, 27, 48);
	TO_BASE64(28, 49, 7);
	TO_BASE64(50, 8, 29);
	TO_BASE64(9, 30, 51);
	TO_BASE64(31, 52, 10);
	TO_BASE64(53, 11, 32);
	TO_BASE64(12, 33, 54);
	TO_BASE64(34, 55, 13);
	TO_BASE64(56, 14, 35);
	TO_BASE64(15, 36, 57);
	TO_BASE64(37, 58, 16);
	TO_BASE64(59, 17, 38);
	TO_BASE64(18, 39, 60);
	TO_BASE64(40, 61, 19);
	TO_BASE64(62, 20, 41);
	//TO_BASE64(-, -, 63);
	pos[0] = itoa64[out[63] & 63];
	pos[1] = itoa64[out[63] >> 6];
	pos[2] = 0;
}


void sha512_process_block(uint64_t* state, uint64_t* W);
#define SHA512_INIT_STATE(state) \
	buffer_len = 0, num_blocks = 0;\
	state[0] = 0x6A09E667F3BCC908ULL;\
	state[1] = 0xBB67AE8584CAA73BULL;\
	state[2] = 0x3C6EF372FE94F82BULL;\
	state[3] = 0xA54FF53A5F1D36F1ULL;\
	state[4] = 0x510E527FADE682D1ULL;\
	state[5] = 0x9B05688C2B3E6C1FULL;\
	state[6] = 0x1F83D9ABFB41BD6BULL;\
	state[7] = 0x5BE0CD19137E2179ULL;

#define SHA512_END_CTX(state) \
	buffer[buffer_len] = 0x80;\
	if (buffer_len >= 112)\
	{\
		memset(buffer + buffer_len + 1, 0, 256 - buffer_len - 1);\
		((uint64_t*)buffer)[16 + 15] = (num_blocks*128ull+buffer_len) << 3;\
		swap_endianness_array64((uint64_t*)buffer, 16);\
		sha512_process_block(state, (uint64_t*)buffer);\
		swap_endianness_array64((uint64_t*)(buffer + 128), 14);\
		sha512_process_block(state, (uint64_t*)(buffer + 128));\
	}\
	else\
	{\
		memset(buffer + buffer_len + 1, 0, 128 - buffer_len - 1);\
		((uint64_t*)buffer)[15] = (num_blocks*128ull+buffer_len) << 3;\
		swap_endianness_array64((uint64_t*)buffer, 14);\
		sha512_process_block(state, (uint64_t*)buffer);\
	}\
	swap_endianness_array64(state, 8);
PRIVATE void pre_cycle(const char* cleartext, uint32_t key_len, const crypt_sha256_salt* salt, char* buffer, uint64_t* out_state, char* p_bytes, char* s_bytes)
{
	uint64_t sha512_state[8];
	uint32_t buffer_len, num_blocks;

	// 1st digest: Support buffer_len<=51
	SHA512_INIT_STATE(sha512_state);
	memcpy(buffer + buffer_len, cleartext, key_len); buffer_len += key_len;
	memcpy(buffer + buffer_len, salt->salt, salt->saltlen); buffer_len += salt->saltlen;
	memcpy(buffer + buffer_len, cleartext, key_len); buffer_len += key_len;
	SHA512_END_CTX(sha512_state);

	// 2nd digest: Support buffer_len<=37
	SHA512_INIT_STATE(out_state);
	memcpy(buffer + buffer_len, cleartext, key_len); buffer_len += key_len;
	memcpy(buffer + buffer_len, salt->salt, salt->saltlen); buffer_len += salt->saltlen;
	memcpy(buffer + buffer_len, sha512_state, key_len); buffer_len += key_len;
	for (uint32_t j = key_len; j > 0; j >>= 1)
	{
		if (j & 1)
		{
			memcpy(buffer + buffer_len, sha512_state, 64);
			buffer_len += 64;
		}
		else
		{
			memcpy(buffer + buffer_len, cleartext, key_len);
			buffer_len += key_len;
		}
		if (buffer_len >= 128)
		{
			swap_endianness_array64((uint64_t*)buffer, 16);
			sha512_process_block(out_state, (uint64_t*)buffer);
			buffer_len -= 128;
			num_blocks++;
			memcpy(buffer, buffer + 128, buffer_len);
		}
	}
	SHA512_END_CTX(out_state);

	// Start computation of P byte sequence.
	SHA512_INIT_STATE(sha512_state);
	for (uint32_t i = 0; i < key_len; i++)
	{
		memcpy(buffer + buffer_len, cleartext, key_len);
		buffer_len += key_len;
		if (buffer_len >= 128)
		{
			swap_endianness_array64((uint64_t*)buffer, 16);
			sha512_process_block(sha512_state, (uint64_t*)buffer);
			buffer_len -= 128;
			num_blocks++;
			memcpy(buffer, buffer + 128, buffer_len);
		}
	}
	SHA512_END_CTX(sha512_state);
	memcpy(p_bytes, sha512_state, key_len);

	// Start computation of S byte sequence.
	SHA512_INIT_STATE(sha512_state);
	for (uint32_t i = 0; i < (16u + ((unsigned char*)out_state)[0]); i++)
	{
		memcpy(buffer + buffer_len, salt->salt, salt->saltlen);
		buffer_len += salt->saltlen;
		if (buffer_len >= 128)
		{
			swap_endianness_array64((uint64_t*)buffer, 16);
			sha512_process_block(sha512_state, (uint64_t*)buffer);
			buffer_len -= 128;
			num_blocks++;
			memcpy(buffer, buffer + 128, buffer_len);
		}
	}
	SHA512_END_CTX(sha512_state);
	memcpy(s_bytes, sha512_state, salt->saltlen);
}
typedef void copy_pattern_same_size_func(void* pattern, const void* state);
PRIVATE uint8_t g[] = { 0, 7, 3, 5, 3, 7, 1, 6, 3, 5, 3, 7, 1, 7, 2, 5, 3, 7, 1, 7, 3, 4, 3, 7, 1, 7, 3, 5, 2, 7, 1, 7, 3, 5, 3, 6, 1, 7, 3, 5, 3, 7 };
typedef void sha512_process_block_func(void* state, void* tmp_block, const void* block);
PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, sha512_process_block_func* kernels_asm[], uint32_t keys_in_parallel, copy_pattern_same_size_func* copy_asm[])
{
	//                                           keys sha256 tmp state                                   simple_buffer    ordered_keys
	uint32_t* buffer = (uint32_t*)_aligned_malloc((4 + 32*8 + 16 + 8) * sizeof(uint64_t) * keys_in_parallel + 256 + MAX_KEY_SIZE*(MAX_KEY_SIZE+1)*keys_in_parallel, 32);
	uint64_t* sha256_buffer = (uint64_t*)(buffer + 8 * keys_in_parallel);// size: 32 * 8 * keys_in_parallel
	uint64_t* tmp_buffer = sha256_buffer + 32 * 8 * keys_in_parallel;// size: 16 * keys_in_parallel
	uint64_t* state = tmp_buffer + 16 * keys_in_parallel;// size: 8 * keys_in_parallel
	uint8_t* simple_buffer = (uint8_t*)(state + 8 * keys_in_parallel);// size: 128
	char* ordered_keys = simple_buffer + 256;

	unsigned char key[MAX_KEY_LENGHT_SMALL];
	memset(buffer, 0, 8 * sizeof(uint32_t) * keys_in_parallel);

	// Keys buffer by length
	assert(keys_in_parallel < 128);
	uint8_t count_by_length[MAX_KEY_SIZE + 1];
	char* ptr_by_length[MAX_KEY_SIZE + 1];

	memset(count_by_length, 0, sizeof(count_by_length));
	memset(ordered_keys, 0, MAX_KEY_SIZE * (MAX_KEY_SIZE + 1) * keys_in_parallel);
	for (size_t i = 0; i <= MAX_KEY_SIZE; ordered_keys += i * 2 * keys_in_parallel, i++)
		ptr_by_length[i] = ordered_keys;

	while (TRUE)
	{
		uint32_t last_iteration = FALSE;
		uint32_t num_keys_gen = param->gen(buffer, keys_in_parallel, param->thread_id);
		assert(num_keys_gen <= keys_in_parallel);
		// Save keys to ordered buffer
		for (uint32_t i = 0; i < num_keys_gen; i++)
		{
			utf8_coalesc2utf8_key(buffer, key, keys_in_parallel, i);
			uint32_t key_length = (uint32_t)strlen(key);

			memcpy(ptr_by_length[key_length] + count_by_length[key_length] * key_length, key, key_length);
			count_by_length[key_length]++;
		}

process_keys:
		for (uint32_t key_length = 0; !stop_universe && key_length <= MAX_KEY_SIZE; key_length++)
			if (count_by_length[key_length] && (count_by_length[key_length] >= keys_in_parallel || last_iteration))
			{
				for (uint32_t current_salt_index = 0; current_salt_index < num_diff_salts; current_salt_index++)
				{
					const crypt_sha256_salt* salt = ((crypt_sha256_salt*)salts_values) + current_salt_index;

					// Pre-calculations
					uint32_t need_2nd_block_by_g[4] = {
						(    key_length + 64                ) >= 112 ? 16 : 0,
						(2 * key_length + 64                ) >= 112 ? 16 : 0,
						(    key_length + 64 + salt->saltlen) >= 112 ? 16 : 0,
						(2 * key_length + 64 + salt->saltlen) >= 112 ? 16 : 0
					};

					memset(sha256_buffer, 0, 32 * 8 * sizeof(uint64_t) * keys_in_parallel);
					for (uint32_t i = 0; i < keys_in_parallel; i++)
					{
						char p_bytes[MAX_KEY_SIZE];
						char s_bytes[MAX_SALT_SIZE];
						uint64_t tmp_state[8];

						pre_cycle(ptr_by_length[key_length] + i * key_length, key_length, salt, simple_buffer, tmp_state, p_bytes, s_bytes);
						for (uint32_t j = 0; j < 8; j++)
							state[j * keys_in_parallel + i] = tmp_state[j];

						// Patterns---------------------------------------------------------------------------------------------
						//pattern[0]=alt pass
						memset(simple_buffer, 0, 256);
						memcpy(simple_buffer, p_bytes, key_length);
						simple_buffer[key_length] = 0x80;
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < 32; j++)
							sha256_buffer[(32 * 0 + (j + 8)) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[1]=alt pass pass
						memset(simple_buffer, 0, 256);
						memcpy(simple_buffer, p_bytes, key_length);
						memcpy(simple_buffer + key_length, p_bytes, key_length);
						simple_buffer[2 * key_length] = 0x80;
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < 32; j++)
							sha256_buffer[(32 * 1 + (j + 8)) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[2]=alt salt pass
						memset(simple_buffer, 0, 256);
						memcpy(simple_buffer, s_bytes, salt->saltlen);
						memcpy(simple_buffer + salt->saltlen, p_bytes, key_length);
						simple_buffer[salt->saltlen + key_length] = 0x80;
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < 32; j++)
							sha256_buffer[(32 * 2 + (j + 8)) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[3]=alt salt pass pass
						memset(simple_buffer, 0, 256);
						memcpy(simple_buffer, s_bytes, salt->saltlen);
						memcpy(simple_buffer + salt->saltlen, p_bytes, key_length);
						memcpy(simple_buffer + salt->saltlen + key_length, p_bytes, key_length);
						simple_buffer[salt->saltlen + 2 * key_length] = 0x80;
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < 32; j++)
							sha256_buffer[(32 * 3 + (j + 8)) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[4]=pass alt
						memset(simple_buffer, 0, 256);
						memcpy(simple_buffer, p_bytes, key_length);
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < 32; j++)
							sha256_buffer[(32 * 4 + j) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[5]=pass pass alt
						memset(simple_buffer, 0, 256);
						memcpy(simple_buffer, p_bytes, key_length);
						memcpy(simple_buffer + key_length, p_bytes, key_length);
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < 32; j++)
							sha256_buffer[(32 * 5 + j) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[6]=pass salt alt
						memcpy(simple_buffer, p_bytes, key_length);
						memcpy(simple_buffer + key_length, s_bytes, salt->saltlen);
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < (key_length + salt->saltlen + 3) / 4; j++)
							sha256_buffer[(32 * 6 + j) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];
						//pattern[7]=pass salt pass alt
						memcpy(simple_buffer, p_bytes, key_length);
						memcpy(simple_buffer + key_length, s_bytes, salt->saltlen);
						memcpy(simple_buffer + key_length + salt->saltlen, p_bytes, key_length);
						swap_endianness_array64((uint64_t*)simple_buffer, 32);
						for (uint32_t j = 0; j < (2 * key_length + salt->saltlen + 3) / 4; j++)
							sha256_buffer[(32 * 7 + j) * keys_in_parallel + i] = ((uint64_t*)simple_buffer)[j];

						// Size
						sha256_buffer[(32 * 0 + need_2nd_block_by_g[0] + 15) * keys_in_parallel + i] = (       key_length + 64ull                ) << 3;
						sha256_buffer[(32 * 1 + need_2nd_block_by_g[1] + 15) * keys_in_parallel + i] = (2ull * key_length + 64ull                ) << 3;
						sha256_buffer[(32 * 2 + need_2nd_block_by_g[2] + 15) * keys_in_parallel + i] = (       key_length + 64ull + salt->saltlen) << 3;
						sha256_buffer[(32 * 3 + need_2nd_block_by_g[3] + 15) * keys_in_parallel + i] = (2ull * key_length + 64ull + salt->saltlen) << 3;
						sha256_buffer[(32 * 4 + need_2nd_block_by_g[0] + 15) * keys_in_parallel + i] = (       key_length + 64ull                ) << 3;
						sha256_buffer[(32 * 5 + need_2nd_block_by_g[1] + 15) * keys_in_parallel + i] = (2ull * key_length + 64ull                ) << 3;
						sha256_buffer[(32 * 6 + need_2nd_block_by_g[2] + 15) * keys_in_parallel + i] = (       key_length + 64ull + salt->saltlen) << 3;
						sha256_buffer[(32 * 7 + need_2nd_block_by_g[3] + 15) * keys_in_parallel + i] = (2ull * key_length + 64ull + salt->saltlen) << 3;
						// end patterns------------------------------------------------------------------------------------------------------------
					}

					// Big cycle
					swap_endianness_array64(state, 8 * keys_in_parallel);
					for (uint32_t k = 0, g_index = 0; k < salt->rounds; k++, g_index++)
					{
						uint64_t* pattern_buffer = sha256_buffer + 32 * keys_in_parallel * g[g_index];
						uint32_t need_2nd_block = need_2nd_block_by_g[g[g_index] & 3];
						if (k & 1)// Copy at end
						{
							uint32_t len = (uint32_t)(pattern_buffer[(need_2nd_block + 15) * keys_in_parallel] >> 3) - 64;
							uint32_t len3 = len & 7;
							len /= 8;

							if (len3)// Note: Use 7 versions of functions because register shifts are incredible expensive
								copy_asm[len3 - 1](pattern_buffer + len * keys_in_parallel, state);
							else
							{
								memcpy(pattern_buffer + len * keys_in_parallel, state, 64 * keys_in_parallel);
								for (uint32_t i = 0; i < keys_in_parallel; i++)
									pattern_buffer[(len + 8) * keys_in_parallel + i] = 0x80ull << 56;
							}
						}
						else// Copy at begining
							memcpy(pattern_buffer, state, 64 * keys_in_parallel);

						// Two sha512 calls
						kernels_asm[0](state, tmp_buffer, pattern_buffer);
						if (need_2nd_block)
							kernels_asm[1](state, tmp_buffer, pattern_buffer + 16 * keys_in_parallel);

						if (g_index == 41)
							g_index = -1;
					}

					// Search for a match
					uint32_t indx = salt_index[current_salt_index];

					while (indx != NO_ELEM)
					{
						uint64_t* bin = ((uint64_t*)binary_values) + indx * 8;

						for (uint32_t i = 0; i < keys_in_parallel; i++)
							// Total match
							if (bin[0] == state[0 * keys_in_parallel + i] && bin[1] == state[1 * keys_in_parallel + i] && bin[2] == state[2 * keys_in_parallel + i] && bin[3] == state[3 * keys_in_parallel + i] &&
								bin[4] == state[4 * keys_in_parallel + i] && bin[5] == state[5 * keys_in_parallel + i] && bin[6] == state[6 * keys_in_parallel + i] && bin[7] == state[7 * keys_in_parallel + i])
							{
								memcpy(key, ptr_by_length[key_length] + i * key_length, key_length);
								key[key_length] = 0;
								password_was_found(indx, key);
							}

						indx = same_salt_next[indx];
					}
				}

				if (last_iteration)
				{
					report_keys_processed(count_by_length[key_length]);
					count_by_length[key_length] = 0;
				}
				else
				{
					count_by_length[key_length] -= keys_in_parallel;
					memcpy(ptr_by_length[key_length], ptr_by_length[key_length] + keys_in_parallel * key_length, count_by_length[key_length] * key_length);
					report_keys_processed(keys_in_parallel);
				}
			}

		// Cycle checks
		if (num_keys_gen == 0  || !continue_attack)
		{
			uint32_t total_keys = 0;
			for (uint32_t key_length = 0; key_length <= MAX_KEY_SIZE; key_length++)
				total_keys += count_by_length[key_length];

			if (!stop_universe && total_keys)
			{
				// TODO: Group keys by length+salt_length to provide faster finish
				last_iteration = TRUE;
				send_message_gui(MESSAGE_FLUSHING_KEYS);
				goto process_keys;
			}
			else
				break;
		}
	}

	_aligned_free(buffer);

	finish_thread();
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _M_X64
void sha512_process_block_c(void* state, void* tmp_block, const void* block)
{
	memcpy(tmp_block, block, 128);
	sha512_process_block(state, tmp_block);
}
void sha512_process_first_block_c(uint64_t* state, void* tmp_block, const void* block)
{
	state[0] = 0x6A09E667F3BCC908ULL;
	state[1] = 0xBB67AE8584CAA73BULL;
	state[2] = 0x3C6EF372FE94F82BULL;
	state[3] = 0xA54FF53A5F1D36F1ULL;
	state[4] = 0x510E527FADE682D1ULL;
	state[5] = 0x9B05688C2B3E6C1FULL;
	state[6] = 0x1F83D9ABFB41BD6BULL;
	state[7] = 0x5BE0CD19137E2179ULL;

	sha512_process_block_c(state, tmp_block, block);
}
#define define_copy_pattern_c_code(index) \
PRIVATE void copy_pattern_c_code_ ## index(uint64_t* pattern, const uint64_t* state)\
{\
	uint64_t buffer_value = pattern[0] & (0xFFFFFFFFFFFFFF00ULL << (56-8*index));\
	for (uint32_t j = 0; j < 8; j++, pattern++)\
	{\
		uint64_t state_value = state[j];\
		pattern[0] = buffer_value | (state_value >> (8*index));\
		buffer_value = state_value << (64-8*index);\
	}\
	pattern[0] = buffer_value | (0x80ull << (56-8*index));\
}

define_copy_pattern_c_code(1)
define_copy_pattern_c_code(2)
define_copy_pattern_c_code(3)
define_copy_pattern_c_code(4)
define_copy_pattern_c_code(5)
define_copy_pattern_c_code(6)
define_copy_pattern_c_code(7)

PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_c_code[] = { 
		copy_pattern_c_code_1, copy_pattern_c_code_2, copy_pattern_c_code_3, copy_pattern_c_code_4, 
		copy_pattern_c_code_5, copy_pattern_c_code_6, copy_pattern_c_code_7
	};
	sha512_process_block_func* kernels[] = { sha512_process_first_block_c, sha512_process_block_c };
	crypt_utf8_coalesc_protocol_body(param, kernels, 1, copy_pattern_c_code);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// V128 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "arch_simd.h"

#define define_copy_pattern_v128(index) \
PRIVATE void copy_pattern_v128_ ## index(V128_WORD* pattern, const V128_WORD* state)\
{\
	V128_WORD buffer_value = V128_AND(V128_LOAD(pattern), V128_CONST64(0xFFFFFFFFFFFFFF00ULL << (56-8*index)));\
	for (uint32_t j = 0; j < 8; j++, pattern++)\
	{\
		V128_WORD state_value = V128_LOAD(state + j);\
		V128_STORE(pattern, V128_OR(buffer_value, V128_SR64(state_value, 8*index)));\
		buffer_value = V128_SL64(state_value, 64-8*index);\
	}\
	V128_STORE(pattern, V128_OR(buffer_value, V128_CONST64(0x80ull << (56-8*index))));\
}

define_copy_pattern_v128(1)
define_copy_pattern_v128(2)
define_copy_pattern_v128(3)
define_copy_pattern_v128(4)
define_copy_pattern_v128(5)
define_copy_pattern_v128(6)
define_copy_pattern_v128(7)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

#define R_E(x) SSE2_3XOR(SSE2_ROTATE64(x,50), SSE2_ROTATE64(x,46), SSE2_ROTATE64(x,23))
#define R_A(x) SSE2_3XOR(SSE2_ROTATE64(x,36), SSE2_ROTATE64(x,30), SSE2_ROTATE64(x,25))
#define R0(x)  SSE2_3XOR(SSE2_ROTATE64(x,63), SSE2_ROTATE64(x,56), SSE2_SR64(x,7))
#define R1(x)  SSE2_3XOR(SSE2_ROTATE64(x,45), SSE2_ROTATE64(x,3 ), SSE2_SR64(x,6))

PRIVATE void sha512_process_block_sse2(SSE2_WORD* state, SSE2_WORD* W, const SSE2_WORD* orig_W)
{
	SSE2_WORD A = state[0];
	SSE2_WORD B = state[1];
	SSE2_WORD C = state[2];
	SSE2_WORD D = state[3];
	SSE2_WORD E = state[4];
	SSE2_WORD F = state[5];
	SSE2_WORD G = state[6];
	SSE2_WORD H = state[7];

	/* Rounds */
	W[ 0] = orig_W[ 0]; H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0x428A2F98D728AE22ULL), W[0 ]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 1] = orig_W[ 1]; G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0x7137449123EF65CDULL), W[1 ]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[ 2] = orig_W[ 2]; F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0xB5C0FBCFEC4D3B2FULL), W[2 ]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[ 3] = orig_W[ 3]; E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0xE9B5DBA58189DBBCULL), W[3 ]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[ 4] = orig_W[ 4]; D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x3956C25BF348B538ULL), W[4 ]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[ 5] = orig_W[ 5]; C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x59F111F1B605D019ULL), W[5 ]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[ 6] = orig_W[ 6]; B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x923F82A4AF194F9BULL), W[6 ]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[ 7] = orig_W[ 7]; A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0xAB1C5ED5DA6D8118ULL), W[7 ]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
	W[ 8] = orig_W[ 8]; H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0xD807AA98A3030242ULL), W[8 ]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 9] = orig_W[ 9]; G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0x12835B0145706FBEULL), W[9 ]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[10] = orig_W[10]; F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0x243185BE4EE4B28CULL), W[10]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[11] = orig_W[11]; E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0x550C7DC3D5FFB4E2ULL), W[11]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[12] = orig_W[12]; D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x72BE5D74F27B896FULL), W[12]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[13] = orig_W[13]; C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x80DEB1FE3B1696B1ULL), W[13]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[14] = orig_W[14]; B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x9BDC06A725C71235ULL), W[14]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[15] = orig_W[15]; A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0xC19BF174CF692694ULL), W[15]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

	W[ 0] = SSE2_4ADD64(W[ 0], R1(W[14]), W[9 ], R0(W[1 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0xE49B69C19EF14AD2ULL), W[ 0]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 1] = SSE2_4ADD64(W[ 1], R1(W[15]), W[10], R0(W[2 ])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0xEFBE4786384F25E3ULL), W[ 1]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[ 2] = SSE2_4ADD64(W[ 2], R1(W[0 ]), W[11], R0(W[3 ])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0x0FC19DC68B8CD5B5ULL), W[ 2]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[ 3] = SSE2_4ADD64(W[ 3], R1(W[1 ]), W[12], R0(W[4 ])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0x240CA1CC77AC9C65ULL), W[ 3]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[ 4] = SSE2_4ADD64(W[ 4], R1(W[2 ]), W[13], R0(W[5 ])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x2DE92C6F592B0275ULL), W[ 4]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[ 5] = SSE2_4ADD64(W[ 5], R1(W[3 ]), W[14], R0(W[6 ])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x4A7484AA6EA6E483ULL), W[ 5]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[ 6] = SSE2_4ADD64(W[ 6], R1(W[4 ]), W[15], R0(W[7 ])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x5CB0A9DCBD41FBD4ULL), W[ 6]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[ 7] = SSE2_4ADD64(W[ 7], R1(W[5 ]), W[0 ], R0(W[8 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x76F988DA831153B5ULL), W[ 7]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
	W[ 8] = SSE2_4ADD64(W[ 8], R1(W[6 ]), W[1 ], R0(W[9 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0x983E5152EE66DFABULL), W[ 8]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 9] = SSE2_4ADD64(W[ 9], R1(W[7 ]), W[2 ], R0(W[10])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0xA831C66D2DB43210ULL), W[ 9]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[10] = SSE2_4ADD64(W[10], R1(W[8 ]), W[3 ], R0(W[11])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0xB00327C898FB213FULL), W[10]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[11] = SSE2_4ADD64(W[11], R1(W[9 ]), W[4 ], R0(W[12])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0xBF597FC7BEEF0EE4ULL), W[11]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[12] = SSE2_4ADD64(W[12], R1(W[10]), W[5 ], R0(W[13])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0xC6E00BF33DA88FC2ULL), W[12]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[13] = SSE2_4ADD64(W[13], R1(W[11]), W[6 ], R0(W[14])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0xD5A79147930AA725ULL), W[13]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[14] = SSE2_4ADD64(W[14], R1(W[12]), W[7 ], R0(W[15])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x06CA6351E003826FULL), W[14]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[15] = SSE2_4ADD64(W[15], R1(W[13]), W[8 ], R0(W[0 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x142929670A0E6E70ULL), W[15]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

	W[ 0] = SSE2_4ADD64(W[ 0], R1(W[14]), W[9 ], R0(W[1 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0x27B70A8546D22FFCULL), W[ 0]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 1] = SSE2_4ADD64(W[ 1], R1(W[15]), W[10], R0(W[2 ])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0x2E1B21385C26C926ULL), W[ 1]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[ 2] = SSE2_4ADD64(W[ 2], R1(W[0 ]), W[11], R0(W[3 ])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0x4D2C6DFC5AC42AEDULL), W[ 2]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[ 3] = SSE2_4ADD64(W[ 3], R1(W[1 ]), W[12], R0(W[4 ])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0x53380D139D95B3DFULL), W[ 3]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[ 4] = SSE2_4ADD64(W[ 4], R1(W[2 ]), W[13], R0(W[5 ])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x650A73548BAF63DEULL), W[ 4]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[ 5] = SSE2_4ADD64(W[ 5], R1(W[3 ]), W[14], R0(W[6 ])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x766A0ABB3C77B2A8ULL), W[ 5]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[ 6] = SSE2_4ADD64(W[ 6], R1(W[4 ]), W[15], R0(W[7 ])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x81C2C92E47EDAEE6ULL), W[ 6]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[ 7] = SSE2_4ADD64(W[ 7], R1(W[5 ]), W[0 ], R0(W[8 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x92722C851482353BULL), W[ 7]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
	W[ 8] = SSE2_4ADD64(W[ 8], R1(W[6 ]), W[1 ], R0(W[9 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0xA2BFE8A14CF10364ULL), W[ 8]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 9] = SSE2_4ADD64(W[ 9], R1(W[7 ]), W[2 ], R0(W[10])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0xA81A664BBC423001ULL), W[ 9]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[10] = SSE2_4ADD64(W[10], R1(W[8 ]), W[3 ], R0(W[11])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0xC24B8B70D0F89791ULL), W[10]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[11] = SSE2_4ADD64(W[11], R1(W[9 ]), W[4 ], R0(W[12])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0xC76C51A30654BE30ULL), W[11]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[12] = SSE2_4ADD64(W[12], R1(W[10]), W[5 ], R0(W[13])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0xD192E819D6EF5218ULL), W[12]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[13] = SSE2_4ADD64(W[13], R1(W[11]), W[6 ], R0(W[14])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0xD69906245565A910ULL), W[13]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[14] = SSE2_4ADD64(W[14], R1(W[12]), W[7 ], R0(W[15])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0xF40E35855771202AULL), W[14]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[15] = SSE2_4ADD64(W[15], R1(W[13]), W[8 ], R0(W[0 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x106AA07032BBD1B8ULL), W[15]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

	W[ 0] = SSE2_4ADD64(W[ 0], R1(W[14]), W[9 ], R0(W[1 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0x19A4C116B8D2D0C8ULL), W[ 0]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 1] = SSE2_4ADD64(W[ 1], R1(W[15]), W[10], R0(W[2 ])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0x1E376C085141AB53ULL), W[ 1]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[ 2] = SSE2_4ADD64(W[ 2], R1(W[0 ]), W[11], R0(W[3 ])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0x2748774CDF8EEB99ULL), W[ 2]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[ 3] = SSE2_4ADD64(W[ 3], R1(W[1 ]), W[12], R0(W[4 ])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0x34B0BCB5E19B48A8ULL), W[ 3]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[ 4] = SSE2_4ADD64(W[ 4], R1(W[2 ]), W[13], R0(W[5 ])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x391C0CB3C5C95A63ULL), W[ 4]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[ 5] = SSE2_4ADD64(W[ 5], R1(W[3 ]), W[14], R0(W[6 ])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x4ED8AA4AE3418ACBULL), W[ 5]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[ 6] = SSE2_4ADD64(W[ 6], R1(W[4 ]), W[15], R0(W[7 ])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x5B9CCA4F7763E373ULL), W[ 6]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[ 7] = SSE2_4ADD64(W[ 7], R1(W[5 ]), W[0 ], R0(W[8 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x682E6FF3D6B2B8A3ULL), W[ 7]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
	W[ 8] = SSE2_4ADD64(W[ 8], R1(W[6 ]), W[1 ], R0(W[9 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0x748F82EE5DEFB2FCULL), W[ 8]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 9] = SSE2_4ADD64(W[ 9], R1(W[7 ]), W[2 ], R0(W[10])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0x78A5636F43172F60ULL), W[ 9]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[10] = SSE2_4ADD64(W[10], R1(W[8 ]), W[3 ], R0(W[11])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0x84C87814A1F0AB72ULL), W[10]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[11] = SSE2_4ADD64(W[11], R1(W[9 ]), W[4 ], R0(W[12])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0x8CC702081A6439ECULL), W[11]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[12] = SSE2_4ADD64(W[12], R1(W[10]), W[5 ], R0(W[13])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x90BEFFFA23631E28ULL), W[12]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[13] = SSE2_4ADD64(W[13], R1(W[11]), W[6 ], R0(W[14])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0xA4506CEBDE82BDE9ULL), W[13]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[14] = SSE2_4ADD64(W[14], R1(W[12]), W[7 ], R0(W[15])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0xBEF9A3F7B2C67915ULL), W[14]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[15] = SSE2_4ADD64(W[15], R1(W[13]), W[8 ], R0(W[0 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0xC67178F2E372532BULL), W[15]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
	
	W[ 0] = SSE2_4ADD64(W[ 0], R1(W[14]), W[9 ], R0(W[1 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0xCA273ECEEA26619CULL), W[ 0]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 1] = SSE2_4ADD64(W[ 1], R1(W[15]), W[10], R0(W[2 ])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0xD186B8C721C0C207ULL), W[ 1]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[ 2] = SSE2_4ADD64(W[ 2], R1(W[0 ]), W[11], R0(W[3 ])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0xEADA7DD6CDE0EB1EULL), W[ 2]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[ 3] = SSE2_4ADD64(W[ 3], R1(W[1 ]), W[12], R0(W[4 ])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0xF57D4F7FEE6ED178ULL), W[ 3]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[ 4] = SSE2_4ADD64(W[ 4], R1(W[2 ]), W[13], R0(W[5 ])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x06F067AA72176FBAULL), W[ 4]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[ 5] = SSE2_4ADD64(W[ 5], R1(W[3 ]), W[14], R0(W[6 ])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x0A637DC5A2C898A6ULL), W[ 5]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[ 6] = SSE2_4ADD64(W[ 6], R1(W[4 ]), W[15], R0(W[7 ])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x113F9804BEF90DAEULL), W[ 6]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[ 7] = SSE2_4ADD64(W[ 7], R1(W[5 ]), W[0 ], R0(W[8 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x1B710B35131C471BULL), W[ 7]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
	W[ 8] = SSE2_4ADD64(W[ 8], R1(W[6 ]), W[1 ], R0(W[9 ])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST64(0x28db77f523047d84ULL), W[ 8]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
	W[ 9] = SSE2_4ADD64(W[ 9], R1(W[7 ]), W[2 ], R0(W[10])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST64(0x32caab7b40c72493ULL), W[ 9]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
	W[10] = SSE2_4ADD64(W[10], R1(W[8 ]), W[3 ], R0(W[11])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST64(0x3c9ebe0a15c9bebcULL), W[10]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
	W[11] = SSE2_4ADD64(W[11], R1(W[9 ]), W[4 ], R0(W[12])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST64(0x431d67c49c100d4cULL), W[11]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
	W[12] = SSE2_4ADD64(W[12], R1(W[10]), W[5 ], R0(W[13])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST64(0x4cc5d4becb3e42b6ULL), W[12]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
	W[13] = SSE2_4ADD64(W[13], R1(W[11]), W[6 ], R0(W[14])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST64(0x597f299cfc657e2aULL), W[13]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
	W[14] = SSE2_4ADD64(W[14], R1(W[12]), W[7 ], R0(W[15])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST64(0x5fcb6fab3ad6faecULL), W[14]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
	W[15] = SSE2_4ADD64(W[15], R1(W[13]), W[8 ], R0(W[0 ])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST64(0x6c44198c4a475817ULL), W[15]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

	state[0] = SSE2_ADD64(state[0], A);
	state[1] = SSE2_ADD64(state[1], B);
	state[2] = SSE2_ADD64(state[2], C);
	state[3] = SSE2_ADD64(state[3], D);
	state[4] = SSE2_ADD64(state[4], E);
	state[5] = SSE2_ADD64(state[5], F);
	state[6] = SSE2_ADD64(state[6], G);
	state[7] = SSE2_ADD64(state[7], H);
}
PRIVATE void sha512_process_first_block_sse2(SSE2_WORD* state, SSE2_WORD* W, const SSE2_WORD* orig_W)
{
	V128_STORE(state + 0, V128_CONST64(0x6A09E667F3BCC908ULL));
	V128_STORE(state + 1, V128_CONST64(0xBB67AE8584CAA73BULL));
	V128_STORE(state + 2, V128_CONST64(0x3C6EF372FE94F82BULL));
	V128_STORE(state + 3, V128_CONST64(0xA54FF53A5F1D36F1ULL));
	V128_STORE(state + 4, V128_CONST64(0x510E527FADE682D1ULL));
	V128_STORE(state + 5, V128_CONST64(0x9B05688C2B3E6C1FULL));
	V128_STORE(state + 6, V128_CONST64(0x1F83D9ABFB41BD6BULL));
	V128_STORE(state + 7, V128_CONST64(0x5BE0CD19137E2179ULL));

	sha512_process_block_sse2(state, W, orig_W);
}
PRIVATE void crypt_utf8_coalesc_protocol_sse2(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_v128[] = { 
		copy_pattern_v128_1, copy_pattern_v128_2, copy_pattern_v128_3, copy_pattern_v128_4, 
		copy_pattern_v128_5, copy_pattern_v128_6,copy_pattern_v128_7
	};
	sha512_process_block_func* kernels[] = { sha512_process_first_block_sse2, sha512_process_block_sse2 };
	crypt_utf8_coalesc_protocol_body(param, kernels, 2, copy_pattern_v128);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
void md5_one_block_neon(void* state, const void* block);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_v128[] = { copy_pattern_v128_1, copy_pattern_v128_2, copy_pattern_v128_3 };
	crypt_utf8_coalesc_protocol_body(param, md5_one_block_neon, 8, copy_pattern_v128);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void sha512_process_first_block_avx(void* state, void* tmp_block, const void* block);
void sha512_process_block_avx(void* state, void* tmp_block, const void* block);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_v128[] = {
		copy_pattern_v128_1, copy_pattern_v128_2, copy_pattern_v128_3, copy_pattern_v128_4,
		copy_pattern_v128_5, copy_pattern_v128_6,copy_pattern_v128_7
	};
	sha512_process_block_func* kernels[] = { sha512_process_first_block_avx, sha512_process_block_avx };
	crypt_utf8_coalesc_protocol_body(param, kernels, 2, copy_pattern_v128);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_avx2.h"

#define define_copy_pattern_avx2(index) \
PRIVATE void copy_pattern_avx2_ ## index(AVX2_WORD* pattern, const AVX2_WORD* state)\
{\
	AVX2_WORD buffer_value = AVX2_AND(AVX2_LOAD(pattern), AVX2_CONST64(0xFFFFFFFFFFFFFF00ULL << (56-8*index)));\
	for (uint32_t j = 0; j < 8; j++, pattern++)\
	{\
		AVX2_WORD state_value = AVX2_LOAD(state + j);\
		AVX2_STORE(pattern, AVX2_OR(buffer_value, AVX2_SR64(state_value, 8*index)));\
		buffer_value = AVX2_SL64(state_value, 64-8*index);\
	}\
	AVX2_STORE(pattern, AVX2_OR(buffer_value, AVX2_CONST64(0x80ull << (56-8*index))));\
}

define_copy_pattern_avx2(1)
define_copy_pattern_avx2(2)
define_copy_pattern_avx2(3)
define_copy_pattern_avx2(4)
define_copy_pattern_avx2(5)
define_copy_pattern_avx2(6)
define_copy_pattern_avx2(7)

void sha512_process_first_block_avx2(void* state, void* tmp_block, const void* block);
void sha512_process_block_avx2(void* state, void* tmp_block, const void* block);
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_avx2[] = { 
		copy_pattern_avx2_1, copy_pattern_avx2_2, copy_pattern_avx2_3, copy_pattern_avx2_4, 
		copy_pattern_avx2_5, copy_pattern_avx2_6,copy_pattern_avx2_7
	};
	sha512_process_block_func* kernels[] = { sha512_process_first_block_avx2, sha512_process_block_avx2 };
	crypt_utf8_coalesc_protocol_body(param, kernels, 4, copy_pattern_avx2);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT

#define KERNEL_INIT_PART		param->kernels[0]
#define KERNEL_COMPARE_RESULT	param->kernels[1]

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_work_body(OpenCL_Param* param, cl_uint length, cl_uint gpu_max_num_keys, cl_uint gpu_base_pos, cl_uint salt_index, size_t num_work_items)
{
	cl_uint num_found;
	const crypt_sha256_salt* salt = ((const crypt_sha256_salt*)salts_values) + salt_index;

	// Init
	pclSetKernelArg(KERNEL_INIT_PART, 3, sizeof(cl_uint), &gpu_base_pos);
	pclSetKernelArg(KERNEL_INIT_PART, 4, sizeof(cl_uint), &length);
	pclSetKernelArg(KERNEL_INIT_PART, 5, sizeof(cl_uint), &salt_index);
	pclEnqueueNDRangeKernel(param->queue, KERNEL_INIT_PART, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	// SHA256 cycle
	cl_kernel sha256_kernel = param->additional_kernels[length * MAX_SALT_SIZE + salt->saltlen - 1];
	cl_uint repeat_rounds = param->param0;
	cl_uint rounds = 0;

	pclSetKernelArg(sha256_kernel, 1, sizeof(cl_uint), &repeat_rounds);
	for (; rounds < (salt->rounds-param->param0); rounds += param->param0)
		pclEnqueueNDRangeKernel(param->queue, sha256_kernel, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
	
	repeat_rounds = salt->rounds - rounds;
	if (repeat_rounds)
	{
		pclFinish(param->queue);
		pclSetKernelArg(sha256_kernel, 1, sizeof(cl_uint), &repeat_rounds);
		pclEnqueueNDRangeKernel(param->queue, sha256_kernel, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
	}

	// Compare results
	pclSetKernelArg(KERNEL_COMPARE_RESULT, 3, sizeof(cl_uint), &salt_index);
	pclEnqueueNDRangeKernel(param->queue, KERNEL_COMPARE_RESULT, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	// Find matches
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

	// GPU found some passwords
	if (num_found)
		ocl_slow_ordered_found(param, &num_found, gpu_max_num_keys, gpu_base_pos, length);
}
PRIVATE uint32_t ocl_gen_update_buffer_be(char* block[32], const char* data_prefix, uint32_t data_len, uint32_t buffer_len)
{
	if (data_len)
	{
		uint32_t len3 = 8u * (buffer_len & 3u);
		if (len3)
		{
			sprintf(block[buffer_len / 4] + strlen(block[buffer_len / 4]), "W%02u|=%s0>>%uu;", (buffer_len / 4) & 15, data_prefix, len3);

			uint32_t i = 1;
			for (; i < ((data_len + 3) / 4); i++) {
				sprintf(block[buffer_len / 4 + i], "W%02u=bytealign(%s%u,%s%u,%uu);", (buffer_len / 4 + i) & 15, data_prefix, i - 1, data_prefix, i, len3 / 8);
			}
			// Overflow
			if ((data_len & 3u) == 0 || ((buffer_len & 3u) + (data_len & 3u)) > 4)
				sprintf(block[buffer_len / 4 + i], "W%02u=%s%u<<%uu;", (buffer_len / 4 + i) & 15, data_prefix, i - 1, 32 - len3);
		}
		else {
			for (uint32_t i = 0; i < ((data_len + 3) / 4); i++)
				sprintf(block[buffer_len / 4 + i], "W%02u=%s%u;", (buffer_len / 4 + i) & 15, data_prefix, i);
		}
	}

	return data_len;
}
PRIVATE void ocl_gen_finish_buffer_be(char* block[32], uint32_t buffer_len)
{
	// End buffer
	uint32_t len3 = 8u * (buffer_len & 3u);
	if (len3)
		sprintf(block[buffer_len / 4] + strlen(block[buffer_len / 4]), "W%02u|=%uu;", (buffer_len / 4) & 15, 0x80000000 >> len3);
	else
		sprintf(block[buffer_len / 4], "W%02u=0x80000000;", (buffer_len / 4) & 15);

	// Zero terminate
	uint32_t len_pos = buffer_len >= 56u ? 31 : 15;
	for (uint32_t i = buffer_len / 4 + 1; i < 31; i++)
		sprintf(block[i], "W%02u=0;", i & 15);
	sprintf(block[len_pos], "W%02u=%uu;", len_pos & 15, buffer_len << 3u);
}
PRIVATE void ocl_gen_load_w(char* block[32], 
	const char* data_prefix0, const char* data_prefix1, const char* data_prefix2, const char* data_prefix3, 
	uint32_t data_len0, uint32_t data_len1, uint32_t data_len2, uint32_t data_len3)
{
	// Load W
	uint32_t buffer_len = 0;
	buffer_len += ocl_gen_update_buffer_be(block, data_prefix0, data_len0, buffer_len);
	buffer_len += ocl_gen_update_buffer_be(block, data_prefix1, data_len1, buffer_len);
	if(data_prefix2)
		buffer_len += ocl_gen_update_buffer_be(block, data_prefix2, data_len2, buffer_len);
	if (data_prefix3)
		buffer_len += ocl_gen_update_buffer_be(block, data_prefix3, data_len3, buffer_len);
	ocl_gen_finish_buffer_be(block, buffer_len);
}
PRIVATE void ocl_gen_sha256body_by_lenght(char* source, OpenCL_Param* param, cl_uint key_len, cl_uint salt_len)
{
	sprintf(source + strlen(source),
		"\n__kernel void sha256crypt_cycle%ux%u(__global uint* current_data,uint rounds)"
		"{"
			"uint idx=get_global_id(0);", key_len, salt_len);

	sprintf(source + strlen(source), "uint A,B,C,D,E,F,G,H;");
	// Handle block vars used
	for (cl_uint i = 0; i < 16; i++)
		sprintf(source + strlen(source), "uint W%02u=0;", i);

	// Load key
	for (cl_uint i = 0; i < (key_len + 3) / 4; i++)
		sprintf(source + strlen(source), "uint key%u=GET_DATA(8u+%iu);", i, i);
	if (key_len & 3)
		sprintf(source + strlen(source), "key%u&=%uu;", key_len / 4, 0xffffff00 << (24 - 8 * (key_len & 3)));

	// Load salt
	for (cl_uint i = 0; i < (salt_len + 3) / 4; i++)
		sprintf(source + strlen(source), "uint salt%u=GET_DATA(16u+%iu);", i, i);
	if (salt_len & 3)
		sprintf(source + strlen(source), "salt%u&=%uu;", salt_len / 4, 0xffffff00 << (24 - 8 * (salt_len & 3)));

	sprintf(source + strlen(source),
			"uint state0=GET_DATA(0u);"
			"uint state1=GET_DATA(1u);"
			"uint state2=GET_DATA(2u);"
			"uint state3=GET_DATA(3u);"
			"uint state4=GET_DATA(4u);"
			"uint state5=GET_DATA(5u);"
			"uint state6=GET_DATA(6u);"
			"uint state7=GET_DATA(7u);"

			"for(uint i=0u;i<rounds;i++)"
			"{"
				"uint g_value=(i&1u)<<2u;"
				// Convert %3 and %7 tests converted to MULTIPLICATION_INVERSE and comparison: "Hackers Delight 2nd" Chapter 10-17
				"g_value|=((i*0xAAAAAAABu)>=0x55555555u)?2u:0u;"
				"g_value|=((i*0xB6DB6DB7u)>=0x24924924u)?1u:0u;"

				"switch(g_value)"
				"{");
	
		char* block[32 * 9];
		char* block_ptr = malloc(32 * 64 * 9);
		memset(block_ptr, 0, 32 * 64 * 9);
		for (size_t i = 0; i < 32 * 9; i++)
			block[i] = block_ptr + i * 64;
		//pattern[0]=alt pass-------------------------------------------------------------------------------------
		ocl_gen_load_w(block + 0 * 32, "state", "key"  ,   NULL ,   NULL ,   32   ,  key_len,    0   ,    0);
		//pattern[1]=alt pass pass-------------------------------------------------------------------------------
		ocl_gen_load_w(block + 1 * 32, "state", "key"  ,  "key" ,   NULL ,   32   ,  key_len, key_len,    0);
		//pattern[2]=alt salt pass--------------------------------------------------------------------------------
		ocl_gen_load_w(block + 2 * 32, "state", "salt" ,  "key" ,   NULL ,   32   , salt_len, key_len,    0);
		//pattern[3]=alt salt pass pass---------------------------------------------------------------------------
		ocl_gen_load_w(block + 3 * 32, "state", "salt" ,  "key" ,  "key" ,   32   , salt_len, key_len, key_len);
		//pattern[4]=pass alt-------------------------------------------------------------------------------------
		ocl_gen_load_w(block + 4 * 32, "key"  , "state",   NULL ,   NULL , key_len,    32   ,    0   ,    0);
		//pattern[5]=pass pass alt--------------------------------------------------------------------------------
		ocl_gen_load_w(block + 5 * 32, "key"  , "key"  , "state",   NULL , key_len,  key_len,    32  ,    0);
		//pattern[6]=pass salt alt--------------------------------------------------------------------------------
		ocl_gen_load_w(block + 6 * 32, "key"  , "salt" , "state",   NULL , key_len, salt_len,    32  ,    0);
		//pattern[7]=pass salt pass alt---------------------------------------------------------------------------
		ocl_gen_load_w(block + 7 * 32, "key"  , "salt" ,   "key", "state", key_len, salt_len, key_len,    32);

		// Search W for load patterns
		for (size_t i = 0; i < 16; i++)
		{
			int is_same = TRUE;// Has W[i] the same value for each pattern of g_value?
			for (cl_uint pattern_index = 0; pattern_index < 7; pattern_index++)
				if (strcmp(block[i + pattern_index * 32], block[i + (pattern_index+1) * 32]))
				{
					is_same = FALSE;
					break;
				}

			if (is_same)
			{
				// Add pattern to common
				strcpy(block[i + 8 * 32], block[i + 0 * 32]);
				// Delete pattern
				for (cl_uint pattern_index = 0; pattern_index < 8; pattern_index++)
					strcpy(block[i + pattern_index * 32], "");
			}
		}
		// Generate switch case
		for (cl_uint pattern_index = 0; pattern_index < 8; pattern_index++)
		{
			sprintf(source + strlen(source), "case %u:", pattern_index);
			for (size_t i = 0; i < 16; i++)
				sprintf(source + strlen(source), "%s", block[i + pattern_index * 32]);
			sprintf(source + strlen(source), "break;");
		}		

		sprintf(source + strlen(source), 
			    "}");
		// Load common patterns of W
		for (size_t i = 0; i < 16; i++)
			sprintf(source + strlen(source), "%s", block[i + 8 * 32]);

		// Cache 'state' for 2nd sha256 when needed
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 0)) sprintf(source + strlen(source), "uint tt7=state7;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 1)) sprintf(source + strlen(source), "uint tt6=state6;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 2)) sprintf(source + strlen(source), "uint tt5=state5;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 3)) sprintf(source + strlen(source), "uint tt4=state4;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 4)) sprintf(source + strlen(source), "uint tt3=state3;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 5)) sprintf(source + strlen(source), "uint tt2=state2;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 6)) sprintf(source + strlen(source), "uint tt1=state1;");
		if ((32 + 2 * key_len + salt_len) > (64 + 4 * 7)) sprintf(source + strlen(source), "uint tt0=state0;");

		// First sha256 compress hash function
		sprintf(source + strlen(source),
				"state0=0x6A09E667;"
				"state1=0xBB67AE85;"
				"state2=0x3C6EF372;"
				"state3=0xA54FF53A;"
				"state4=0x510E527F;"
				"state5=0x9B05688C;"
				"state6=0x1F83D9AB;"
				"state7=0x5BE0CD19;"

				"sha256_process_block_base(state0,state1,state2,state3,state4,state5,state6,state7);");

		// Need 2nd sha256 in some cases
		if ((32 + 2 * key_len + salt_len) >= 56)
		{
			memset(block_ptr, 0, 32 * 64 * 9);
			// Load W
			sprintf(source + strlen(source),
				"switch(g_value)"
				"{");
			//pattern[0]=alt pass-------------------------------------------------------------------------------------------------------------------------
			if ((32 + key_len) >= 56)              ocl_gen_load_w(block + 0 * 32, "tt" ,  "key",  NULL,  NULL,    32  ,  key_len,    0   ,    0);
			//pattern[1]=alt pass pass--------------------------------------------------------------------------------------------------------------------
			if ((32 + 2*key_len) >= 56)            ocl_gen_load_w(block + 1 * 32, "tt" ,  "key", "key",  NULL,    32  ,  key_len, key_len,    0);
			//pattern[2]=alt salt pass--------------------------------------------------------------------------------------------------------------------
			if ((32 + salt_len + key_len) >= 56)   ocl_gen_load_w(block + 2 * 32, "tt" , "salt", "key",  NULL,    32  , salt_len, key_len,    0);
			//pattern[3]=alt salt pass pass---------------------------------------------------------------------------------------------------------------
			if ((32 + salt_len + 2*key_len) >= 56) ocl_gen_load_w(block + 3 * 32, "tt" , "salt", "key", "key",    32  , salt_len, key_len, key_len);
			//pattern[4]=pass alt-------------------------------------------------------------------------------------------------------------------------
			if ((key_len + 32) >= 56)              ocl_gen_load_w(block + 4 * 32, "key",  "tt" , NULL ,  NULL, key_len,    32   ,    0   ,    0);
			//pattern[5]=pass pass alt--------------------------------------------------------------------------------------------------------------------											          
			if ((2*key_len + 32) >= 56)            ocl_gen_load_w(block + 5 * 32, "key",  "key", "tt" ,  NULL, key_len,  key_len,    32  ,    0);
			//pattern[6]=pass salt alt--------------------------------------------------------------------------------------------------------------------													          
			if ((key_len + salt_len + 32) >= 56)   ocl_gen_load_w(block + 6 * 32, "key", "salt", "tt" ,  NULL, key_len, salt_len,    32  ,    0);
			//pattern[7]=pass salt pass alt---------------------------------------------------------------------------------------------------------------
			if ((2*key_len + salt_len + 32) >= 56) ocl_gen_load_w(block + 7 * 32, "key", "salt", "key",  "tt", key_len, salt_len, key_len,    32);

			// Search W for load patterns
			for (size_t i = 16; i < 32; i++)
			{
				int is_same = TRUE;// Has W[i] the same value for each pattern of g_value?
				for (cl_uint pattern_index = 0; pattern_index < 8; pattern_index++)
					for (cl_uint pattern_index1 = 0; pattern_index1 < 8; pattern_index1++)
						if (strlen(block[i + pattern_index * 32]) && strlen(block[i + pattern_index1 * 32]) && 
							strcmp(block[i + pattern_index * 32],           block[i + pattern_index1 * 32]))
						{
							is_same = FALSE;
							break;
						}

				if (is_same)
				{
					// Add pattern to common
					for (cl_uint pattern_index = 0; pattern_index < 8; pattern_index++)
						if (strlen(block[i + pattern_index * 32]))
						{
							strcpy(block[i + 8 * 32], block[i + pattern_index * 32]);
							break;
						}
					// Delete pattern
					for (cl_uint pattern_index = 0; pattern_index < 8; pattern_index++)
						strcpy(block[i + pattern_index * 32], "");
				}
			}
			
			// Generate switch case
			for (cl_uint pattern_index = 0; pattern_index < 8; pattern_index++)
			{
				int is_empty_case = TRUE;
				for (size_t i = 16; i < 32; i++)
					if (strlen(block[i + pattern_index * 32]))
						is_empty_case = FALSE;

				if (is_empty_case) continue;

				sprintf(source + strlen(source), "case %u:", pattern_index);
				for (size_t i = 16; i < 32; i++)
					sprintf(source + strlen(source), "%s", block[i + pattern_index * 32]);
				sprintf(source + strlen(source), "break;");
			}

			// 2nd sha256 compress hash function
			sprintf(source + strlen(source),
				"}"
				"switch(g_value)"
				"{");
			//pattern[0]=alt pass-------------------------------------------------------------
			if ((32 + key_len) >= 56)                sprintf(source + strlen(source), "case 0:");
			//pattern[1]=alt pass pass--------------------------------------------------------
			if ((32 + 2 * key_len) >= 56)            sprintf(source + strlen(source), "case 1:");
			//pattern[2]=alt salt pass--------------------------------------------------------
			if ((32 + salt_len + key_len) >= 56)     sprintf(source + strlen(source), "case 2:");
			//pattern[3]=alt salt pass pass---------------------------------------------------
			if ((32 + salt_len + 2 * key_len) >= 56) sprintf(source + strlen(source), "case 3:");
			//pattern[4]=pass alt-------------------------------------------------------------
			if ((key_len + 32) >= 56)                sprintf(source + strlen(source), "case 4:");
			//pattern[5]=pass pass alt--------------------------------------------------------
			if ((2 * key_len + 32) >= 56)            sprintf(source + strlen(source), "case 5:");
			//pattern[6]=pass salt alt--------------------------------------------------------
			if ((key_len + salt_len + 32) >= 56)     sprintf(source + strlen(source), "case 6:");
			//pattern[7]=pass salt pass alt---------------------------------------------------
			if ((2 * key_len + salt_len + 32) >= 56) sprintf(source + strlen(source), "case 7:");
		
			// Load common patterns of W
			for (size_t i = 16; i < 32; i++)
				sprintf(source + strlen(source), "%s", block[i + 8 * 32]);

			sprintf(source + strlen(source),
					"sha256_process_block_base(state0,state1,state2,state3,state4,state5,state6,state7);"
					"break;"
				"}");
		}

		free(block_ptr);
		// End rounds cycle
		sprintf(source + strlen(source),
			"}"

			"GET_DATA(0u)=state0;"
			"GET_DATA(1u)=state1;"
			"GET_DATA(2u)=state2;"
			"GET_DATA(3u)=state3;"
			"GET_DATA(4u)=state4;"
			"GET_DATA(5u)=state5;"
			"GET_DATA(6u)=state6;"
			"GET_DATA(7u)=state7;"
		"}\n");
}
PRIVATE char* ocl_gen_kernels(GPUDevice* gpu, OpenCL_Param* param, int use_rules)
{
	// Generate code
	assert(use_rules >= 0);
	char* source = malloc(32 * 1024 * (1 + use_rules) + 8 * 1024 * (MAX_KEY_SIZE + 1) * MAX_SALT_SIZE);
	source[0] = 0;
	// Header definitions
	//if(num_passwords_loaded > 1 )
	strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");
	if (gpu->flags & GPU_FLAG_SUPPORT_AMD_OPS)
		strcat(source, "#pragma OPENCL EXTENSION cl_amd_media_ops : enable\n");

	sprintf(source + strlen(source), "#define bytealign(high,low,shift) (%s)\n", (gpu->flags & GPU_FLAG_SUPPORT_AMD_OPS) ? "amd_bytealign(high,low,shift)" : "((high<<(32u-shift*8u))|(low>>(shift*8u)))");
	sprintf(source + strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
	sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");

	//Initial values
	sprintf(source + strlen(source),
		"typedef struct {"
			"uint rounds;"
			"uint saltlen;"
			"uint salt[4];"
		"} crypt_sha256_salt;\n"

		"#define GET_DATA(index) current_data[(%uu+index)*%uu+get_global_id(0)]\n"
		, use_rules ? 8 : 0, param->NUM_KEYS_OPENCL);

	// Helpers
	sprintf(source + strlen(source), "\n"
		"#ifdef __ENDIAN_LITTLE__\n"
			"#define SWAP_ENDIANNESS(x,data) x=rotate(data,16u);x=((x&0x00FF00FFu)<<8u)|((x>>8u)&0x00FF00FFu);\n"
		"#else\n"
			"#define SWAP_ENDIANNESS(x,data) x=data;\n"
		"#endif\n"
		"inline uint update_buffer_be(uint block[32],uint* data,uint data_len,uint buffer_len)"
		"{"
			"uint len3=8u*(buffer_len&3u);"
			"if(len3)"
			"{"
				"uint block_value=block[buffer_len/4]&(0xffffff00u<<(24u-len3));"

				"for(uint i=0;i<((data_len+3)/4);i++){"
					"uint data_value=data[i];"
					"block[buffer_len/4+i]=block_value|(data_value>>len3);"
					"block_value=data_value<<(32u-len3);"
				"}"
				"block[buffer_len/4+((data_len+3)/4)]=block_value;"
			"}else{"
				"for(uint i=0;i<((data_len+3)/4);i++)"
					"block[buffer_len/4+i]=data[i];"
			"}"
			"return data_len;"
		"}");
	// Main hash function
	sprintf(source + strlen(source), "\n"
		"#define sha256_process_block(state0,state1,state2,state3,state4,state5,state6,state7,W,w_base_index) "
			"W00=W[w_base_index+0u];"
			"W01=W[w_base_index+1u];"
			"W02=W[w_base_index+2u];"
			"W03=W[w_base_index+3u];"
			"W04=W[w_base_index+4u];"
			"W05=W[w_base_index+5u];"
			"W06=W[w_base_index+6u];"
			"W07=W[w_base_index+7u];"
			"W08=W[w_base_index+8u];"
			"W09=W[w_base_index+9u];"
			"W10=W[w_base_index+10u];"
			"W11=W[w_base_index+11u];"
			"W12=W[w_base_index+12u];"
			"W13=W[w_base_index+13u];"
			"W14=W[w_base_index+14u];"
			"W15=W[w_base_index+15u];"
			"sha256_process_block_base(state0,state1,state2,state3,state4,state5,state6,state7);\n"

		"#define R_E(x) (rotate(x,26u)^rotate(x,21u)^rotate(x,7u))\n"
		"#define R_A(x) (rotate(x,30u)^rotate(x,19u)^rotate(x,10u))\n"
		"#define R0(x)  (rotate(x,25u)^rotate(x,14u)^(x>>3))\n"
		"#define R1(x)  (rotate(x,15u)^rotate(x,13u)^(x>>10))\n"
		"#define sha256_process_block_base(state0,state1,state2,state3,state4,state5,state6,state7) "

			"A=state0;"
			"B=state1;"
			"C=state2;"
			"D=state3;"
			"E=state4;"
			"F=state5;"
			"G=state6;"
			"H=state7;"

			/* Rounds */
			"H+=R_E(E)+bs(G,F,E)+0x428A2F98u+W00;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"G+=R_E(D)+bs(F,E,D)+0x71374491u+W01;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"F+=R_E(C)+bs(E,D,C)+0xB5C0FBCFu+W02;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"E+=R_E(B)+bs(D,C,B)+0xE9B5DBA5u+W03;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"D+=R_E(A)+bs(C,B,A)+0x3956C25Bu+W04;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"C+=R_E(H)+bs(B,A,H)+0x59F111F1u+W05;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"B+=R_E(G)+bs(A,H,G)+0x923F82A4u+W06;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5u+W07;E+=A;A+=R_A(B)+MAJ(B,C,D);"
			"H+=R_E(E)+bs(G,F,E)+0xD807AA98u+W08;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"G+=R_E(D)+bs(F,E,D)+0x12835B01u+W09;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"F+=R_E(C)+bs(E,D,C)+0x243185BEu+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"E+=R_E(B)+bs(D,C,B)+0x550C7DC3u+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"D+=R_E(A)+bs(C,B,A)+0x72BE5D74u+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"C+=R_E(H)+bs(B,A,H)+0x80DEB1FEu+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"B+=R_E(G)+bs(A,H,G)+0x9BDC06A7u+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"A+=R_E(F)+bs(H,G,F)+0xC19BF174u+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);"

			"W00+=R1(W14)+W09+R0(W01);H+=R_E(E)+bs(G,F,E)+0xE49B69C1u+W00;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W01+=R1(W15)+W10+R0(W02);G+=R_E(D)+bs(F,E,D)+0xEFBE4786u+W01;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"W02+=R1(W00)+W11+R0(W03);F+=R_E(C)+bs(E,D,C)+0x0FC19DC6u+W02;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"W03+=R1(W01)+W12+R0(W04);E+=R_E(B)+bs(D,C,B)+0x240CA1CCu+W03;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"W04+=R1(W02)+W13+R0(W05);D+=R_E(A)+bs(C,B,A)+0x2DE92C6Fu+W04;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"W05+=R1(W03)+W14+R0(W06);C+=R_E(H)+bs(B,A,H)+0x4A7484AAu+W05;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"W06+=R1(W04)+W15+R0(W07);B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCu+W06;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"W07+=R1(W05)+W00+R0(W08);A+=R_E(F)+bs(H,G,F)+0x76F988DAu+W07;E+=A;A+=R_A(B)+MAJ(B,C,D);"
			"W08+=R1(W06)+W01+R0(W09);H+=R_E(E)+bs(G,F,E)+0x983E5152u+W08;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W09+=R1(W07)+W02+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA831C66Du+W09;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"W10+=R1(W08)+W03+R0(W11);F+=R_E(C)+bs(E,D,C)+0xB00327C8u+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"W11+=R1(W09)+W04+R0(W12);E+=R_E(B)+bs(D,C,B)+0xBF597FC7u+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"W12+=R1(W10)+W05+R0(W13);D+=R_E(A)+bs(C,B,A)+0xC6E00BF3u+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"W13+=R1(W11)+W06+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD5A79147u+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"W14+=R1(W12)+W07+R0(W15);B+=R_E(G)+bs(A,H,G)+0x06CA6351u+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"W15+=R1(W13)+W08+R0(W00);A+=R_E(F)+bs(H,G,F)+0x14292967u+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);"

			"W00+=R1(W14)+W09+R0(W01);H+=R_E(E)+bs(G,F,E)+0x27B70A85u+W00;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W01+=R1(W15)+W10+R0(W02);G+=R_E(D)+bs(F,E,D)+0x2E1B2138u+W01;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"W02+=R1(W00)+W11+R0(W03);F+=R_E(C)+bs(E,D,C)+0x4D2C6DFCu+W02;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"W03+=R1(W01)+W12+R0(W04);E+=R_E(B)+bs(D,C,B)+0x53380D13u+W03;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"W04+=R1(W02)+W13+R0(W05);D+=R_E(A)+bs(C,B,A)+0x650A7354u+W04;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"W05+=R1(W03)+W14+R0(W06);C+=R_E(H)+bs(B,A,H)+0x766A0ABBu+W05;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"W06+=R1(W04)+W15+R0(W07);B+=R_E(G)+bs(A,H,G)+0x81C2C92Eu+W06;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"W07+=R1(W05)+W00+R0(W08);A+=R_E(F)+bs(H,G,F)+0x92722C85u+W07;E+=A;A+=R_A(B)+MAJ(B,C,D);"
			"W08+=R1(W06)+W01+R0(W09);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A1u+W08;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W09+=R1(W07)+W02+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664Bu+W09;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"W10+=R1(W08)+W03+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70u+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"W11+=R1(W09)+W04+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A3u+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"W12+=R1(W10)+W05+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819u+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"W13+=R1(W11)+W06+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD6990624u+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"W14+=R1(W12)+W07+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E3585u+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"W15+=R1(W13)+W08+R0(W00);A+=R_E(F)+bs(H,G,F)+0x106AA070u+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);"

			"W00+=R1(W14)+W09+R0(W01);H+=R_E(E)+bs(G,F,E)+0x19A4C116u+W00;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W01+=R1(W15)+W10+R0(W02);G+=R_E(D)+bs(F,E,D)+0x1E376C08u+W01;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"W02+=R1(W00)+W11+R0(W03);F+=R_E(C)+bs(E,D,C)+0x2748774Cu+W02;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"W03+=R1(W01)+W12+R0(W04);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5u+W03;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"W04+=R1(W02)+W13+R0(W05);D+=R_E(A)+bs(C,B,A)+0x391C0CB3u+W04;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"W05+=R1(W03)+W14+R0(W06);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4Au+W05;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"W06+=R1(W04)+W15+R0(W07);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4Fu+W06;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"W07+=R1(W05)+W00+R0(W08);A+=R_E(F)+bs(H,G,F)+0x682E6FF3u+W07;E+=A;A+=R_A(B)+MAJ(B,C,D);"
			"W08+=R1(W06)+W01+R0(W09);H+=R_E(E)+bs(G,F,E)+0x748F82EEu+W08;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W09+=R1(W07)+W02+R0(W10);G+=R_E(D)+bs(F,E,D)+0x78A5636Fu+W09;C+=G;G+=R_A(H)+MAJ(H,A,B);"
			"W10+=R1(W08)+W03+R0(W11);F+=R_E(C)+bs(E,D,C)+0x84C87814u+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
			"W11+=R1(W09)+W04+R0(W12);E+=R_E(B)+bs(D,C,B)+0x8CC70208u+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
			"W12+=R1(W10)+W05+R0(W13);D+=R_E(A)+bs(C,B,A)+0x90BEFFFAu+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
			"W13+=R1(W11)+W06+R0(W14);C+=R_E(H)+bs(B,A,H)+0xA4506CEBu+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
			"W14+=R1(W12)+W07+R0(W15);B+=R_E(G)+bs(A,H,G)+0xBEF9A3F7u+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
			"W15+=R1(W13)+W08+R0(W00);A+=R_E(F)+bs(H,G,F)+0xC67178F2u+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);"

			"state0+=A;"
			"state1+=B;"
			"state2+=C;"
			"state3+=D;"
			"state4+=E;"
			"state5+=F;"
			"state6+=G;"
			"state7+=H;"
		"\n");

	// Init function definition
	sprintf(source + strlen(source), "\n"
		"#define SHA256_INIT_STATE(state0,state1,state2,state3,state4,state5,state6,state7) "
			"buffer_len=0,num_blocks=0;"
			"state0=0x6A09E667;"
			"state1=0xBB67AE85;"
			"state2=0x3C6EF372;"
			"state3=0xA54FF53A;"
			"state4=0x510E527F;"
			"state5=0x9B05688C;"
			"state6=0x1F83D9AB;"
			"state7=0x5BE0CD19;\n"
		"#define SHA256_END_CTX(state0,state1,state2,state3,state4,state5,state6,state7)"
			"len3=8u*(buffer_len&3u);"
			"if(len3){"
				"uint block_value=w[buffer_len/4]&(0xffffff00u<<(24u-len3));"
				"w[buffer_len/4]=block_value|(0x80000000u>>len3);"
			"}else{"
				"w[buffer_len/4]=0x80000000;}"
			"if (buffer_len>=56u)"
			"{"
				"for(uint i=buffer_len/4+1;i<31u;i++)"
					"w[i]=0;"
				"w[16+15]=(num_blocks*64u+buffer_len)<<3u;"
				"sha256_process_block(state0,state1,state2,state3,state4,state5,state6,state7,w,0u);"
				"sha256_process_block(state0,state1,state2,state3,state4,state5,state6,state7,w,16u);"
			"}"
			"else"
			"{"
				"for(uint i=buffer_len/4+1;i<15u;i++)"
					"w[i]=0;"
				"w[15u]=(num_blocks*64u+buffer_len)<<3u;"
				"sha256_process_block(state0,state1,state2,state3,state4,state5,state6,state7,w,0u);"
			"}\n"

		"__kernel void init_part(__global uint* current_key,__global uint* current_data,__global crypt_sha256_salt* salts,uint base_len,uint len,uint salt_index)"
		"{"
			"uint idx=get_global_id(0);"

			"uint tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7;"
			"uint alt_state0,alt_state1,alt_state2,alt_state3,alt_state4,alt_state5,alt_state6,alt_state7;"
			"uint w[32];"
			"uint buffer_len,num_blocks,len3;"

			"uint A,B,C,D,E,F,G,H;"
			"uint W00,W01,W02,W03,W04,W05,W06,W07,W08,W09,W10,W11,W12,W13,W14,W15;"

			"if(len>%iu)return;"

			// Load key
			"uint key[7];"
			"for(uint i=0;i<((len+3u)/4u);i++)"
			"{"
				"uint tmp=current_key[idx+i*%uu+base_len];"
				"SWAP_ENDIANNESS(tmp,tmp);"
				"key[i]=tmp;"
			"}"

			// Load salt
			"uint salt[4];"
			"uint saltlen=salts[salt_index].saltlen;"
			"for(uint i=0;i<((saltlen+3u)/4u);i++)"
			"{"
				"uint tmp=salts[salt_index].salt[i];"
				"SWAP_ENDIANNESS(tmp,tmp);"
				"salt[i]=tmp;"
			"}"
		, MAX_KEY_SIZE, param->param1 * 2);		
		
	sprintf(source + strlen(source),	
			// 1st digest
			"SHA256_INIT_STATE(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7);"
			"buffer_len+=update_buffer_be(w,key,len,buffer_len);"// Copy key
			"buffer_len+=update_buffer_be(w,salt,saltlen,buffer_len);"// Copy salt
			"buffer_len+=update_buffer_be(w,key,len,buffer_len);"// Copy key
			"SHA256_END_CTX(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7);"

			// 2nd digest
			"SHA256_INIT_STATE(alt_state0,alt_state1,alt_state2,alt_state3,alt_state4,alt_state5,alt_state6,alt_state7);"
			"buffer_len+=update_buffer_be(w,key,len,buffer_len);"// Copy key
			"buffer_len+=update_buffer_be(w,salt,saltlen,buffer_len);"// Copy salt
			"w[24]=tmp_state0;w[25]=tmp_state1;w[26]=tmp_state2;w[27]=tmp_state3;w[28]=tmp_state4;w[29]=tmp_state5;w[30]=tmp_state6;w[31]=tmp_state7;"
			"buffer_len+=update_buffer_be(w,w+24,len,buffer_len);"// Copy state
			"for(uint j=len;j>0;j>>=1u)"
			"{"
				"if(j & 1u)"
				"{"
					"w[24]=tmp_state0;w[25]=tmp_state1;w[26]=tmp_state2;w[27]=tmp_state3;w[28]=tmp_state4;w[29]=tmp_state5;w[30]=tmp_state6;w[31]=tmp_state7;"
					"buffer_len+=update_buffer_be(w,w+24,32u,buffer_len);"// Copy state
				"}"
				"else"
				"{"
					"buffer_len+=update_buffer_be(w,key,len,buffer_len);"// Copy key
				"}"
				"if(buffer_len>=64u)"
				"{"
					"sha256_process_block(alt_state0,alt_state1,alt_state2,alt_state3,alt_state4,alt_state5,alt_state6,alt_state7,w,0u);"
					"buffer_len-=64u;"
					"num_blocks++;"
					"for(uint i=0;i<((buffer_len+3u)/4u);i++)"// Copy block end to begining
						"w[i]=w[16u+i];"
				"}"
			"}"
			"SHA256_END_CTX(alt_state0,alt_state1,alt_state2,alt_state3,alt_state4,alt_state5,alt_state6,alt_state7);"
			// Save state for big cycle
			"GET_DATA(0u)=alt_state0;"
			"GET_DATA(1u)=alt_state1;"
			"GET_DATA(2u)=alt_state2;"
			"GET_DATA(3u)=alt_state3;"
			"GET_DATA(4u)=alt_state4;"
			"GET_DATA(5u)=alt_state5;"
			"GET_DATA(6u)=alt_state6;"
			"GET_DATA(7u)=alt_state7;"

			// Start computation of P byte sequence.
			"SHA256_INIT_STATE(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7);"
			"for(uint j=0;j<len;j++)"
			"{"
				"buffer_len+=update_buffer_be(w,key,len,buffer_len);"// Copy key
				"if(buffer_len>=64u)"
				"{"
					"sha256_process_block(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7,w,0u);"
					"buffer_len-=64u;"
					"num_blocks++;"
					"for(uint i=0;i<((buffer_len+3u)/4u);i++)"// Copy block end to begining
						"w[i]=w[16u+i];"
				"}"
			"}"
			"SHA256_END_CTX(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7);"
			//"memcpy(p_bytes, tmp_state, key_len);"
			           "GET_DATA(8u+0u)=tmp_state0;"
			"if(len>4u){GET_DATA(8u+1u)=tmp_state1;}"
			"if(len>8u){GET_DATA(8u+2u)=tmp_state2;}"
			"if(len>12u){GET_DATA(8u+3u)=tmp_state3;}"
			"if(len>16u){GET_DATA(8u+4u)=tmp_state4;}"
			"if(len>20u){GET_DATA(8u+5u)=tmp_state5;}"
			"if(len>24u){GET_DATA(8u+6u)=tmp_state6;}"

			// Start computation of S byte sequence.
			"SHA256_INIT_STATE(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7);"
			"for(uint j=0;j<(16u+(alt_state0>>24u));j++)"
			"{"
				"buffer_len+=update_buffer_be(w,salt,saltlen,buffer_len);"// Copy salt
				"if (buffer_len>=64u)"
				"{"
					"sha256_process_block(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7,w,0u);"
					"buffer_len-=64u;"
					"num_blocks++;"
					"for(uint i=0;i<((buffer_len+3u)/4u);i++)"// Copy block end to begining
						"w[i]=w[16u+i];"
				"}"
			"}"
			"SHA256_END_CTX(tmp_state0,tmp_state1,tmp_state2,tmp_state3,tmp_state4,tmp_state5,tmp_state6,tmp_state7);"
			//memcpy(s_bytes, tmp_state, salt.saltlen);
							"GET_DATA(16u+0u)=tmp_state0;"
			"if(saltlen> 4u){GET_DATA(16u+1u)=tmp_state1;}"
			"if(saltlen> 8u){GET_DATA(16u+2u)=tmp_state2;}"
			"if(saltlen>12u){GET_DATA(16u+3u)=tmp_state3;}"
	"}");

	sprintf(source + strlen(source), "\n__kernel void compare_result(__global uint* current_data,__global uint* output,const __global uint* bin,"
		"uint current_salt_index,const __global uint* salt_index,const __global uint* same_salt_next)"
	"{"
		"uint idx=get_global_id(0);"

		"uint index=salt_index[current_salt_index];"
		"while(index!=0xffffffff)"
		"{"
			"if(GET_DATA(0)==bin[8u*index+0]&&GET_DATA(1)==bin[8u*index+1u]&&GET_DATA(2)==bin[8u*index+2u]&&GET_DATA(3)==bin[8u*index+3u]&&"
				"GET_DATA(4)==bin[8u*index+4]&&GET_DATA(5)==bin[8u*index+5u]&&GET_DATA(6)==bin[8u*index+6u]&&GET_DATA(7)==bin[8u*index+7u])"
			"{"
				"uint found=atomic_inc(output);"
				"output[2*found+1]=idx;"
				"output[2*found+2]=index;"
			"}"
			"index=same_salt_next[index];"
		"}"
	"}");

	//sprintf(source + strlen(source),
	//	"\n__kernel void sha256crypt_cycle(__global uint* current_data,uint len,uint rounds,uint saltlen)"
	//	"{"
	//		"if(len>%iu)return;"

	//		"uint A,B,C,D,E,F,G,H;"
	//		"uint W00,W01,W02,W03,W04,W05,W06,W07,W08,W09,W10,W11,W12,W13,W14,W15;"

	//		// Load data from global memory
	//		"uint idx=get_global_id(0);"

	//		"uint salt0=(saltlen)?GET_DATA(16u+0u):0;"
	//		"uint salt1=(saltlen>4)?GET_DATA(16u+1u):0;"
	//		"uint salt2=(saltlen>8)?GET_DATA(16u+2u):0;"
	//		"uint salt3=(saltlen>12)?GET_DATA(16u+3u):0;"

	//		"uint key0=(len)?GET_DATA(8u+0u):0;"
	//		"uint key1=(len>4)?GET_DATA(8u+1u):0;"
	//		"uint key2=(len>8)?GET_DATA(8u+2u):0;"
	//		"uint key3=(len>12)?GET_DATA(8u+3u):0;"
	//		"uint key4=(len>16)?GET_DATA(8u+4u):0;"
	//		"uint key5=(len>20)?GET_DATA(8u+5u):0;"
	//		"uint key6=(len>24)?GET_DATA(8u+6u):0;"

	//		"uint state0=GET_DATA(0u);"
	//		"uint state1=GET_DATA(1u);"
	//		"uint state2=GET_DATA(2u);"
	//		"uint state3=GET_DATA(3u);"
	//		"uint state4=GET_DATA(4u);"
	//		"uint state5=GET_DATA(5u);"
	//		"uint state6=GET_DATA(6u);"
	//		"uint state7=GET_DATA(7u);"
	//, MAX_KEY_SIZE);


	//sprintf(source + strlen(source),
	//		"uint w[32];"
	//		"uint buffer_len=0;"

	//		"for(uint i=0u;i<rounds;i++)"
	//		"{"
	//			"if(i&1u)"
	//			"{"
	//				"w[0]=key0;"
	//				"w[1]=key1;"
	//				"w[2]=key2;"
	//				"w[3]=key3;"
	//				"w[4]=key4;"
	//				"w[5]=key5;"
	//				"w[6]=key6;"
	//				"buffer_len=len;"
	//			"}else{"
	//				"w[0]=state0;"
	//				"w[1]=state1;"
	//				"w[2]=state2;"
	//				"w[3]=state3;"
	//				"w[4]=state4;"
	//				"w[5]=state5;"
	//				"w[6]=state6;"
	//				"w[7]=state7;"
	//				"buffer_len=32u;"
	//			"}"
	//			"if(i%%3u)"
	//			"{"
	//				"w[28]=salt0;"
	//				"w[29]=salt1;"
	//				"w[30]=salt2;"
	//				"w[31]=salt3;"
	//				"buffer_len+=update_buffer_be(w,w+28u,saltlen,buffer_len);"
	//			"}"
	//			"if(i%%7u)"
	//			"{"
	//				"w[25]=key0;"
	//				"w[26]=key1;"
	//				"w[27]=key2;"
	//				"w[28]=key3;"
	//				"w[29]=key4;"
	//				"w[30]=key5;"
	//				"w[31]=key6;"
	//				"buffer_len+=update_buffer_be(w,w+25u,len,buffer_len);"
	//			"}"
	//			"if(i&1u)"
	//			"{"
	//				"w[24]=state0;"
	//				"w[25]=state1;"
	//				"w[26]=state2;"
	//				"w[27]=state3;"
	//				"w[28]=state4;"
	//				"w[29]=state5;"
	//				"w[30]=state6;"
	//				"w[31]=state7;"
	//				"buffer_len+=update_buffer_be(w,w+24u,32u,buffer_len);"
	//			"}else{"
	//				"w[25]=key0;"
	//				"w[26]=key1;"
	//				"w[27]=key2;"
	//				"w[28]=key3;"
	//				"w[29]=key4;"
	//				"w[30]=key5;"
	//				"w[31]=key6;"
	//				"buffer_len+=update_buffer_be(w,w+25u,len,buffer_len);"
	//			"}"
	//			
	//			 // End buffer
	//			"uint len3=8u*(buffer_len&3u);"
	//			"if(len3){"
	//				"uint block_value=w[buffer_len/4]&(0xffffff00u<<(24u-len3));"
	//				"w[buffer_len/4]=block_value|(0x80000000>>len3);"
	//			"}else{"
	//				"w[buffer_len/4]=0x80000000;}"

	//			// Zero terminate
	//			"uint len_pos=buffer_len>=56u?31:15;"
	//			"for(uint i=buffer_len/4+1;i<len_pos;i++)"
	//				"w[i]=0;"
	//			"w[len_pos]=buffer_len<<3u;"

	//			// Compress hash function
	//			"state0=0x6A09E667;"
	//			"state1=0xBB67AE85;"
	//			"state2=0x3C6EF372;"
	//			"state3=0xA54FF53A;"
	//			"state4=0x510E527F;"
	//			"state5=0x9B05688C;"
	//			"state6=0x1F83D9AB;"
	//			"state7=0x5BE0CD19;"

	//			"sha256_process_block(state0,state1,state2,state3,state4,state5,state6,state7,w,0u);"
	//			"if(buffer_len>=56u)"
	//			"{"
	//				"sha256_process_block(state0,state1,state2,state3,state4,state5,state6,state7,w,16u);"
	//			"}"
	//		"}"

	//		"GET_DATA(0u)=state0;"
	//		"GET_DATA(1u)=state1;"
	//		"GET_DATA(2u)=state2;"
	//		"GET_DATA(3u)=state3;"
	//		"GET_DATA(4u)=state4;"
	//		"GET_DATA(5u)=state5;"
	//		"GET_DATA(6u)=state6;"
	//		"GET_DATA(7u)=state7;"
	//	"}\n");

	uint32_t exist_salt_by_len[MAX_SALT_SIZE+1];
	memset(exist_salt_by_len, FALSE, sizeof(exist_salt_by_len));
	for (uint32_t i = 0; i < num_diff_salts; i++)
		exist_salt_by_len[((const crypt_sha256_salt*)salts_values)->saltlen] = TRUE;

	// Generate specific code for each length
	for (cl_uint key_len = 0; key_len <= MAX_KEY_SIZE; key_len++)
		for (uint32_t salt_len = 1; salt_len <= MAX_SALT_SIZE; salt_len++)
			if(exist_salt_by_len[salt_len])
				ocl_gen_sha256body_by_lenght(source + strlen(source), param, key_len, salt_len);

	//size_t len = strlen(source);
	return source;
}
PRIVATE int ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules)
{
	// Only one hash
	// For Intel HD 4600 best DIVIDER=?
	//  1	4.00K
	//	2	3.94K
	//	4	3.90K
	//	8	3.55K
	//	16	2.99K
	//	32	2.84K
	// For AMD HD 7970 best DIVIDER=?
	//  1	146K
	//	2	146K
	//	4	144K
	//	8	141K
	//	16	138K
	//	32	131K
	// For Nvidia GTX 970 best DIVIDER=?
	//  1	99K
	//	2	142K
	//	4	139K
	//	8	119K
	//	16	101K
	//	32	127K

	// For AMD HD 7970
	// Hashcat: 
	// Theoretical: 
	// HS by len : 
	if (!ocl_init_slow_hashes_ordered(param, gpu_index, gen, gpu_crypt, ocl_kernel_provider, use_rules, (use_rules ? 8 : 0) + 20, BINARY_SIZE, SALT_SIZE, ocl_gen_kernels, ocl_work_body, 4, MAX_KEY_SIZE, TRUE))
		return FALSE;

	// Crypt Kernels
	cl_int code;
	KERNEL_INIT_PART = pclCreateKernel(param->additional_program, "init_part", &code);
	KERNEL_COMPARE_RESULT = pclCreateKernel(param->additional_program, "compare_result", &code);

	if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
	{
		create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
		create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
	}
	else
	{
		create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
	}

	// Set OpenCL kernel params
	//__kernel void init_part(__global uint* current_key,__global uint* current_data,__global crypt_sha256_salt* salts, uint base_len, uint len, uint salt_index)
	pclSetKernelArg(KERNEL_INIT_PART, 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
	pclSetKernelArg(KERNEL_INIT_PART, 1, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(KERNEL_INIT_PART, 2, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

	//__kernel void compare_result(__global uint* current_data,__global uint* output,const __global uint* bin,uint current_salt_index,const __global uint* salt_index,const __global uint* same_salt_next)
	pclSetKernelArg(KERNEL_COMPARE_RESULT, 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(KERNEL_COMPARE_RESULT, 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
	pclSetKernelArg(KERNEL_COMPARE_RESULT, 2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
	pclSetKernelArg(KERNEL_COMPARE_RESULT, 4, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
	pclSetKernelArg(KERNEL_COMPARE_RESULT, 5, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);

	if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, 4 * num_passwords_loaded, salt_index, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4 * num_passwords_loaded, same_salt_next, 0, NULL, NULL);
	}
	pclFinish(param->queue);

	// Create the kernels by length
	param->additional_kernels_size = (MAX_KEY_SIZE + 1) * MAX_SALT_SIZE;
	param->additional_kernels = malloc(param->additional_kernels_size * sizeof(cl_kernel));
	memset(param->additional_kernels, 0, param->additional_kernels_size * sizeof(cl_kernel));
	assert(param->additional_kernels);
	// Pre-calculate salt sizes
	uint32_t exist_salt_by_len[MAX_SALT_SIZE + 1];
	memset(exist_salt_by_len, FALSE, sizeof(exist_salt_by_len));
	for (uint32_t i = 0; i < num_diff_salts; i++)
		exist_salt_by_len[((const crypt_sha256_salt*)salts_values)->saltlen] = TRUE;

	for (cl_uint key_len = 0; key_len <= MAX_KEY_SIZE; key_len++)
		for (uint32_t salt_len = 1; salt_len <= MAX_SALT_SIZE; salt_len++)
			if (exist_salt_by_len[salt_len])
			{
				cl_int code;
				char name[32];
				sprintf(name, "sha256crypt_cycle%ux%u", key_len, salt_len);
				param->additional_kernels[key_len * MAX_SALT_SIZE + salt_len - 1] = pclCreateKernel(param->additional_program, name, &code);

				//	                        keylen-x-saltlen
				//__kernel void sha256crypt_cycle%ux%u(__global uint* current_data,uint rounds)
				if (code == CL_SUCCESS)
					pclSetKernelArg(param->additional_kernels[key_len * MAX_SALT_SIZE + salt_len - 1], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
			}

	// Select best params
	uint32_t max_salt_len = MAX_SALT_SIZE;
	for (; !exist_salt_by_len[max_salt_len]; max_salt_len--);
	cl_uint rounds = 42*8;
	ocl_calculate_best_work_group(param, param->additional_kernels + MAX_KEY_SIZE * MAX_SALT_SIZE + (max_salt_len-1), INT32_MAX, &rounds, 1, FALSE, CL_TRUE);
	// Manage rounds
	if (rounds == 0) rounds = 1;
	// if it's too low
	if (rounds < 42)
	{
		// TODO: uncomment this
		//param->NUM_KEYS_OPENCL = floor_power_2(param->NUM_KEYS_OPENCL * rounds / 42);
		//param->param1 = param->NUM_KEYS_OPENCL;
		rounds = 42;
	}
	// If it's too high
	uint32_t min_rounds = UINT32_MAX;
	for (size_t i = 0; i < num_diff_salts; i++)
		if (min_rounds > ((const crypt_sha256_salt*)salts_values)->rounds)
			min_rounds = ((const crypt_sha256_salt*)salts_values)->rounds;

	if (rounds > min_rounds)
	{
		uint32_t new_rounds = (min_rounds / 42) * 42;
		// TODO: uncomment this
		//param->NUM_KEYS_OPENCL = floor_power_2(param->NUM_KEYS_OPENCL * rounds / new_rounds);
		//param->param1 = param->NUM_KEYS_OPENCL;
		rounds = new_rounds;
	}

	param->param0 = (rounds / 42) * 42;// Ensure it's a multiple of 42

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
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

Format sha512crypt_format = {
	"SHA512CRYPT",
	"SHA512-based crypt(3).",
	"$6$",
	MAX_KEY_SIZE,
	BINARY_SIZE,
	SALT_SIZE,
	14,
	NULL,
	0,
	get_binary,
	binary2hex,
	DEFAULT_VALUE_MAP_INDEX,
	DEFAULT_VALUE_MAP_INDEX,
	is_valid,
	add_hash_from_line,
	NULL,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}},
#else
#ifdef HS_ARM
	{{CPU_CAP_NEON, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
#else
	{{CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code } },
#endif
#endif
#ifdef HS_OPENCL_SUPPORT
	{ { PROTOCOL_CHARSET_OCL_NO_ALIGNED, ocl_protocol_charset_init }, { PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init }, { PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init }, { PROTOCOL_UTF8, ocl_protocol_utf8_init } }
#endif
};