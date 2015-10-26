// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#define DCC_MAX_KEY_LENGHT	27
#define BINARY_SIZE			16
#define SALT_SIZE			(11*4)
#define NT_NUM_KEYS		    64

PUBLIC int dcc_line_is_valid(char* user_name, char* dcc, char* unused, char* unused1)
{
	if (user_name && dcc && valid_hex_string(dcc, 32) && strlen(user_name) <= 19)
		return TRUE;

	return FALSE;
}

PUBLIC void dcc_add_hash_from_line(ImportParam* param, char* user_name, char* dcc, sqlite3_int64 tag_id, int db_index)
{
	if (user_name && dcc && valid_hex_string(dcc, 32) && strlen(user_name) <= 19)
	{
		char cipher_text[19 + 1 + 32 + 1];
		sprintf(cipher_text, "%s:%s", _strlwr(user_name), _strupr(dcc));
		// Insert hash and account
		insert_hash_account(param, user_name, cipher_text, db_index, tag_id);
	}

}
PRIVATE void add_hash_from_line(ImportParam* param, char* user_name, char* dcc, char* unused, char* unused1, sqlite3_int64 tag_id)
{
	dcc_add_hash_from_line(param, user_name, dcc, tag_id, DCC_INDEX);
}

PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, void* salt_void)
{
	unsigned int* out = (unsigned int*)binary;
	unsigned int* salt = (unsigned int*)salt_void;
	unsigned int i = 0;
	unsigned int temp;
	unsigned int salt_lenght = 0;
	char ciphertext_buffer[64];

	//length=11 to save memory
	memset(salt, 0, SALT_SIZE);
	// Lowercase username
	ciphertext = _strlwr( strcpy(ciphertext_buffer, ciphertext) );
	// Get salt length
	for(; ciphertext[salt_lenght] != ':'; salt_lenght++);
	// Convert salt-----------------------------------------------------
	for(; i < salt_lenght/2; i++)
		salt[i] = ((unsigned int)ciphertext[2*i]) | ((unsigned int)ciphertext[2*i+1]) << 16;

	salt[i] = (salt_lenght%2) ? ((unsigned int)ciphertext[2*i]) | 0x800000 : 0x80;
	salt[10] = (8 + salt_lenght) << 4;

	ciphertext += salt_lenght + 1;
	//end convert salt----------------------------------------------------

	for (i = 0; i < 4; i++)
	{
 		temp  = (hex_to_num[ciphertext[i*8+0]])<<4;
 		temp |= (hex_to_num[ciphertext[i*8+1]]);
		
		temp |= (hex_to_num[ciphertext[i*8+2]])<<12;
		temp |= (hex_to_num[ciphertext[i*8+3]])<<8;
		
		temp |= (hex_to_num[ciphertext[i*8+4]])<<20;
		temp |= (hex_to_num[ciphertext[i*8+5]])<<16;
		
		temp |= (hex_to_num[ciphertext[i*8+6]])<<28;
		temp |= (hex_to_num[ciphertext[i*8+7]])<<24;
		
		out[i] = temp;
	}

	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;

	// Reversed	b += (c ^ d ^ a) + salt_buffer[11] +  SQRT_3; b = (b << 15) | (b >> 17);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	// Reversed	c += (d ^ a ^ b) + salt_buffer[3]  +  SQRT_3; c = (c << 11) | (c >> 21);
	out[2] = (out[2] << 21) | (out[2] >> 11);
	out[2]-= SQRT_3 + (out[3] ^ out[0] ^ out[1]) + salt[3];
	// Reversed	d += (a ^ b ^ c) + salt_buffer[7]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
	out[3]  = (out[3] << 23) | (out[3] >> 9);
	out[3] -= SQRT_3 + (out[0] ^ out[1] ^ out[2]) + salt[7];
	//+ SQRT_3; d = (d << 9 ) | (d >> 23);
	out[3]=(out[3] << 23 ) | (out[3] >> 9);
	out[3]-=SQRT_3;
	
	return out[3];
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef void dcc_ntlm_part_func(void* nt_buffer, unsigned int* crypt_result);
typedef void dcc_salt_part_func(void* salt_buffer, unsigned int* crypt_result);
PRIVATE void crypt_ntlm_protocol_body(CryptParam* param, int NUM_KEYS, unsigned int uint_in_parallel, dcc_ntlm_part_func* dcc_ntlm_part, dcc_salt_part_func** dcc_salt_part)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16 * sizeof(unsigned int)* NUM_KEYS, 32);
	unsigned int* crypt_result = (unsigned int*)_aligned_malloc(uint_in_parallel*sizeof(unsigned int)* 12, 32);

	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_SMALL, sizeof(unsigned char));

	memset(nt_buffer, 0, 16 * sizeof(unsigned int)* NUM_KEYS);

	while (continue_attack && param->gen(nt_buffer, NUM_KEYS, param->thread_id))
	{
		for (unsigned int i = 0; i < NUM_KEYS / uint_in_parallel; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part(nt_buffer + uint_in_parallel*i, crypt_result);

			//Another MD4_crypt for the salt
			// For all salts
			for(unsigned int j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part[salt_buffer[10] >> 4](salt_buffer, crypt_result);

				// All salts differents
				if (num_passwords_loaded == num_diff_salts)
				{
					unsigned int* bin = ((unsigned int*)binary_values) + j * 4;

					for (unsigned int k = 0; k < uint_in_parallel; k++)
					{
						// Search for a match
						unsigned int a, b, c, d = crypt_result[(8 + 3)*uint_in_parallel + k];

						if (d != bin[3]) continue;
						d = rotate(d + SQRT_3, 9);

						c = crypt_result[(8 + 2)*uint_in_parallel + k];
						b = crypt_result[(8 + 1)*uint_in_parallel + k];
						a = crypt_result[(8 + 0)*uint_in_parallel + k];

						c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
						if (c != bin[2]) continue;

						b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
						if (b != bin[1]) continue;

						a += (b ^ c ^ d) + crypt_result[3 * uint_in_parallel + k] + SQRT_3; a = rotate(a, 3);
						if (a != bin[0]) continue;

						// Total match
						password_was_found(j, ntlm2utf8_key(nt_buffer, key, NUM_KEYS, uint_in_parallel * i + k));
					}
				}
				else
					for (unsigned int k = 0; k < uint_in_parallel; k++)
					{
						// Search for a match
						unsigned int index = salt_index[j];

						// Partial match
						while(index != NO_ELEM)
						{
							unsigned int a, b, c, d = crypt_result[(8 + 3)*uint_in_parallel + k];
							unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

							if(d != bin[3]) goto next_iteration;
							d = rotate(d + SQRT_3, 9);

							c = crypt_result[(8+2)*uint_in_parallel+k];
							b = crypt_result[(8+1)*uint_in_parallel+k];
							a = crypt_result[(8+0)*uint_in_parallel+k];

							c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
							if(c != bin[2]) goto next_iteration;

							b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
							if(b != bin[1]) goto next_iteration;

							a += (b ^ c ^ d) + crypt_result[3 * uint_in_parallel + k] + SQRT_3; a = rotate(a, 3);
							if(a != bin[0]) goto next_iteration;

							// Total match
							password_was_found(index, ntlm2utf8_key(nt_buffer, key, NUM_KEYS, uint_in_parallel * i + k));

						next_iteration:
							index = same_salt_next[index];
						}
					}
			}
		}

		report_keys_processed(NUM_KEYS);
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM

void dcc_ntlm_part_neon(void* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon4(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon5(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon6(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon7(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon8(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon9(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon10(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon11(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon12(void* salt_buffer, unsigned int* crypt_result);
void dcc_salt_part_neon13(void* salt_buffer, unsigned int* crypt_result);
#define NT_NUM_KEYS_NEON 64

PRIVATE void crypt_ntlm_protocol_neon(CryptParam* param)
{
	dcc_salt_part_func* dcc_salt_parts[] = {
		dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4,
		dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4,
		dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon5, dcc_salt_part_neon5,
		dcc_salt_part_neon6, dcc_salt_part_neon6, dcc_salt_part_neon7, dcc_salt_part_neon7,
		dcc_salt_part_neon8, dcc_salt_part_neon8, dcc_salt_part_neon9, dcc_salt_part_neon9,
		dcc_salt_part_neon10, dcc_salt_part_neon10, dcc_salt_part_neon11, dcc_salt_part_neon11,
		dcc_salt_part_neon12, dcc_salt_part_neon12, dcc_salt_part_neon13, dcc_salt_part_neon13
	};

	crypt_ntlm_protocol_body(param, NT_NUM_KEYS_NEON, 8, dcc_ntlm_part_neon, dcc_salt_parts);
}

#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PUBLIC void dcc_salt_part_c_code(unsigned int* salt_buffer, unsigned int* crypt_result)
{
	unsigned int a,b,c,d;
	/* Round 1 */
	a = crypt_result[4+0];
	b = crypt_result[4+1];
	c = crypt_result[4+2];
	d = crypt_result[4+3];

	a += (d ^ (b & (c ^ d))) + salt_buffer[0] ; a = rotate(a, 3);
	d += (c ^ (a & (b ^ c))) + salt_buffer[1] ; d = rotate(d, 7);
	c += (b ^ (d & (a ^ b))) + salt_buffer[2] ; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a))) + salt_buffer[3] ; b = rotate(b, 19);

	a += (d ^ (b & (c ^ d))) + salt_buffer[4] ; a = rotate(a, 3);
	d += (c ^ (a & (b ^ c))) + salt_buffer[5] ; d = rotate(d, 7);
	c += (b ^ (d & (a ^ b))) + salt_buffer[6] ; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a))) + salt_buffer[7] ; b = rotate(b, 19);

	a += (d ^ (b & (c ^ d))) + salt_buffer[8] ; a = rotate(a, 3);
	d += (c ^ (a & (b ^ c))) + salt_buffer[9] ; d = rotate(d, 7);
	c += (b ^ (d & (a ^ b))) + salt_buffer[10]; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a)))				  ; b = rotate(b, 19);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + crypt_result[0]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c)) +  salt_buffer[0]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b)) +  salt_buffer[4]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a)) +  salt_buffer[8]  + SQRT_2; b = rotate(b, 13);

	a += ((b & (c | d)) | (c & d)) + crypt_result[1]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c)) +  salt_buffer[1]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b)) +  salt_buffer[5]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a)) +  salt_buffer[9]  + SQRT_2; b = rotate(b, 13);

	a += ((b & (c | d)) | (c & d)) + crypt_result[2]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c)) +  salt_buffer[2]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b)) +  salt_buffer[6]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a)) +  salt_buffer[10] + SQRT_2; b = rotate(b, 13);

	a += ((b & (c | d)) | (c & d)) + crypt_result[3]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c)) +  salt_buffer[3]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b)) +  salt_buffer[7]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a))					  + SQRT_2; b = rotate(b, 13);

	/* Round 3 */
	a += (b ^ c ^ d) +crypt_result[0]  + SQRT_3; a = rotate(a, 3);
	d += (a ^ b ^ c) + salt_buffer[4]  + SQRT_3; d = rotate(d, 9);
	c += (d ^ a ^ b) + salt_buffer[0]  + SQRT_3; c = rotate(c, 11);
	b += (c ^ d ^ a) + salt_buffer[8]  + SQRT_3; b = rotate(b, 15);

	a += (b ^ c ^ d) +crypt_result[2]  + SQRT_3; a = rotate(a, 3);
	d += (a ^ b ^ c) + salt_buffer[6]  + SQRT_3; d = rotate(d, 9);
	c += (d ^ a ^ b) + salt_buffer[2]  + SQRT_3; c = rotate(c, 11);
	b += (c ^ d ^ a) + salt_buffer[10] + SQRT_3; b = rotate(b, 15);

	a += (b ^ c ^ d) +crypt_result[1]  + SQRT_3; a = rotate(a, 3);
	d += (a ^ b ^ c) + salt_buffer[5];

	crypt_result[8+0] = a;
	crypt_result[8+1] = b;
	crypt_result[8+2] = c;
	crypt_result[8+3] = d;
}
#if !defined(_M_X64) || defined(HS_TESTING)
PUBLIC void dcc_ntlm_part_c_code(unsigned int* nt_buffer, unsigned int* crypt_result)
{
	unsigned int a,b,c,d;

	/* Round 1 */
	a = 		0xFFFFFFFF					 + nt_buffer[0*NT_NUM_KEYS]; a = rotate(a, 3);
	d = INIT_D+(INIT_C ^ (a & 0x77777777))   + nt_buffer[1*NT_NUM_KEYS]; d = rotate(d, 7);
	c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2*NT_NUM_KEYS]; c = rotate(c, 11);
	b = INIT_B + (a ^ (c & (d ^ a)))		 + nt_buffer[3*NT_NUM_KEYS]; b = rotate(b, 19);

	a += (d ^ (b & (c ^ d))) + nt_buffer[4*NT_NUM_KEYS] ; a = rotate(a, 3 );
	d += (c ^ (a & (b ^ c))) + nt_buffer[5*NT_NUM_KEYS] ; d = rotate(d, 7 );
	c += (b ^ (d & (a ^ b))) + nt_buffer[6*NT_NUM_KEYS] ; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a))) + nt_buffer[7*NT_NUM_KEYS] ; b = rotate(b, 19);
									 
	a += (d ^ (b & (c ^ d))) + nt_buffer[8*NT_NUM_KEYS] ; a = rotate(a, 3 );
	d += (c ^ (a & (b ^ c))) + nt_buffer[9*NT_NUM_KEYS] ; d = rotate(d, 7 );
	c += (b ^ (d & (a ^ b))) + nt_buffer[10*NT_NUM_KEYS]; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a))) + nt_buffer[11*NT_NUM_KEYS]; b = rotate(b, 19);
									 
	a += (d ^ (b & (c ^ d))) + nt_buffer[12*NT_NUM_KEYS]; a = rotate(a, 3 );
	d += (c ^ (a & (b ^ c))) + nt_buffer[13*NT_NUM_KEYS]; d = rotate(d, 7 );
	c += (b ^ (d & (a ^ b))) + nt_buffer[14*NT_NUM_KEYS]; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a))) 							; b = rotate(b, 19);
			
	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0*NT_NUM_KEYS] + SQRT_2; a = rotate(a, 3 );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4*NT_NUM_KEYS] + SQRT_2; d = rotate(d, 5 );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8*NT_NUM_KEYS] + SQRT_2; c = rotate(c, 9 );
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12*NT_NUM_KEYS]+ SQRT_2; b = rotate(b, 13);
			
	a += ((b & (c | d)) | (c & d)) + nt_buffer[1*NT_NUM_KEYS] + SQRT_2; a = rotate(a, 3 );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5*NT_NUM_KEYS] + SQRT_2; d = rotate(d, 5 );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9*NT_NUM_KEYS] + SQRT_2; c = rotate(c, 9 );
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13*NT_NUM_KEYS]+ SQRT_2; b = rotate(b, 13);
			
	a += ((b & (c | d)) | (c & d)) + nt_buffer[2*NT_NUM_KEYS] + SQRT_2; a = rotate(a, 3 );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6*NT_NUM_KEYS] + SQRT_2; d = rotate(d, 5 );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10*NT_NUM_KEYS]+ SQRT_2; c = rotate(c, 9 );
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14*NT_NUM_KEYS]+ SQRT_2; b = rotate(b, 13);
			
	a += ((b & (c | d)) | (c & d)) + nt_buffer[3*NT_NUM_KEYS] + SQRT_2; a = rotate(a, 3 );
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7*NT_NUM_KEYS] + SQRT_2; d = rotate(d, 5 );
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11*NT_NUM_KEYS]+ SQRT_2; c = rotate(c, 9 );
	b += ((c & (d | a)) | (d & a))							  + SQRT_2; b = rotate(b, 13);
			
	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0*NT_NUM_KEYS]  + SQRT_3; a = rotate(a, 3 );
	d += (c ^ b ^ a) + nt_buffer[8*NT_NUM_KEYS]  + SQRT_3; d = rotate(d, 9 );
	c += (b ^ a ^ d) + nt_buffer[4*NT_NUM_KEYS]  + SQRT_3; c = rotate(c, 11);
	b += (a ^ d ^ c) + nt_buffer[12*NT_NUM_KEYS] + SQRT_3; b = rotate(b, 15);
			
	a += (d ^ c ^ b) + nt_buffer[2*NT_NUM_KEYS]  + SQRT_3; a = rotate(a, 3 );
	d += (c ^ b ^ a) + nt_buffer[10*NT_NUM_KEYS] + SQRT_3; d = rotate(d, 9 );
	c += (b ^ a ^ d) + nt_buffer[6*NT_NUM_KEYS]  + SQRT_3; c = rotate(c, 11);
	b += (a ^ d ^ c) + nt_buffer[14*NT_NUM_KEYS] + SQRT_3; b = rotate(b, 15);
			
	a += (d ^ c ^ b) + nt_buffer[1*NT_NUM_KEYS]  + SQRT_3; a = rotate(a, 3 );
	d += (c ^ b ^ a) + nt_buffer[9*NT_NUM_KEYS]  + SQRT_3; d = rotate(d, 9 );
	c += (b ^ a ^ d) + nt_buffer[5*NT_NUM_KEYS]  + SQRT_3; c = rotate(c, 11);
	b += (a ^ d ^ c) + nt_buffer[13*NT_NUM_KEYS] + SQRT_3; b = rotate(b, 15);

	a += (d ^ c ^ b) + nt_buffer[3*NT_NUM_KEYS]  + SQRT_3; a = rotate(a, 3 );
	d += (c ^ b ^ a) + nt_buffer[11*NT_NUM_KEYS] + SQRT_3; d = rotate(d, 9 );
	c += (b ^ a ^ d) + nt_buffer[7*NT_NUM_KEYS]  + SQRT_3; c = rotate(c, 11);
	b += (a ^ d ^ c)							 + SQRT_3; b = rotate(b, 15);

	crypt_result[0] = a + INIT_A;
	crypt_result[1] = b + INIT_B;
	crypt_result[2] = c + INIT_C;
	crypt_result[3] = d + INIT_D;

	//Another MD4_crypt for the salt
	/* Round 1 */
	a = 				0xFFFFFFFF 	              + crypt_result[0]; a = rotate(a, 3);
	d = INIT_D + ( INIT_C ^ ( a & 0x77777777))    + crypt_result[1]; d = rotate(d, 7);
	c = INIT_C + ( INIT_B ^ ( d & ( a ^ INIT_B))) + crypt_result[2]; c = rotate(c, 11);
	b = INIT_B + (    a   ^ ( c & ( d ^    a  ))) + crypt_result[3]; b = rotate(b, 19);
			
	crypt_result[4+0] = a;
	crypt_result[4+1] = b;
	crypt_result[4+2] = c;
	crypt_result[4+3] = d;
}

PRIVATE void crypt_ntlm_protocol_c_code(CryptParam* param)
{
	dcc_salt_part_func* dcc_salt_parts[28];

	for (int i = 0; i < LENGHT(dcc_salt_parts); i++)
		dcc_salt_parts[i] = (dcc_salt_part_func*)dcc_salt_part_c_code;

	crypt_ntlm_protocol_body(param, NT_NUM_KEYS, 1, (dcc_ntlm_part_func*)dcc_ntlm_part_c_code, dcc_salt_parts);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void dcc_ntlm_part_avx(void* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_avx(void* salt_buffer, unsigned int* crypt_result);
#define NT_NUM_KEYS_AVX 256
PRIVATE void crypt_ntlm_protocol_avx(CryptParam* param)
{
	dcc_salt_part_func* dcc_salt_parts[28];

	for (int i = 0; i < LENGHT(dcc_salt_parts); i++)
		dcc_salt_parts[i] = dcc_salt_part_avx;

	crypt_ntlm_protocol_body(param, NT_NUM_KEYS_AVX, 8, dcc_ntlm_part_avx, dcc_salt_parts);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void dcc_ntlm_part_avx2(void* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_avx2(void* salt_buffer, unsigned int* crypt_result);
PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	dcc_salt_part_func* dcc_salt_parts[28];

	for (int i = 0; i < LENGHT(dcc_salt_parts); i++)
		dcc_salt_parts[i] = dcc_salt_part_avx2;

	crypt_ntlm_protocol_body(param, NT_NUM_KEYS_AVX, 16, dcc_ntlm_part_avx2, dcc_salt_parts);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_simd.h"

// Normal
#define STEP1(a,b,c,d,index,rot)																		\
	a = SSE2_ADD(a, SSE2_ADD(nt_buffer[index*NT_NUM_KEYS/4], SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP2(a,b,c,d,index,rot)																		\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_2, SSE2_ADD(nt_buffer[index*NT_NUM_KEYS/4], SSE2_OR(SSE2_AND(b, SSE2_OR(c, d)), SSE2_AND(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3(a,b,c,d,index,rot)																			\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_3, SSE2_ADD(nt_buffer[index*NT_NUM_KEYS/4], SSE2_XOR(SSE2_XOR(d, c), b))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

// Salt
#define STEP1_SALT(a,b,c,d,value,rot)														   \
	a = SSE2_ADD(a, SSE2_ADD(SSE2_CONST(value), SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP2_SALT(a,b,c,d,value,rot)																		\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_2, SSE2_ADD(SSE2_CONST(value), SSE2_OR(SSE2_AND(b, SSE2_OR(c, d)), SSE2_AND(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3_SALT(a,b,c,d,value,rot)																\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_3, SSE2_ADD(SSE2_CONST(value), SSE2_XOR(SSE2_XOR(d, c), b))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

// Crypt
#define STEP2_CRYPT(a,b,c,d,value,rot)																		\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_2, SSE2_ADD(value, SSE2_OR(SSE2_AND(b, SSE2_OR(c, d)), SSE2_AND(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3_CRYPT(a,b,c,d,value,rot)												\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_3, SSE2_ADD(value, SSE2_XOR(SSE2_XOR(d, c), b))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3_PART(a,b,c,d,value)	a = SSE2_ADD(a, SSE2_ADD(SSE2_CONST(value), SSE2_XOR(SSE2_XOR(d, c), b)));

PUBLIC void dcc_ntlm_part_sse2(__m128i* nt_buffer, __m128i* crypt_result)
{
	__m128i a, b, c, d;

	__m128i init_a = SSE2_CONST(INIT_A);
	__m128i init_b = SSE2_CONST(INIT_B);
	__m128i init_c = SSE2_CONST(INIT_C);
	__m128i init_d = SSE2_CONST(INIT_D);
	__m128i sqrt_2 = SSE2_CONST(SQRT_2);
	__m128i sqrt_3 = SSE2_CONST(SQRT_3);

	/* Round 1 */
	a = SSE2_ADD(SSE2_CONST(0xFFFFFFFF), nt_buffer[0 * NT_NUM_KEYS / 4]); a = SSE2_ROTATE(a, 3);
	d = SSE2_ADD(SSE2_ADD(init_d, SSE2_XOR(init_c, SSE2_AND(a, SSE2_CONST(0x77777777)))), nt_buffer[1 * NT_NUM_KEYS / 4]); d = SSE2_ROTATE(d, 7);
	c = SSE2_ADD(SSE2_ADD(init_c, SSE2_XOR(init_b, SSE2_AND(d, SSE2_XOR(a, init_b)))), nt_buffer[2*NT_NUM_KEYS/4]); c = SSE2_ROTATE(c, 11);
	b = SSE2_ADD(SSE2_ADD(init_b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a)))), nt_buffer[3*NT_NUM_KEYS/4]); b = SSE2_ROTATE(b, 19);
			
	STEP1(a, b, c, d, 4 , 3 );
	STEP1(d, a, b, c, 5 , 7 );
	STEP1(c, d, a, b, 6 , 11);
	STEP1(b, c, d, a, 7 , 19);

	STEP1(a, b, c, d, 8 , 3 );
	STEP1(d, a, b, c, 9 , 7 );
	STEP1(c, d, a, b, 10, 11);
	STEP1(b, c, d, a, 11, 19);

	STEP1(a, b, c, d, 12, 3 );
	STEP1(d, a, b, c, 13, 7 );
	STEP1(c, d, a, b, 14, 11);
	STEP1(b, c, d, a, 15, 19);
		
	/* Round 2 */
	STEP2(a, b, c, d, 0 , 3 );
	STEP2(d, a, b, c, 4 , 5 );
	STEP2(c, d, a, b, 8 , 9 );
	STEP2(b, c, d, a, 12, 13);

	STEP2(a, b, c, d, 1 , 3 );
	STEP2(d, a, b, c, 5 , 5 );
	STEP2(c, d, a, b, 9 , 9 );
	STEP2(b, c, d, a, 13, 13);

	STEP2(a, b, c, d, 2 , 3 );
	STEP2(d, a, b, c, 6 , 5 );
	STEP2(c, d, a, b, 10 , 9 );
	STEP2(b, c, d, a, 14, 13);
		
	STEP2(a, b, c, d, 3 , 3 );
	STEP2(d, a, b, c, 7 , 5 );
	STEP2(c, d, a, b, 11, 9 );
	STEP2(b, c, d, a, 15, 13);

	/* Round 3 */
	STEP3(a, b, c, d, 0 , 3 );
	STEP3(d, a, b, c, 8 , 9 );
	STEP3(c, d, a, b, 4 , 11);
	STEP3(b, c, d, a, 12, 15);

	STEP3(a, b, c, d, 2 , 3 );
	STEP3(d, a, b, c, 10, 9 );
	STEP3(c, d, a, b, 6 , 11);
	STEP3(b, c, d, a, 14, 15);
			
	STEP3(a, b, c, d, 1 , 3 );
	STEP3(d, a, b, c, 9 , 9 );
	STEP3(c, d, a, b, 5 , 11);
	STEP3(b, c, d, a, 13, 15);

	STEP3(a, b, c, d, 3 , 3 );
	STEP3(d, a, b, c, 11, 9 );
	STEP3(c, d, a, b, 7 , 11);
	STEP3(b, c, d, a, 15, 15);

	crypt_result[0] = SSE2_ADD(a, init_a);
	crypt_result[1] = SSE2_ADD(b, init_b);
	crypt_result[2] = SSE2_ADD(c, init_c);
	crypt_result[3] = SSE2_ADD(d, init_d);

	//Another MD4_crypt for the salt
	/* Round 1 */
	a = SSE2_ADD(SSE2_CONST(0xFFFFFFFF), crypt_result[0]); a = SSE2_ROTATE(a, 3);
	d = SSE2_ADD(SSE2_ADD(init_d, SSE2_XOR(init_c, SSE2_AND(a, SSE2_CONST(0x77777777)))), crypt_result[1]); d = SSE2_ROTATE(d, 7);
	c = SSE2_ADD(SSE2_ADD(init_c, SSE2_XOR(init_b, SSE2_AND(d, SSE2_XOR(a, init_b)))), crypt_result[2]); c = SSE2_ROTATE(c, 11);
	b = SSE2_ADD(SSE2_ADD(init_b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a)))), crypt_result[3]); b = SSE2_ROTATE(b, 19);
			
	crypt_result[4+0] = a;
	crypt_result[4+1] = b;
	crypt_result[4+2] = c;
	crypt_result[4+3] = d;
}
PUBLIC void dcc_salt_part_sse2(unsigned int* salt_buffer, __m128i* crypt_result)
{
	__m128i a, b, c, d;

	__m128i sqrt_2 = SSE2_CONST(SQRT_2);
	__m128i sqrt_3 = SSE2_CONST(SQRT_3);

	/* Round 1 */
	a = crypt_result[4+0];
	b = crypt_result[4+1];
	c = crypt_result[4+2];
	d = crypt_result[4+3];

	STEP1_SALT(a, b, c, d, salt_buffer[0] , 3 );
	STEP1_SALT(d, a, b, c, salt_buffer[1] , 7 );
	STEP1_SALT(c, d, a, b, salt_buffer[2] , 11);
	STEP1_SALT(b, c, d, a, salt_buffer[3] , 19);

	STEP1_SALT(a, b, c, d, salt_buffer[4] , 3 );
	STEP1_SALT(d, a, b, c, salt_buffer[5] , 7 );
	STEP1_SALT(c, d, a, b, salt_buffer[6] , 11);
	STEP1_SALT(b, c, d, a, salt_buffer[7] , 19);

	STEP1_SALT(a, b, c, d, salt_buffer[8] , 3 );
	STEP1_SALT(d, a, b, c, salt_buffer[9] , 7 );
	STEP1_SALT(c, d, a, b, salt_buffer[10], 11);
	STEP1_SALT(b, c, d, a,		0		  , 19);
				
	/* Round 2 */
	STEP2_CRYPT(a, b, c, d,crypt_result[0], 3 );
	STEP2_SALT(d, a, b, c, salt_buffer[0] , 5 );
	STEP2_SALT(c, d, a, b, salt_buffer[4] , 9 );
	STEP2_SALT(b, c, d, a, salt_buffer[8] , 13);

	STEP2_CRYPT(a, b, c, d,crypt_result[1], 3 );
	STEP2_SALT(d, a, b, c, salt_buffer[1] , 5 );
	STEP2_SALT(c, d, a, b, salt_buffer[5] , 9 );
	STEP2_SALT(b, c, d, a, salt_buffer[9] , 13);
				
	STEP2_CRYPT(a, b, c, d,crypt_result[2], 3 );
	STEP2_SALT(d, a, b, c, salt_buffer[2] , 5 );
	STEP2_SALT(c, d, a, b, salt_buffer[6] , 9 );
	STEP2_SALT(b, c, d, a, salt_buffer[10], 13);

	STEP2_CRYPT(a, b, c, d,crypt_result[3], 3 );
	STEP2_SALT(d, a, b, c, salt_buffer[3] , 5 );
	STEP2_SALT(c, d, a, b, salt_buffer[7] , 9 );
	STEP2_SALT(b, c, d, a,		0		  , 13);
				
	/* Round 3 */
	STEP3_CRYPT(a, b, c, d,crypt_result[0], 3 );
	STEP3_SALT(d, a, b, c, salt_buffer[4] , 9 );
	STEP3_SALT(c, d, a, b, salt_buffer[0] , 11);
	STEP3_SALT(b, c, d, a, salt_buffer[8] , 15);

	STEP3_CRYPT(a, b, c, d,crypt_result[2], 3 );
	STEP3_SALT(d, a, b, c, salt_buffer[6] , 9 );
	STEP3_SALT(c, d, a, b, salt_buffer[2] , 11);
	STEP3_SALT(b, c, d, a, salt_buffer[10], 15);

	STEP3_CRYPT(a, b, c, d,crypt_result[1], 3 );
	STEP3_PART(d, a, b, c, salt_buffer[5]);

	crypt_result[8+0] = a;
	crypt_result[8+1] = b;
	crypt_result[8+2] = c;
	crypt_result[8+3] = d;
}
PRIVATE void crypt_ntlm_protocol_sse2(CryptParam* param)
{
	dcc_salt_part_func* dcc_salt_parts[28];

	for (int i = 0; i < LENGHT(dcc_salt_parts); i++)
		dcc_salt_parts[i] = (dcc_salt_part_func*)dcc_salt_part_sse2;

	crypt_ntlm_protocol_body(param, NT_NUM_KEYS, 4, (dcc_ntlm_part_func*)dcc_ntlm_part_sse2, dcc_salt_parts);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
#define MAX_SALTS_IN_KERNEL_CHARSET	16
#define MAX_SALTS_IN_KERNEL_OTHER	64
#define MAX_SALTS_UNROLL			8

PRIVATE void ocl_write_dcc_header(char* source, GPUDevice* gpu, cl_uint unused)
{
	source[0] = 0;
	// Header definitions
	if(num_passwords_loaded > 1 )
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT)?"bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
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

"#define SQRT_2 0x5a827999\n"
"#define SQRT_3 0x6ed9eba1\n"

"#define NUM_DIFF_SALTS %uU\n", num_diff_salts);

	sprintf(source+strlen(source),
	"#ifdef __ENDIAN_LITTLE__\n"
		//little-endian
		"#define GET_1(x) ((((x)<<8)&0xff0000)+((x)&0xff))\n"
		"#define GET_2(x) ((((x)>>8)&0xff0000)+(((x)>>16)&0xff))\n"
	"#else\n"
		//big-endian
		"#define GET_1(x) ((((x)>>8)&0xff0000)+(((x)>>24)&0xff))\n"
		"#define GET_2(x) ((((x)<<16)&0xff0000)+(((x)>>8)&0xff))\n"
	"#endif\n");
}

PUBLIC cl_uint* ocl_dcc_shrink_salts_size(char salt_values_str[11][20], cl_uint* num_salt_diff_parts)
{
	cl_uchar equal_salt[SALT_SIZE/4];
	cl_uchar mapped_pos[SALT_SIZE/4];
	cl_uint j, diff_pos = 0;
	cl_uint* salt_ptr = (cl_uint*)salts_values;
	memset(equal_salt, 1, sizeof(equal_salt));

	// Find salts parts that are equals
	for (cl_uint i = 1; i < num_diff_salts; i++)
		for(j = 0; j < SALT_SIZE/4; j++)
			if(salt_ptr[j] != salt_ptr[i*(SALT_SIZE/4)+j])
				equal_salt[j] = FALSE;

	// Process result
	for(j = 0; j < SALT_SIZE/4; j++)
		if(equal_salt[j])
		{
			if(salt_ptr[j])
				sprintf(salt_values_str[j], "+%uu", salt_ptr[j]);
			else
				salt_values_str[j][0] = 0;
		}
		else
		{
			num_salt_diff_parts[0]++;
			sprintf(salt_values_str[j], "+salt_values[j+%uu]", diff_pos);
			mapped_pos[j] = diff_pos;
			diff_pos++;
		}

	// Only use different values of salt
	cl_uint* small_salts_values = (cl_uint*)malloc(4 * num_salt_diff_parts[0] * num_diff_salts);
	for (cl_uint i = 0; i < num_diff_salts; i++)
		for(j = 0; j < SALT_SIZE/4; j++)
			if(!equal_salt[j])
				small_salts_values[i*num_salt_diff_parts[0]+mapped_pos[j]] = salt_ptr[i*(SALT_SIZE/4)+j];

	return small_salts_values;
}
PRIVATE void ocl_mscash_test_empty()
{
	unsigned int i;
	unsigned int* salt_buffer = (unsigned int*)salts_values;
	unsigned int a,b,c,d;
	unsigned int index;

	for(i = 0; i < num_diff_salts; i++, salt_buffer += 11)
	{
		/* Round 1 */
		a = 0x067eb187;   b = 0x66ce2570;   c = 0x9e29f7ff;   d = 0x7456a070;

		a += (d ^ (b & (c ^ d))) + salt_buffer[0] ; a = rotate(a, 3);
		d += (c ^ (a & (b ^ c))) + salt_buffer[1] ; d = rotate(d, 7);
		c += (b ^ (d & (a ^ b))) + salt_buffer[2] ; c = rotate(c, 11);
		b += (a ^ (c & (d ^ a))) + salt_buffer[3] ; b = rotate(b, 19);

		a += (d ^ (b & (c ^ d))) + salt_buffer[4] ; a = rotate(a, 3);
		d += (c ^ (a & (b ^ c))) + salt_buffer[5] ; d = rotate(d, 7);
		c += (b ^ (d & (a ^ b))) + salt_buffer[6] ; c = rotate(c, 11);
		b += (a ^ (c & (d ^ a))) + salt_buffer[7] ; b = rotate(b, 19);

		a += (d ^ (b & (c ^ d))) + salt_buffer[8] ; a = rotate(a, 3);
		d += (c ^ (a & (b ^ c))) + salt_buffer[9] ; d = rotate(d, 7);
		c += (b ^ (d & (a ^ b))) + salt_buffer[10]; c = rotate(c, 11);
		b += (a ^ (c & (d ^ a)))				  ; b = rotate(b, 19);

		/* Round 2 */
		a += ((b & (c | d)) | (c & d)) +    0xe0cfd631   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c)) + salt_buffer[0]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b)) + salt_buffer[4]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a)) + salt_buffer[8]  + SQRT_2; b = rotate(b, 13);

		a += ((b & (c | d)) | (c & d)) +    0x31e96ad1   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c)) + salt_buffer[1]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b)) + salt_buffer[5]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a)) + salt_buffer[9]  + SQRT_2; b = rotate(b, 13);

		a += ((b & (c | d)) | (c & d)) +    0xd7593cb7   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c)) + salt_buffer[2]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b)) + salt_buffer[6]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a)) + salt_buffer[10] + SQRT_2; b = rotate(b, 13);

		a += ((b & (c | d)) | (c & d)) +    0xc089c0e0   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c)) + salt_buffer[3]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b)) + salt_buffer[7]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a))					 + SQRT_2; b = rotate(b, 13);

		/* Round 3 */
		a += (b ^ c ^ d) +    0xe0cfd631   + SQRT_3; a = rotate(a, 3);
		d += (a ^ b ^ c) + salt_buffer[4]  + SQRT_3; d = rotate(d, 9);
		c += (d ^ a ^ b) + salt_buffer[0]  + SQRT_3; c = rotate(c, 11);
		b += (c ^ d ^ a) + salt_buffer[8]  + SQRT_3; b = rotate(b, 15);

		a += (b ^ c ^ d) +    0xd7593cb7   + SQRT_3; a = rotate(a, 3);
		d += (a ^ b ^ c) + salt_buffer[6]  + SQRT_3; d = rotate(d, 9);
		c += (d ^ a ^ b) + salt_buffer[2]  + SQRT_3; c = rotate(c, 11);
		b += (c ^ d ^ a) + salt_buffer[10] + SQRT_3; b = rotate(b, 15);

		a += (b ^ c ^ d) +    0x31e96ad1   + SQRT_3; a = rotate(a, 3);
		d += (a ^ b ^ c) + salt_buffer[5];

		// Search for a match
		index = salt_index[i];

		// Partial match
		while(index != NO_ELEM)
		{
			unsigned int aa, bb, cc, dd;
			unsigned int* bin = ((unsigned int*)binary_values) + index*4;

			if(d != bin[3]) goto next_iteration;
			dd = d + SQRT_3; dd = rotate(dd, 9);

			cc = c + (dd ^ a ^ b) + salt_buffer[1] + SQRT_3; cc = rotate(cc, 11);
			if(cc != bin[2]) goto next_iteration;

			bb = b + (cc ^ dd ^ a) + salt_buffer[9]+ SQRT_3; bb = rotate(bb, 15);
			if(bb != bin[1]) goto next_iteration;

			aa = a + (bb ^ cc ^ dd) +   0xc089c0e0 + SQRT_3; aa = rotate(aa, 3);
			if(aa != bin[0]) goto next_iteration;

			// Total match
			password_was_found(index, "");

next_iteration:
			index = same_salt_next[index];
		}
	}
}

PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint num_salt_diff_parts, char salt_values_str[11][20], cl_uint output_size)
{
	cl_uint i;
	DivisionParams div_param = get_div_params(num_char_in_charset);
	char* str_comp[] = {".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf"};
	char* nt_buffer[] = {"+nt_buffer0" , "+nt_buffer1" , "+nt_buffer2" , "+nt_buffer3" , 
						 "+nt_buffer4" , "+nt_buffer5" , "+nt_buffer6" , "+nt_buffer7" , 
						 "+nt_buffer8" , "+nt_buffer9" , "+nt_buffer10", "+nt_buffer11", 
						 "+nt_buffer12", "+nt_buffer13"};
	char buffer[4];
	buffer[0] = 0;

	if(vector_size == 1) str_comp[0] = "";
	if(vector_size > 1)	 sprintf(buffer, "%u", vector_size);

	// Begin function code
	sprintf(source+strlen(source), "){"
									"uint max_number=get_global_id(0);"
									"uint%s a,b,c,d,nt_buffer0=0,xx;"
									"uint indx;", buffer);

	// Load salt values into local_memory
	//if (num_diff_salts > 1 && num_salt_diff_parts*num_diff_salts*sizeof(cl_uint) < local_memory_size)
	//{
	//	// Prefetch in local memory
	//	sprintf(source + strlen(source), "local uint salt_values[%i];", num_salt_diff_parts*num_diff_salts);
	//	// Copy from global to local
	//	sprintf(source + strlen(source), "for(uint i=get_local_id(0); i < %uu; i+=get_local_size(0))"
	//										"salt_values[i]=salt_values1[i];"
	//									"barrier(CLK_LOCAL_MEM_FENCE);", num_salt_diff_parts*num_diff_salts);
	//}

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_uint bits_by_char;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	cl_uint chars_in_reg = 32 / bits_by_char;
#endif

	for (i = 0; i < key_lenght / 2; i++)
		for (cl_uint j = 0; j < 2; j++)
			if (i || j)
			{
				cl_uint key_index = 2 * i + j;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
				key_index--;
				sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
				sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
				// Perform division
				if (div_param.magic)sprintf(source + strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
				else				sprintf(source + strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

				if (j)
					sprintf(source + strlen(source), "nt_buffer%u+=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<16u;", i);
				else
					sprintf(source + strlen(source), "uint nt_buffer%u=charset[max_number-NUM_CHAR_IN_CHARSET*indx];", i);

				sprintf(source + strlen(source), "max_number=indx;");
			}

	if (key_lenght == 1)
	{
		sprintf(source + strlen(source), "nt_buffer0=0x800000;");
	}
	else if(key_lenght & 1)
	{
		cl_uint key_index = key_lenght - 1;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		key_index--;
		sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
		sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
		// Perform division
		if(div_param.magic)	sprintf(source+strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

		sprintf(source+strlen(source), "uint nt_buffer%u=((uint)(charset[max_number-NUM_CHAR_IN_CHARSET*indx]))+0x800000;", i);
	}
	else
		nt_buffer[i] = "+0x80";

	for (i = key_lenght / 2 + 1; i < 14; i++)
		nt_buffer[i] = "";

	// Small optimization
	if( is_charset_consecutive(charset) )
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset)-vector_size+i);

	if(key_lenght > 2) sprintf(source+strlen(source), "nt_buffer1+=INIT_D;");
	if(key_lenght > 4) sprintf(source+strlen(source), "nt_buffer2+=INIT_C;");
	if(key_lenght > 6) sprintf(source+strlen(source), "nt_buffer3+=INIT_B;");

	// Begin cycle changing first character
	sprintf(source+strlen(source), "for(uint i=0;i<%uU;i++){", (num_char_in_charset+vector_size-1)/vector_size);

	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s^=charset[NUM_CHAR_IN_CHARSET+%uu*i+%uu];", str_comp[i], vector_size, i);

		/* Round 1 */
sprintf(source+strlen(source), 
		"a=0xFFFFFFFF+nt_buffer0;a<<=3u;"
		"d=%sbs(INIT_C,INIT_B,a)%s;d=rotate(d,7u);"
		"c=%sbs(INIT_B,a,d)%s;c=rotate(c,11u);"
		"b=%sbs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)+%uu;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, key_lenght > 2 ? "" : "INIT_D+", nt_buffer[1], key_lenght > 4 ? "" : "INIT_C+", nt_buffer[2], key_lenght > 6 ? "" : "INIT_B+", nt_buffer[3]
		, nt_buffer[4] , nt_buffer[5] , nt_buffer[6], nt_buffer[7], nt_buffer[8], nt_buffer[9], nt_buffer[10], nt_buffer[11], nt_buffer[12], nt_buffer[13]
		, key_lenght << 4);

		/* Round 2 */
sprintf(source+strlen(source),
		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+%uu;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);"
		, nt_buffer[0], nt_buffer[4], nt_buffer[8] , nt_buffer[12]
		, nt_buffer[1], key_lenght > 2 ? "+0x4A502523" : "+SQRT_2", nt_buffer[5], nt_buffer[9], nt_buffer[13]
		, nt_buffer[2], key_lenght > 4 ? "+0xC1C79C9B" : "+SQRT_2", nt_buffer[6], nt_buffer[10], (key_lenght<<4)+SQRT_2
		, nt_buffer[3], key_lenght > 6 ? "+0x6AB4CE10" : "+SQRT_2", nt_buffer[7], nt_buffer[11]);

		/* Round 3 */
sprintf(source+strlen(source),
		"xx=c^b;"
		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s%s;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+%uu;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s%s;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s%s;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+SQRT_3;b=rotate(b,15u);"
		, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12]
		, nt_buffer[2], key_lenght > 4 ? "+0xD61F0EA3" : "+SQRT_3", nt_buffer[10], nt_buffer[6], (key_lenght<<4)+SQRT_3
		, nt_buffer[1], key_lenght > 2 ? "+0x5EA7972B" : "+SQRT_3", nt_buffer[9] , nt_buffer[5], nt_buffer[13]
		, nt_buffer[3], key_lenght > 6 ? "+0x7F0C4018" : "+SQRT_3", nt_buffer[11], nt_buffer[7]);
	

// End key hashing
sprintf(source+strlen(source),	"uint%s crypt_a=a+%uU;"
								"uint%s crypt_b=b+%uU;"
								"uint%s crypt_c=c+%uU;"
								"uint%s crypt_d=d+%uU;", buffer, 0x67452300/*INIT_A+0xFFFFFFFF*/, buffer, INIT_B+INIT_D, buffer, 0x3175B9FC/*INIT_C+INIT_C*/, buffer, INIT_D+INIT_B);
//Another MD4_crypt for the salt
if (num_diff_salts > 1)
{
	sprintf(source + strlen(source),
		"uint%s last_a=rotate(crypt_a,3u);"
		"uint%s last_d=(INIT_C^(last_a&0x77777777))+crypt_b;last_d=rotate(last_d,7u);"
		"uint%s last_c=bs(INIT_B,last_a,last_d)+crypt_c;last_c=rotate(last_c,11u);"
		"uint%s last_b=bs(last_a,last_d,last_c)+crypt_d;last_b=rotate(last_b,19u);"

		"last_a+=bs(last_d,last_c,last_b);"
		, buffer, buffer, buffer, buffer);

	// For all salts
	if (num_diff_salts > MAX_SALTS_UNROLL)
		sprintf(source + strlen(source),
		"uint max_salt_index=min(%s+%iu,NUM_DIFF_SALTS)*%uu;"
		"for(uint j=%s*%uu;j<max_salt_index;j+=%uu)"
		"{"
			"a=last_a;b=last_b;c=last_c;d=last_d;"
			, num_diff_salts>MAX_SALTS_IN_KERNEL_CHARSET?"begin_salt_index":"0u", MAX_SALTS_IN_KERNEL_CHARSET, num_salt_diff_parts
			, num_diff_salts>MAX_SALTS_IN_KERNEL_CHARSET?"begin_salt_index":"0u", num_salt_diff_parts, num_salt_diff_parts);
}
else
	strcat(source,	"a=rotate(crypt_a,3u);"
					"d=(INIT_C^(a&0x77777777))+crypt_b;d=rotate(d,7u);"
					"c=bs(INIT_B,a,d)+crypt_c;c=rotate(c,11u);"
					"b=bs(a,d,c)+crypt_d;b=rotate(b,19u);"

					"a+=bs(d,c,b);");

if (num_diff_salts <= MAX_SALTS_UNROLL)
{
	cl_uint* salts = (cl_uint*)salts_values;

	for (cl_uint i = 0; i < num_diff_salts; i++)
	{
		if (num_diff_salts > 1)
			sprintf(source + strlen(source), "a=last_a;b=last_b;c=last_c;d=last_d;");

		/* Round 1 */
		sprintf(source+strlen(source),
		"a=rotate(a+%uu,3u);"
		"d+=bs(c,b,a)+%uu;d=rotate(d,7u);"
		"c+=bs(b,a,d)+%uu;c=rotate(c,11u);"
		"b+=bs(a,d,c)+%uu;b=rotate(b,19u);"

		"a+=bs(d,c,b)+%uu;a=rotate(a,3u);"
		"d+=bs(c,b,a)+%uu;d=rotate(d,7u);"
		"c+=bs(b,a,d)+%uu;c=rotate(c,11u);"
		"b+=bs(a,d,c)+%uu;b=rotate(b,19u);"

		"a+=bs(d,c,b)+%uu;a=rotate(a,3u);"
		"d+=bs(c,b,a)+%uu;d=rotate(d,7u);"
		"c+=bs(b,a,d)+%uu;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, salts[11*i+0], salts[11*i+1], salts[11*i+2] , salts[11*i+3] 
		, salts[11*i+4], salts[11*i+5], salts[11*i+6] , salts[11*i+7]
		, salts[11*i+8], salts[11*i+9], salts[11*i+10]);

		/* Round 2 */
		sprintf(source+strlen(source),
		"a+=MAJ(b,c,d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+%uu;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+%uu;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+%uu;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+%uu;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+%uu;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+%uu;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+%uu;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+%uu;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+%uu;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+%uu;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+%uu;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);"
		, SQRT_2-0xFFFFFFFF
		, salts[11*i+0 ]+SQRT_2, salts[11*i+4]+SQRT_2, salts[11*i+8]+SQRT_2, SQRT_2 - INIT_D, salts[11*i+1]+SQRT_2
		, salts[11*i+5 ]+SQRT_2, salts[11*i+9]+SQRT_2, SQRT_2 - INIT_C, salts[11*i+2]+SQRT_2, salts[11*i+6]+SQRT_2
		, salts[11*i+10]+SQRT_2, SQRT_2 - INIT_B, salts[11*i+3]+SQRT_2, salts[11*i+7]+SQRT_2);

		/* Round 3 */
		sprintf(source+strlen(source),
		"xx=c^b;"
		"a+=(xx^d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=(a^xx)+%uu;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)+%uu;c=rotate(c,11u);"
		"b+=(c^xx)+%uu;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=(a^xx)+%uu;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)+%uu;c=rotate(c,11u);"
		"b+=(c^xx)+%uu;b=rotate(b,15u);"

		"a+=(c^b^d)+crypt_b+%uU;a=rotate(a,3u);"
		"a+=crypt_d;"
		, SQRT_3 - 0xFFFFFFFF
		, salts[11*i+4]+SQRT_3, salts[11*i+0 ]+SQRT_3, salts[11*i+8]+SQRT_3, SQRT_3 - INIT_C, salts[11*i+6]+SQRT_3
		, salts[11*i+2]+SQRT_3, salts[11*i+10]+SQRT_3, SQRT_3 - INIT_D);

		cl_uint hash_index = salt_index[i];
		while (hash_index!=NO_ELEM)
		{
			cl_uint a = ((cl_uint*)binary_values)[4 * hash_index + 0];
			cl_uint b = ((cl_uint*)binary_values)[4 * hash_index + 1];
			cl_uint c = ((cl_uint*)binary_values)[4 * hash_index + 2];
			cl_uint d = ((cl_uint*)binary_values)[4 * hash_index + 3];
			cl_uint d_more = rotate(d + SQRT_3, 9);
			cl_uint c_d = c^d_more;

			a = rotate(a, 32 - 3) - SQRT_3 - (b^c^d_more);
			b = rotate(b, 32 - 15) - SQRT_3 - salts[11*i+9];
			c = rotate(c, 32 - 11) - SQRT_3 - salts[11*i+1];
			d -= salts[11 * i + 5];

			char found_str[64];
			if (num_passwords_loaded > 1)
				sprintf(found_str, "uint found=atomic_inc(output);if(found<%uu){", output_size);
			else
				strcpy(found_str, "output[0]=1;{");
			for (cl_uint comp = 0; comp < vector_size; comp++)
				sprintf(source + strlen(source),
					"if(a%s==%uU)"
					"{"
						"a%s-=crypt_d%s;"
						"d%s+=(a%s^c%s^b%s);"

						"c%s+=(%uU^a%s^b%s);"
						"b%s+=(%uU^a%s);"

						"if(c%s==%uu&&b%s==%uu&&d%s==%uu)"
						"{"
							"%s"
							"output[%s1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i*%uU+%uu)%%NUM_CHAR_IN_CHARSET;"
							"output[%s2]=%uu;}"
						"}"
					"}"
				, str_comp[comp], a+INIT_B

				, str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], d_more, str_comp[comp], str_comp[comp]
				, str_comp[comp], c_d, str_comp[comp]

				, str_comp[comp], c, str_comp[comp], b, str_comp[comp], d

				, found_str
				, num_passwords_loaded > 1 ? "2*found+" : "", vector_size, comp
				, num_passwords_loaded > 1 ? "2*found+" : "", hash_index);

			hash_index = same_salt_next[hash_index];
		}
	}
}
else
{
		/* Round 1 */
sprintf(source+strlen(source),
		"a=rotate(a%s,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, salt_values_str[0], salt_values_str[1], salt_values_str[2] , salt_values_str[3] 
		, salt_values_str[4], salt_values_str[5], salt_values_str[6] , salt_values_str[7]
		, salt_values_str[8], salt_values_str[9], salt_values_str[10]);

		/* Round 2 */
sprintf(source+strlen(source),
		"a+=MAJ(b,c,d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);"
		, SQRT_2-0xFFFFFFFF
		, salt_values_str[0], salt_values_str[4], salt_values_str[8], SQRT_2 - INIT_D, salt_values_str[1]
		, salt_values_str[5], salt_values_str[9], SQRT_2 - INIT_C, salt_values_str[2], salt_values_str[6]
		, salt_values_str[10], SQRT_2 - INIT_B, salt_values_str[3], salt_values_str[7]);

		/* Round 3 */
sprintf(source+strlen(source),
		"xx=c^b;"
		"a+=(xx^d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=(a^xx)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=(a^xx)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=(a^xx)%s;"
		, SQRT_3 - 0xFFFFFFFF
		, salt_values_str[4], salt_values_str[0], salt_values_str[8], SQRT_3 - INIT_C, salt_values_str[6]
		, salt_values_str[2], salt_values_str[10], SQRT_3 - INIT_D, num_diff_salts > 1 ? salt_values_str[5] : "");

		// Search for a match
		DivisionParams div_salts = get_div_params(num_salt_diff_parts);
		// Perform division
		if(div_salts.magic)	sprintf(source+strlen(source), "indx=mul_hi(j+%iU,%uU)>>%iU;", (int)div_salts.sum_one, div_salts.magic, (int)div_salts.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=j>>%iU;", (int)div_salts.shift);// Power of two division

		if (num_diff_salts < num_passwords_loaded)
			strcat(source,
		"indx=salt_index[indx];"
		// Iterate by all hashes with same salt
		"while(indx!=0xffffffff)"
		"{");
	
		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			sprintf(source+strlen(source),
				"if(d%s==binary_values[indx])"
				"{"
					"d%s+=SQRT_3;d%s=rotate(d%s,9u);"

					"c%s+=(d%s^a%s^b%s)%s+SQRT_3;c%s=rotate(c%s,11u);"
					"b%s+=(c%s^d%s^a%s)%s+SQRT_3;b%s=rotate(b%s,15u);"
					"a%s+=(b%s^c%s^d%s)+crypt_d%s+%uU;a%s=rotate(a%s,3u);"

					"if(c%s==binary_values[indx+%uu]&&b%s==binary_values[indx+%uu]&&a%s==binary_values[indx+%uu])"
					"{"
						"uint found=atomic_inc(output);"
						"if(found<%uu){"
						"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i*%uU+%uU)%%NUM_CHAR_IN_CHARSET;"
						"output[2*found+2]=indx;}"
					"}"
					// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same d
					//"a%s=rotate(a%s,29u);a%s-=(b%s^c%s^d%s)+crypt_d%s+SQRT_3;"
					//"b%s=rotate(b%s,17u);b%s-=(c%s^d%s^a%s)%s+SQRT_3;"
					//"c%s=rotate(c%s,21u);c%s-=(d%s^a%s^b%s)%s+SQRT_3;"

					//"d%s=rotate(d%s,23u);d%s-=SQRT_3;"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[1], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[9], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], SQRT_3 - INIT_B, str_comp[comp]
				, str_comp[comp], str_comp[comp], 3*num_passwords_loaded, str_comp[comp], 2*num_passwords_loaded, str_comp[comp], num_passwords_loaded
				, output_size, vector_size, comp
				// Reverse
				/*, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[9]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[1]
				, str_comp[comp], str_comp[comp], str_comp[comp]*/);
		}

		// Next iteration
		if (num_diff_salts < num_passwords_loaded)
sprintf(source+strlen(source), "indx=same_salt_next[indx];}");
		strcat(source, "}");
}
	strcat(source, "}}");
}
PRIVATE char* ocl_gen_charset_code(GPUDevice* gpu, cl_uint num_salt_diff_parts, char salt_values_str[11][20], cl_uint output_size)
{
	char* source = (char*)malloc(1024 * 32 * __max(1, max_lenght + 1 - current_key_lenght));
	source[0] = 0;

	if(num_passwords_loaded > 1)
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a)  (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
	sprintf(source+strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");

	//Initial values
	sprintf(source+strlen(source),
"#define INIT_A 0x67452301\n"
"#define INIT_B 0xefcdab89\n"
"#define INIT_C 0x98badcfe\n"
"#define INIT_D 0x10325476\n"

"#define SQRT_2 0x5a827999\n"
"#define SQRT_3 0x6ed9eba1\n"

"#define NUM_CHAR_IN_CHARSET %uU\n"
"#define NUM_DIFF_SALTS %uU\n"

"__constant uchar charset[]={", num_char_in_charset, num_diff_salts);

	// Fill charset
	for (cl_uint i = 0; i < num_char_in_charset; i++)
		sprintf(source + strlen(source), "%s%uU", i ? "," : "", (cl_uint)charset[i%num_char_in_charset]);
	// XOR fast
	if (!is_charset_consecutive(charset))
	{
		for (cl_uint i = 0; i < num_char_in_charset; i += gpu->vector_int_size)
		{
			sprintf(source + strlen(source), ",%uU", i ? (cl_uint)(charset[i] ^ charset[i - gpu->vector_int_size]) : (cl_uint)(charset[0]));

			for (cl_uint j = 1; j < gpu->vector_int_size; j++)
				sprintf(source + strlen(source), ",%uU", i ? (cl_uint)(charset[(i + j) % num_char_in_charset] ^ charset[i + j - gpu->vector_int_size]) : (cl_uint)(charset[j]));
		}
	}
	strcat(source, "};\n");

	for (cl_uint i = current_key_lenght; i < (max_lenght + 1); i++)
	{
		// Function definition
		sprintf(source + strlen(source), "\n__kernel void crypt%u(", i);

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		cl_uint bits_by_char;
		cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, i - 1, &bits_by_char);

		for (cl_uint i = 0; i < num_param_regs; i++)
			sprintf(source + strlen(source), "uint current_key%u,", i);
#else
		sprintf(source + strlen(source), "__constant uchar* current_key __attribute__((max_constant_size(%u))),", __max(2, i));
#endif

		sprintf(source + strlen(source), "__global uint* restrict output");

		if (num_diff_salts > MAX_SALTS_UNROLL)
		{
			strcat(source, ",const __global uint* restrict binary_values,const __global uint* restrict salt_values");

			if (num_diff_salts < num_passwords_loaded)
				strcat(source, ",const __global uint* restrict salt_index,const __global uint* restrict same_salt_next");

			if (num_diff_salts > MAX_SALTS_IN_KERNEL_CHARSET) strcat(source, ",uint begin_salt_index");
		}

		ocl_gen_kernel_with_lenght(source + strlen(source), i, gpu->vector_int_size, num_salt_diff_parts, salt_values_str, output_size);
	}

	return source;
}

PRIVATE void ocl_protocol_charset_work(OpenCL_Param* param)
{
	cl_uchar buffer[MAX_KEY_LENGHT_SMALL+2*sizeof(cl_uint)];
	cl_uint num_found = 0;
	int is_consecutive = is_charset_consecutive(charset);
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	// Params compresed
	cl_uint bits_by_char, chars_in_reg;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	chars_in_reg = 32 / bits_by_char;
	cl_uint max_j = 33 - bits_by_char;
#endif

	HS_SET_PRIORITY_GPU_THREAD;

	while (continue_attack && param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id))
	{
		cl_uint key_lenght = ((cl_uint*)buffer)[8];
		cl_uint num_keys_filled = ((cl_uint*)buffer)[9];
		size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_filled, param->max_work_group_size);// Convert to multiple of work_group_size

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		// Set registers params
		cl_uint num_param_regs = (key_lenght + chars_in_reg - 2) / chars_in_reg;
		cl_uint key_index = 1;
		for (cl_uint i = 0; i < num_param_regs; i++)
		{
			cl_uint key_param = buffer[key_index]; key_index++;

			for (cl_uint j = bits_by_char; j < max_j && key_index < key_lenght; j += bits_by_char, key_index++)
				key_param |= buffer[key_index] << j;

			pclSetKernelArg(param->kernels[key_lenght], i, sizeof(cl_uint), (void*)&key_param);
		}
#else
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, 0, key_lenght, buffer, 0, NULL, NULL);
#endif
		// TODO: Check if there is some problem
		num_keys_filled *= num_char_in_charset;
		int num_keys_reported = 0;

		// Create a batch
		for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_CHARSET)
		{
			if (num_diff_salts > MAX_SALTS_IN_KERNEL_CHARSET)
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
				pclSetKernelArg(param->kernels[key_lenght], num_param_regs + ((num_diff_salts < num_passwords_loaded) ? 5 : 3), sizeof(current_salt_index), (void*)&current_salt_index);
#else
				pclSetKernelArg(param->kernels[key_lenght], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(current_salt_index), (void*)&current_salt_index);
#endif
			pclEnqueueNDRangeKernel(param->queue, param->kernels[key_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			if (((current_salt_index / MAX_SALTS_IN_KERNEL_CHARSET) & 0x7) == 0x7)
			{
				pclFinish(param->queue);
				// Report keys processed from time to time to maintain good Rate
				int num_keys_reported_add = (int)(((int64_t)num_keys_filled)*current_salt_index / num_diff_salts) - num_keys_reported;
				if (num_keys_reported_add > 0)
				{
					num_keys_reported += num_keys_reported_add;
					report_keys_processed(num_keys_reported_add);
				}
			}
			else
				pclFlush(param->queue);
		}
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

		// GPU found some passwords
		if(num_found)
			ocl_charset_process_found(param, &num_found, is_consecutive, buffer, key_lenght);

		if (continue_attack)
		{
			num_keys_filled -= num_keys_reported;
			if (num_keys_filled > 0)
				report_keys_processed(num_keys_filled);
		}
		else
			report_keys_processed(-num_keys_reported);
	}

	release_opencl_param(param);
	finish_thread();
}
PRIVATE void ocl_protocol_charset_init_common(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_mscash_crypt)
{
	// Optimize salts
	cl_uint num_salt_diff_parts = 0;
	char salt_values_str[11][20];
	cl_uint output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Do not allow blank in GPU
	if(current_key_lenght == 0)
	{
		ocl_mscash_test_empty();
		current_key_lenght = 1;
		report_keys_processed(1);
	}

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= 2 * __max(1, 120/num_char_in_charset);
	if(num_diff_salts >= 4)
		param->NUM_KEYS_OPENCL /= 2;
	if(num_diff_salts >= 16)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*__min(param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / (2 * 2 * sizeof(cl_uint))));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Find similar "salts parts" and optimize it---------------------------------
	cl_uint* small_salts_values = ocl_dcc_shrink_salts_size(salt_values_str, &num_salt_diff_parts);

	// Create memory objects
#ifndef HS_OCL_CURRENT_KEY_AS_REGISTERS
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY , MAX_KEY_LENGHT, NULL);
#endif
	create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL);
	
	if(num_diff_salts > MAX_SALTS_UNROLL)
	{
		create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_salt_diff_parts*num_diff_salts, NULL);

		if (num_diff_salts < num_passwords_loaded)
		{
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
		}
	}

	// Copy data to GPU
	unsigned char zero[MAX_KEY_LENGHT_SMALL];
	memset(zero, 0, MAX_KEY_LENGHT_SMALL);
#ifndef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_write_buffer(param, GPU_CURRENT_KEY, MAX_KEY_LENGHT, zero);
#endif
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), zero);
	if (num_diff_salts > MAX_SALTS_UNROLL)
	{
		// Facilitate cache
		cl_uint* bin = (cl_uint*)binary_values;
		cl_uint* my_binary_values = (cl_uint*)malloc(BINARY_SIZE*num_passwords_loaded);
		for (cl_uint i = 0; i < num_passwords_loaded; i++)
		{
			my_binary_values[i + 0 * num_passwords_loaded] = bin[4 * i + 3];
			my_binary_values[i + 1 * num_passwords_loaded] = bin[4 * i + 0];
			my_binary_values[i + 2 * num_passwords_loaded] = bin[4 * i + 1];
			my_binary_values[i + 3 * num_passwords_loaded] = bin[4 * i + 2];
		}

		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, my_binary_values);
		pclFinish(param->queue);
		free(my_binary_values);

		if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY) && num_diff_salts < num_passwords_loaded)
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, 4 * num_passwords_loaded, salt_index, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4 * num_passwords_loaded, same_salt_next, 0, NULL, NULL);
		}
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, sizeof(cl_uint)* num_salt_diff_parts*num_diff_salts, small_salts_values, 0, NULL, NULL);
	}

	// Generate code
	char* source = ocl_gen_charset_code(&gpu_devices[gpu_index], num_salt_diff_parts, salt_values_str, output_size / 2 / sizeof(cl_uint));// Generate opencl code

	//size_t len = strlen(source);
	//{// Uncomment this to view opencl code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\dcc_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return;
	}

	// Crypt by length
	for (cl_uint i = current_key_lenght; i < (max_lenght + 1); i++)
	{
		char name_buffer[16];
		sprintf(name_buffer, "crypt%u", i);
		cl_int code = create_kernel(param, i, name_buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return;
		}

		// Set OpenCL kernel params
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		cl_uint bits_by_char;
		cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, i-1, &bits_by_char);
		for (cl_uint j = 0; j < num_param_regs; j++)
			pclSetKernelArg(param->kernels[i], j, sizeof(cl_uint), (void*)zero);
#else
		cl_uint num_param_regs = 1;
		pclSetKernelArg(param->kernels[i], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
#endif
		pclSetKernelArg(param->kernels[i], num_param_regs, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

		if (num_diff_salts > MAX_SALTS_UNROLL)
		{
			pclSetKernelArg(param->kernels[i], num_param_regs+1, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->kernels[i], num_param_regs+2, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

			if (num_diff_salts < num_passwords_loaded)
			{
				pclSetKernelArg(param->kernels[i], num_param_regs+3, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
				pclSetKernelArg(param->kernels[i], num_param_regs+4, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);
			}
		}
	}

	// Select best work_group
	if (num_diff_salts > MAX_SALTS_IN_KERNEL_CHARSET)
	{
		cl_uint bits_by_char;
		cl_uint param_index = get_number_of_32regs(num_char_in_charset, max_lenght - 1, &bits_by_char) + ((num_diff_salts < num_passwords_loaded) ? 5 : 3);
		pclSetKernelArg(param->kernels[max_lenght], param_index, sizeof(cl_uint), (void*)zero);
	}
	ocl_calculate_best_work_group(param, param->kernels + max_lenght, UINT_MAX / num_char_in_charset, NULL, 0, CL_FALSE, CL_TRUE);

	pclFinish(param->queue);

	free(source);
	free(small_salts_values);
	
	*gpu_mscash_crypt = ocl_protocol_charset_work;
}

PRIVATE void ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_mscash_crypt)
{
	ocl_protocol_charset_init_common(param, gpu_index, gen, gpu_mscash_crypt);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_dcc(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint num_salt_diff_parts, char salt_values_str[11][20], cl_uint prefered_vector_size)
{
	char nt_buffer[16][16];
	char buffer_vector_size[16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// Function definition
	sprintf(source+strlen(source), "\n__kernel void %s(const __global uint* restrict keys,__global uint* restrict output", kernel_name);

	if (num_diff_salts > 1)
	{
		strcat(source, ",const __global uint* restrict binary_values,const __global uint* restrict salt_values");
		if (num_diff_salts < num_passwords_loaded)
			strcat(source, ",const __global uint* restrict salt_index,const __global uint* restrict same_salt_next");
	}

	if(num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER) strcat(source, ",uint begin_salt_index");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		int rest = (num_diff_salts < num_passwords_loaded) ? 0 : 2;
		*aditional_param = (num_diff_salts > 1) ? ((num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER ? 7 : 6)-rest) : 2;
	}

	// Begin function code
	sprintf(source+strlen(source), "){uint indx;");

	// Convert the key into a nt_buffer
	memset(buffer_vector_size, 1, sizeof(buffer_vector_size));
	cl_uint vector_size = ocl_load(source, nt_buffer, buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
	char buffer[16];
	buffer[0] = 0;
	if (vector_size > 1) sprintf(buffer, "%u", vector_size);

	sprintf(source + strlen(source), "uint%s a,b,c,d,xx,crypt_a,crypt_b,crypt_c,crypt_d;", buffer);
													   
		/* Round 1 */								   
	sprintf(source + strlen(source),				   
		"a=0xffffffff%s;a<<=3u;"
		"d=INIT_D+bs(INIT_C,INIT_B,a)%s;d=rotate(d,7u);"
		"c=INIT_C+bs(INIT_B,a,d)%s;c=rotate(c,11u);"
		"b=INIT_B+bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, nt_buffer[0], nt_buffer[1], nt_buffer[2], nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], nt_buffer[7]
		, nt_buffer[8], nt_buffer[9], nt_buffer[10], nt_buffer[11], nt_buffer[12], nt_buffer[13], nt_buffer[14]);

	/* Round 2 */
	sprintf(source + strlen(source),
		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)  +SQRT_2;b=rotate(b,13u);"
		, nt_buffer[0], nt_buffer[4], nt_buffer[8], nt_buffer[12], nt_buffer[1], nt_buffer[5], nt_buffer[9], nt_buffer[13]
		, nt_buffer[2], nt_buffer[6], nt_buffer[10], nt_buffer[14], nt_buffer[3], nt_buffer[7], nt_buffer[11]);

	/* Round 3 */
	sprintf(source + strlen(source),
		"xx=c^b;"
		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+SQRT_3;b=rotate(b,15u);"
		, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12], nt_buffer[2], nt_buffer[10]
		, nt_buffer[6], nt_buffer[14], nt_buffer[1], nt_buffer[9], nt_buffer[5], nt_buffer[13]
		, nt_buffer[3], nt_buffer[11], nt_buffer[7]);

		// End key hashing
sprintf(source+strlen(source),	"crypt_a=a+%uU;"
								"crypt_b=b+%uU;"
								"crypt_c=c+%uU;"
								"crypt_d=d+%uU;", 0x67452300/*INIT_A+0xFFFFFFFF*/, INIT_B+INIT_D, 0x3175B9FC/*INIT_C+INIT_C*/, INIT_D+INIT_B);

//Another MD4_crypt for the salt
if(num_diff_salts > 1)
{
	sprintf(source + strlen(source), "uint%s last_a,last_b,last_c,last_d;", buffer);

	sprintf(source+strlen(source),
		"last_a=rotate(crypt_a,3u);"
		"last_d=(INIT_C^(last_a&0x77777777))+crypt_b;last_d=rotate(last_d,7u);"
		"last_c=bs(INIT_B,last_a,last_d)+crypt_c;last_c=rotate(last_c,11u);"
		"last_b=bs(last_a,last_d,last_c)+crypt_d;last_b=rotate(last_b,19u);"

		// For all salts
		"uint max_salt_index=min(%s+%iu,NUM_DIFF_SALTS)*%uu;"
		"for(uint j=%s*%uu;j<max_salt_index;j+=%uu)"
		"{"
			"a=last_a;b=last_b;c=last_c;d=last_d;"
			, num_diff_salts>MAX_SALTS_IN_KERNEL_OTHER?"begin_salt_index":"0u", MAX_SALTS_IN_KERNEL_OTHER, num_salt_diff_parts
			, num_diff_salts>MAX_SALTS_IN_KERNEL_OTHER?"begin_salt_index":"0u", num_salt_diff_parts, num_salt_diff_parts);
}
else
	strcat(source,	"a=rotate(crypt_a,3u);"
					"d=(INIT_C^(a&0x77777777))+crypt_b;d=rotate(d,7u);"
					"c=bs(INIT_B,a,d)+crypt_c;c=rotate(c,11u);"
					"b=bs(a,d,c)+crypt_d;b=rotate(b,19u);");

		/* Round 1 */
sprintf(source+strlen(source),
		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, salt_values_str[0], salt_values_str[1], salt_values_str[2] , salt_values_str[3] 
		, salt_values_str[4], salt_values_str[5], salt_values_str[6] , salt_values_str[7]
		, salt_values_str[8], salt_values_str[9], salt_values_str[10]);

		/* Round 2 */
sprintf(source+strlen(source),
		"a+=MAJ(b,c,d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);"
		, SQRT_2-0xFFFFFFFF
		, salt_values_str[0] , salt_values_str[4], salt_values_str[8] , SQRT_2-INIT_D, salt_values_str[1] 
		, salt_values_str[5] , salt_values_str[9], SQRT_2-INIT_C, salt_values_str[2] , salt_values_str[6]
		, salt_values_str[10], SQRT_2-INIT_B, salt_values_str[3], salt_values_str[7]);

		/* Round 3 */
sprintf(source+strlen(source),
		"xx=c^b;"
		"a+=(xx^d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=(a^xx)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=(a^xx)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=(a^xx)%s;"
		, SQRT_3-0xFFFFFFFF
		, salt_values_str[4], salt_values_str[0 ], salt_values_str[8], SQRT_3-INIT_C, salt_values_str[6] 
		, salt_values_str[2], salt_values_str[10], SQRT_3-INIT_D, num_diff_salts > 1 ? salt_values_str[5] : "");

	// Search for a match
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (vector_size == 1) str_comp[0] = "";

	if(num_diff_salts > 1)
	{
		DivisionParams div_salts = get_div_params(num_salt_diff_parts);
		// Perform division
		if(div_salts.magic)	sprintf(source+strlen(source), "indx=mul_hi(j+%iU,%uU)>>%iU;", (int)div_salts.sum_one, div_salts.magic, (int)div_salts.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=j>>%iU;", (int)div_salts.shift);// Power of two division

		if (num_diff_salts < num_passwords_loaded)
			strcat(source,
		"indx=salt_index[indx];"
		// Iterate by all hashes with same salt
		"while(indx!=0xffffffff)"
		"{");
		
		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u*found+3u]=%s+%uu;", found_param_3, comp);

			sprintf(source+strlen(source),
			"if(d%s==binary_values[4*indx+3])"
			"{"
				"d%s+=SQRT_3;d%s=rotate(d%s,9u);"

				"c%s+=(d%s^a%s^b%s)%s+SQRT_3;c%s=rotate(c%s,11u);"
				"b%s+=(c%s^d%s^a%s)%s+SQRT_3;b%s=rotate(b%s,15u);"
				"a%s+=(b%s^c%s^d%s)+crypt_d%s+%uU;a%s=rotate(a%s,3u);"

				"if(c%s==binary_values[4*indx+2]&&b%s==binary_values[4*indx+1]&&a%s==binary_values[4*indx+0])"
				"{"
					"uint found=atomic_inc(output);"
					"output[%i*found+1]=get_global_id(0);"
					"output[%i*found+2]=indx;"
					"%s"
				"}"
				// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same d
				//"a=rotate(a,29u);a-=(b^c^d)+crypt_d+%uU;"
				//"b=rotate(b,17u);b-=(c^d^a)%s+SQRT_3;"
				//"c=rotate(c,21u);c-=(d^a^b)%s+SQRT_3;"

				//"d=rotate(d,23u);d-=SQRT_3;"
			"}"
			, str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[1], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[9], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], SQRT_3-INIT_B, str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp]
			, found_multiplier, found_multiplier, output_3
		// Reverse
		/*, SQRT_3-INIT_B, salt_values_str[9], salt_values_str[1]*/);
		}

if (num_diff_salts < num_passwords_loaded)
	strcat(source, "indx=same_salt_next[indx];}");
strcat(source, "}");
	}
	else
	{
		for(cl_uint i = 0; i < num_passwords_loaded; i++)
		{
			cl_uint a = ((cl_uint*)binary_values)[4*i+0];
			cl_uint b = ((cl_uint*)binary_values)[4*i+1];
			cl_uint c = ((cl_uint*)binary_values)[4*i+2];
			cl_uint d = ((cl_uint*)binary_values)[4*i+3];
			cl_uint d_more = rotate(d+SQRT_3, 9);
			cl_uint c_d = c^d_more;

			char output_index[12];
			output_index[0] = 0;
			if (num_passwords_loaded > 1)
				sprintf(output_index, "%i*found+", found_multiplier);

			a = rotate(a, 32 - 3 ) - SQRT_3 - (b^c^d_more);
			b = rotate(b, 32 - 15) - SQRT_3 - ((cl_uint*)salts_values)[9];
			c = rotate(c, 32 - 11) - SQRT_3 - ((cl_uint*)salts_values)[1];
			d -= ((cl_uint*)salts_values)[5];

			for (cl_uint comp = 0; comp < vector_size; comp++)
			{
				if (found_param_3)
					sprintf(output_3, "output[3u%s]=%s+%uu;", (num_passwords_loaded > 1) ? "*found+3u" : "", found_param_3, comp);

				sprintf(source+strlen(source),
					"if(d%s==%uU)"
					"{"
						"c%s+=(%uU^a%s^b%s);"
						"b%s+=(%uU^a%s);"
						"a%s+=crypt_d%s-%uU;"

						"if(c%s==%uu&&b%s==%uu&&a%s==%uu)"
						"{"
							"%s;"
							"output[%s1]=get_global_id(0);"
							"output[%s2]=%uu;"
							"%s"
						"}"
					"}"
					, str_comp[comp], d 
					, str_comp[comp], d_more, str_comp[comp], str_comp[comp]
					, str_comp[comp], c_d, str_comp[comp]
					, str_comp[comp], str_comp[comp], INIT_B
					, str_comp[comp], c, str_comp[comp], b, str_comp[comp], a
					, num_passwords_loaded > 1 ? "uint found=atomic_inc(output)" : "output[0]=1"
					, output_index, output_index, i
					, output_3);
			}
		}
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}
PRIVATE void ocl_work(OpenCL_Param* param)
{
	cl_uint num_found = 0;
	int use_buffer = 1, num_keys_filled;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer1 = malloc(kernel2common->get_buffer_size(param));
	void* buffer2 = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer1, 0, kernel2common->get_buffer_size(param));
	memset(buffer2, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer1, param->NUM_KEYS_OPENCL, param->thread_id);
	while (continue_attack && result)
	{
		size_t num_work_items = kernel2common->process_buffer(use_buffer ? buffer1 : buffer2, result, param, &num_keys_filled);// Convert to multiple of work_group_size
		int num_keys_reported = 0;

		for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
		{
			if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
				pclSetKernelArg(param->kernels[0], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(current_salt_index), (void*)&current_salt_index);

			pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			if ((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER & 0x7) == 0x7)
			{
				pclFinish(param->queue);
				// Report keys processed from time to time to maintain good Rate
				int num_keys_reported_add = (int)(((int64_t)num_keys_filled)*current_salt_index / num_diff_salts) - num_keys_reported;
				if (num_keys_reported_add > 0)
				{
					num_keys_reported += num_keys_reported_add;
					report_keys_processed(num_keys_reported_add);
				}
			}
			else
				pclFlush(param->queue);
		}

		if (continue_attack)
		{
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			pclFlush(param->queue);
			// Generate keys in the CPU concurrently with GPU processing
			result = param->gen(use_buffer ? buffer2 : buffer1, param->NUM_KEYS_OPENCL, param->thread_id);
			use_buffer ^= 1;
			pclFinish(param->queue);

			// GPU found some passwords
			if (num_found)
				ocl_common_process_found(param, &num_found, kernel2common->get_key, use_buffer ? buffer2 : buffer1, num_work_items, num_keys_filled);

			num_keys_filled -= num_keys_reported;
			if (num_keys_filled > 0)
				report_keys_processed(num_keys_filled);
		}
		else
			report_keys_processed(-num_keys_reported);
	}

	free(buffer1);
	free(buffer2);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE void ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc_crypt, ocl_gen_processed_key* gen_processed_key, ocl_setup_proccessed_keys_params* setup_proccessed_keys_params, cl_uint keys_multipler)
{
	// Optimize salts
	cl_uint num_salt_diff_parts = 0;
	char salt_values_str[11][20];
	cl_uint output_size = 2 * sizeof(cl_uint) * num_passwords_loaded;

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= keys_multipler;

	while (param->NUM_KEYS_OPENCL >= gpu_devices[gpu_index].max_mem_alloc_size/32)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint) * param->NUM_KEYS_OPENCL;
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Find similar "salts parts" and optimize it---------------------------------
	cl_uint* small_salts_values = ocl_dcc_shrink_salts_size(salt_values_str, &num_salt_diff_parts);

	/// Generate code
	char* source = (char*)malloc(1024 * 32);

	// Write the definitions needed by the opencl implementation
	ocl_write_dcc_header(source, &gpu_devices[gpu_index], 0);
	// Kernel needed to convert from * to the common format
	gen_processed_key(source, param->NUM_KEYS_OPENCL);

	// Write the kernel
	ocl_gen_kernel_dcc(source, "dcc_crypt", ocl_rule_simple_copy_unicode, NULL, NULL, NULL, DCC_MAX_KEY_LENGHT, param->NUM_KEYS_OPENCL, num_salt_diff_parts, salt_values_str, gpu_devices[gpu_index].vector_int_size);
	//{// Comment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}
	
	// Perform runtime source compilation
	if(!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return;
	}

	// Kernels
	cl_int code = create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return;
	}

	// Generate kernels by lenght
	code = create_kernel(param, 0, "dcc_crypt");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return;
	}

	// Create memory objects
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL);
	if(num_diff_salts > 1)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			if (num_diff_salts < num_passwords_loaded)
			{
				create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
				create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
			}
		}
		else
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			if (num_diff_salts < num_passwords_loaded)
			{
				create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
				create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			}
		}
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_salt_diff_parts*num_diff_salts, NULL);
	}
	setup_proccessed_keys_params(param, &gpu_devices[gpu_index]);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[0], 0, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[0], 1, sizeof(cl_mem), (void*) &param->mems[GPU_OUTPUT]);

	if(num_diff_salts > 1)
	{
		pclSetKernelArg(param->kernels[0], 2, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
		pclSetKernelArg(param->kernels[0], 3, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_VALUES]);
		if (num_diff_salts < num_passwords_loaded)
		{
			pclSetKernelArg(param->kernels[0], 4, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
			pclSetKernelArg(param->kernels[0], 5, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);
		}
	}

	// Copy data to GPU
	memset(source, 0, sizeof(cl_uint));
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, sizeof(cl_uint), source, 0, NULL, NULL);
	if(num_diff_salts > 1)
	{
		if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES] , CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
			if (num_diff_salts < num_passwords_loaded)
			{
				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, sizeof(cl_uint)* num_passwords_loaded, salt_index, 0, NULL, NULL);
				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, sizeof(cl_uint)* num_passwords_loaded, same_salt_next, 0, NULL, NULL);
			}
		}
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, sizeof(cl_uint)*num_salt_diff_parts*num_diff_salts, small_salts_values, 0, NULL, NULL);
	}

	pclFinish(param->queue);
	free(source);
	free(small_salts_values);

	// Find working workgroup
	size_t num_work_items = param->NUM_KEYS_OPENCL;
	int bad_execution = FALSE;
	cl_uint zero = 0;
	if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
		pclSetKernelArg(param->kernels[0], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(zero), (void*)&zero);

	if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
		bad_execution = TRUE;
	if (CL_SUCCESS != pclFinish(param->queue))
		bad_execution = TRUE;
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);

	while (bad_execution && param->max_work_group_size >= 64)
	{
		param->max_work_group_size /= 2;
		bad_execution = FALSE;
		if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
			bad_execution = TRUE;
		if (CL_SUCCESS != pclFinish(param->queue))
			bad_execution = TRUE;
		cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);
	}
	pclFinish(param->queue);
	
	*gpu_dcc_crypt = ocl_work;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	ocl_protocol_common_init(param, gpu_index, gen, gpu_ntlm_crypt, kernels2common[UTF8_INDEX_IN_KERNELS].gen_kernel, kernels2common[UTF8_INDEX_IN_KERNELS].setup_params, 4);
	param->additional_param = kernels2common + UTF8_INDEX_IN_KERNELS;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	ocl_protocol_common_init(param, gpu_index, gen, gpu_ntlm_crypt, kernels2common[PHRASES_INDEX_IN_KERNELS].gen_kernel, kernels2common[PHRASES_INDEX_IN_KERNELS].setup_params, 16);
	param->additional_param = kernels2common + PHRASES_INDEX_IN_KERNELS;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc_crypt)
{
	ocl_rules_init(param, gpu_index, gen, gpu_dcc_crypt, BINARY_SIZE, 0, ocl_write_dcc_header, ocl_gen_kernel_dcc, RULE_UNICODE_INDEX, 1);
}
#endif

PRIVATE int bench_values[] = {1,4,16,64};
Format dcc_format = {
	"DCC"/*"MSCASH"*/,
	"Domain Cache Credentials (also know as MSCASH).",
	DCC_MAX_KEY_LENGHT,
	BINARY_SIZE,
	SALT_SIZE,
	3,
	bench_values,
	LENGHT(bench_values),
	get_binary,
	dcc_line_is_valid,
	add_hash_from_line,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_NTLM, crypt_ntlm_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_NTLM, crypt_ntlm_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_NTLM, crypt_ntlm_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
	#endif
#endif

#ifdef HS_OPENCL_SUPPORT
	{ {PROTOCOL_CHARSET_OCL, ocl_protocol_charset_init }, { PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init }, { PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init }, { PROTOCOL_UTF8, ocl_protocol_utf8_init } }
#endif
};
