// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa. See LICENSE.

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

PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, unsigned int* salt)
{
	unsigned int* out = (unsigned int*)binary;
	unsigned int i = 0;
	unsigned int temp;
	unsigned int salt_lenght = 0;
	char ciphertext_buffer[64];

	//length=11 for save memory
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

typedef int salt_part_func(void* salt_buffer, unsigned int* crypt_result);
PRIVATE salt_part_func* dcc_salt_part_neons[] = {
	dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4,
	dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon4,
	dcc_salt_part_neon4, dcc_salt_part_neon4, dcc_salt_part_neon5, dcc_salt_part_neon5,
	dcc_salt_part_neon6, dcc_salt_part_neon6, dcc_salt_part_neon7, dcc_salt_part_neon7,
	dcc_salt_part_neon8, dcc_salt_part_neon8, dcc_salt_part_neon9, dcc_salt_part_neon9,
	dcc_salt_part_neon10, dcc_salt_part_neon10, dcc_salt_part_neon11, dcc_salt_part_neon11,
	dcc_salt_part_neon12, dcc_salt_part_neon12, dcc_salt_part_neon13, dcc_salt_part_neon13
};

PRIVATE void crypt_ntlm_protocol_neon(CryptParam* param)
{
	unsigned int* nt_buffer		= (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS_NEON, 32);
	unsigned int* crypt_result	= (unsigned int*)_aligned_malloc(16*2*4*3, 32);

	unsigned int i, j, k;
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS_NEON);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_NEON, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS_NEON/8; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_neon(nt_buffer+4*2*i, crypt_result);

			//Another MD4_crypt For all salts
			for(j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				//dcc_salt_part_neon13(salt_buffer, crypt_result);
				dcc_salt_part_neons[salt_buffer[10] >> 4](salt_buffer, crypt_result);

				for(k = 0; k < 8; k++)
				{
					// Search for a match
					unsigned int index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int a, b, c, d = crypt_result[8*8+3*8+k];
						unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

						if(d != bin[3]) goto next_iteration;
						d = rotate(d + SQRT_3, 9);

						c = crypt_result[8*8+2*8+k];
						b = crypt_result[8*8+1*8+k];
						a = crypt_result[8*8+0*8+k];

						c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
						if(c != bin[2]) goto next_iteration;

						b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
						if(b != bin[1]) goto next_iteration;

						a += (b ^ c ^ d) + crypt_result[3*8+k] + SQRT_3; a = rotate(a, 3);
						if(a != bin[0]) goto next_iteration;

						// Total match
						password_was_found(index, ntlm2utf8_key((unsigned int*)nt_buffer, key, NT_NUM_KEYS_NEON, 8*i+k));
next_iteration:
						index = same_salt_next[index];
					}
				}
			}
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}

#endif

#ifndef _M_X64
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
	b += (a ^ d ^ c)							   + SQRT_3; b = rotate(b, 15);

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
PUBLIC void dcc_salt_part_c_code(unsigned int* salt_buffer, unsigned int* crypt_result)
{
	unsigned int a,b,c,d;
	/* Round 1 */
	a = crypt_result[4+0];
	b = crypt_result[4+1];
	c = crypt_result[4+2];
	d = crypt_result[4+3];
				
	a += (d ^ (b & (c ^ d)))  + salt_buffer[0] ; a = rotate(a, 3);
	d += (c ^ (a & (b ^ c)))  + salt_buffer[1] ; d = rotate(d, 7);
	c += (b ^ (d & (a ^ b)))  + salt_buffer[2] ; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a)))  + salt_buffer[3] ; b = rotate(b, 19);
				
	a += (d ^ (b & (c ^ d)))  + salt_buffer[4] ; a = rotate(a, 3);
	d += (c ^ (a & (b ^ c)))  + salt_buffer[5] ; d = rotate(d, 7);
	c += (b ^ (d & (a ^ b)))  + salt_buffer[6] ; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a)))  + salt_buffer[7] ; b = rotate(b, 19);
				
	a += (d ^ (b & (c ^ d)))  + salt_buffer[8] ; a = rotate(a, 3);
	d += (c ^ (a & (b ^ c)))  + salt_buffer[9] ; d = rotate(d, 7);
	c += (b ^ (d & (a ^ b)))  + salt_buffer[10]; c = rotate(c, 11);
	b += (a ^ (c & (d ^ a)))				   ; b = rotate(b, 19);
				
	/* Round 2 */
	a += ((b & (c | d)) | (c & d))  + crypt_result[0]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c))  +  salt_buffer[0]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b))  +  salt_buffer[4]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a))  +  salt_buffer[8]  + SQRT_2; b = rotate(b, 13);
				
	a += ((b & (c | d)) | (c & d))  + crypt_result[1]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c))  +  salt_buffer[1]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b))  +  salt_buffer[5]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a))  +  salt_buffer[9]  + SQRT_2; b = rotate(b, 13);
				
	a += ((b & (c | d)) | (c & d))  + crypt_result[2]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c))  +  salt_buffer[2]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b))  +  salt_buffer[6]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a))  +  salt_buffer[10] + SQRT_2; b = rotate(b, 13);
				
	a += ((b & (c | d)) | (c & d))  + crypt_result[3]  + SQRT_2; a = rotate(a, 3);
	d += ((a & (b | c)) | (b & c))  +  salt_buffer[3]  + SQRT_2; d = rotate(d, 5);
	c += ((d & (a | b)) | (a & b))  +  salt_buffer[7]  + SQRT_2; c = rotate(c, 9);
	b += ((c & (d | a)) | (d & a))					   + SQRT_2; b = rotate(b, 13);
				
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

PRIVATE void crypt_ntlm_protocol_c_code(CryptParam* param)
{
	unsigned int i,j;
	
	unsigned int * nt_buffer = (unsigned int* )calloc(16*NT_NUM_KEYS, sizeof(unsigned int));
	unsigned char* key       = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));
	unsigned int crypt_result[12];

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;

			dcc_ntlm_part_c_code(nt_buffer+i, crypt_result);

			// For all salts
			for(j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				// Search for a match
				unsigned int index = salt_index[j];

				dcc_salt_part_c_code(salt_buffer, crypt_result);

				// Partial match
				while(index != NO_ELEM)
				{
					unsigned int a, b, c, d = crypt_result[8+3];
					unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

					if(d != bin[3]) goto next_iteration;
					d = rotate(d + SQRT_3, 9);

					a = crypt_result[8+0];
					b = crypt_result[8+1];
					c = crypt_result[8+2];
		
					c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
					if(c != bin[2]) goto next_iteration;  
														  
					b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
					if(b != bin[1]) goto next_iteration;  
														  
					a += (b ^ c ^ d) +crypt_result[3] + SQRT_3; a = rotate(a, 3);
					if(a != bin[0]) goto next_iteration;

					// Total match
					password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

	next_iteration:
					index = same_salt_next[index];
				}
			}
		}
	}

	free(key);
	free(nt_buffer);
	finish_thread();
}
#else
void dcc_ntlm_part_avx(void* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_avx(void* salt_buffer, unsigned int* crypt_result);
#define NT_NUM_KEYS_AVX 256
PRIVATE void crypt_ntlm_protocol_avx(CryptParam* param)
{
	unsigned int* nt_buffer		= (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS_AVX, 32);
	unsigned int* crypt_result	= (unsigned int*)_aligned_malloc(16*2*12, 32);

	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		for(unsigned int i = 0; i < NT_NUM_KEYS_AVX/8; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_avx(nt_buffer+4*2*i, crypt_result);

			//Another MD4_crypt for the salt
			// For all salts
			for(unsigned int j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_avx(salt_buffer, crypt_result);

				for(unsigned int k = 0; k < 8; k++)
				{
					// Search for a match
					unsigned int index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int a, b, c, d = crypt_result[8*8+3*8+k];
						unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

						if(d != bin[3]) goto next_iteration;
						d = rotate(d + SQRT_3, 9);

						c = crypt_result[8*8+2*8+k];
						b = crypt_result[8*8+1*8+k];
						a = crypt_result[8*8+0*8+k];

						c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
						if(c != bin[2]) goto next_iteration;

						b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
						if(b != bin[1]) goto next_iteration;

						a += (b ^ c ^ d) + crypt_result[3*8+k] + SQRT_3; a = rotate(a, 3);
						if(a != bin[0]) goto next_iteration;

						// Total match
						password_was_found(index, ntlm2utf8_key((unsigned int*)nt_buffer, key, NT_NUM_KEYS_AVX, 8*i+k));

next_iteration:
						index = same_salt_next[index];
					}
				}
			}
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}

void dcc_ntlm_part_avx2(void* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_avx2(void* salt_buffer, unsigned int* crypt_result);
PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16 * 4 * NT_NUM_KEYS_AVX, 32);
	unsigned int* crypt_result = (unsigned int*)_aligned_malloc(32 * 2 * 4 * 3, 32);

	unsigned int i, j, k;
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));

	memset(nt_buffer, 0, 16 * 4 * NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS_AVX/16; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_avx2(nt_buffer+8*2*i, crypt_result);

			//Another MD4_crypt for the salt
			// For all salts
			for(j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_avx2(salt_buffer, crypt_result);

				for(k = 0; k < 16; k++)
				{
					// Search for a match
					unsigned int index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int a, b, c, d = crypt_result[16*8+3*16+k];
						unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

						if(d != bin[3]) goto next_iteration;
						d = rotate(d + SQRT_3, 9);

						c = crypt_result[16*8+2*16+k];
						b = crypt_result[16*8+1*16+k];
						a = crypt_result[16*8+0*16+k];

						c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
						if(c != bin[2]) goto next_iteration;

						b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
						if(b != bin[1]) goto next_iteration;

						a += (b ^ c ^ d) + crypt_result[3*16+k] + SQRT_3; a = rotate(a, 3);
						if(a != bin[0]) goto next_iteration;

						// Total match
						password_was_found(index, ntlm2utf8_key((unsigned int*)nt_buffer, key, NT_NUM_KEYS_AVX, 16*i+k));

next_iteration:
						index = same_salt_next[index];
					}
				}
			}
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
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include <emmintrin.h>

#define SSE2_AND(a,b)	_mm_and_si128(a,b)
#define SSE2_OR(a,b)	_mm_or_si128(a,b)
#define SSE2_XOR(a,b)	_mm_xor_si128(a,b)
#define SSE2_ADD(a,b)	_mm_add_epi32(a,b)

#define SSE2_ROTATE(a,rot)	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

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
	a = SSE2_ADD(a, SSE2_ADD(_mm_set1_epi32(value), SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP2_SALT(a,b,c,d,value,rot)																		\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_2, SSE2_ADD(_mm_set1_epi32(value), SSE2_OR(SSE2_AND(b, SSE2_OR(c, d)), SSE2_AND(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3_SALT(a,b,c,d,value,rot)																\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_3, SSE2_ADD(_mm_set1_epi32(value), SSE2_XOR(SSE2_XOR(d, c), b))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

// Crypt
#define STEP2_CRYPT(a,b,c,d,value,rot)																		\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_2, SSE2_ADD(value, SSE2_OR(SSE2_AND(b, SSE2_OR(c, d)), SSE2_AND(c, d)))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3_CRYPT(a,b,c,d,value,rot)												\
	a = SSE2_ADD(a, SSE2_ADD(sqrt_3, SSE2_ADD(value, SSE2_XOR(SSE2_XOR(d, c), b))));\
	a = SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot));

#define STEP3_PART(a,b,c,d,value)	a = SSE2_ADD(a, SSE2_ADD(_mm_set1_epi32(value), SSE2_XOR(SSE2_XOR(d, c), b)));

PUBLIC void dcc_ntlm_part_sse2(__m128i* nt_buffer, __m128i* crypt_result)
{
	__m128i a, b, c, d;

	__m128i init_a = _mm_set1_epi32(INIT_A);
	__m128i init_b = _mm_set1_epi32(INIT_B);
	__m128i init_c = _mm_set1_epi32(INIT_C);
	__m128i init_d = _mm_set1_epi32(INIT_D);
	__m128i sqrt_2 = _mm_set1_epi32(SQRT_2);
	__m128i sqrt_3 = _mm_set1_epi32(SQRT_3);

	/* Round 1 */
	a = SSE2_ADD(_mm_set1_epi32(0xFFFFFFFF), nt_buffer[0*NT_NUM_KEYS/4]); SSE2_ROTATE(a, 3);
	d = SSE2_ADD(SSE2_ADD(init_d, SSE2_XOR(init_c, SSE2_AND(a, _mm_set1_epi32(0x77777777)))), nt_buffer[1*NT_NUM_KEYS/4]); SSE2_ROTATE(d, 7);
	c = SSE2_ADD(SSE2_ADD(init_c, SSE2_XOR(init_b, SSE2_AND(d, SSE2_XOR(a, init_b)))), nt_buffer[2*NT_NUM_KEYS/4]); SSE2_ROTATE(c, 11);
	b = SSE2_ADD(SSE2_ADD(init_b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a)))), nt_buffer[3*NT_NUM_KEYS/4]); SSE2_ROTATE(b, 19);
			
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
	a = SSE2_ADD(_mm_set1_epi32(0xFFFFFFFF), crypt_result[0]); SSE2_ROTATE(a, 3);
	d = SSE2_ADD(SSE2_ADD(init_d, SSE2_XOR(init_c, SSE2_AND(a, _mm_set1_epi32(0x77777777)))), crypt_result[1]); SSE2_ROTATE(d, 7);
	c = SSE2_ADD(SSE2_ADD(init_c, SSE2_XOR(init_b, SSE2_AND(d, SSE2_XOR(a, init_b)))), crypt_result[2]); SSE2_ROTATE(c, 11);
	b = SSE2_ADD(SSE2_ADD(init_b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a)))), crypt_result[3]); SSE2_ROTATE(b, 19);
			
	crypt_result[4+0] = a;
	crypt_result[4+1] = b;
	crypt_result[4+2] = c;
	crypt_result[4+3] = d;
}
PUBLIC void dcc_salt_part_sse2(unsigned int* salt_buffer, __m128i* crypt_result)
{
	__m128i a, b, c, d;

	__m128i sqrt_2 = _mm_set1_epi32(SQRT_2);
	__m128i sqrt_3 = _mm_set1_epi32(SQRT_3);

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
	__m128i* nt_buffer = (__m128i*)_aligned_malloc(16*4*NT_NUM_KEYS, 16);
	__m128i crypt_result[12];

	unsigned int i, j, k;
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS/4; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_sse2(nt_buffer+i, crypt_result);

			// For all salts
			for(j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_sse2(salt_buffer, crypt_result);

				for(k = 0; k < 4; k++)
				{
					// Search for a match
					unsigned int index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int a, b, c, d = ((unsigned int*)crypt_result)[4*8+3*4+k];
						unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

						if(d != bin[3]) goto next_iteration;
						d = rotate(d + SQRT_3, 9);

						a = ((unsigned int*)crypt_result)[4*8+0*4+k];
						b = ((unsigned int*)crypt_result)[4*8+1*4+k];
						c = ((unsigned int*)crypt_result)[4*8+2*4+k];

						c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
						if(c != bin[2]) goto next_iteration;

						b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
						if(b != bin[1]) goto next_iteration;

						a += (b ^ c ^ d) + ((unsigned int*)crypt_result)[3*4+k] + SQRT_3; a = rotate(a, 3);
						if(a != bin[0]) goto next_iteration;

						// Total match
						password_was_found(index, ntlm2utf8_key((unsigned int*)nt_buffer, key, NT_NUM_KEYS, 4*i+k));

next_iteration:
						index = same_salt_next[index];
					}
				}
			}
		}
	}

	free(key);
	_aligned_free(nt_buffer);
	finish_thread();
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define MAX_SALTS_IN_KERNEL_CHARSET	16
#define MAX_SALTS_IN_KERNEL_OTHER	64

PRIVATE void ocl_write_dcc_header(char* source, GPUDevice* gpu)
{
	source[0] = 0;
	// Header definitions
	if(num_passwords_loaded > 1 )
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a) (%s)\n", gpu->native_bitselect?"bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
	sprintf(source+strlen(source), "#define s2(b,c,d) (%s)\n", gpu->native_bitselect?"bs(bs(b,c,d),bs(d,b,c),b)" : "(b&(c|d))|(c&d)");
	
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

PRIVATE unsigned int* ocl_shrink_salts_size(char salt_values_str[11][20], unsigned int* num_salt_diff_parts)
{
	unsigned char equal_salt[SALT_SIZE/4];
	unsigned char mapped_pos[SALT_SIZE/4];
	unsigned int j, diff_pos = 0;
	unsigned int* salt_ptr = (unsigned int*)salts_values;
	memset(equal_salt, 1, sizeof(equal_salt));

	// Find salts parts that are equals
	for(unsigned int i = 1; i < num_diff_salts; i++)
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
	unsigned int* small_salts_values = (unsigned int*)malloc(4*num_salt_diff_parts[0]*num_diff_salts);
	for(unsigned int i = 0; i < num_diff_salts; i++)
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

		a += (d ^ (b & (c ^ d)))  + salt_buffer[0]  ; a = rotate(a, 3);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[1]  ; d = rotate(d, 7);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[2]  ; c = rotate(c, 11);
		b += (a ^ (c & (d ^ a)))  + salt_buffer[3]  ; b = rotate(b, 19);

		a += (d ^ (b & (c ^ d)))  + salt_buffer[4]  ; a = rotate(a, 3);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[5]  ; d = rotate(d, 7);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[6]  ; c = rotate(c, 11);
		b += (a ^ (c & (d ^ a)))  + salt_buffer[7]  ; b = rotate(b, 19);

		a += (d ^ (b & (c ^ d)))  + salt_buffer[8]  ; a = rotate(a, 3);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[9]  ; d = rotate(d, 7);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[10] ; c = rotate(c, 11);
		b += (a ^ (c & (d ^ a)))					; b = rotate(b, 19);

		/* Round 2 */
		a += ((b & (c | d)) | (c & d))  +     0xe0cfd631   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[0]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[4]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[8]  + SQRT_2; b = rotate(b, 13);

		a += ((b & (c | d)) | (c & d))  +     0x31e96ad1   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[1]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[5]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[9]  + SQRT_2; b = rotate(b, 13);

		a += ((b & (c | d)) | (c & d))  +     0xd7593cb7     + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[2]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[6]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[10] + SQRT_2; b = rotate(b, 13);

		a += ((b & (c | d)) | (c & d))  +     0xc089c0e0   + SQRT_2; a = rotate(a, 3);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[3]  + SQRT_2; d = rotate(d, 5);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[7]  + SQRT_2; c = rotate(c, 9);
		b += ((c & (d | a)) | (d & a))					   + SQRT_2; b = rotate(b, 13);

		/* Round 3 */
		a += (b ^ c ^ d) +    0xe0cfd631   +  SQRT_3; a = rotate(a, 3);
		d += (a ^ b ^ c) + salt_buffer[4]  +  SQRT_3; d = rotate(d, 9);
		c += (d ^ a ^ b) + salt_buffer[0]  +  SQRT_3; c = rotate(c, 11);
		b += (c ^ d ^ a) + salt_buffer[8]  +  SQRT_3; b = rotate(b, 15);

		a += (b ^ c ^ d) +    0xd7593cb7   +  SQRT_3; a = rotate(a, 3);
		d += (a ^ b ^ c) + salt_buffer[6]  +  SQRT_3; d = rotate(d, 9);
		c += (d ^ a ^ b) + salt_buffer[2]  +  SQRT_3; c = rotate(c, 11);
		b += (c ^ d ^ a) + salt_buffer[10] +  SQRT_3; b = rotate(b, 15);

		a += (b ^ c ^ d) +    0x31e96ad1   +  SQRT_3; a = rotate(a, 3);
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

			cc = c + (dd ^ a ^ b) + salt_buffer[1] +  SQRT_3; cc = rotate(cc, 11);
			if(cc != bin[2]) goto next_iteration;

			bb = b + (cc ^ dd ^ a) + salt_buffer[9]+  SQRT_3; bb = rotate(bb, 15);
			if(bb != bin[1]) goto next_iteration;

			aa = a + (bb ^ cc ^ dd) +   0xc089c0e0 +  SQRT_3; aa = rotate(aa, 3);
			if(aa != bin[0]) goto next_iteration;

			// Total match
			password_was_found(index, "");

next_iteration:
			index = same_salt_next[index];
		}
	}
}
PRIVATE void ocl_gen_kernel_with_lenght(char* source, unsigned int key_lenght, unsigned int vector_size, unsigned int num_salt_diff_parts, char salt_values_str[11][20])
{
	unsigned int i;
	DivisionParams div_param = get_div_params(num_char_in_charset);
	char* str_comp[] = {".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf"};
	char* nt_buffer[] = {"+nt_buffer0" , "+nt_buffer1" , "+nt_buffer2" , "+nt_buffer3" , 
						 "+nt_buffer4" , "+nt_buffer5" , "+nt_buffer6" , "+nt_buffer7" , 
						 "+nt_buffer8" , "+nt_buffer9" , "+nt_buffer10", "+nt_buffer11", 
						 "+nt_buffer12", "+nt_buffer13"};
	char buffer[4];
	buffer[0] = 0;

	if(vector_size == 1) str_comp[0] = "";
	if(vector_size > 1)	 itoa(vector_size, buffer, 10);

	// Function definition
	sprintf(source+strlen(source), "\n__kernel void dcc_crypt%u(__constant uchar* current_key __attribute__((max_constant_size(%u))),__global uint* output", key_lenght, __max(2, key_lenght));

	if(num_diff_salts > 1)
		strcat(source, ",const __global uint* binary_values,const __global uint* salt_values,const __global uint* salt_index,const __global uint* same_salt_next");

	if(num_diff_salts > MAX_SALTS_IN_KERNEL_CHARSET) strcat(source, ",uint begin_salt_index");

	// Begin function code
	sprintf(source+strlen(source), "){"
									"uint max_number=get_global_id(0)+current_key[1];"
									"uint%s a,b,c,d,nt_buffer0,xx;"
									"uint indx;", buffer);

	// Perform division
	if(div_param.magic)	sprintf(source+strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source+strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

	strcat(source,	"nt_buffer0=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<16;"
					"max_number=indx;");

	for(i = 1; i < key_lenght/2; i++)
	{
		sprintf(source+strlen(source), "max_number+=current_key[%i];", 2*i);
		// Perform division
		if(div_param.magic)	sprintf(source+strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

		sprintf(source+strlen(source),	"uint nt_buffer%u=charset[max_number-NUM_CHAR_IN_CHARSET*indx];"
										"max_number=indx;"
										"max_number+=current_key[%i];", i, 2*i+1);
		// Perform division
		if(div_param.magic)	sprintf(source+strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

		sprintf(source+strlen(source),	"nt_buffer%u|=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<16;"
										"max_number=indx;", i);
	}

	if(key_lenght == 1)
		sprintf(source+strlen(source), "nt_buffer0=0x800000;");
	else if(key_lenght & 1)
	{
		sprintf(source+strlen(source), "max_number+=current_key[%i];", key_lenght-1);
		// Perform division
		if(div_param.magic)	sprintf(source+strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

		sprintf(source+strlen(source), "uint nt_buffer%u=((uint)(charset[max_number-NUM_CHAR_IN_CHARSET*indx]))|0x800000;", i);
	}
	else
		nt_buffer[i] = "+0x80";

	for(i = 0; i < 14; i++)
		if(i > key_lenght/2)
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
		sprintf(source+strlen(source), "nt_buffer0^=first_xor[i];");

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
		"a+=s2(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)+%uu;b=rotate(b,13u);"

		"a+=s2(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)+SQRT_2;b=rotate(b,13u);"
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
if(num_diff_salts > 1)
	sprintf(source+strlen(source),
		"uint%s last_a=rotate(crypt_a,3u);"
		"uint%s last_d=(INIT_C^(last_a&0x77777777))+crypt_b;last_d=rotate(last_d,7u);"
		"uint%s last_c=bs(INIT_B,last_a,last_d)+crypt_c;last_c=rotate(last_c,11u);"
		"uint%s last_b=bs(last_a,last_d,last_c)+crypt_d;last_b=rotate(last_b,19u);"

		// For all salts
		"uint max_salt_index=min(%s+%iu,NUM_DIFF_SALTS)*%uu;"
		"for(uint j=%s*%uu;j<max_salt_index;j+=%uu)"
		"{"
			"a=last_a;b=last_b;c=last_c;d= last_d;"
			, buffer, buffer, buffer, buffer, num_diff_salts>MAX_SALTS_IN_KERNEL_CHARSET?"begin_salt_index":"0u", MAX_SALTS_IN_KERNEL_CHARSET, num_salt_diff_parts
			, num_diff_salts>MAX_SALTS_IN_KERNEL_CHARSET?"begin_salt_index":"0u", num_salt_diff_parts, num_salt_diff_parts);
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
		"a+=s2(b,c,d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)+SQRT_2;b=rotate(b,13u);"
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

{
	unsigned int comp;

	// Search for a match
	if(num_diff_salts > 1)
	{
		DivisionParams div_salts = get_div_params(num_salt_diff_parts);
		// Perform division
		if(div_salts.magic)	sprintf(source+strlen(source), "indx=mul_hi(j+%iU,%uU)>>%iU;", (int)div_salts.sum_one, div_salts.magic, (int)div_salts.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=j>>%iU;", (int)div_salts.shift);// Power of two division

		strcat(source,	"indx=salt_index[indx];");
		// Iterate by all hashes with same salt
sprintf(source+strlen(source),
		"while(indx!=0xffffffff)"
		"{");
	
		for(comp = 0; comp < vector_size; comp++)
		{
			sprintf(source+strlen(source),
				"if(d%s==binary_values[4*indx+3])"
				"{"
					"d%s+=SQRT_3;d%s=rotate(d%s,9u);"

					"c%s+=(d%s^a%s^b%s)%s+SQRT_3;c%s=rotate(c%s,11u);"
					"b%s+=(c%s^d%s^a%s)%s+SQRT_3;b%s=rotate(b%s,15u);"
					"a%s+=(b%s^c%s^d%s)+crypt_d%s+%uU;a%s=rotate(a%s,3u);"

					"if(c%s==binary_values[4*indx+2]&&b%s==binary_values[4*indx+1]&&a%s==binary_values[4*indx+0])"
					"{"
						"uint found=atom_inc(output);"
						"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i*%uU+%uU)%%NUM_CHAR_IN_CHARSET;"
						"output[2*found+2]=indx;"
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
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], SQRT_3-INIT_B, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], vector_size, comp
				// Reverse
				/*, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[9]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], salt_values_str[1]
				, str_comp[comp], str_comp[comp], str_comp[comp]*/);
		}

		// Next iteration
sprintf(source+strlen(source), "indx=same_salt_next[indx];}}");
	}
	else
		for(i = 0; i < num_passwords_loaded; i++)
		{
			unsigned int a = ((unsigned int*)binary_values)[4*i+0];
			unsigned int b = ((unsigned int*)binary_values)[4*i+1];
			unsigned int c = ((unsigned int*)binary_values)[4*i+2];
			unsigned int d = ((unsigned int*)binary_values)[4*i+3];
			unsigned int d_more = rotate(d+SQRT_3, 9);
			unsigned int c_d = c^d_more;

			a = rotate(a, 32-3) - SQRT_3 - (b^c^d_more);
			b = rotate(b, 32-15) - SQRT_3 - ((unsigned int*)salts_values)[9];
			c = rotate(c, 32-11) - SQRT_3 - ((unsigned int*)salts_values)[1];
			d -= ((unsigned int*)salts_values)[5];

			for(comp = 0; comp < vector_size; comp++)
				sprintf(source+strlen(source),
					"if(d%s==%uU)"
					"{"
						"c%s+=(%uU^a%s^b%s);"
						"b%s+=(%uU^a%s);"
						"a%s+=crypt_d%s-%uU;"

						"if(c%s==%uu&&b%s==%uu&&a%s==%uu)"
						"{"
							"%s;"
							"output[%s1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i*%uU+%uu)%%NUM_CHAR_IN_CHARSET;"
							"output[%s2]=%uu;"
						"}"
						// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same d
					"}"
					, str_comp[comp], d
					, str_comp[comp], d_more, str_comp[comp], str_comp[comp]
					, str_comp[comp], c_d, str_comp[comp]
					, str_comp[comp], str_comp[comp], INIT_B
					, str_comp[comp], c, str_comp[comp], b, str_comp[comp], a
					, num_passwords_loaded > 1 ? "uint found=atom_inc(output)" : "output[0]=1"
					, num_passwords_loaded > 1 ? "2*found+" : "", vector_size, comp
					, num_passwords_loaded > 1 ? "2*found+" : "", i
					// Reverse
					);
		}
}
	strcat(source, "}}");
}
PRIVATE char* ocl_gen_charset_code(GPUDevice* gpu, unsigned int num_salt_diff_parts, char salt_values_str[11][20])
{
	unsigned int i,j;
	char* source = (char*)malloc(1024*32*__max(1, max_lenght-current_key_lenght+1));// TODO: reduce this
	source[0] = 0;

	if(num_passwords_loaded > 1)
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a) (%s)\n", gpu->native_bitselect?"bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
	sprintf(source+strlen(source), "#define s2(b,c,d) (%s)\n", gpu->native_bitselect?"bs(bs(b,c,d),bs(d,b,c),b)" : "(b&(c|d))|(c&d)");

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
	for(i = 0; i < num_char_in_charset; i++)
		sprintf(source+strlen(source), "%s%uU", i?",":"", (unsigned int)charset[i%num_char_in_charset]);
	strcat(source, "};\n");

	// XOR fast
	if( !is_charset_consecutive(charset) )
	{
		if(gpu->vector_int_size > 1)sprintf(source+strlen(source), "\n__constant uint%u first_xor[]={", gpu->vector_int_size);
		else						sprintf(source+strlen(source), "\n__constant uint first_xor[]={");
	
		for(i = 0; i < num_char_in_charset; i+=gpu->vector_int_size)
		{
			if(gpu->vector_int_size > 1)
				sprintf(source+strlen(source), "%s((uint%u)(%uU", i?",":"", gpu->vector_int_size, i ? (unsigned int)(charset[i] ^ charset[i-gpu->vector_int_size]) : (unsigned int)(charset[0]));
			else
				sprintf(source+strlen(source), "%s%uU", i?",":"", i ? (unsigned int)(charset[i] ^ charset[i-gpu->vector_int_size]) : (unsigned int)(charset[0]));

			for (j = 1; j < gpu->vector_int_size; j++)
				sprintf(source+strlen(source), ",%uU",i ? (unsigned int)(charset[(i+j)%num_char_in_charset] ^ charset[(i-(gpu->vector_int_size-j))%num_char_in_charset]) : (unsigned int)(charset[j]));
			if(gpu->vector_int_size > 1) sprintf(source+strlen(source), "))");
		}
		strcat(source, "};\n");
	}

	for(i = current_key_lenght; i <= max_lenght; i++)
	{
		cl_uint vector_int_size = is_charset_consecutive(charset) ? gpu->vector_int_size_when_consecutive : gpu->vector_int_size;
		ocl_gen_kernel_with_lenght(source+strlen(source), i, vector_int_size, num_salt_diff_parts, salt_values_str);
	}

	//{// Comment this code for release
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	return source;
}

PRIVATE void ocl_protocol_charset_work(OpenCL_Param* param)
{
	unsigned char buffer[MAX_KEY_LENGHT+2*sizeof(cl_uint)];
	unsigned int num_found = 0;
	int is_consecutive = is_charset_consecutive(charset);

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	while(continue_attack && param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id))
	{
		unsigned int key_lenght = ((unsigned int*)buffer)[8];
		size_t num_work_items = (((unsigned int*)buffer)[9] + (param->max_work_group_size-1)) & ~(param->max_work_group_size-1);// Convert to multiple of work_group_size
		// TODO: Check if there is some problem
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, 0, key_lenght, buffer, 0, NULL, NULL);

		// Create a batch
		for (unsigned int current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_CHARSET)
		{
			if (num_diff_salts > MAX_SALTS_IN_KERNEL_CHARSET)
				pclSetKernelArg(param->kernels[key_lenght], 6, sizeof(current_salt_index), (void*)&current_salt_index);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[key_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			if ((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER & 0x7) == 0x7)
				pclFinish(param->queue);
			else
				pclFlush(param->queue);
		}
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

		// GPU found some passwords
		if(num_found)
			ocl_charset_process_found(param, &num_found, is_consecutive, buffer, key_lenght);
	}

	release_opencl_param(param);
	finish_thread();
}
PRIVATE OpenCL_Param* ocl_protocol_charset_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_mscash_crypt)
{
	cl_int code;
	unsigned int i;
	char* source;
	// Optimize salts
	unsigned int num_salt_diff_parts = 0;
	char salt_values_str[11][20];
	unsigned int output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	OpenCL_Param* param = create_opencl_param(gpu_device_index, gen, output_size, FALSE);
	if(!param)	return NULL;

	// Do not allow blank in GPU
	if(current_key_lenght == 0)
	{
		ocl_mscash_test_empty();
		current_key_lenght = 1;
		num_keys_served_from_save++;
	}

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= 2 * __max(1, 60/num_char_in_charset);
	if(num_diff_salts >= 4)
		param->NUM_KEYS_OPENCL /= 2;
	if(num_diff_salts >= 16)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*__min(param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_device_index].max_mem_alloc_size / (2 * 2 * sizeof(cl_uint))));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Find similar "salts parts" and optimize it---------------------------------
	unsigned int* small_salts_values = ocl_shrink_salts_size(salt_values_str, &num_salt_diff_parts);

	/// Generate code
	source = ocl_gen_charset_code(&gpu_devices[gpu_device_index], num_salt_diff_parts, salt_values_str);// Generate opencl code
	
	// Perform runtime source compilation
	if(!build_opencl_program(param, source, gpu_devices[gpu_device_index].compiler_options))
	{
		release_opencl_param(param);
		return NULL;
	}

	// Crypt by length
	for(i = current_key_lenght; i <= max_lenght; i++)
	{
		char name_buffer[16];
		sprintf(name_buffer, "dcc_crypt%u", i);
		code = create_kernel(param, i, name_buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return NULL;
		}
	}

	// Create memory objects
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY , MAX_KEY_LENGHT, NULL);
	create_opencl_mem(param, GPU_OUTPUT		, CL_MEM_READ_WRITE, 4+output_size, NULL);
	if(num_diff_salts > 1)
	{
		if(gpu_devices[gpu_device_index].has_unified_memory)
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, 4*num_salt_diff_parts*num_diff_salts, NULL);
	}

	// Set OpenCL kernel params
	for(i = current_key_lenght; i <= max_lenght; i++)
	{
		pclSetKernelArg(param->kernels[i], 0, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
		pclSetKernelArg(param->kernels[i], 1, sizeof(cl_mem), (void*) &param->mems[GPU_OUTPUT]);

		if(num_diff_salts > 1)
		{
			pclSetKernelArg(param->kernels[i], 2, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->kernels[i], 3, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_VALUES]);
			pclSetKernelArg(param->kernels[i], 4, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_INDEX]);
			pclSetKernelArg(param->kernels[i], 5, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_SALT_NEXT]);
		}
	}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT);
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, 0, MAX_KEY_LENGHT , source, 0, NULL, NULL);
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT]		, CL_FALSE, 0, sizeof(cl_uint), source, 0, NULL, NULL);
	if(num_diff_salts > 1)
	{
		if(!gpu_devices[gpu_device_index].has_unified_memory)
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES] , CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX]	   , CL_FALSE, 0, 4*num_passwords_loaded, salt_index, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4*num_passwords_loaded, same_salt_next, 0, NULL, NULL);
		}
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, 4*num_salt_diff_parts*num_diff_salts, small_salts_values, 0, NULL, NULL);
	}

	// Select best work_group
	if (num_diff_salts > MAX_SALTS_IN_KERNEL_CHARSET)
		pclSetKernelArg(param->kernels[max_lenght], 6, sizeof(cl_uint), (void*)source);
	ocl_calculate_best_work_group(param, param->kernels[max_lenght], UINT_MAX / num_char_in_charset);

	free(source);
	free(small_salts_values);
	
	*gpu_mscash_crypt = ocl_protocol_charset_work;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_dcc(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, unsigned int lenght, unsigned int NUM_KEYS_OPENCL, unsigned int num_salt_diff_parts, char salt_values_str[11][20])
{
	char nt_buffer[16][16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	if (found_param_3)
		sprintf(output_3, "output[3%s]=%s;", num_passwords_loaded > 1 ? "*found+3" : "", found_param_3);

	// Function definition
	sprintf(source+strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output", kernel_name);

	if(num_diff_salts > 1)
		strcat(source, ",const __global uint* binary_values,const __global uint* salt_values,const __global uint* salt_index,const __global uint* same_salt_next");

	if(num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER) strcat(source, ",uint begin_salt_index");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = (num_diff_salts > 1) ? (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER ? 7 : 6) : 2;
	}

	// Begin function code
	sprintf(source+strlen(source), "){"
									"uint a,b,c,d,xx;"
									"uint indx;");

	// Convert the key into a nt_buffer
	ocl_load(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

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
		"a+=s2(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)  +SQRT_2;b=rotate(b,13u);"
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
sprintf(source+strlen(source),	"uint crypt_a=a+%uU;"
								"uint crypt_b=b+%uU;"
								"uint crypt_c=c+%uU;"
								"uint crypt_d=d+%uU;", 0x67452300/*INIT_A+0xFFFFFFFF*/, INIT_B+INIT_D, 0x3175B9FC/*INIT_C+INIT_C*/, INIT_D+INIT_B);

//Another MD4_crypt for the salt
if(num_diff_salts > 1)
	sprintf(source+strlen(source),
		"uint last_a=rotate(crypt_a,3u);"
		"uint last_d=(INIT_C^(last_a&0x77777777))+crypt_b;last_d=rotate(last_d,7u);"
		"uint last_c=bs(INIT_B,last_a,last_d)+crypt_c;last_c=rotate(last_c,11u);"
		"uint last_b=bs(last_a,last_d,last_c)+crypt_d;last_b=rotate(last_b,19u);"

		// For all salts
		"uint max_salt_index=min(%s+%iu,NUM_DIFF_SALTS)*%uu;"
		"for(uint j=%s*%uu;j<max_salt_index;j+=%uu)"
		"{"
			"a=last_a;b=last_b;c=last_c;d= last_d;"
			, num_diff_salts>MAX_SALTS_IN_KERNEL_OTHER?"begin_salt_index":"0u", MAX_SALTS_IN_KERNEL_OTHER, num_salt_diff_parts
			, num_diff_salts>MAX_SALTS_IN_KERNEL_OTHER?"begin_salt_index":"0u", num_salt_diff_parts, num_salt_diff_parts);
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
		"a+=s2(b,c,d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=s2(b,c,d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=s2(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=s2(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=s2(c,d,a)+SQRT_2;b=rotate(b,13u);"
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
	if(num_diff_salts > 1)
	{
		DivisionParams div_salts = get_div_params(num_salt_diff_parts);
		// Perform division
		if(div_salts.magic)	sprintf(source+strlen(source), "indx=mul_hi(j+%iU,%uU)>>%iU;", (int)div_salts.sum_one, div_salts.magic, (int)div_salts.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=j>>%iU;", (int)div_salts.shift);// Power of two division

		strcat(source,	"indx=salt_index[indx];");
		// Iterate by all hashes with same salt
sprintf(source+strlen(source),
		"while(indx!=0xffffffff)"
		"{"
			"if(d==binary_values[4*indx+3])"
			"{"
				"d+=SQRT_3;d=rotate(d,9u);"

				"c+=(d^a^b)%s+SQRT_3;c=rotate(c,11u);"
				"b+=(c^d^a)%s+SQRT_3;b=rotate(b,15u);"
				"a+=(b^c^d)+crypt_d+%uU;a=rotate(a,3u);"

				"if(c==binary_values[4*indx+2]&&b==binary_values[4*indx+1]&&a==binary_values[4*indx+0])"
				"{"
					"uint found=atom_inc(output);"
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
			"indx=same_salt_next[indx];"
		"}}"
		, salt_values_str[1], salt_values_str[9], SQRT_3-INIT_B, found_multiplier, found_multiplier, output_3
		// Reverse
		/*, SQRT_3-INIT_B, salt_values_str[9], salt_values_str[1]*/);
	}
	else
		for(unsigned int i = 0; i < num_passwords_loaded; i++)
		{
			char output_index[12];
			output_index[0] = 0;
			if (num_passwords_loaded > 1)
				sprintf(output_index, "%i*found+", found_multiplier);

			unsigned int a = ((unsigned int*)binary_values)[4*i+0];
			unsigned int b = ((unsigned int*)binary_values)[4*i+1];
			unsigned int c = ((unsigned int*)binary_values)[4*i+2];
			unsigned int d = ((unsigned int*)binary_values)[4*i+3];
			unsigned int d_more = rotate(d+SQRT_3, 9);
			unsigned int c_d = c^d_more;

			a = rotate(a, 32-3 ) - SQRT_3 - (b^c^d_more);
			b = rotate(b, 32-15) - SQRT_3 - ((unsigned int*)salts_values)[9];
			c = rotate(c, 32-11) - SQRT_3 - ((unsigned int*)salts_values)[1];
			d -= ((unsigned int*)salts_values)[5];

			sprintf(source+strlen(source),
				"if(d==%uU)"
				"{"
					"c+=(%uU^a^b);"
					"b+=(%uU^a);"
					"a+=crypt_d-%uU;"

					"if(c==%uu&&b==%uu&&a==%uu)"
					"{"
						"%s;"
						"output[%s1]=get_global_id(0);"
						"output[%s2]=%uu;"
						"%s"
					"}"
					// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same d
				"}"
				, d , d_more, c_d, INIT_B
				, c, b, a
				, num_passwords_loaded > 1 ? "uint found=atom_inc(output)" : "output[0]=1"
				, output_index, output_index, i
				, output_3
				// Reverse
				);
		}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}
PRIVATE void ocl_work(OpenCL_Param* param)
{
	unsigned int num_found = 0;
	int use_buffer = 1, num_keys_filled;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer1 = malloc(kernel2common->get_buffer_size(param));
	void* buffer2 = malloc(kernel2common->get_buffer_size(param));

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	memset(buffer1, 0, kernel2common->get_buffer_size(param));
	memset(buffer2, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer1, param->NUM_KEYS_OPENCL, param->thread_id);
	while (continue_attack && result)
	{
		size_t num_work_items = kernel2common->process_buffer(use_buffer ? buffer1 : buffer2, result, param, &num_keys_filled);// Convert to multiple of work_group_size

		for (unsigned int current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
		{
			if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
				pclSetKernelArg(param->kernels[0], 6, sizeof(current_salt_index), (void*)&current_salt_index);

			pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			if ((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER & 0x7) == 0x7)
				pclFinish(param->queue);
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
				ocl_common_process_found(param, &num_found, kernel2common->get_key, use_buffer ? buffer2 : buffer1, num_work_items);
		}
	}

	free(buffer1);
	free(buffer2);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE OpenCL_Param* ocl_protocol_common_init(unsigned int gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc_crypt, ocl_gen_processed_key* gen_processed_key, ocl_setup_proccessed_keys_params* setup_proccessed_keys_params, unsigned int keys_multipler)
{
	cl_int code;
	unsigned int local_num_found = 0;
	// Optimize salts
	unsigned int num_salt_diff_parts = 0;
	char salt_values_str[11][20];
	unsigned int output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	OpenCL_Param* param = create_opencl_param(gpu_index, gen, output_size, FALSE);
	if(!param)	return NULL;

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= keys_multipler;

	while (param->NUM_KEYS_OPENCL >= gpu_devices[gpu_index].max_mem_alloc_size/32)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*param->NUM_KEYS_OPENCL;
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Find similar "salts parts" and optimize it---------------------------------
	unsigned int* small_salts_values = ocl_shrink_salts_size(salt_values_str, &num_salt_diff_parts);

	/// Generate code
	char* source = (char*)malloc(1024 * 32);

	// Write the definitions needed by the opencl implementation
	ocl_write_dcc_header(source, &gpu_devices[gpu_index]);
	// Kernel needed to convert from * to the common format
	gen_processed_key(source, param->NUM_KEYS_OPENCL);

	// Write the kernel
	ocl_gen_kernel_dcc(source, "dcc_crypt", ocl_rule_simple_copy, NULL, NULL, NULL, DCC_MAX_KEY_LENGHT, param->NUM_KEYS_OPENCL, num_salt_diff_parts, salt_values_str);
	//{// Comment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}
	
	// Perform runtime source compilation
	if(!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return NULL;
	}

	// Kernels
	code = create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return NULL;
	}

	// Generate kernels by lenght
	code = create_kernel(param, 0, "dcc_crypt");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return NULL;
	}

	// Create memory objects
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY , 32 * param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param, GPU_OUTPUT		, CL_MEM_READ_WRITE, 4+output_size, NULL);
	if(num_diff_salts > 1)
	{
		if(gpu_devices[gpu_index].has_unified_memory)
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, 4*num_salt_diff_parts*num_diff_salts, NULL);
	}
	setup_proccessed_keys_params(param, &gpu_devices[gpu_index]);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[0], 0, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[0], 1, sizeof(cl_mem), (void*) &param->mems[GPU_OUTPUT]);

	if(num_diff_salts > 1)
	{
		pclSetKernelArg(param->kernels[0], 2, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
		pclSetKernelArg(param->kernels[0], 3, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_VALUES]);
		pclSetKernelArg(param->kernels[0], 4, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_INDEX]);
		pclSetKernelArg(param->kernels[0], 5, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_SALT_NEXT]);
	}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT);
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT]		, CL_FALSE, 0, 4, &local_num_found, 0, NULL, NULL);
	if(num_diff_salts > 1)
	{
		if(!gpu_devices[gpu_index].has_unified_memory)
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES] , CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX]	   , CL_FALSE, 0, 4*num_passwords_loaded, salt_index, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4*num_passwords_loaded, same_salt_next, 0, NULL, NULL);
		}
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, 4*num_salt_diff_parts*num_diff_salts, small_salts_values, 0, NULL, NULL);
	}

	pclFinish(param->queue);
	free(source);
	free(small_salts_values);
	
	*gpu_dcc_crypt = ocl_work;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE OpenCL_Param* ocl_protocol_utf8_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	OpenCL_Param* param = ocl_protocol_common_init(gpu_device_index, gen, gpu_ntlm_crypt, kernels2common[UTF8_INDEX_IN_KERNELS].gen_kernel, kernels2common[UTF8_INDEX_IN_KERNELS].setup_params, 4);
	param->additional_param = kernels2common + UTF8_INDEX_IN_KERNELS;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE OpenCL_Param* ocl_protocol_phrases_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	OpenCL_Param* param = ocl_protocol_common_init(gpu_device_index, gen, gpu_ntlm_crypt, kernels2common[PHRASES_INDEX_IN_KERNELS].gen_kernel, kernels2common[PHRASES_INDEX_IN_KERNELS].setup_params, 16);
	param->additional_param = kernels2common + PHRASES_INDEX_IN_KERNELS;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern int current_rules_count;
extern apply_rule_funtion** current_rules;
extern int provider_index;
void rules_calculate_key_space(int64_t num_keys_generate, unsigned int num_keys_original, int64_t num_keys_in_memory, int gpu_device_index);

PRIVATE char* ocl_gen_rules_code(GPUDevice* gpu, OpenCL_Param* param, int kernel2common_index, unsigned int num_salt_diff_parts, char salt_values_str[11][20])
{
	char* source = (char*)malloc(1024 * 32 * __max(1, current_rules_count)*(DCC_MAX_KEY_LENGHT + 1));

	// This is because AMD compiler do not support __constant vars inside a kernel
	ocl_write_code** constants_written = (ocl_write_code**)malloc(current_rules_count*sizeof(ocl_write_code*));
	int num_constants_written = 0;

	// Write the definitions needed by the opencl implementation
	ocl_write_dcc_header(source, gpu);

	// Kernel needed to convert from * to the common format
	kernels2common[kernel2common_index].gen_kernel(source, param->NUM_KEYS_OPENCL);
	// Kernel needed to convert from common format to the ordered by lenght format
	ocl_gen_kernel_common_2_ordered(source, param->NUM_KEYS_OPENCL, DCC_MAX_KEY_LENGHT);

	// Generate one kernel for each rule
	for (unsigned int lenght = 0; lenght <= DCC_MAX_KEY_LENGHT; lenght++)
	{
		for (int i = 0; i < current_rules_count; i++)
		{
			char kernel_name[12];
			char found_param[64];
			int* need_param_ptr = NULL;
			// Find the index of the current rule
			int rule_index;
			for (rule_index = 0; rule_index < num_rules; rule_index++)
			if (rules[rule_index].function == current_rules[i])
				break;

			if (rules[rule_index].ocl.max_param_value)
				need_param_ptr = &param->param0;

			// If needed to use constants -> write it only once
			if (rules[rule_index].ocl.setup_constants)
			{
				int constants_already_written = FALSE, j;
				// Check if was written before
				for (j = 0; j < num_constants_written; j++)
				if (rules[rule_index].ocl.setup_constants == constants_written[j])
				{
					constants_already_written = TRUE;
					break;
				}
				if (!constants_already_written)
				{
					constants_written[num_constants_written] = rules[rule_index].ocl.setup_constants;
					num_constants_written++;
					rules[rule_index].ocl.setup_constants(source);
				}
			}
			// Write the kernel
			sprintf(kernel_name, "dcc_%il%i", i, lenght);
			sprintf(found_param, "(%uu+%s)", (rule_index << 22) + (lenght << 27), rules[rule_index].ocl.found_param);
			ocl_gen_kernel_dcc(source, kernel_name, rules[rule_index].ocl.begin, rules[rule_index].ocl.end, found_param, need_param_ptr, lenght, param->NUM_KEYS_OPENCL, num_salt_diff_parts, salt_values_str);
		}
	}

	free(constants_written);

	//{// Comment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	return source;
}
PRIVATE void ocl_protocol_rules_work(OpenCL_Param* param)
{
	unsigned int gpu_num_keys_by_len[DCC_MAX_KEY_LENGHT + 1];
	unsigned int gpu_pos_ordered_by_len[DCC_MAX_KEY_LENGHT + 1];
	unsigned int num_found = 0;
	unsigned int num_iterations = (num_diff_salts + MAX_SALTS_IN_KERNEL_OTHER - 1) / MAX_SALTS_IN_KERNEL_OTHER;
	int num_keys_filled;
	// To obtain rules index
	int* rules_remapped = (int*)malloc(sizeof(int)*current_rules_count);

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	// Size in uint
	for (unsigned int i = 0, j = 32; i <= DCC_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->NUM_KEYS_OPENCL;
	}

	// Find the index of the current rules
	for (int i = 0; i < current_rules_count; i++)
		for (int j = 0; j < num_rules; j++)
			if (rules[j].function == current_rules[i])
			{
				rules_remapped[i] = j;
				break;
			}

	unsigned int num_keys_to_read = param->NUM_KEYS_OPENCL;
	int result = param->gen(buffer, num_keys_to_read, param->thread_id);
	int64_t num_keys_in_memory = 0;
	while (continue_attack && result)
	{
		// Enqueue the process_key kernel
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Convert to ordered by lenght
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_ORDERED_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (DCC_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
		num_keys_to_read = 0;
		num_keys_in_memory = 0;
		// Calculate the number of keys in memory
		for (int lenght = 0; lenght <= DCC_MAX_KEY_LENGHT; lenght++)
			for (int i = 0; i < current_rules_count; i++)
			{
				int64_t multipler = rules[rules_remapped[i]].multipler;
				if (rules[rules_remapped[i]].depend_key_lenght)
					multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

				num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
			}
		rules_calculate_key_space(-num_keys_filled, num_keys_filled, num_keys_in_memory, param->gpu_device_index);

		for (int lenght = 0; continue_attack && lenght <= DCC_MAX_KEY_LENGHT; lenght++)
			if (gpu_num_keys_by_len[lenght] >= param->NUM_KEYS_OPENCL/4*3)
			{
				size_t num_work_items_len = (gpu_num_keys_by_len[lenght] + (param->max_work_group_size - 1)) & ~(param->max_work_group_size - 1);// Convert to multiple of work_group_size
				// Do actual hashing
				for (int i = 0; continue_attack && i < current_rules_count; i++)
					if (rules[rules_remapped[i]].ocl.max_param_value)
					{
						// Some params
						int64_t multipler = rules[rules_remapped[i]].multipler / rules[rules_remapped[i]].ocl.max_param_value;
						int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
						if (rules[rules_remapped[i]].depend_key_lenght)
							max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;
						multipler *= gpu_num_keys_by_len[lenght];

						int64_t num_keys_by_batch = multipler*16/num_iterations;
						multipler -= num_keys_by_batch*(num_iterations/16);

						for (int j = 0; continue_attack && j < max_param_value; j++)
						{
							pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param

							for (unsigned int current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
							{
								if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
									pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], 6, sizeof(current_salt_index), (void*)&current_salt_index);

								pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
								// For large different salts to behave properly
								if (((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
								{
									num_keys_in_memory -= num_keys_by_batch;
									rules_calculate_key_space(num_keys_by_batch, 0, num_keys_in_memory, param->gpu_device_index);
									pclFinish(param->queue);
								}
								else
									pclFlush(param->queue);
							}
							
							// For kernels with large params to behave properly
							if ((j & 0xf) == 0xf)
								pclFinish(param->queue);
							else
								pclFlush(param->queue);

							num_keys_in_memory -= multipler;
							rules_calculate_key_space(multipler, 0, num_keys_in_memory, param->gpu_device_index);
						}
					}
					else
					{
						int64_t multipler = rules[rules_remapped[i]].multipler;
						if (rules[rules_remapped[i]].depend_key_lenght)
							multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
						multipler *= gpu_num_keys_by_len[lenght];

						int64_t num_keys_by_batch = multipler*16/num_iterations;
						multipler -= num_keys_by_batch*(num_iterations/16);

						for (unsigned int current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
						{
							if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
								pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], 6, sizeof(current_salt_index), (void*)&current_salt_index);

							pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);

							// For large different salts to behave properly
							if (((current_salt_index/MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
							{
								num_keys_in_memory -= num_keys_by_batch;
								rules_calculate_key_space(num_keys_by_batch, 0, num_keys_in_memory, param->gpu_device_index);
								pclFinish(param->queue);
							}
							else
								pclFlush(param->queue);
						}

						num_keys_in_memory -= multipler;
						rules_calculate_key_space(multipler, 0, num_keys_in_memory, param->gpu_device_index);
					}

				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, lenght*sizeof(cl_uint), sizeof(cl_uint), &num_found, 0, NULL, NULL);
			}
			// Find fullest lenght
			else if (gpu_num_keys_by_len[lenght] > num_keys_to_read)
			{
				num_keys_to_read = gpu_num_keys_by_len[lenght];
			}
		// Next block of keys
		if (continue_attack)
		{
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			pclFlush(param->queue);

			// Generate keys in the CPU concurrently with GPU processing
			// Calculate the free space left in the fullest lenght
			num_keys_to_read = param->NUM_KEYS_OPENCL - num_keys_to_read;
			num_keys_to_read &= ~(param->max_work_group_size - 1);// Make it a multiple of work_group_size
			result = param->gen(buffer, num_keys_to_read, param->thread_id);

			pclFinish(param->queue);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len);
		}
	}

	// Get the last passwords from memory
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (DCC_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
	num_keys_in_memory = 0;
	// Calculate the number of keys in memory
	for (int lenght = 0; lenght <= DCC_MAX_KEY_LENGHT; lenght++)
		for (int i = 0; i < current_rules_count; i++)
		{
			int64_t multipler = rules[rules_remapped[i]].multipler;
			if (rules[rules_remapped[i]].depend_key_lenght)
				multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

			num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
		}
	rules_calculate_key_space(0, 0, num_keys_in_memory, param->gpu_device_index);

	for (int lenght = 0; /*continue_attack &&*/ lenght <= DCC_MAX_KEY_LENGHT; lenght++)
		if (gpu_num_keys_by_len[lenght])
		{
			size_t num_work_items_len = (gpu_num_keys_by_len[lenght] + (param->max_work_group_size - 1)) & ~(param->max_work_group_size - 1);// Convert to multiple of work_group_size;
			// Do actual hashing
			for (int i = 0; /*continue_attack &&*/ i < current_rules_count; i++)
				if (rules[rules_remapped[i]].ocl.max_param_value)
				{
					// Some params
					int64_t multipler = rules[rules_remapped[i]].multipler / rules[rules_remapped[i]].ocl.max_param_value;
					int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
					if (rules[rules_remapped[i]].depend_key_lenght)
						max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;
					multipler *= gpu_num_keys_by_len[lenght];

					int64_t num_keys_by_batch = multipler*16/num_iterations;
					multipler -= num_keys_by_batch*(num_iterations/16);

					for (int j = 0; /*continue_attack &&*/ j < max_param_value; j++)
					{
						pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param

						for (unsigned int current_salt_index = 0; /*continue_attack &&*/ current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
						{
							if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
								pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], 6, sizeof(current_salt_index), (void*)&current_salt_index);

							pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
							// For large different salts to behave properly
							if (((current_salt_index/MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
							{
								num_keys_in_memory -= num_keys_by_batch;
								rules_calculate_key_space(num_keys_by_batch, 0, num_keys_in_memory, param->gpu_device_index);
								pclFinish(param->queue);
							}
							else
								pclFlush(param->queue);
						}
						// For kernels with large params to behave properly
						if ((j & 0xf) == 0xf)
							pclFinish(param->queue);
						else
							pclFlush(param->queue);

						num_keys_in_memory -= multipler;
						rules_calculate_key_space(multipler, 0, num_keys_in_memory, param->gpu_device_index);
					}
				}
				else
				{
					int64_t multipler = rules[rules_remapped[i]].multipler;
					if (rules[rules_remapped[i]].depend_key_lenght)
						multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
					multipler *= gpu_num_keys_by_len[lenght];

					int64_t num_keys_by_batch = multipler*16/num_iterations;
					multipler -= num_keys_by_batch*(num_iterations/16);

					for (unsigned int current_salt_index = 0; /*continue_attack &&*/ current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
					{
						if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
							pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], 6, sizeof(current_salt_index), (void*)&current_salt_index);

						pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
						// For large different salts to behave properly
						if (((current_salt_index/MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
						{
							num_keys_in_memory -= num_keys_by_batch;
							rules_calculate_key_space(num_keys_by_batch, 0, num_keys_in_memory, param->gpu_device_index);
							pclFinish(param->queue);
						}
						else
							pclFlush(param->queue);
					}

					num_keys_in_memory -= multipler;
					rules_calculate_key_space(multipler, 0, num_keys_in_memory, param->gpu_device_index);
				}

			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len);
		}

	free(rules_remapped);
	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE OpenCL_Param* ocl_protocol_rules_init(unsigned int gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc_crypt)
{
	cl_int code;
	int i, kernel2common_index, len;
	char* source;
	unsigned int gpu_key_buffer_lenght;
	OpenCL_Param* param;
	unsigned int output_size = 3 * sizeof(cl_uint)*num_passwords_loaded;
	int multipler = 0;
	// Optimize salts
	unsigned int num_salt_diff_parts = 0;
	char salt_values_str[11][20];

	// Find a compatible generate_key_funtion function for a given key_provider
	for (i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	param = create_opencl_param(gpu_index, gen, output_size, FALSE);
	if (!param)	return NULL;

	// Count the possible number of generated keys
	for (i = 0; i < current_rules_count; i++)
	{
		// Find the index of the current rule
		int rule_index;
		for (rule_index = 0; rule_index < num_rules; rule_index++)
			if (rules[rule_index].function == current_rules[i])
				break;

		multipler += rules[rule_index].multipler;
	}

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i <= DCC_MAX_KEY_LENGHT; i++)
		gpu_key_buffer_lenght += (i + 3) / 4 * sizeof(cl_uint);

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL /= 4;
	param->NUM_KEYS_OPENCL *= multipler < 95 ? 64 : 1;
	if (num_diff_salts <= 32 && param->NUM_KEYS_OPENCL < UINT_MAX/2) param->NUM_KEYS_OPENCL *= 2;
	if (num_diff_salts <= 16 && param->NUM_KEYS_OPENCL < UINT_MAX/2) param->NUM_KEYS_OPENCL *= 2;
	if (num_diff_salts <= 4  && param->NUM_KEYS_OPENCL < UINT_MAX/2) param->NUM_KEYS_OPENCL *= 2;
	if (num_diff_salts <= 2  && param->NUM_KEYS_OPENCL < UINT_MAX/2) param->NUM_KEYS_OPENCL *= 2;

	while (param->NUM_KEYS_OPENCL >= (gpu_devices[gpu_index].max_mem_alloc_size - 32 * sizeof(cl_uint))/gpu_key_buffer_lenght)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && multipler*param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		// Reserve to output at maximum half the MAX_MEM_ALLOC_SIZE
		output_size = 3 * sizeof(cl_uint)*__min(multipler*param->NUM_KEYS_OPENCL, 4 * 1024 * 1024);
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Find similar "salts parts" and optimize it---------------------------------
	unsigned int* small_salts_values = ocl_shrink_salts_size(salt_values_str, &num_salt_diff_parts);

	// Generate code
	source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, num_salt_diff_parts, salt_values_str);// Generate opencl code

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return NULL;
	}

	// Crypt by length
	code = create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return NULL;
	}
	code = create_kernel(param, KERNEL_ORDERED_INDEX, "common2ordered");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return NULL;
	}
	// Create rules kernels
	param->num_rules_kernels = current_rules_count*(DCC_MAX_KEY_LENGHT + 1);
	param->rules_kernels = (cl_kernel*)malloc(sizeof(cl_kernel)*param->num_rules_kernels);
	for (len = 0; len <= DCC_MAX_KEY_LENGHT; len++)
		for (i = 0; i < current_rules_count; i++)
		{
			char name_buffer[12];
			sprintf(name_buffer, "dcc_%il%i", i, len);
			param->rules_kernels[i + len*current_rules_count] = pclCreateKernel(param->program, name_buffer, &code);
			if (code != CL_SUCCESS)
			{
				release_opencl_param(param);
				return NULL;
			}
		}

	// Create memory objects
	create_opencl_mem(param, GPU_ORDERED_KEYS, CL_MEM_READ_WRITE, 32 * sizeof(cl_uint)+param->NUM_KEYS_OPENCL*gpu_key_buffer_lenght, NULL);
	create_opencl_mem(param, GPU_CURRENT_KEY , CL_MEM_READ_WRITE, MAX_KEY_LENGHT*param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param, GPU_OUTPUT		 , CL_MEM_READ_WRITE, 4 + output_size, NULL);

	if(num_diff_salts > 1)
	{
		if(gpu_devices[gpu_index].has_unified_memory)
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, 4*num_salt_diff_parts*num_diff_salts, NULL);
	}

	// Set OpenCL kernel params
	kernels2common[kernel2common_index].setup_params(param, &gpu_devices[gpu_index]);

	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 1, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);

	for (len = 0; len <= DCC_MAX_KEY_LENGHT; len++)
		for (i = 0; i < current_rules_count; i++)
		{
			pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
			pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

			if(num_diff_salts > 1)
			{
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 2, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 3, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_VALUES]);
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 4, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_INDEX]);
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 5, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_SALT_NEXT]);
			}
		}

	// Copy data to GPU
	memset(source, 0, 32 * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, 4, source);
	cl_write_buffer(param, GPU_ORDERED_KEYS, 32 * sizeof(cl_uint), source);
	if(num_diff_salts > 1)
	{
		if(!gpu_devices[gpu_index].has_unified_memory)
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES] , CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX]	   , CL_FALSE, 0, 4*num_passwords_loaded, salt_index, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4*num_passwords_loaded, same_salt_next, 0, NULL, NULL);
		}
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, 4*num_salt_diff_parts*num_diff_salts, small_salts_values, 0, NULL, NULL);
	}

	pclFinish(param->queue);
	free(source);
	free(small_salts_values);

	*gpu_dcc_crypt = ocl_protocol_rules_work;
	param->additional_param = kernels2common + kernel2common_index;
	return param;
}
#endif

PRIVATE int bench_values[] = {1,4,16,64};
Format mscash_format = {
	"DCC"/*"MSCASH"*/,
	"Domain Cache Credentials (also know as MSCASH).",
	DCC_MAX_KEY_LENGHT,
	BINARY_SIZE,
	SALT_SIZE,
	3,
	bench_values,
	LENGHT(bench_values),
	get_binary,
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
		{{PROTOCOL_CHARSET_OCL, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
	#endif
};
