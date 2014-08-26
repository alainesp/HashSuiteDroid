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

#define BINARY_SIZE			16
#define NTLM_MAX_KEY_LENGHT	27

PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	unsigned int* out = (unsigned int*)binary;
	unsigned int i = 0;
	unsigned int temp;

	for (; i < 4; i++)
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
	
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3;
	
	return out[1];
}

#ifdef HS_ARM

#define NT_NUM_KEYS		    128
PRIVATE void crypt_ntlm_protocol_arm(CryptParam* param)
{
	int i;
	
	unsigned int nt_buffer[15*NT_NUM_KEYS];
	unsigned int a, b, c, d, index;

	unsigned char key[MAX_KEY_LENGHT];

	memset(nt_buffer, 0, sizeof(nt_buffer));
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			/* Round 1 */
			a = 		0xFFFFFFFF					 + nt_buffer[0*NT_NUM_KEYS+i]; a=rotate(a, 3);
			d = INIT_D+(INIT_C ^ (a & 0x77777777))   + nt_buffer[1*NT_NUM_KEYS+i]; d=rotate(d, 7);
			c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2*NT_NUM_KEYS+i]; c=rotate(c, 11);
			b = INIT_B + (a ^ (c & (d ^ a)))		 + nt_buffer[3*NT_NUM_KEYS+i]; b=rotate(b, 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[4*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[5*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[6*NT_NUM_KEYS+i] ; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer[7*NT_NUM_KEYS+i] ; b = rotate(b , 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[8*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[9*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[10*NT_NUM_KEYS+i]; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer[11*NT_NUM_KEYS+i]; b = rotate(b , 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[12*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[13*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[14*NT_NUM_KEYS+i] ; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))								 ; b = rotate(b , 19);

			/* Round 2 */
			a += ((b & (c | d)) | (c & d)) + nt_buffer[0*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[4*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[8*NT_NUM_KEYS+i] + SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[12*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[1*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[5*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[9*NT_NUM_KEYS+i] + SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[13*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[2*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[6*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[10*NT_NUM_KEYS+i]+ SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[14*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[11*NT_NUM_KEYS+i]+ SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a))								+ SQRT_2; b = rotate(b , 13);

			/* Round 3 */
			a += (d ^ c ^ b) + nt_buffer[0*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 );
			d += (c ^ b ^ a) + nt_buffer[8*NT_NUM_KEYS+i]  + SQRT_3; d = rotate(d , 9 );
			c += (b ^ a ^ d) + nt_buffer[4*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11);
			b += (a ^ d ^ c) + nt_buffer[12*NT_NUM_KEYS+i] + SQRT_3; b = rotate(b , 15);

			a += (d ^ c ^ b) + nt_buffer[2*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 );
			d += (c ^ b ^ a) + nt_buffer[10*NT_NUM_KEYS+i] + SQRT_3; d = rotate(d , 9 );
			c += (b ^ a ^ d) + nt_buffer[6*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11);
			b += (a ^ d ^ c) + nt_buffer[14*NT_NUM_KEYS+i] + SQRT_3; b = rotate(b , 15);

			a += (d ^ c ^ b) + nt_buffer[1*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 );
			d += (c ^ b ^ a) + nt_buffer[9*NT_NUM_KEYS+i]  + SQRT_3; d = rotate(d , 9 );
			c += (b ^ a ^ d) + nt_buffer[5*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11);
			b += (a ^ d ^ c) + nt_buffer[13*NT_NUM_KEYS+i];								

			// Search for a match
			index = table[b & size_table];

			// Partial match
			while(index != NO_ELEM)
			{
				unsigned int aa, bb, cc, dd;
				unsigned int* bin = ((unsigned int*)binary_values) + index*4;

				if(b != bin[1]) goto next_iteration;
				bb = b + SQRT_3; bb = rotate(bb , 15);
	
				aa = a + (bb ^ c ^ d) + nt_buffer[3*NT_NUM_KEYS+i]  + SQRT_3; aa = rotate(aa , 3 );
				if(aa != bin[0]) goto next_iteration;
				
				dd = d + (aa ^ bb ^ c) + nt_buffer[11*NT_NUM_KEYS+i] + SQRT_3; dd = rotate(dd , 9 );
				if(dd != bin[3]) goto next_iteration;
				
				cc = c + (dd ^ aa ^ bb) + nt_buffer[7*NT_NUM_KEYS+i]  + SQRT_3; cc = rotate(cc , 11);	
				if(cc != bin[2]) goto next_iteration;

				// Total match
				password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

next_iteration:
				index = same_hash_next[index];
			}
		}
	}

	finish_thread();
}

void crypt_ntlm_neon_kernel_asm(unsigned int* buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_ntlm_protocol_neon(CryptParam* param)
{
	int i;

	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS+5*4*NT_NUM_KEYS, 32);

	unsigned int* unpacked_as = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS);
	unsigned int* unpacked_bs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 1*NT_NUM_KEYS);
	unsigned int* unpacked_cs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 2*NT_NUM_KEYS);
	unsigned int* unpacked_ds = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 3*NT_NUM_KEYS);
	unsigned int* indexs	  = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 4*NT_NUM_KEYS);

	unsigned char key[MAX_KEY_LENGHT];

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_ntlm_neon_kernel_asm(nt_buffer, bit_table, size_bit_table);

		for (i = 0; i < NT_NUM_KEYS; i++)
			if(indexs[i])
			{
				// Search for a match
				unsigned int index = table[unpacked_bs[i] & size_table];

				// Partial match
				while (index != NO_ELEM)
				{
					unsigned int aa, bb, cc, dd;
					unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

					if (unpacked_bs[i] != bin[1]) goto next_iteration;
					bb = unpacked_bs[i] + SQRT_3; bb = rotate(bb, 15);

					aa = unpacked_as[i] + (bb ^ unpacked_cs[i] ^ unpacked_ds[i]) + nt_buffer[3 * NT_NUM_KEYS + i] + SQRT_3; aa = rotate(aa, 3);
					if (aa != bin[0]) goto next_iteration;

					dd = unpacked_ds[i] + (aa ^ bb ^ unpacked_cs[i]) + nt_buffer[11 * NT_NUM_KEYS + i] + SQRT_3; dd = rotate(dd, 9);
					if (dd != bin[3]) goto next_iteration;

					cc = unpacked_cs[i] + (dd ^ aa ^ bb) + nt_buffer[7 * NT_NUM_KEYS + i] + SQRT_3; cc = rotate(cc, 11);
					if (cc != bin[2]) goto next_iteration;

					// Total match
					password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

next_iteration:
					index = same_hash_next[index];
				}
			}
	}
	_aligned_free(nt_buffer);

	finish_thread();
}

#else
#define NT_NUM_KEYS		    256
#ifndef _M_X64
PRIVATE void crypt_ntlm_protocol_x86(CryptParam* param)
{
	int i;
	
	// TODO: To much stack -> Move all this to heap
	unsigned int nt_buffer[16*NT_NUM_KEYS];
	unsigned int as[NT_NUM_KEYS];
	unsigned int bs[NT_NUM_KEYS];
	unsigned int cs[NT_NUM_KEYS];
	unsigned int ds[NT_NUM_KEYS];

	unsigned int a, b, c, d;

	unsigned int indexs[NT_NUM_KEYS];

	unsigned char key[MAX_KEY_LENGHT];

	memset(nt_buffer, 0, sizeof(nt_buffer));
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			/* Round 1 */
			a = 		0xFFFFFFFF					 + nt_buffer[0*NT_NUM_KEYS+i]; a=rotate(a, 3);
			d = INIT_D+(INIT_C ^ (a & 0x77777777))   + nt_buffer[1*NT_NUM_KEYS+i]; d=rotate(d, 7);
			c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2*NT_NUM_KEYS+i]; c=rotate(c, 11); cs[i] = c;
			b = INIT_B + (a ^ (c & (d ^ a)))		 + nt_buffer[3*NT_NUM_KEYS+i]; b=rotate(b, 19); bs[i] = b;

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[4*NT_NUM_KEYS+i] ; a = rotate(a , 3 ); as[i] = a;
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[5*NT_NUM_KEYS+i] ; d = rotate(d , 7 ); ds[i] = d;
		}
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			a = as[i]; b = bs[i]; c = cs[i]; d = ds[i];

			c += (b ^ (d & (a ^ b)))  +  nt_buffer[6*NT_NUM_KEYS+i] ; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer[7*NT_NUM_KEYS+i] ; b = rotate(b , 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[8*NT_NUM_KEYS+i] ; a = rotate(a , 3 ); as[i] = a;
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[9*NT_NUM_KEYS+i] ; d = rotate(d , 7 ); ds[i] = d;
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[10*NT_NUM_KEYS+i]; c = rotate(c , 11); cs[i] = c;
			b += (a ^ (c & (d ^ a)))  +  nt_buffer[11*NT_NUM_KEYS+i]; b = rotate(b , 19); bs[i] = b;
		}
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			a = as[i]; b = bs[i]; c = cs[i]; d = ds[i];

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[12*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[13*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[14*NT_NUM_KEYS+i] ; c = rotate(c , 11); cs[i] = c;
			b += (a ^ (c & (d ^ a)))								 ; b = rotate(b , 19); bs[i] = b;

			/* Round 2 */
			a += ((b & (c | d)) | (c & d)) + nt_buffer[0*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 ); as[i] = a;
			d += ((a & (b | c)) | (b & c)) + nt_buffer[4*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 ); ds[i] = d;
		}
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			a = as[i]; b = bs[i]; c = cs[i]; d = ds[i];

			c += ((d & (a | b)) | (a & b)) + nt_buffer[8*NT_NUM_KEYS+i] + SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[12*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[1*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 ); as[i] = a;
			d += ((a & (b | c)) | (b & c)) + nt_buffer[5*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 ); ds[i] = d;
			c += ((d & (a | b)) | (a & b)) + nt_buffer[9*NT_NUM_KEYS+i] + SQRT_2; c = rotate(c , 9 ); cs[i] = c;
			b += ((c & (d | a)) | (d & a)) + nt_buffer[13*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13); bs[i] = b;
		}
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			a = as[i]; b = bs[i]; c = cs[i]; d = ds[i];

			a += ((b & (c | d)) | (c & d)) + nt_buffer[2*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[6*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[10*NT_NUM_KEYS+i]+ SQRT_2; c = rotate(c , 9 ); cs[i] = c;
			b += ((c & (d | a)) | (d & a)) + nt_buffer[14*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13); bs[i] = b;

			a += ((b & (c | d)) | (c & d)) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 ); as[i] = a;
			d += ((a & (b | c)) | (b & c)) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 ); ds[i] = d;
		}
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			a = as[i]; b = bs[i]; c = cs[i]; d = ds[i];

			c += ((d & (a | b)) | (a & b)) + nt_buffer[11*NT_NUM_KEYS+i]+ SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a))								+ SQRT_2; b = rotate(b , 13);

			/* Round 3 */
			a += (d ^ c ^ b) + nt_buffer[0*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 ); as[i] = a;
			d += (c ^ b ^ a) + nt_buffer[8*NT_NUM_KEYS+i]  + SQRT_3; d = rotate(d , 9 ); ds[i] = d;
			c += (b ^ a ^ d) + nt_buffer[4*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11); cs[i] = c;
			b += (a ^ d ^ c) + nt_buffer[12*NT_NUM_KEYS+i] + SQRT_3; b = rotate(b , 15); bs[i] = b;
		}
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			a = as[i]; b = bs[i]; c = cs[i]; d = ds[i];

			a += (d ^ c ^ b) + nt_buffer[2*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 );
			d += (c ^ b ^ a) + nt_buffer[10*NT_NUM_KEYS+i] + SQRT_3; d = rotate(d , 9 );
			c += (b ^ a ^ d) + nt_buffer[6*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11);
			b += (a ^ d ^ c) + nt_buffer[14*NT_NUM_KEYS+i] + SQRT_3; b = rotate(b , 15);

			a += (d ^ c ^ b) + nt_buffer[1*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 ); as[i] = a;
			d += (c ^ b ^ a) + nt_buffer[9*NT_NUM_KEYS+i]  + SQRT_3; d = rotate(d , 9 ); ds[i] = d;
			c += (b ^ a ^ d) + nt_buffer[5*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11); cs[i] = c;
			b += (a ^ d ^ c) + nt_buffer[13*NT_NUM_KEYS+i];								 bs[i] = b;
		}

		// Search for a match
		for(i = 0; i < NT_NUM_KEYS; i++)
			indexs[i] = table[bs[i] & size_table];

		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			unsigned int indx = indexs[i];
			// Partial match
			while(indx != NO_ELEM)
			{
				unsigned int aa, bb, cc, dd;
				unsigned int* bin = ((unsigned int*)binary_values) + indx*4;

				if(bs[i] != bin[1]) goto next_iteration;
				bb = bs[i] + SQRT_3; bb = rotate(bb , 15);
	
				aa = as[i] + (bb ^ cs[i] ^ ds[i]) + nt_buffer[3*NT_NUM_KEYS+i]  + SQRT_3; aa = rotate(aa , 3 );
				if(aa != bin[0]) goto next_iteration;
				
				dd = ds[i] + (aa ^ bb ^ cs[i]) + nt_buffer[11*NT_NUM_KEYS+i] + SQRT_3; dd = rotate(dd , 9 );
				if(dd != bin[3]) goto next_iteration;
				
				cc = cs[i] + (dd ^ aa ^ bb) + nt_buffer[7*NT_NUM_KEYS+i]  + SQRT_3; cc = rotate(cc , 11);	
				if(cc != bin[2]) goto next_iteration;

				// Total match
				password_was_found(indx, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

next_iteration:
				indx = same_hash_next[indx];
			}
		}
	}

	finish_thread();
}
#else
void crypt_ntlm_avx_kernel_asm(unsigned int* nt_buffer);
PRIVATE void crypt_ntlm_protocol_avx(CryptParam* param)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS+5*4*NT_NUM_KEYS, 32);

	unsigned int* unpacked_as = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS);
	unsigned int* unpacked_bs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 1*NT_NUM_KEYS);
	unsigned int* unpacked_cs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 2*NT_NUM_KEYS);
	unsigned int* unpacked_ds = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 3*NT_NUM_KEYS);
	unsigned int* indexs	  = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 4*NT_NUM_KEYS);

	unsigned int i;
	unsigned char key[MAX_KEY_LENGHT];

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_ntlm_avx_kernel_asm(nt_buffer);

		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			if(indexs[i])
			{
				unsigned int indx = table[unpacked_bs[i] & size_table];
				// Partial match
				while(indx != NO_ELEM)
				{
					unsigned int aa, bb, cc, dd;
					unsigned int* bin = ((unsigned int*)binary_values) + indx*4;

					if(unpacked_bs[i] != bin[1]) goto next_iteration;
					bb = unpacked_bs[i] + SQRT_3; bb = rotate(bb , 15);

					aa = unpacked_as[i] + (bb ^ unpacked_cs[i] ^ unpacked_ds[i]) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_3; aa = rotate(aa , 3 );
					if(aa != bin[0]) goto next_iteration;

					dd = unpacked_ds[i] + (aa ^ bb ^ unpacked_cs[i]) + nt_buffer[11*NT_NUM_KEYS+i] + SQRT_3; dd = rotate(dd , 9 );
					if(dd != bin[3]) goto next_iteration;

					cc = unpacked_cs[i] + (dd ^ aa ^ bb) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_3; cc = rotate(cc , 11);	
					if(cc != bin[2]) goto next_iteration;

					// Total match
					password_was_found(indx, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

next_iteration:
					indx = same_hash_next[indx];
				}
			}
		}
	}

	_aligned_free(nt_buffer);

	finish_thread();
}

void crypt_ntlm_avx2_kernel_asm(unsigned int* nt_buffer);
PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS+5*4*NT_NUM_KEYS, 32);

	unsigned int* unpacked_as = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS);
	unsigned int* unpacked_bs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 1*NT_NUM_KEYS);
	unsigned int* unpacked_cs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 2*NT_NUM_KEYS);
	unsigned int* unpacked_ds = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 3*NT_NUM_KEYS);
	unsigned int* indexs	  = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 4*NT_NUM_KEYS);

	unsigned int i;
	unsigned char key[MAX_KEY_LENGHT];

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_ntlm_avx2_kernel_asm(nt_buffer);

		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			if(indexs[i])
			{
				unsigned int indx = table[unpacked_bs[i] & size_table];
				// Partial match
				while(indx != NO_ELEM)
				{
					unsigned int aa, bb, cc, dd;
					unsigned int* bin = ((unsigned int*)binary_values) + indx*4;

					if(unpacked_bs[i] != bin[1]) goto next_iteration;
					bb = unpacked_bs[i] + SQRT_3; bb = rotate(bb , 15);

					aa = unpacked_as[i] + (bb ^ unpacked_cs[i] ^ unpacked_ds[i]) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_3; aa = rotate(aa , 3 );
					if(aa != bin[0]) goto next_iteration;

					dd = unpacked_ds[i] + (aa ^ bb ^ unpacked_cs[i]) + nt_buffer[11*NT_NUM_KEYS+i] + SQRT_3; dd = rotate(dd , 9 );
					if(dd != bin[3]) goto next_iteration;

					cc = unpacked_cs[i] + (dd ^ aa ^ bb) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_3; cc = rotate(cc , 11);	
					if(cc != bin[2]) goto next_iteration;

					// Total match
					password_was_found(indx, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

next_iteration:
					indx = same_hash_next[indx];
				}
			}
		}
	}

	_aligned_free(nt_buffer);

	finish_thread();
}
#endif
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void crypt_ntlm_sse2_kernel_asm(unsigned int* nt_buffer);
PRIVATE void crypt_ntlm_protocol_sse2(CryptParam* param)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS+5*4*NT_NUM_KEYS, 32);

	unsigned int* unpacked_as = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS);
	unsigned int* unpacked_bs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 1*NT_NUM_KEYS);
	unsigned int* unpacked_cs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 2*NT_NUM_KEYS);
	unsigned int* unpacked_ds = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 3*NT_NUM_KEYS);
	unsigned int* indexs	  = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 4*NT_NUM_KEYS);

	unsigned int i;
	unsigned char key[MAX_KEY_LENGHT];

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_ntlm_sse2_kernel_asm(nt_buffer);

		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			if(indexs[i])
			{
				unsigned int indx = table[unpacked_bs[i] & size_table];
				// Partial match
				while(indx != NO_ELEM)
				{
					unsigned int aa, bb, cc, dd;
					unsigned int* bin = ((unsigned int*)binary_values) + indx*4;

					if(unpacked_bs[i] != bin[1]) goto next_iteration;
					bb = unpacked_bs[i] + SQRT_3; bb = rotate(bb , 15);

					aa = unpacked_as[i] + (bb ^ unpacked_cs[i] ^ unpacked_ds[i]) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_3; aa = rotate(aa , 3 );
					if(aa != bin[0]) goto next_iteration;

					dd = unpacked_ds[i] + (aa ^ bb ^ unpacked_cs[i]) + nt_buffer[11*NT_NUM_KEYS+i] + SQRT_3; dd = rotate(dd , 9 );
					if(dd != bin[3]) goto next_iteration;

					cc = unpacked_cs[i] + (dd ^ aa ^ bb) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_3; cc = rotate(cc , 11);	
					if(cc != bin[2]) goto next_iteration;

					// Total match
					password_was_found(indx, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

next_iteration:
					indx = same_hash_next[indx];
				}
			}
		}
	}

	_aligned_free(nt_buffer);

	finish_thread();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
PRIVATE void ocl_write_ntlm_header(char* source, GPUDevice* gpu, unsigned int ntlm_size_bit_table)
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
"#define SQRT_3 0x6ed9eba1\n");

	if(num_passwords_loaded > 1 )
		sprintf(source+strlen(source),
"#define SIZE_TABLE %uu\n"
"#define SIZE_BIT_TABLE %uu\n", size_table, ntlm_size_bit_table);

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
PRIVATE void ocl_ntlm_test_empty()
{
	unsigned int i;
	unsigned int* bin = (unsigned int*)binary_values;

	for(i = 0; i < num_passwords_loaded; i++, bin+=4)
		if(bin[0] == 0x798ab330 && bin[1] == 0xc08c4545 && bin[2] == 0x3e9e5fb9 && bin[3] == 0xb0576c6a)
			password_was_found(i, "");
}
PRIVATE void ocl_gen_kernel_with_lenght_onehash(char* source, unsigned int key_lenght, unsigned int vector_size, char** nt_buffer)
{
	char* str_comp[] = {".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf"};
	unsigned int i;

	cl_uint a = ((unsigned int*)binary_values)[0];
	cl_uint b = ((unsigned int*)binary_values)[1];
	cl_uint c = ((unsigned int*)binary_values)[2];
	cl_uint d = ((unsigned int*)binary_values)[3];

	if(vector_size==1)	str_comp[0] = "";

	sprintf(source+strlen(source), 
	"uint a1,b1,c1,d1,xx;"

	"a1=rotate(nt_buffer0%s,3u);"
	"d1=INIT_D+(INIT_C^(a1&0x77777777))%s;d1=rotate(d1,7u);"
	"uint val_d=d1&0xFFFC07FF;"
	//"uint val_c = INIT_C + (INIT_B ^ (d1 & (a1 ^ INIT_B))) %s; val_c = rotate(val_c, 11u) & 0x7FF0;"
	, str_comp[0], nt_buffer[1]/*, nt_buffer[2]*/);
	

	b += SQRT_3; b = rotate(b, 15);
	// Reverse
	c = rotate(c, 21u);	c -= (d ^ a ^ b) + SQRT_3;
	d = rotate(d, 23u);	d -= SQRT_3;
	
	//if(key_lenght == 14) c -= 14<<4;
	//if(key_lenght <= 14) d -= (a ^ b ^ c);

	//if(key_lenght > 14)
	{
		sprintf(source+strlen(source), "c1=%uu-%s;", c, key_lenght >= 14 ? (nt_buffer[7]+1) : "0");
		sprintf(source+strlen(source), "d1=%uu-((%uu^c1)%s);", d, a^b, nt_buffer[11]);
	}

	a = rotate(a, 29); a -= SQRT_3;
	/* Round 3 */
	sprintf(source+strlen(source),
		"xx=d1^c1;"
		"a1=%uu-((xx^%uu)%s);"

		"b1=%uu-((a1^xx)%s);"
		"xx=b1^a1;"
		"c1=rotate(c1,21u);c1-=(xx^d1)%s+SQRT_3;"
		"d1=rotate(d1,23u);d1-=(c1^xx)%s+SQRT_3;"
		"xx=d1^c1;"
		"a1=rotate(a1,29u);a1-=(xx^b1)%s+SQRT_3;"

		"b1=rotate(b1,17u);b1-=(a1^xx)+%uu;"
		"xx=b1^a1;"
		"c1=rotate(c1,21u);c1-=(xx^d1)%s+SQRT_3;"
		"d1=rotate(d1,23u);d1-=(c1^xx)%s+SQRT_3;"
		"xx=d1^c1;"
		"a1=rotate(a1,29u);a1-=(xx^b1)%s+SQRT_3;"

		"b1=rotate(b1,17u);b1-=(a1^xx)%s+SQRT_3;"
		"xx=b1^a1;"
		"c1=rotate(c1,21u);c1-=(xx^d1)%s+SQRT_3;"
		"d1=rotate(d1,23u);d1-=(c1^xx)%s+SQRT_3;"
		"a1=rotate(a1,29u);a1-=(d1^c1^b1)+SQRT_3;"

		"b1=rotate(b1,19u);b1-=SQRT_2;"
		"uint c1_rot=rotate(c1,23u);c1_rot-=SQRT_2;"
		"uint d1_rot=rotate(d1,27u);d1_rot-=SQRT_2;"
		, a, b, nt_buffer[3], ((unsigned int*)binary_values)[1], nt_buffer[13]
		, nt_buffer[5], nt_buffer[9], nt_buffer[1], (key_lenght<<4)+SQRT_3, nt_buffer[6]
		, nt_buffer[10], nt_buffer[2], nt_buffer[12], nt_buffer[4], nt_buffer[8]);

	if(key_lenght > 2) strcat(source, "nt_buffer1+=SQRT_2;");
	if(key_lenght > 4) strcat(source, "nt_buffer2+=SQRT_2;");
	if(key_lenght > 6) strcat(source, "nt_buffer3+=SQRT_2;");
	if(key_lenght > 8) strcat(source, "nt_buffer4+=SQRT_2;");

	if( is_charset_consecutive(charset) )
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset)-1+i);

	// Begin cycle changing first character
	sprintf(source+strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s^=first_xor[i+%uU];", str_comp[i], i);

			/* Round 2 */
sprintf(source+strlen(source), 
			"a=a1-%s;"

			"b=b1-s2(c1,d1,a);"
			"c=c1_rot-s2(d1,a,b)%s;"
			"d=d1_rot-s2(a,b,c)%s;"
			"a=rotate(a,29u);a-=s2(b,c,d)%s%s;"

			"b=rotate(b,19u);b-=s2(c,d,a)+%uu;"
			"c=rotate(c,23u);c-=s2(d,a,b)%s+SQRT_2;"
			"d=rotate(d,27u);d-=s2(a,b,c)%s+SQRT_2;"
			"a=rotate(a,29u);a-=s2(b,c,d)%s%s;"

			"b=rotate(b,19u);b-=s2(c,d,a)%s+SQRT_2;"
			"c=rotate(c,23u);c-=s2(d,a,b)%s+SQRT_2;"
			"d=rotate(d,27u);d-=s2(a,b,c)%s+SQRT_2;"
			"a=rotate(a,29u);a-=s2(b,c,d)%s%s;"

			"b=rotate(b,19u);b-=s2(c,d,a)%s+SQRT_2;"
			"c=rotate(c,23u);c-=s2(d,a,b)%s+SQRT_2;"
			"d=rotate(d,27u);d-=s2(a,b,c)%s%s;"
			"a=rotate(a,29u);a-=s2(b,c,d)%s+SQRT_2;"
			, nt_buffer[0]
			, nt_buffer[11], nt_buffer[7], nt_buffer[3], key_lenght>6?"":"+SQRT_2", (key_lenght<<4)+SQRT_2, nt_buffer[10], nt_buffer[6], nt_buffer[2], key_lenght>4?"":"+SQRT_2"
			, nt_buffer[13], nt_buffer[9], nt_buffer[5], nt_buffer[1], key_lenght>2?"":"+SQRT_2", nt_buffer[12] , nt_buffer[8] , nt_buffer[4], key_lenght>8?"":"+SQRT_2", nt_buffer[0]);

			/* Round 1 */
sprintf(source+strlen(source), 
			"b=rotate(b,13u);b-=bs(a,d,c);"
			"c=rotate(c,21u);c-=bs(b,a,d)+%uu;"
			"d=rotate(d,25u);d-=bs(c,b,a)%s;"
			"a=rotate(a,29u);a-=bs(d,c,b)%s;"

			"b=rotate(b,13u);b-=bs(a,d,c)%s;"
			"c=rotate(c,21u);c-=bs(b,a,d)%s;"
			"d=rotate(d,25u);d-=bs(c,b,a)%s;"
			"a=rotate(a,29u);a-=bs(d,c,b)%s;"

			"b=rotate(b,13u);b-=bs(a,d,c)%s;"
			"c=rotate(c,21u);c-=bs(b,a,d)%s;"
			, key_lenght << 4, 
			nt_buffer[13], nt_buffer[12], nt_buffer[11], nt_buffer[10], 
			nt_buffer[9] , nt_buffer[8] , nt_buffer[7] , nt_buffer[6]);

			{
				unsigned int comp;

				//for(comp = 0; comp < vector_size; comp++)
				//{
					//sprintf(source+strlen(source), "if((c%s&0x7FF0)==val_c){", str_comp[comp]);
					//sprintf(source+strlen(source), "d%s=rotate(d%s,25u);d%s-=bs(c%s,b%s,a%s)%s;", str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[5]);
				sprintf(source+strlen(source), "d=rotate(d,25u);d-=bs(c,b,a)%s;", nt_buffer[5]);

				for(comp = 0; comp < vector_size; comp++)
				{
					sprintf(source+strlen(source),
					"if((d%s&0xFFFC07FF)==val_d)"
					"{"
						"a%s=rotate(a%s,29u);a%s-=bs(d%s,c%s,b%s)%s%s;"
						"b%s=rotate(b%s,13u);b%s-=bs(a%s,d%s,c%s)%s%s;"
						"if(b%s==INIT_B)"
						"{"
							"c%s=rotate(c%s,21u);c%s-=bs(b%s,a%s,d%s)%s%s;"
							"d%s=rotate(d%s,25u);d%s-=bs(c%s,b%s,a%s)%s%s;"
							"a%s=rotate(a%s,29u);a%s-=%s%s;"

							"if(c%s==INIT_C&&d%s==INIT_D&&a%s==0xFFFFFFFF)"
							"{"
								"output[0]=1;"
								"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
								"output[2]=0;"
							"}"
						"}"
					"}",
					 str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],nt_buffer[4], key_lenght<=8?"":"-SQRT_2",
					 str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3], key_lenght<=6?"":"-SQRT_2",
					 str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],nt_buffer[2], key_lenght<=4?"":"-SQRT_2",
					 str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[1], key_lenght<=2?"":"-SQRT_2",
					 str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[0]  , str_comp[comp],
					 str_comp[comp], str_comp[comp], str_comp[comp], comp);
				}
			}

	strcat(source, "}}");
}
PRIVATE void ocl_gen_kernel_with_lenght(char* source, unsigned int key_lenght, unsigned int vector_size, unsigned int ntlm_size_bit_table)
{
	unsigned int i;
	DivisionParams div_param = get_div_params(num_char_in_charset);
	char* str_comp[] = {".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf"};
	char* nt_buffer[] = {"+nt_buffer0" , "+nt_buffer1" , "+nt_buffer2" , "+nt_buffer3" , 
						 "+nt_buffer4" , "+nt_buffer5" , "+nt_buffer6" , "+nt_buffer7" , 
						 "+nt_buffer8" , "+nt_buffer9" , "+nt_buffer10", "+nt_buffer11", 
						 "+nt_buffer12", "+nt_buffer13"};
	char buffer[16];
	buffer[0] = 0;

	if(vector_size == 1)str_comp[0] = "";
	if(vector_size > 1)	itoa(vector_size, buffer, 10);

	// Function definition
	sprintf(source+strlen(source), "\n__kernel void nt_crypt%u(__constant uchar* current_key __attribute__((max_constant_size(%u))),__global uint* restrict output", key_lenght, __max(2, key_lenght));

	if(num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict table,const __global uint* restrict binary_values,const __global uint* restrict same_hash_next,const __global uint* restrict bit_table");

	// Begin function code
	sprintf(source+strlen(source),	"){"
									"uint max_number=get_global_id(0)+current_key[1];"
									"uint%s a,b,c,d,nt_buffer0;"
									"uint indx;", buffer);

	// Prefetch in local memory
	//if ((ntlm_size_bit_table/32+1) <= 1024 && num_passwords_loaded > 1)
	//{
	//	sprintf(source + strlen(source), "local uint lbit_table[%i];", ntlm_size_bit_table/32+1);
	//	// Copy from global to local
	//	sprintf(source + strlen(source), "for(uint i=get_local_id(0); i < %uu; i+=get_local_size(0))"
	//										"lbit_table[i]=bit_table[i];"

	//									"barrier(CLK_LOCAL_MEM_FENCE);", ntlm_size_bit_table/32+1);
	//}

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

	// Generate optimized code for particular case of only one hash
	if(num_passwords_loaded==1)
	{
		ocl_gen_kernel_with_lenght_onehash(source+strlen(source), key_lenght, vector_size, nt_buffer);
		return;
	}

	// Small optimization
	if( is_charset_consecutive(charset) )
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset)-vector_size+i);

	if(key_lenght > 2) sprintf(source+strlen(source), "nt_buffer1+=INIT_D;");
	if(key_lenght > 4) sprintf(source+strlen(source), "nt_buffer2+=INIT_C;");
	if(key_lenght > 6) sprintf(source+strlen(source), "nt_buffer3+=INIT_B;");

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s^=first_xor[i+%uU];", str_comp[i], i);

		/* Round 1 */
sprintf(source+strlen(source), 
		"a=0xffffffff+nt_buffer0;a<<=3u;"
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
		"uint%s xx=c^b;"
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
		"b+=(xx^c)%s;"
		, buffer
		, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12]
		, nt_buffer[2], key_lenght > 4 ? "+0xD61F0EA3" : "+SQRT_3", nt_buffer[10], nt_buffer[6], (key_lenght<<4)+SQRT_3
		, nt_buffer[1], key_lenght > 2 ? "+0x5EA7972B" : "+SQRT_3", nt_buffer[9] , nt_buffer[5], nt_buffer[13]);

	// Find match
	{
		unsigned int comp;

		for(comp = 0; comp < vector_size; comp++)
		{
			sprintf(source+strlen(source), 
				"indx=(b%s)&SIZE_BIT_TABLE;"

				"if((bit_table[indx>>5]>>(indx&31))&1)"
				"{"
					"indx=table[(b%s)&SIZE_TABLE];"

					"while(indx!=0xffffffff)"
					//"if(indx!=0xffffffff)"
					"{"
						"if(b%s==binary_values[indx*4u+1u])"
						"{"
							"b%s+=SQRT_3;b%s=rotate(b%s,15u);"

							"a%s+=(b%s^c%s^d%s)%s%s;a%s=rotate(a%s,3u);"
							"d%s+=(a%s^b%s^c%s)%s+SQRT_3;d%s=rotate(d%s,9u);"
							"c%s+=(d%s^a%s^b%s)%s+SQRT_3;c%s=rotate(c%s,11u);"
							"if(a%s==binary_values[indx*4u]&&d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u])"
							"{"
								"uint found=atom_inc(output);"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
								"output[2*found+2]=indx;"
							"}"
							// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same b
							"c%s=rotate(c%s,21u);c%s-=(d%s^a%s^b%s)%s+SQRT_3;"
							"d%s=rotate(d%s,23u);d%s-=(a%s^b%s^c%s)%s+SQRT_3;"
							"a%s=rotate(a%s,29u);a%s-=(b%s^c%s^d%s)%s%s;"
							"b%s=rotate(b%s,17u);b%s-=SQRT_3;"
						"}"

						"indx=same_hash_next[indx];"
					"}"
				"}",
			str_comp[comp],
			//((ntlm_size_bit_table / 32 + 1) <= 1024 && num_passwords_loaded > 1) ? "l" : "",
			str_comp[comp], str_comp[comp], str_comp[comp], 
			str_comp[comp], str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3], key_lenght > 6 ? "+0x7F0C4018" : "+SQRT_3",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11],
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7], 
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], comp
			// begin to reverse
			,str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7],
			 str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11],
			 str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3], key_lenght > 6 ? "+0x7F0C4018" : "+SQRT_3", 
			 str_comp[comp], str_comp[comp], str_comp[comp]);
		}
	}

	strcat(source, "}}");
}
PRIVATE char* ocl_gen_charset_code(unsigned int ntlm_size_bit_table, GPUDevice* gpu)
{
	unsigned int i,j;
	char* source = (char*)malloc(1024*16*__max(1, max_lenght-current_key_lenght+1));

	//Initial values
	ocl_write_ntlm_header(source, gpu, ntlm_size_bit_table);
	sprintf(source+strlen(source), "#define NUM_CHAR_IN_CHARSET %uu\n", num_char_in_charset);

	strcat(source,	"__constant uchar charset[]={");

	// Fill charset
	for(i = 0; i < num_char_in_charset; i++)
		sprintf(source+strlen(source), "%s%uU", i?",":"", (unsigned int)charset[i%num_char_in_charset]);
	strcat(source, "};\n");

	// XOR fast
	if(	!is_charset_consecutive(charset) )
	{
		sprintf(source+strlen(source), "\n__constant uint first_xor[]={");
	
		for(i = 0; i < num_char_in_charset; i+=gpu->vector_int_size)
		{
			sprintf(source+strlen(source), "%s%uU", i?",":"", i ? (unsigned int)(charset[i] ^ charset[i-gpu->vector_int_size]) : (unsigned int)(charset[0]));

			for (j = 1; j < gpu->vector_int_size; j++)
				sprintf(source+strlen(source), ",%uU", i ? (unsigned int)(charset[(i+j)%num_char_in_charset] ^ charset[i+j-gpu->vector_int_size]) : (unsigned int)(charset[j]));
		}
		strcat(source, "};\n");
	}

	// Generate code for all lengths in range
	for(i = current_key_lenght; i <= max_lenght; i++)
	{
		cl_uint vector_int_size = is_charset_consecutive(charset) ? gpu->vector_int_size_when_consecutive : gpu->vector_int_size;
		ocl_gen_kernel_with_lenght(source+strlen(source), i, vector_int_size, ntlm_size_bit_table);
	}

	//{// Uncomment this to view opencl code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	return source;
}

PRIVATE void ocl_protocol_charset_work(OpenCL_Param* param)
{
	unsigned char buffer[MAX_KEY_LENGHT+2*sizeof(unsigned int)];
	unsigned int num_found = 0;
	int is_consecutive = is_charset_consecutive(charset);

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	while(continue_attack && param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id))
	{
		unsigned int key_lenght = ((unsigned int*)buffer)[8];
		size_t num_work_items = (((unsigned int*)buffer)[9] + (param->max_work_group_size-1)) & ~(param->max_work_group_size-1);// Convert to multiple of work_group_size

		// TODO: Check if there is some problem
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, 0, key_lenght, buffer, 0, NULL, NULL);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[key_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

		// GPU found some passwords
		if(num_found)
			ocl_charset_process_found(param, &num_found, is_consecutive, buffer, key_lenght);
	}

	release_opencl_param(param);
	finish_thread();
}
PRIVATE OpenCL_Param* ocl_protocol_charset_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	cl_int code;
	unsigned int i;
	char* source;
	unsigned int ntlm_size_bit_table;
	unsigned int output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	OpenCL_Param* param = create_opencl_param(gpu_device_index, gen, 2*sizeof(cl_uint)*num_passwords_loaded, FALSE);
	if(!param)	return NULL;

	// Do not allow blank in GPU
	if(current_key_lenght == 0)
	{
		ocl_ntlm_test_empty();
		current_key_lenght = 1;
		num_keys_served_from_save++;
	}

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= 4*__max(1, 120/num_char_in_charset);
	if(num_passwords_loaded == 1) param->NUM_KEYS_OPENCL *= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*__min(param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_device_index].max_mem_alloc_size / (2 * 2 * sizeof(cl_uint))));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Take into account the amount of cache
	if(gpu_devices[gpu_device_index].has_unified_memory)
		ntlm_size_bit_table = size_bit_table;
	else
		ntlm_size_bit_table = get_bit_table_mask(num_passwords_loaded, gpu_devices[gpu_device_index].l1_cache_size*1024, gpu_devices[gpu_device_index].l2_cache_size*1024);
	
	// Generate code
	source = ocl_gen_charset_code(ntlm_size_bit_table, &gpu_devices[gpu_device_index]);// Generate opencl code
	
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
		sprintf(name_buffer, "nt_crypt%u", i);
		code = create_kernel(param, i, name_buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return NULL;
		}
	}

	// Create memory objects
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY , MAX_KEY_LENGHT , NULL);
	create_opencl_mem(param, GPU_OUTPUT		, CL_MEM_READ_WRITE, 4 + output_size, NULL);
	if(num_passwords_loaded > 1)
	{
		if(gpu_devices[gpu_device_index].has_unified_memory)
		{
			create_opencl_mem(param, GPU_TABLE		   , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(size_table+1), table);
			create_opencl_mem(param, GPU_BIT_TABLE	   , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(ntlm_size_bit_table/32+1), bit_table);
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT, CL_MEM_READ_ONLY|CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_hash_next);
		}
		else
		{
			create_opencl_mem(param, GPU_TABLE		   , CL_MEM_READ_ONLY, sizeof(cl_uint)*(size_table+1), NULL);
			create_opencl_mem(param, GPU_BIT_TABLE	   , CL_MEM_READ_ONLY, sizeof(cl_uint)*(ntlm_size_bit_table/32+1), NULL);
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}

	// Set OpenCL kernel params
	for(i = current_key_lenght; i <= max_lenght; i++)
	{
		pclSetKernelArg(param->kernels[i], 0, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
		pclSetKernelArg(param->kernels[i], 1, sizeof(cl_mem), (void*) &param->mems[GPU_OUTPUT]);

		if(num_passwords_loaded > 1)
		{
			pclSetKernelArg(param->kernels[i], 2, sizeof(cl_mem), (void*) &param->mems[GPU_TABLE]);
			pclSetKernelArg(param->kernels[i], 3, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->kernels[i], 4, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_HASH_NEXT]);
			pclSetKernelArg(param->kernels[i], 5, sizeof(cl_mem), (void*) &param->mems[GPU_BIT_TABLE]);
		}
	}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT);
	cl_write_buffer(param, GPU_CURRENT_KEY, MAX_KEY_LENGHT , source);
	cl_write_buffer(param, GPU_OUTPUT	  , sizeof(cl_uint), source);
	if(num_passwords_loaded > 1 && !gpu_devices[gpu_device_index].has_unified_memory)
	{
		// Create and initialize bitmaps
		unsigned int* my_bit_table = (unsigned int*) calloc(ntlm_size_bit_table/32+1, sizeof(unsigned int));

		for(i = 0; i < num_passwords_loaded; i++)
		{
			unsigned int value_map = ((unsigned int*)binary_values)[i*4+1] & ntlm_size_bit_table;
			my_bit_table[value_map >> 5] |= 1 << (value_map & 31);
		}

		cl_write_buffer(param, GPU_TABLE, 4*(size_table+1), table);
		cl_write_buffer(param, GPU_BIT_TABLE, 4*(ntlm_size_bit_table/32+1), my_bit_table);
		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, binary_values);
		cl_write_buffer(param, GPU_SAME_HASH_NEXT, 4*num_passwords_loaded, same_hash_next);

		pclFinish(param->queue);

		free(my_bit_table);
	}

	// Select best work_group
	ocl_calculate_best_work_group(param, param->kernels[max_lenght], UINT_MAX / num_char_in_charset);
	
	free(source);
	*gpu_ntlm_crypt = ocl_protocol_charset_work;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_ntlm(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	char nt_buffer[16][16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	if (found_param_3)
		sprintf(output_3, "output[3%s]=%s;", num_passwords_loaded > 1 ? "*found+3" : "", found_param_3);

	// NTLM Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict table,const __global uint* restrict binary_values,const __global uint* restrict same_hash_next,const __global uint* restrict bit_table");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = num_passwords_loaded > 1 ? 6 : 2;
	}

	// Begin function code
	sprintf(source + strlen(source), "){"
		"uint a,b,c,d,indx;");

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
		"uint xx=c^b;"
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
		"b+=(xx^c)%s;"
		, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12], nt_buffer[2], nt_buffer[10]
		, nt_buffer[6], nt_buffer[14], nt_buffer[1], nt_buffer[9], nt_buffer[5], nt_buffer[13]);


	// Match
	if (num_passwords_loaded == 1)
		sprintf(source + strlen(source),
		"if(b==%uu)"
		"{"
			"b+=SQRT_3;b=rotate(b,15u);"

			"a+=(b^c^d)%s+SQRT_3;a=rotate(a,3u);"
			"d+=(a^b^c)%s+SQRT_3;d=rotate(d,9u);"
			"c+=(d^a^b)%s+SQRT_3;c=rotate(c,11u);"
			"if(a==%uu&&d==%uu&&c==%uu)"
			"{"
				"output[0]=1;"
				"output[1]=get_global_id(0);"
				"output[2]=0;"
				"%s"
			"}"
		"}",
		((unsigned int*)binary_values)[1], nt_buffer[3], nt_buffer[11], nt_buffer[7],
		((unsigned int*)binary_values)[0], ((unsigned int*)binary_values)[3], ((unsigned int*)binary_values)[2], output_3);
	else
		sprintf(source + strlen(source),
		"indx=b&SIZE_BIT_TABLE;"

		"if((bit_table[indx>>5]>>(indx&31))&1)"
		"{"
			"indx=table[b&SIZE_TABLE];"

			"while(indx!=0xffffffff)"
			"{"
				"if(b==binary_values[indx*4u+1u])"
				"{"
					"b+=SQRT_3;b=rotate(b,15u);"

					"a+=(b^c^d)%s+SQRT_3;a=rotate(a,3u);"
					"d+=(a^b^c)%s+SQRT_3;d=rotate(d,9u);"
					"c+=(d^a^b)%s+SQRT_3;c=rotate(c,11u);"
					"if(a==binary_values[indx*4u]&&d==binary_values[indx*4u+3u]&&c==binary_values[indx*4u+2u])"
					"{"
						"uint found=atom_inc(output);"
						"output[%i*found+1]=get_global_id(0);"
						"output[%i*found+2]=indx;"
						"%s"
					"}"
					// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same b
					"c=rotate(c,21u);c-=(d^a^b)%s+SQRT_3;"
					"d=rotate(d,23u);d-=(a^b^c)%s+SQRT_3;"
					"a=rotate(a,29u);a-=(b^c^d)%s+SQRT_3;"
					"b=rotate(b,17u);b-=SQRT_3;"
				"}"

				"indx=same_hash_next[indx];"
		"}}",
		nt_buffer[3], nt_buffer[11], nt_buffer[7], found_multiplier, found_multiplier, output_3,
		// begin to reverse
		nt_buffer[7], nt_buffer[11], nt_buffer[3]);

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}
PRIVATE void ocl_work(OpenCL_Param* param)
{
	unsigned int num_found = 0;
	int use_buffer = 1;
	int result, num_keys_filled;
	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer1 = malloc(kernel2common->get_buffer_size(param));
	void* buffer2 = malloc(kernel2common->get_buffer_size(param));

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	memset(buffer1, 0, kernel2common->get_buffer_size(param));
	memset(buffer2, 0, kernel2common->get_buffer_size(param));

	result = param->gen(buffer1, param->NUM_KEYS_OPENCL, param->thread_id);
	while (continue_attack && result)
	{
		size_t num_work_items = kernel2common->process_buffer(use_buffer ? buffer1 : buffer2, result, param, &num_keys_filled);// Convert to multiple of work_group_size

		// Do actual hashing
		pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
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

	free(buffer1);
	free(buffer2);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE OpenCL_Param* ocl_protocol_common_init(unsigned int gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt, ocl_gen_processed_key* gen_processed_key, ocl_setup_proccessed_keys_params* setup_proccessed_keys_params, unsigned int keys_multipler)
{
	cl_int code;
	unsigned int i;
	char* source;
	unsigned int ntlm_size_bit_table;
	unsigned int output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	OpenCL_Param* param = create_opencl_param(gpu_index, gen, output_size, FALSE);
	if (!param)	return NULL;

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

	// Take into account the amount of cache
	if (gpu_devices[gpu_index].has_unified_memory)
		ntlm_size_bit_table = size_bit_table;
	else
		ntlm_size_bit_table = get_bit_table_mask(num_passwords_loaded, gpu_devices[gpu_index].l1_cache_size * 1024, gpu_devices[gpu_index].l2_cache_size * 1024);

	// Generate code-------------------------
	source = (char*)malloc(1024 * 16);

	// Write the definitions needed by the opencl implementation
	ocl_write_ntlm_header(source, &gpu_devices[gpu_index], ntlm_size_bit_table);
	// Kernel needed to convert from * to the common format
	gen_processed_key(source, param->NUM_KEYS_OPENCL);

	// Write the kernel
	ocl_gen_kernel_ntlm(source, "nt_crypt", ocl_rule_simple_copy, NULL, NULL, NULL, NTLM_MAX_KEY_LENGHT, param->NUM_KEYS_OPENCL);
	//{// Uncomment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
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
	code = create_kernel(param, 0, "nt_crypt");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return NULL;
	}

	// Create memory objects
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, 32 * param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param, GPU_OUTPUT		, CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL);

	if (num_passwords_loaded > 1)
	{
		if (gpu_devices[gpu_index].has_unified_memory)
		{
			create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(size_table + 1), table);
			create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(ntlm_size_bit_table / 32 + 1), bit_table);
			create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_hash_next);
		}
		else
		{
			create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY, sizeof(cl_uint)*(size_table + 1), NULL);
			create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY, sizeof(cl_uint)*(ntlm_size_bit_table / 32 + 1), NULL);
			create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}
	setup_proccessed_keys_params(param, &gpu_devices[gpu_index]);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[0], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[0], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

	if (num_passwords_loaded > 1)
	{
		pclSetKernelArg(param->kernels[0], 2, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
		pclSetKernelArg(param->kernels[0], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
		pclSetKernelArg(param->kernels[0], 4, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_HASH_NEXT]);
		pclSetKernelArg(param->kernels[0], 5, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
	}

	// Copy data to GPU
	memset(source, 0, 32 * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, 4, source);
	if (num_passwords_loaded > 1 && !gpu_devices[gpu_index].has_unified_memory)
	{
		// Create and initialize bitmaps
		unsigned int* my_bit_table = (unsigned int*)calloc(ntlm_size_bit_table / 32 + 1, sizeof(unsigned int));

		for (i = 0; i < num_passwords_loaded; i++)
		{
			unsigned int value_map = ((unsigned int*)binary_values)[i * 4 + 1] & ntlm_size_bit_table;
			my_bit_table[value_map >> 5] |= 1 << (value_map & 31);
		}

		cl_write_buffer(param, GPU_TABLE, 4 * (size_table + 1), table);
		cl_write_buffer(param, GPU_BIT_TABLE, 4 * (ntlm_size_bit_table / 32 + 1), my_bit_table);
		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, binary_values);
		cl_write_buffer(param, GPU_SAME_HASH_NEXT, 4 * num_passwords_loaded, same_hash_next);

		pclFinish(param->queue);
		free(my_bit_table);
	}

	pclFinish(param->queue);
	free(source);

	*gpu_ntlm_crypt = ocl_work;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE OpenCL_Param* ocl_protocol_utf8_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	OpenCL_Param* param = ocl_protocol_common_init(gpu_device_index, gen, gpu_ntlm_crypt, kernels2common[UTF8_INDEX_IN_KERNELS].gen_kernel, kernels2common[UTF8_INDEX_IN_KERNELS].setup_params, 4/*consider 2 for Nvidia*/);
	param->additional_param = kernels2common + UTF8_INDEX_IN_KERNELS;
	return param;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE OpenCL_Param* ocl_protocol_phrases_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	OpenCL_Param* param = ocl_protocol_common_init(gpu_device_index, gen, gpu_ntlm_crypt, kernels2common[PHRASES_INDEX_IN_KERNELS].gen_kernel, kernels2common[PHRASES_INDEX_IN_KERNELS].setup_params, 64/*consider 32 for Nvidia*/);
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

PRIVATE char* ocl_gen_rules_code(unsigned int ntlm_size_bit_table, GPUDevice* gpu, OpenCL_Param* param, int kernel2common_index)//, size_t* pos_in_source, cl_uint* thread_id_by_lenght)
{
	char* base_source = (char*)malloc(1024 * 16 * __max(1, current_rules_count)*(NTLM_MAX_KEY_LENGHT + 1));
	base_source[0] = 0;

	// Kernel needed to convert from * to the common format
	kernels2common[kernel2common_index].gen_kernel(base_source, param->NUM_KEYS_OPENCL);
	// Kernel needed to convert from common format to the ordered by lenght format
	ocl_gen_kernel_common_2_ordered(base_source, param->NUM_KEYS_OPENCL, NTLM_MAX_KEY_LENGHT);
	
	char* source = base_source;
	// This is because AMD compiler do not support __constant vars inside a kernel
	ocl_write_code** constants_written = (ocl_write_code**)malloc(current_rules_count*sizeof(ocl_write_code*));
	int num_constants_written = 0;
		
	// Write the definitions needed by the opencl implementation
	ocl_write_ntlm_header(source+strlen(source), gpu, ntlm_size_bit_table);

	unsigned int lenght = 0;
	unsigned int max_lenght = NTLM_MAX_KEY_LENGHT + 1;
	// Generate one kernel for each rule
	for (; lenght < max_lenght; lenght++)
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
			sprintf(kernel_name, "nt_%il%i", i, lenght);
			sprintf(found_param, "(%uu+%s)", (rule_index << 22) + (lenght << 27), rules[rule_index].ocl.found_param);
			ocl_gen_kernel_ntlm(source+strlen(source), kernel_name, rules[rule_index].ocl.begin, rules[rule_index].ocl.end, found_param, need_param_ptr, lenght, param->NUM_KEYS_OPENCL);
		}
	}
	free(constants_written);

	//{// Uncomment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(base_source, 1, strlen(base_source), code);
	//	fclose(code);
	//}

	return base_source;
}
PRIVATE void ocl_protocol_rules_work(OpenCL_Param* param)
{
	unsigned int gpu_num_keys_by_len[NTLM_MAX_KEY_LENGHT + 1];
	unsigned int gpu_pos_ordered_by_len[NTLM_MAX_KEY_LENGHT + 1];
	unsigned int num_found = 0;
	int num_keys_filled;
	// To obtain rules index
	int* rules_remapped = (int*)malloc(sizeof(int)*current_rules_count);

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	// Size in uint
	for (unsigned int i = 0, j = 32; i <= NTLM_MAX_KEY_LENGHT; i++)
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
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
		num_keys_to_read = 0;
		num_keys_in_memory = 0;
		// Calculate the number of keys in memory
		for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			for (int i = 0; i < current_rules_count; i++)
			{
				int64_t multipler = rules[rules_remapped[i]].multipler;
				if (rules[rules_remapped[i]].depend_key_lenght)
					multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

				num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
			}
		rules_calculate_key_space(-num_keys_filled, num_keys_filled, num_keys_in_memory, param->gpu_device_index);

		for (int lenght = 0; continue_attack && lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
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

						for (int j = 0; continue_attack && j < max_param_value; j++)
						{
							pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param
							pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
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
						pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
						pclFlush(param->queue);

						int64_t multipler = rules[rules_remapped[i]].multipler;
						if (rules[rules_remapped[i]].depend_key_lenght)
							multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
						multipler *= gpu_num_keys_by_len[lenght];

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
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
	num_keys_in_memory = 0;
	// Calculate the number of keys in memory
	for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		for (int i = 0; i < current_rules_count; i++)
		{
			int64_t multipler = rules[rules_remapped[i]].multipler;
			if (rules[rules_remapped[i]].depend_key_lenght)
				multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

			num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
		}
	rules_calculate_key_space(0, 0, num_keys_in_memory, param->gpu_device_index);

	for (int lenght = 0; /*continue_attack &&*/ lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
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

					for (int j = 0; /*continue_attack &&*/ j < max_param_value; j++)
					{
						pclSetKernelArg(param->rules_kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param
						pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
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
					pclEnqueueNDRangeKernel(param->queue, param->rules_kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &param->max_work_group_size, 0, NULL, NULL);
					pclFlush(param->queue);

					int64_t multipler = rules[rules_remapped[i]].multipler;
					if (rules[rules_remapped[i]].depend_key_lenght)
						multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
					multipler *= gpu_num_keys_by_len[lenght];

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
PRIVATE OpenCL_Param* ocl_protocol_rules_init(unsigned int gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	cl_int code;
	int i, kernel2common_index, len;
	char* source;
	unsigned int ntlm_size_bit_table, gpu_key_buffer_lenght;
	OpenCL_Param* param;
	unsigned int output_size = 3 * sizeof(cl_uint)*num_passwords_loaded;
	int multipler = 0;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	param = create_opencl_param(gpu_device_index, gen, output_size, FALSE);
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
	for (i = 1, gpu_key_buffer_lenght = 0; i <= NTLM_MAX_KEY_LENGHT; i++)
		gpu_key_buffer_lenght += (i + 3) / 4 * sizeof(cl_uint);

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= multipler < 95 ? 64 : 4;
	while (param->NUM_KEYS_OPENCL >= (gpu_devices[gpu_device_index].max_mem_alloc_size - 32 * sizeof(cl_uint))/gpu_key_buffer_lenght)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && multipler*param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		// Reserve to output at maximum half the MAX_MEM_ALLOC_SIZE
		output_size = 3 * sizeof(cl_uint)*__min(multipler*param->NUM_KEYS_OPENCL, 4 * 1024 * 1024);
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Take into account the amount of cache
	if (gpu_devices[gpu_device_index].has_unified_memory)
		ntlm_size_bit_table = size_bit_table;
	else
		ntlm_size_bit_table = get_bit_table_mask(num_passwords_loaded, gpu_devices[gpu_device_index].l1_cache_size * 1024, gpu_devices[gpu_device_index].l2_cache_size * 1024);

	// Generate code
	source = ocl_gen_rules_code(ntlm_size_bit_table, &gpu_devices[gpu_device_index], param, kernel2common_index);//, pos_in_source, thread_id_by_lenght);// Generate opencl code

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_device_index].compiler_options))
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
	param->num_rules_kernels = current_rules_count*(NTLM_MAX_KEY_LENGHT + 1);
	param->rules_kernels = (cl_kernel*)malloc(sizeof(cl_kernel)*param->num_rules_kernels);
	for (len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
		for (i = 0; i < current_rules_count; i++)
		{
			char name_buffer[12];
			sprintf(name_buffer, "nt_%il%i", i, len);
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

	if (num_passwords_loaded > 1)
	{
		if (gpu_devices[gpu_device_index].has_unified_memory)
		{
			create_opencl_mem(param, GPU_TABLE			, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(size_table + 1), table);
			create_opencl_mem(param, GPU_BIT_TABLE		, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(ntlm_size_bit_table / 32 + 1), bit_table);
			create_opencl_mem(param, GPU_BINARY_VALUES	, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT	, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_hash_next);
		}
		else
		{
			create_opencl_mem(param, GPU_TABLE			, CL_MEM_READ_ONLY, sizeof(cl_uint)*(size_table + 1), NULL);
			create_opencl_mem(param, GPU_BIT_TABLE		, CL_MEM_READ_ONLY, sizeof(cl_uint)*(ntlm_size_bit_table / 32 + 1), NULL);
			create_opencl_mem(param, GPU_BINARY_VALUES	, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT	, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}

	// Set OpenCL kernel params
	kernels2common[kernel2common_index].setup_params(param, &gpu_devices[gpu_device_index]);

	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 1, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);

	for (len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
		for (i = 0; i < current_rules_count; i++)
		{
			pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
			pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

			if (num_passwords_loaded > 1)
			{
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 2, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 4, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_HASH_NEXT]);
				pclSetKernelArg(param->rules_kernels[i + len*current_rules_count], 5, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
			}
		}

	// Copy data to GPU
	memset(source, 0, 32 * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, 4, source);
	cl_write_buffer(param, GPU_ORDERED_KEYS, 32 * sizeof(cl_uint), source);
	if (num_passwords_loaded > 1 && !gpu_devices[gpu_device_index].has_unified_memory)
	{
		// Create and initialize bitmaps
		unsigned int* my_bit_table = (unsigned int*)calloc(ntlm_size_bit_table / 32 + 1, sizeof(unsigned int));

		for (i = 0; i < (int)num_passwords_loaded; i++)
		{
			unsigned int value_map = ((unsigned int*)binary_values)[i * 4 + 1] & ntlm_size_bit_table;
			my_bit_table[value_map >> 5] |= 1 << (value_map & 31);
		}

		cl_write_buffer(param, GPU_TABLE		 , 4 * (size_table + 1), table);
		cl_write_buffer(param, GPU_BIT_TABLE	 , 4 * (ntlm_size_bit_table / 32 + 1), my_bit_table);
		cl_write_buffer(param, GPU_BINARY_VALUES , BINARY_SIZE*num_passwords_loaded, binary_values);
		cl_write_buffer(param, GPU_SAME_HASH_NEXT, 4 * num_passwords_loaded, same_hash_next);

		pclFinish(param->queue);
		free(my_bit_table);
	}

	pclFinish(param->queue);
	free(source);

	*gpu_ntlm_crypt = ocl_protocol_rules_work;
	param->additional_param = kernels2common + kernel2common_index;
	return param;
}
#endif

PRIVATE int bench_values[] = {1,10,100,1000,10000,65536,100000,1000000};
Format ntlm_format = {
	"NTLM",
	"MD4 based.",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	2,
	bench_values,
	LENGHT(bench_values),
	get_binary,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_NTLM, crypt_ntlm_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_NTLM, crypt_ntlm_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_NTLM, crypt_ntlm_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_arm}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_arm}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}},
	#endif
#endif
	#ifdef HS_OPENCL_SUPPORT
		{{PROTOCOL_CHARSET_OCL, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
	#endif
};
