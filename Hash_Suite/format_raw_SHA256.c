// This file is part of Hash Suite password cracker,
// Copyright (c) 2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A  0x6a09e667
#define INIT_B  0xbb67ae85
#define INIT_C  0x3c6ef372
#define INIT_D  0xa54ff53a
#define INIT_E  0x510e527f
#define INIT_F  0x9b05688c
#define INIT_G  0x1f83d9ab
#define INIT_H  0x5be0cd19

#define BINARY_SIZE			32
#define NTLM_MAX_KEY_LENGHT	27

#define R_E(x) (rotate(x,26) ^ rotate(x,21) ^ rotate(x,7 ))
#define R_A(x) (rotate(x,30) ^ rotate(x,19) ^ rotate(x,10))
#define R0(x)  (rotate(x,25) ^ rotate(x,14) ^ (x>>3))
#define R1(x)  (rotate(x,15) ^ rotate(x,13) ^ (x>>10))

PRIVATE int is_valid(char* user_name, char* sha256, char* unused, char* unused1)
{
	if (user_name)
	{
		char* hash = sha256 ? sha256 : user_name;

		if (valid_hex_string(hash, 64) || valid_base64_string(hash, 43) || (!memcmp(hash, "$SHA256$", 8) && valid_hex_string(hash+8, 64)) || (!memcmp(hash, "$cisco4$", 8) && valid_base64_string(hash+8, 43)))
			return TRUE;
	}

	return FALSE;
}

PRIVATE void add_hash_from_line(ImportParam* param, char* user_name, char* sha256, char* unused, char* unused1, sqlite3_int64 tag_id)
{
	if (user_name)
	{
		char* hash = sha256 ? sha256 : user_name;
		char* user = sha256 ? user_name : "user";

		if (valid_hex_string(hash, 64))
			insert_hash_account(param, user, _strupr(hash), SHA256_INDEX, tag_id);

		if (!memcmp(hash, "$SHA256$", 8) && valid_hex_string(hash+8, 64))
			insert_hash_account(param, user, _strupr(hash+8), SHA256_INDEX, tag_id);

		if (valid_base64_string(hash, 43) || (!memcmp(hash, "$cisco4$", 8) && valid_base64_string(hash + 8, 43)))
		{
			const char* itoa16 = "0123456789ABCDEF";
			unsigned char hex[65];
			char* p = !memcmp(hash, "$cisco4$", 8) ? hash + 8 : hash;
			char* o = hex;
			
			while(*p)
			{
				unsigned int ch, b;

				// Get 1st byte of input (1st and 2nd)
				ch = *p++;
				b = ((base64_to_num[ch] << 2) & 252) + (base64_to_num[*p] >> 4 & 0x03);
				*o++ = itoa16[b >> 4];
				*o++ = itoa16[b & 0x0f];

				// Get 2nd byte of input (2nd and 3rd)
				ch = *p++;
				b = ((base64_to_num[ch] << 4) & 240) + (base64_to_num[*p] >> 2 & 0x0f);
				*o++ = itoa16[b >> 4];
				*o++ = itoa16[b & 0x0f];

				if (!p[1])
					break;

				// Get 3rd byte of input (3rd and 4th)
				ch = *p++;
				b = ((base64_to_num[ch] << 6) & 192) + (base64_to_num[*p++] & 0x3f);
				*o++ = itoa16[b >> 4];
				*o++ = itoa16[b & 0x0f];
			}
			hex[64] = 0;

			insert_hash_account(param, user, hex, SHA256_INDEX, tag_id);
		}
	}
}
PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	unsigned int* out = (unsigned int*)binary;

	for (unsigned int i = 0; i < 8; i++)
	{
		unsigned int temp = (hex_to_num[ciphertext[i * 8 + 0]]) << 28;
		temp |= (hex_to_num[ciphertext[i * 8 + 1]]) << 24;
		
		temp |= (hex_to_num[ciphertext[i * 8 + 2]]) << 20;
		temp |= (hex_to_num[ciphertext[i * 8 + 3]]) << 16;
		
		temp |= (hex_to_num[ciphertext[i * 8 + 4]]) << 12;
		temp |= (hex_to_num[ciphertext[i * 8 + 5]]) << 8;
		
		temp |= (hex_to_num[ciphertext[i * 8 + 6]]) << 4;
		temp |= (hex_to_num[ciphertext[i * 8 + 7]]) << 0;

		out[i] = temp;
	}

	// Reverse
	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;
	out[4] -= INIT_E;
	out[5] -= INIT_F;
	out[6] -= INIT_G;
	out[7] -= INIT_H;

	//A += R_A(B) + ((B & C) | (D & (B | C)));										E += A;			A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2;
	out[0] -= R_A(out[1]) + ((out[1] & out[2]) | (out[3] & (out[1] | out[2]))); out[4] -= out[0]; out[0] -= R_E(out[5]) + (out[7] ^ (out[5] & (out[6] ^ out[7]))) + 0xC67178F2;

	//B += R_A(C) + ((C & D) | (E & (C | D)));                                   F += B;            B    +=   R_E(G)    + 0xBEF9A3F7
	out[1] -= R_A(out[2]) + ((out[2] & out[3]) | (out[4] & (out[2] | out[3]))); out[5] -= out[1]; out[1] -= R_E(out[6]) + 0xBEF9A3F7;

	// C += R_A(D) + ((D & E) | (F & (D | E)));
	out[2] -= R_A(out[3]) + ((out[3] & out[4]) | (out[5] & (out[3] | out[4])));

	// G += C;                         D += R_A(E) + ((E & F) | (G & (E | F)));
	unsigned int G = out[6] - out[2]; out[3] -= R_A(out[4]) + ((out[4] & out[5]) | (G & (out[4] | out[5])));

	// H += D;                        E += R_A(F) + ((F & G) | (H & (F | G)));
	unsigned int H = out[7] - out[3]; out[4] -= R_A(out[5]) + ((out[5] & G) | (H & (out[5] | G)));

	// F += R_A(G)
	out[5] -= R_A(G);

	// A += E;
	out[0] -= out[4];

	return out[0];
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, crypt_kernel_asm_func* crypt_kernel_asm)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc((8+16+7) * sizeof(unsigned int) * NT_NUM_KEYS, 32);

	unsigned int* unpacked_W  = nt_buffer   + 8  * NT_NUM_KEYS;
	unsigned int* unpacked_as = unpacked_W  + 4  * NT_NUM_KEYS;
	unsigned int* unpacked_bs = unpacked_W  + 16 * NT_NUM_KEYS;
	unsigned int* unpacked_cs = unpacked_bs + NT_NUM_KEYS;
	unsigned int* unpacked_ds = unpacked_cs + NT_NUM_KEYS;
	unsigned int* unpacked_es = unpacked_ds + NT_NUM_KEYS;
	unsigned int* unpacked_fs = unpacked_es + NT_NUM_KEYS;
	unsigned int* unpacked_gs = unpacked_fs + NT_NUM_KEYS;
	unsigned int* unpacked_hs = unpacked_gs + NT_NUM_KEYS;
	unsigned int* indexs	  = unpacked_W  + 6 * NT_NUM_KEYS;

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 8 * sizeof(unsigned int)* NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_kernel_asm(nt_buffer, bit_table, size_bit_table);

		for (unsigned int i = 0; i < NT_NUM_KEYS; i++)
			if (indexs[i])
			{
				unsigned int indx = table[unpacked_as[i] & size_table];
				// Partial match
				while (indx != NO_ELEM)
				{
					unsigned int aa = unpacked_as[i], bb, cc, dd, ee, ff, gg, hh, W10, W12, W14;
					unsigned int* bin = ((unsigned int*)binary_values) + indx * 8;
					unsigned int* W = unpacked_W + i;

					if (aa != bin[0]) goto next_iteration;
					// W-> 0,1,2 ,4, 6
					aa -= W[0  * NT_NUM_KEYS];
					W10 = W[10 * NT_NUM_KEYS] + R1(W[8 * NT_NUM_KEYS])+ W[3 * NT_NUM_KEYS] + R0(W[11 * NT_NUM_KEYS]);
					W12 = W[12 * NT_NUM_KEYS] + R1(W10)               + W[5 * NT_NUM_KEYS] + R0(W[13 * NT_NUM_KEYS]);
					W14 = W[14 * NT_NUM_KEYS] + R1(W12)               + W[7 * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]);

					bb = unpacked_bs[i];
					cc = unpacked_cs[i];
					dd = unpacked_ds[i];
					ee = unpacked_es[i];
					ff = unpacked_fs[i];
					gg = unpacked_gs[i];
					hh = unpacked_hs[i];

					hh += R_E(ee) + (gg ^ (ee & (ff ^ gg))) + 0x748F82EE + W[8 * NT_NUM_KEYS]; dd += hh; hh += R_A(aa) + ((aa & bb) | (cc & (aa | bb)));
					gg += R_E(dd) + (ff ^ (dd & (ee ^ ff))) + 0x78A5636F + W[9 * NT_NUM_KEYS]; cc += gg; gg += R_A(hh) + ((hh & aa) | (bb & (hh | aa)));
					ff += R_E(cc) + (ee ^ (cc & (dd ^ ee))) + 0x84C87814 + W10               ; bb += ff; ff +=           ((gg & hh) | (aa & (gg | hh)));
					ee += R_E(bb) + (dd ^ (bb & (cc ^ dd))) + 0x8CC70208 + W[2 * NT_NUM_KEYS]; aa += ee;
					dd += R_E(aa) + (cc ^ (aa & (bb ^ cc))) + 0x90BEFFFA + W12               ; hh += dd;
					cc += R_E(hh) + (bb ^ (hh & (aa ^ bb))) + 0xA4506CEB + W[1 * NT_NUM_KEYS]; gg += cc;
					bb +=           (aa ^ (gg & (hh ^ aa)))              + W14 ;

					if (bb != bin[1] || cc != bin[2] || dd != bin[3] || ee != bin[4] || ff != bin[5] || gg != bin[6] || hh != bin[7])
						goto next_iteration;

					// Total match
					password_was_found(indx, utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

				next_iteration:
					indx = same_hash_next[indx];
				}
			}

		report_keys_processed(NT_NUM_KEYS);
	}

	_aligned_free(nt_buffer);

	finish_thread();
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _M_X64
PRIVATE void crypt_kernel_c_code(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table)
{
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int* W = nt_buffer + 8 * NT_NUM_KEYS;

	for (int i = 0; i < NT_NUM_KEYS; i++, nt_buffer++, W++)
	{
		SWAP_ENDIANNESS(W[0 * NT_NUM_KEYS], nt_buffer[0 * NT_NUM_KEYS]);
		SWAP_ENDIANNESS(W[1 * NT_NUM_KEYS], nt_buffer[1 * NT_NUM_KEYS]);
		SWAP_ENDIANNESS(W[2 * NT_NUM_KEYS], nt_buffer[2 * NT_NUM_KEYS]);
		SWAP_ENDIANNESS(W[3 * NT_NUM_KEYS], nt_buffer[3 * NT_NUM_KEYS]);
		SWAP_ENDIANNESS(W[4 * NT_NUM_KEYS], nt_buffer[4 * NT_NUM_KEYS]);
		SWAP_ENDIANNESS(W[5 * NT_NUM_KEYS], nt_buffer[5 * NT_NUM_KEYS]);
		SWAP_ENDIANNESS(W[6 * NT_NUM_KEYS], nt_buffer[6 * NT_NUM_KEYS]);
		W[15 * NT_NUM_KEYS] = nt_buffer[7 * NT_NUM_KEYS];

		/* Rounds */
		H  = 0xfc08884d + W[0 * NT_NUM_KEYS];											D=0x9cbf5a55+H;
		G  = R_E(D) + (INIT_F ^ (D & 0xca0b3af3  )) + 0x90bb1e3c + W[ 1 * NT_NUM_KEYS]; C=INIT_C+G; G += R_A(H) + ((H & INIT_A) | (INIT_B & (H | INIT_A)));
		F  = R_E(C) + (INIT_E ^ (C & (D ^ INIT_E))) + 0x50c6645b + W[ 2 * NT_NUM_KEYS]; B=INIT_B+F; F += R_A(G) + ((G & H) | (INIT_A & (G | H)));
		E  = R_E(B) + (D ^ (B & (C ^ D)))			+ 0x3ac42e24 + W[ 3 * NT_NUM_KEYS]; A=INIT_A+E; E += R_A(F) + ((F & G) | (H & (F | G)));
		D += R_E(A) + (C ^ (A & (B ^ C)))			+ 0x3956C25B + W[ 4 * NT_NUM_KEYS]; H += D;	    D += R_A(E) + ((E & F) | (G & (E | F)));
		C += R_E(H) + (B ^ (H & (A ^ B)))			+ 0x59F111F1 + W[ 5 * NT_NUM_KEYS]; G += C;	    C += R_A(D) + ((D & E) | (F & (D | E)));
		B += R_E(G) + (A ^ (G & (H ^ A)))			+ 0x923F82A4 + W[ 6 * NT_NUM_KEYS]; F += B;	    B += R_A(C) + ((C & D) | (E & (C | D)));
		A += R_E(F) + (H ^ (F & (G ^ H)))			+ 0xAB1C5ED5                      ; E += A;	    A += R_A(B) + ((B & C) | (D & (B | C)));
		H += R_E(E) + (G ^ (E & (F ^ G)))			+ 0xD807AA98                      ; D += H;	    H += R_A(A) + ((A & B) | (C & (A | B)));
		G += R_E(D) + (F ^ (D & (E ^ F)))			+ 0x12835B01                      ; C += G;	    G += R_A(H) + ((H & A) | (B & (H | A)));
		F += R_E(C) + (E ^ (C & (D ^ E)))			+ 0x243185BE                      ; B += F;	    F += R_A(G) + ((G & H) | (A & (G | H)));
		E += R_E(B) + (D ^ (B & (C ^ D)))			+ 0x550C7DC3                      ; A += E;	    E += R_A(F) + ((F & G) | (H & (F | G)));
		D += R_E(A) + (C ^ (A & (B ^ C)))			+ 0x72BE5D74                      ; H += D;	    D += R_A(E) + ((E & F) | (G & (E | F)));
		C += R_E(H) + (B ^ (H & (A ^ B)))			+ 0x80DEB1FE                      ; G += C;	    C += R_A(D) + ((D & E) | (F & (D | E)));
		B += R_E(G) + (A ^ (G & (H ^ A)))			+ 0x9BDC06A7                      ; F += B;	    B += R_A(C) + ((C & D) | (E & (C | D)));
		A += R_E(F) + (H ^ (F & (G ^ H)))			+ 0xC19BF174 + W[15 * NT_NUM_KEYS]; E += A;	    A += R_A(B) + ((B & C) | (D & (B | C)));

		W[ 0 * NT_NUM_KEYS] +=					                               R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xE49B69C1 + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS])                       + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xEFBE4786 + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS])                       + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x0FC19DC6 + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS])                       + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x240CA1CC + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS])                       + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x2DE92C6F + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS])                       + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4A7484AA + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS]                          ; B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5CB0A9DC + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS]  = R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS]                          ; A += R_E(F) + (H ^ (F & (G ^ H))) + 0x76F988DA + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS]  = R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS]                          ; H += R_E(E) + (G ^ (E & (F ^ G))) + 0x983E5152 + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS]  = R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS]                          ; G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA831C66D + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS]  = R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS]                          ; F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB00327C8 + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS]  = R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS]                          ; E += R_E(B) + (D ^ (B & (C ^ D))) + 0xBF597FC7 + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS]  = R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS]                          ; D += R_E(A) + (C ^ (A & (B ^ C))) + 0xC6E00BF3 + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS]  = R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS]                          ; C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD5A79147 + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS]  = R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x06CA6351 + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x14292967 + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x27B70A85 + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x2E1B2138 + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x4D2C6DFC + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x53380D13 + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x650A7354 + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x766A0ABB + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x81C2C92E + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x92722C85 + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xA2BFE8A1 + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA81A664B + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS] += R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS] + R0(W[11 * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xC24B8B70 + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS] += R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xC76C51A3 + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS] += R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS] + R0(W[13 * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xD192E819 + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS] += R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD6990624 + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS] += R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xF40E3585 + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x106AA070 + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x19A4C116 + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x1E376C08 + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x2748774C + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x34B0BCB5 + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x391C0CB3 + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4ED8AA4A + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5B9CCA4F + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x682E6FF3 + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]);
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]);
		W[2 * NT_NUM_KEYS] = W[11 * NT_NUM_KEYS] + R1(W[9 * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]);
		W[1 * NT_NUM_KEYS] = W[13 * NT_NUM_KEYS] + R1(W[2 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]);
		W[0 * NT_NUM_KEYS] = W[15 * NT_NUM_KEYS] + R1(W[1 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += W[0 * NT_NUM_KEYS]; 

		W[4  * NT_NUM_KEYS] = A;
		W[16 * NT_NUM_KEYS] = B;
		W[17 * NT_NUM_KEYS] = C;
		W[18 * NT_NUM_KEYS] = D;
		W[19 * NT_NUM_KEYS] = E;
		W[20 * NT_NUM_KEYS] = F;
		W[21 * NT_NUM_KEYS] = G;
		W[22 * NT_NUM_KEYS] = H;

		// Search for a match
		unsigned int val = A & size_bit_table;
		W[6 * NT_NUM_KEYS] = (bit_table[val >> 5] >> (val & 31)) & 1;
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_kernel_c_code);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM

void crypt_sha256_neon_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha256_neon_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_simd.h"

#define SHA1_NUM		(NT_NUM_KEYS/4)
#define LOAD_BIG_ENDIAN_SSE2(x,data) x = SSE2_ROTATE(data, 16); x = SSE2_ADD(_mm_slli_epi32(SSE2_AND(x, mask), 8), SSE2_AND(_mm_srli_epi32(x, 8), mask));

#undef R_E
#undef R_A
#undef R0
#undef R1
#define R_E(x) SSE2_3XOR(SSE2_ROTATE(x,26), SSE2_ROTATE(x,21), SSE2_ROTATE(x,7 ))
#define R_A(x) SSE2_3XOR(SSE2_ROTATE(x,30), SSE2_ROTATE(x,19), SSE2_ROTATE(x,10))
#define R0(x)  SSE2_3XOR(SSE2_ROTATE(x,25), SSE2_ROTATE(x,14), SSE2_SR(x,3))
#define R1(x)  SSE2_3XOR(SSE2_ROTATE(x,15), SSE2_ROTATE(x,13), SSE2_SR(x,10))

PRIVATE void crypt_kernel_sse2(SSE2_WORD* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table)
{
	SSE2_WORD* W = nt_buffer + 8 * SHA1_NUM;
	SSE2_WORD mask = SSE2_CONST(0x00FF00FF);
	SSE2_WORD A, B, C, D, E, F, G, H;

	for (int i = 0; i < SHA1_NUM; i++, nt_buffer++, W++)
	{
		LOAD_BIG_ENDIAN_SSE2(W[0*SHA1_NUM], nt_buffer[0*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[1*SHA1_NUM], nt_buffer[1*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[2*SHA1_NUM], nt_buffer[2*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[3*SHA1_NUM], nt_buffer[3*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[4*SHA1_NUM], nt_buffer[4*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[5*SHA1_NUM], nt_buffer[5*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[6*SHA1_NUM], nt_buffer[6*SHA1_NUM]);
		W[15*SHA1_NUM] = nt_buffer[7*SHA1_NUM];
		
		/* Rounds */
		H = SSE2_ADD(SSE2_CONST(0xfc08884d), W[0 * SHA1_NUM]);						                                                                 D = SSE2_ADD(SSE2_CONST(0x9cbf5a55), H);
		G = SSE2_4ADD(R_E(D), SSE2_XOR(SSE2_CONST(INIT_F), SSE2_AND(D, SSE2_CONST(0xca0b3af3)))         , SSE2_CONST(0x90bb1e3c), W[ 1 * SHA1_NUM]); C = SSE2_ADD(SSE2_CONST(INIT_C),G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, SSE2_CONST(INIT_A)), SSE2_AND(SSE2_CONST(INIT_B), SSE2_OR(H, SSE2_CONST(INIT_A)))));
		F = SSE2_4ADD(R_E(C), SSE2_XOR(SSE2_CONST(INIT_E), SSE2_AND(C, SSE2_XOR(D, SSE2_CONST(INIT_E)))), SSE2_CONST(0x50c6645b), W[ 2 * SHA1_NUM]); B = SSE2_ADD(SSE2_CONST(INIT_B),F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(SSE2_CONST(INIT_A), SSE2_OR(G, H))));
		E = SSE2_4ADD(R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D)))			                        , SSE2_CONST(0x3ac42e24), W[ 3 * SHA1_NUM]); A = SSE2_ADD(SSE2_CONST(INIT_A),E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C)))			                    , SSE2_CONST(0x3956C25B), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D);                 D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B)))			                    , SSE2_CONST(0x59F111F1), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C);                 C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A)))			                    , SSE2_CONST(0x923F82A4), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B);                 B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		A = SSE2_4ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H)))			                    , SSE2_CONST(0xAB1C5ED5)                  ); E = SSE2_ADD(E, A);                 A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		H = SSE2_4ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G)))			                    , SSE2_CONST(0xD807AA98)                  ); D = SSE2_ADD(D, H);                 H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		G = SSE2_4ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F)))			                    , SSE2_CONST(0x12835B01)                  ); C = SSE2_ADD(C, G);                 G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		F = SSE2_4ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E)))			                    , SSE2_CONST(0x243185BE)                  ); B = SSE2_ADD(B, F);                 F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		E = SSE2_4ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D)))			                    , SSE2_CONST(0x550C7DC3)                  ); A = SSE2_ADD(A, E);                 E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		D = SSE2_4ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C)))			                    , SSE2_CONST(0x72BE5D74)                  ); H = SSE2_ADD(H, D);                 D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		C = SSE2_4ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B)))			                    , SSE2_CONST(0x80DEB1FE)                  ); G = SSE2_ADD(G, C);                 C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		B = SSE2_4ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A)))			                    , SSE2_CONST(0x9BDC06A7)                  ); F = SSE2_ADD(F, B);                 B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H)))			                    , SSE2_CONST(0xC19BF174), W[15 * SHA1_NUM]); E = SSE2_ADD(E, A);                 A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

		W[ 0 * SHA1_NUM] = SSE2_ADD (W[ 0 * SHA1_NUM], 				                           R0(W[1  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0xE49B69C1), W[ 0 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA1_NUM] = SSE2_3ADD(W[ 1 * SHA1_NUM], R1(W[15 * SHA1_NUM]),                   R0(W[2  * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0xEFBE4786), W[ 1 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA1_NUM] = SSE2_3ADD(W[ 2 * SHA1_NUM], R1(W[0  * SHA1_NUM]),                   R0(W[3  * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0x0FC19DC6), W[ 2 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA1_NUM] = SSE2_3ADD(W[ 3 * SHA1_NUM], R1(W[1  * SHA1_NUM]),                   R0(W[4  * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0x240CA1CC), W[ 3 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA1_NUM] = SSE2_3ADD(W[ 4 * SHA1_NUM], R1(W[2  * SHA1_NUM]),                   R0(W[5  * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0x2DE92C6F), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA1_NUM] = SSE2_3ADD(W[ 5 * SHA1_NUM], R1(W[3  * SHA1_NUM]),                   R0(W[6  * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0x4A7484AA), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA1_NUM] = SSE2_3ADD(W[ 6 * SHA1_NUM], R1(W[4  * SHA1_NUM]), W[15 * SHA1_NUM]                      ); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x5CB0A9DC), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA1_NUM] = SSE2_ADD (                  R1(W[5  * SHA1_NUM]), W[0  * SHA1_NUM]                      ); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x76F988DA), W[ 7 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA1_NUM] = SSE2_ADD (                  R1(W[6  * SHA1_NUM]), W[1  * SHA1_NUM]                      ); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x983E5152), W[ 8 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA1_NUM] = SSE2_ADD (                  R1(W[7  * SHA1_NUM]), W[2  * SHA1_NUM]                      ); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0xA831C66D), W[ 9 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA1_NUM] = SSE2_ADD (                  R1(W[8  * SHA1_NUM]), W[3  * SHA1_NUM]                      ); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0xB00327C8), W[10 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA1_NUM] = SSE2_ADD (                  R1(W[9  * SHA1_NUM]), W[4  * SHA1_NUM]                      ); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0xBF597FC7), W[11 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA1_NUM] = SSE2_ADD (                  R1(W[10 * SHA1_NUM]), W[5  * SHA1_NUM]                      ); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0xC6E00BF3), W[12 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA1_NUM] = SSE2_ADD (                  R1(W[11 * SHA1_NUM]), W[6  * SHA1_NUM]                      ); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0xD5A79147), W[13 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA1_NUM] = SSE2_3ADD(                  R1(W[12 * SHA1_NUM]), W[7  * SHA1_NUM], R0(W[15 * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x06CA6351), W[14 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA1_NUM] = SSE2_4ADD(W[15 * SHA1_NUM], R1(W[13 * SHA1_NUM]), W[8  * SHA1_NUM], R0(W[0  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x14292967), W[15 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
																    												  
		W[ 0 * SHA1_NUM] = SSE2_4ADD(W[ 0 * SHA1_NUM], R1(W[14 * SHA1_NUM]), W[9  * SHA1_NUM], R0(W[1  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x27B70A85), W[ 0 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA1_NUM] = SSE2_4ADD(W[ 1 * SHA1_NUM], R1(W[15 * SHA1_NUM]), W[10 * SHA1_NUM], R0(W[2  * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0x2E1B2138), W[ 1 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA1_NUM] = SSE2_4ADD(W[ 2 * SHA1_NUM], R1(W[0  * SHA1_NUM]), W[11 * SHA1_NUM], R0(W[3  * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0x4D2C6DFC), W[ 2 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA1_NUM] = SSE2_4ADD(W[ 3 * SHA1_NUM], R1(W[1  * SHA1_NUM]), W[12 * SHA1_NUM], R0(W[4  * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0x53380D13), W[ 3 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA1_NUM] = SSE2_4ADD(W[ 4 * SHA1_NUM], R1(W[2  * SHA1_NUM]), W[13 * SHA1_NUM], R0(W[5  * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0x650A7354), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA1_NUM] = SSE2_4ADD(W[ 5 * SHA1_NUM], R1(W[3  * SHA1_NUM]), W[14 * SHA1_NUM], R0(W[6  * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0x766A0ABB), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA1_NUM] = SSE2_4ADD(W[ 6 * SHA1_NUM], R1(W[4  * SHA1_NUM]), W[15 * SHA1_NUM], R0(W[7  * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x81C2C92E), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA1_NUM] = SSE2_4ADD(W[ 7 * SHA1_NUM], R1(W[5  * SHA1_NUM]), W[0  * SHA1_NUM], R0(W[8  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x92722C85), W[ 7 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA1_NUM] = SSE2_4ADD(W[ 8 * SHA1_NUM], R1(W[6  * SHA1_NUM]), W[1  * SHA1_NUM], R0(W[9  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0xA2BFE8A1), W[ 8 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA1_NUM] = SSE2_4ADD(W[ 9 * SHA1_NUM], R1(W[7  * SHA1_NUM]), W[2  * SHA1_NUM], R0(W[10 * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0xA81A664B), W[ 9 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA1_NUM] = SSE2_4ADD(W[10 * SHA1_NUM], R1(W[8  * SHA1_NUM]), W[3  * SHA1_NUM], R0(W[11 * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0xC24B8B70), W[10 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA1_NUM] = SSE2_4ADD(W[11 * SHA1_NUM], R1(W[9  * SHA1_NUM]), W[4  * SHA1_NUM], R0(W[12 * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0xC76C51A3), W[11 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA1_NUM] = SSE2_4ADD(W[12 * SHA1_NUM], R1(W[10 * SHA1_NUM]), W[5  * SHA1_NUM], R0(W[13 * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0xD192E819), W[12 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA1_NUM] = SSE2_4ADD(W[13 * SHA1_NUM], R1(W[11 * SHA1_NUM]), W[6  * SHA1_NUM], R0(W[14 * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0xD6990624), W[13 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA1_NUM] = SSE2_4ADD(W[14 * SHA1_NUM], R1(W[12 * SHA1_NUM]), W[7  * SHA1_NUM], R0(W[15 * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0xF40E3585), W[14 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA1_NUM] = SSE2_4ADD(W[15 * SHA1_NUM], R1(W[13 * SHA1_NUM]), W[8  * SHA1_NUM], R0(W[0  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x106AA070), W[15 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
																    								 						
		W[ 0 * SHA1_NUM] = SSE2_4ADD(W[ 0 * SHA1_NUM], R1(W[14 * SHA1_NUM]), W[9  * SHA1_NUM], R0(W[1  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x19A4C116), W[ 0 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA1_NUM] = SSE2_4ADD(W[ 1 * SHA1_NUM], R1(W[15 * SHA1_NUM]), W[10 * SHA1_NUM], R0(W[2  * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0x1E376C08), W[ 1 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA1_NUM] = SSE2_4ADD(W[ 2 * SHA1_NUM], R1(W[0  * SHA1_NUM]), W[11 * SHA1_NUM], R0(W[3  * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0x2748774C), W[ 2 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA1_NUM] = SSE2_4ADD(W[ 3 * SHA1_NUM], R1(W[1  * SHA1_NUM]), W[12 * SHA1_NUM], R0(W[4  * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0x34B0BCB5), W[ 3 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA1_NUM] = SSE2_4ADD(W[ 4 * SHA1_NUM], R1(W[2  * SHA1_NUM]), W[13 * SHA1_NUM], R0(W[5  * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0x391C0CB3), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA1_NUM] = SSE2_4ADD(W[ 5 * SHA1_NUM], R1(W[3  * SHA1_NUM]), W[14 * SHA1_NUM], R0(W[6  * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0x4ED8AA4A), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA1_NUM] = SSE2_4ADD(W[ 6 * SHA1_NUM], R1(W[4  * SHA1_NUM]), W[15 * SHA1_NUM], R0(W[7  * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x5B9CCA4F), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA1_NUM] = SSE2_4ADD(W[ 7 * SHA1_NUM], R1(W[5  * SHA1_NUM]), W[0  * SHA1_NUM], R0(W[8  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x682E6FF3), W[ 7 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA1_NUM] = SSE2_4ADD(W[ 8 * SHA1_NUM], R1(W[6  * SHA1_NUM]), W[1  * SHA1_NUM], R0(W[9  * SHA1_NUM]));
		W[ 9 * SHA1_NUM] = SSE2_4ADD(W[ 9 * SHA1_NUM], R1(W[7  * SHA1_NUM]), W[2  * SHA1_NUM], R0(W[10 * SHA1_NUM]));
		W[ 2 * SHA1_NUM] = SSE2_4ADD(W[11 * SHA1_NUM], R1(W[9  * SHA1_NUM]), W[4  * SHA1_NUM], R0(W[12 * SHA1_NUM]));
		W[ 1 * SHA1_NUM] = SSE2_4ADD(W[13 * SHA1_NUM], R1(W[2  * SHA1_NUM]), W[6  * SHA1_NUM], R0(W[14 * SHA1_NUM]));
		W[ 0 * SHA1_NUM] = SSE2_4ADD(W[15 * SHA1_NUM], R1(W[1  * SHA1_NUM]), W[8  * SHA1_NUM], R0(W[0  * SHA1_NUM])); A = SSE2_ADD(A, W[0 * SHA1_NUM]); 

		W[4  * SHA1_NUM] = A;
		W[16 * SHA1_NUM] = B;
		W[17 * SHA1_NUM] = C;
		W[18 * SHA1_NUM] = D;
		W[19 * SHA1_NUM] = E;
		W[20 * SHA1_NUM] = F;
		W[21 * SHA1_NUM] = G;
		W[22 * SHA1_NUM] = H;

		// Search for a match
		A = SSE2_AND(A, SSE2_CONST(size_bit_table));
		for (int j = 0; j < 4; j++)
		{
			unsigned int val = ((unsigned int*)(&A))[j];

			((unsigned int*)W)[6 * NT_NUM_KEYS + j] = (bit_table[val >> 5] >> (val & 31)) & 1;
		}
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_sse2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, (crypt_kernel_asm_func*)crypt_kernel_sse2);
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_sha256_avx_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha256_avx_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_sha256_avx2_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha256_avx2_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#undef R1
#undef R0
#define R0(x)  (rotate(x,25u)^rotate(x,14u)^((x)>>3u))
#define R1(x)  (rotate(x,15u)^rotate(x,13u)^((x)>>10u))
PRIVATE void ocl_write_sha256_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table)
{
	source[0] = 0;
	// Header definitions
	if (num_passwords_loaded > 1)
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source + strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
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
	
	// Definitions
	sprintf(source + strlen(source), 
		"#define R_E(x) (rotate(x,26u)^rotate(x,21u)^rotate(x,7u))\n"
		"#define R_A(x) (rotate(x,30u)^rotate(x,19u)^rotate(x,10u))\n"
		"#define R0(x) (rotate(x,25u)^rotate(x,14u)^((x)>>3u))\n"
		"#define R1(x) (rotate(x,15u)^rotate(x,13u)^((x)>>10u))\n");

	if (num_passwords_loaded > 1)
		sprintf(source + strlen(source),
		"#define SIZE_TABLE %uu\n"
		"#define SIZE_BIT_TABLE %uu\n", size_table, ntlm_size_bit_table);
}

PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission, cl_uint workgroup)
{
	char* nt_buffer[] = { "+nt_buffer0", "+nt_buffer1", "+nt_buffer2", "+nt_buffer3", "+nt_buffer4", "+nt_buffer5", "+nt_buffer6" };

	ocl_charset_load_buffer_be(source, key_lenght, &vector_size, div_param, nt_buffer);

	sprintf(source + strlen(source), "uint A,B,C,D,E,F,G,H,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "nt_buffer0+=%uu;", is_charset_consecutive(charset) << 24u);

	sprintf(source + strlen(source),
		"uint wW1=%uu+R0(0u%s)%s;"
		"uint wW3=R1(wW1)+R0(0u%s)%s;"
		"uint wW5=R1(wW3)+R0(0u%s)%s;"

		"uint R1_wW5=R1(wW5);"

		"uint R0_wW1=R0(wW1);"
		"uint R0_wW3=R0(wW3);"
		"uint R0_wW5=R0(wW5);"

		"uint R0_W1=R0(0u%s);"
		"uint R0_W3=R0(0u%s);"
		"uint R0_W5=R0(0u%s);"
		, R1(key_lenght << 3), nt_buffer[2], nt_buffer[1]
		, nt_buffer[4], nt_buffer[3]
		, nt_buffer[6], nt_buffer[5]

		, nt_buffer[1]
		, nt_buffer[3]
		, nt_buffer[5]);

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "W0=nt_buffer0+(i<<24u);");
	else
		sprintf(source + strlen(source), "W0=nt_buffer0+(((uint)charset[i])<<24u);");

	/* Round 1 */
	sprintf(source + strlen(source),
		"H=0xfc08884dU+W0;D=0x9cbf5a55U+H;"
		"G=R_E(D)+(%uu^(D&%uu))+0x90bb1e3cU%s;C=0x3c6ef372U+G;G+=R_A(H)+MAJ(H,%uu,%uu);"
		"F=R_E(C)+bs(%uu,D,C)+0x50c6645bU%s;B=0xbb67ae85U+F;F+=R_A(G)+MAJ(G,H,%uu);"
		"E=R_E(B)+bs(D,C,B)+0x3ac42e24U%s;A=0x6a09e667U+E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x3956C25BU%s;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x59F111F1U%s;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x923F82A4U%s;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5U;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0xD807AA98U;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0x12835B01U;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x243185BEU;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x550C7DC3U;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x72BE5D74U;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x80DEB1FEU;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x9BDC06A7U;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+%uu;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		, 0x9b05688c, 0xca0b3af3, nt_buffer[1], 0x6a09e667, 0xbb67ae85
		, 0x510e527f, nt_buffer[2], 0x6a09e667
		, nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], (key_lenght << 3) + 0xC19BF174);

	sprintf(source + strlen(source),
			"W0+=R0_W1;"
			"W2=R1(W0)+R0_W3%s;"
			"W4=R1(W2)+R0_W5%s;"
			"W6=R1(W4)+%uu%s;"
			"W7=R1_wW5+W0;"
			"W8=R1(W6)+wW1;"
			"W9=R1(W7)+W2;"
			"W10=R1(W8)+wW3;"
			"W11=R1(W9)+W4;"
			"W12=R1(W10)+wW5;"
			"W13=R1(W11)+W6;"
			"W14=R1(W12)+W7+%uu;"
			"W15=R1(W13)+W8+R0(W0)+%uu;"
			, nt_buffer[2]
			, nt_buffer[4]
			, key_lenght << 3, nt_buffer[6]
			, R0(key_lenght << 3)
			, key_lenght << 3);

	/* Round 2 */
	sprintf(source + strlen(source),
		"H+=R_E(E)+bs(G,F,E)+0xE49B69C1U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xEFBE4786U+wW1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x0FC19DC6U+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x240CA1CCU+wW3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x2DE92C6FU+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x4A7484AAU+wW5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x76F988DAU+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0x983E5152U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xA831C66DU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0xB00327C8U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0xBF597FC7U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0xC6E00BF3U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0xD5A79147U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x06CA6351U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x14292967U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9 +R0_wW1;H+=R_E(E)+bs(G,F,E)+0x27B70A85U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1=wW1+R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x2E1B2138U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0_wW3;F+=R_E(C)+bs(E,D,C)+0x4D2C6DFCU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3=wW3+R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x53380D13U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0_wW5;D+=R_E(A)+bs(C,B,A)+0x650A7354U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5=wW5+R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x766A0ABBU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x81C2C92EU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x92722C85U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A1U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664BU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A3U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD6990624U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E3585U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0);A+=R_E(F)+bs(H,G,F)+0x106AA070U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
													   													  
	/* Round 4 */									   													  
	sprintf(source + strlen(source),				   													  
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x19A4C116U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x1E376C08U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x2748774CU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x391C0CB3U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4AU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4FU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x682E6FF3U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);"
		"W9+=R1(W7)+W2+R0(W10);"
		"W2=W11+R1(W9)+W4+R0(W12);"
		"W1=W13+R1(W2)+W6+R0(W14);"
		"W0=W15+R1(W1)+W8+R0(W0);A+=W0;");

	// Find match
	if (num_passwords_loaded == 1)
	{
		unsigned int* bin = (unsigned int*)binary_values;
		sprintf(source + strlen(source),
				"if(A==%uu)"
				"{"
					"A-=W0;"
					"W10+=R1(W8)+W3+R0(W11);"
					"W12+=R1(W10)+W5+R0(W13);"
					"W14+=R1(W12)+W7+R0(W15);"

					"H+=R_E(E)+bs(G,F,E)+0x748F82EEU+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
					"G+=R_E(D)+bs(F,E,D)+0x78A5636FU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
					"F+=R_E(C)+bs(E,D,C)+0x84C87814U+W10;B+=F;F+=MAJ(G,H,A);"
					"E+=R_E(B)+bs(D,C,B)+0x8CC70208U+W2;A+=E;"
					"D+=R_E(A)+bs(C,B,A)+0x90BEFFFAU+W12;H+=D;"
					"C+=R_E(H)+bs(B,A,H)+0xA4506CEBU+W1;G+=C;"
					"B+=bs(A,H,G)+W14;"

					"if(B==%uu&&C==%uu&&D==%uu&&E==%uu&&F==%uu&&G==%uu&&H==%uu)"
					"{"
						"output[0]=1u;"
						"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
						"output[2]=0;"
					"}"
				"}"
				, bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7]);
	}
	else
	{
		sprintf(source + strlen(source),
			"indx=A&SIZE_BIT_TABLE;"
			"if((bit_table[indx>>5u]>>(indx&31u))&1u)"
			"{"
				"indx=table[A & SIZE_TABLE];"

				"while(indx!=0xffffffff)"
				//"if(indx!=0xffffffff)"
				"{"
					"if(A==binary_values[indx*8u])"
					"{"
						"uint aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"uint ww14=W14+R1(W6)+W7+R0(W15);"
						
						"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"
						
						"hh+=R_E(ee)+bs(gg,ff,ee)+0x748F82EEU+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
						"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]&&"
						   "ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]&&"
						   "hh==binary_values[indx*8u+7u])"
						"{"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
								"output[2*found+2]=indx;}"
						"}", output_size);

	strcat(source, "}"
					"indx=same_hash_next[indx];"
				"}"
			"}");
	}

	strcat(source, "}}");
}

PRIVATE uint32_t sha256_one_char[8*256]={
0xa9d34cc5, 0xb40ea40f, 0xd7c2c05e, 0xb7854398, 0xbf6e6169, 0x1c4e0266, 0x658dc95b, 0xbbced304,
0x8866b527, 0x3034aeab, 0xa0264b6f, 0xd463d9d7, 0x0526a0bb, 0x51507e5b, 0xb8490891, 0x1ba47881,
0x8c73ccea, 0xeca461b2, 0xd69fe65a, 0xf8bfecb2, 0x11f9e9f9, 0x99b3c3f8, 0x2bf310ed, 0x08770c6d,
0x8c1f052d, 0xa0915880, 0x1c1cb6aa, 0xe7034348, 0xcde1a0ff, 0x3a937b4e, 0xf23280ef, 0x521e5cac,
0xb90ab6f1, 0x5f0d3c76, 0x28d27338, 0xc4be8f59, 0x41977f8c, 0xc4439b7a, 0x431cc2f8, 0x25e7d158,
0x2cdfb78b, 0x91cbfd3a, 0x348d2961, 0x58169921, 0x5e5ba2ee, 0x9591f14f, 0x6a672bf1, 0xfed676c2,
0x293c2c31, 0x8ff47005, 0xbba888e4, 0x13c8c997, 0x06c3617b, 0x7f0f71f1, 0xd9196ddb, 0xace51fdd,
0xd4e0d0b8, 0x6ebf8d18, 0x5d7c5515, 0x51a09e69, 0xe8b04e62, 0x33321951, 0x5e43e574, 0xa47e1b60,
0xb7aad1b6, 0xf2828342, 0x7aded40d, 0x1d4ba982, 0x295cfaf2, 0xc7038148, 0x91a4d96d, 0x31e0b581,
0x35acdf65, 0xab878814, 0x7a6612f6, 0x311e4014, 0x8e02c392, 0x8db2426c, 0x6c00e11b, 0x093b6fa0,
0x34eb4e3f, 0x0a5d4137, 0x507c0aff, 0xd513b654, 0xd1e9d6b2, 0xc7f2f263, 0xd00bbe5a, 0x7ee98752,
0x65f0f6e4, 0x651828c0, 0x6b5f1651, 0x47c77b77, 0xf9a467e9, 0x763a3769, 0xf529f986, 0xef9bf68d,
0x422d4b28, 0xace71780, 0x4012af00, 0x4cced208, 0x715824da, 0x2aee7a13, 0x967cf9de, 0x3f63fc5e,
0x6ca4cba2, 0x94f2d221, 0x364cdeb1, 0x5d97c6f7, 0x6e7ddd2a, 0x5fda3d5a, 0xd38ae083, 0xb554ccab,
0x619c5e9a, 0x2edeaa4c, 0xda3bcac4, 0x014fa1d7, 0x23db4969, 0xfd00c5a8, 0xead2630a, 0x3e2c422e,
0xba6fa118, 0x013e1f53, 0x59ca3cdf, 0x8671f0a1, 0x6081f185, 0xa5eab71c, 0x72b70012, 0x872ebf9f,
0xb9bd3607, 0xa2006bdc, 0x94947e12, 0xcb8642c2, 0x8ec194dc, 0xca7102d7, 0x2959588c, 0x2dd7c1ca,
0x8ea1be74, 0xf214a648, 0xb3c32420, 0xfdc47a0f, 0x1c048924, 0x78c52d95, 0xa558cf0a, 0xc16ddaf1,
0xb2b36a67, 0x4a10963f, 0x13c94c56, 0x0ddba4c7, 0xa940b85d, 0x9138a6eb, 0x5737e593, 0x8d3da7f3,
0xc0e4301d, 0x22d5539f, 0x3a1ff093, 0x35c11b16, 0x6c266266, 0x57bf994d, 0x39d4c45b, 0xd42995c9,
0x44a8aa20, 0xe96a7544, 0xdb6e561f, 0xbba9b6ee, 0xfe22b009, 0x04ae3979, 0x8736e0fd, 0x58720b60,
0x661065c1, 0xc2eeb008, 0xf3519277, 0xa77f8f15, 0x421bde16, 0x1b6509f4, 0x1b56fef5, 0x1414b8ef,
0x42513b32, 0xccfc3af5, 0xd7458f63, 0x583d2e09, 0x502ed7e2, 0x798fcf62, 0x8f2d15dd, 0x7e976ca1,
0xa261c606, 0xd79d87d1, 0x54a26b9b, 0xd766ccc0, 0x07625759, 0x2f793bfa, 0xdde501bb, 0xdec2a31b,
0x56a080b3, 0x9ec96f08, 0xc67c44cf, 0x1945fd37, 0x0146925e, 0x152a08ec, 0xf57a3b46, 0x6283ea36,
0x8496e58f, 0xecf16176, 0x271bae39, 0xd40dea89, 0x9275a7ec, 0xffb6ac6e, 0x23ecc261, 0x3fe316bb,
0x524f1ea7, 0x1d32eb96, 0x1e702fdd, 0xe03d1c39, 0x21ba8809, 0x286a52ca, 0x14c1d112, 0x0888a634,
0xc77da159, 0x50f8e913, 0xd3249533, 0xf1c43ec7, 0x11f6729a, 0xe8f96309, 0xa3ed21d1, 0xb96d94e4,
0x787b5008, 0x4698b485, 0xc52e0c03, 0xb1226447, 0xf2e704b8, 0x44a3e1af, 0xe7bfa829, 0x910d32ff,
0xeda0ab9f, 0x18871ba6, 0x6467ea05, 0xba36a7f6, 0x2d9dac82, 0x153a805d, 0x98e15ca4, 0xe58706b4,
0xf5afdc9f, 0xebd1ec2c, 0xd8bee125, 0xf0cebabb, 0x1e3a10db, 0x1c319b84, 0x6d1fbf28, 0xbaa2ad61,
0x317e066b, 0x1b9a914e, 0xdc7fdb9c, 0x69ed9fd0, 0xb18fbd8d, 0xd90baa2b, 0xefd57109, 0xe1412d05,
0x787fa7da, 0x59639ccb, 0x168a5db2, 0x3f040d6f, 0xe1bcd212, 0x202464a2, 0x2f6ff24f, 0x5a33834f,
0x031fcfbc, 0x952b074b, 0xe62e1b73, 0x8dd762e5, 0x61b7d8f1, 0x6d7b204e, 0x47732f81, 0xdfc36e49,
0x74ba4dfc, 0xc5cf8c53, 0x21e58d11, 0x97b859e9, 0xacecc695, 0x184d1dd9, 0xd50801ac, 0x45e562ee,
0xabe23d05, 0xd7f6181d, 0x98d6b9e9, 0x946e058b, 0x42d99ce0, 0x1efafea1, 0xf00c3e7f, 0xa63f2f72,
0x6a389e61, 0xa0d656de, 0xe3eabfd6, 0x03aa0b46, 0x1dcbe6cd, 0x9fe27119, 0xcd7d4650, 0x3af31832,
0x3bcdff79, 0x0f2bff62, 0x7863e902, 0x02e6b566, 0x522c00fd, 0x5be5074c, 0x58f67382, 0x6c51ebd3,
0x23cc9c15, 0x78b791dc, 0x87beffd4, 0xf44b6041, 0x16efa048, 0x349a4704, 0x533b86fb, 0x00b7561f,
0xc15722f6, 0x0561a0e5, 0x83239496, 0x66a52382, 0xcb95c02d, 0xbbfa81b9, 0x165d42e3, 0x198787f0,
0x3fadd532, 0xfe42858a, 0xc413712a, 0xaaf4f433, 0x120e7379, 0x7572d842, 0xf34035ff, 0xf6a9c4b0,
0x6620700d, 0x3859c299, 0x96c9171c, 0x965cac65, 0xdeae7b6a, 0xbee66f1b, 0x30d6b419, 0xabe434d5,
0x7cb9723d, 0xebfc8073, 0x58530e57, 0x2399ecf8, 0x836cc018, 0x38726112, 0x9c5de75e, 0x036882a8,
0xce7da949, 0xd4029dbf, 0x28964f84, 0x6d303f6a, 0x1c0ede3a, 0x65657aed, 0x45aec8c1, 0x49afa022,
0x8ce57656, 0x85829fe5, 0x54260fc7, 0xb2c6a3ef, 0xf12b8c3a, 0x70ca41ad, 0x2d6c0de8, 0x722a66ce,
0xf9ba7bfc, 0x47353e37, 0x0ca9f1d4, 0x47962e4e, 0xc88aa0ff, 0x54df7358, 0x2a7f3b33, 0x3dbe83f9,
0x0a815cb0, 0xe326cf40, 0x95fe37c1, 0x42df36e1, 0xcaf16d3b, 0x4f0f288e, 0x177828fd, 0xd2376c8f,
0x8d8cba42, 0x35ad8b61, 0xf0dfbae2, 0x4f62a656, 0x9276aaca, 0xdbc8aa00, 0xf4b3afd1, 0x621dd3d8,
0x61a50e23, 0x7b9585c6, 0xe5254325, 0xde4ee123, 0x3b40357c, 0x6096c76c, 0x47a5fd8f, 0xcc1a8ad0,
0x00f4bada, 0x0bdb687d, 0x97b11512, 0x1cb1fb02, 0x502db559, 0x13bf25ee, 0xa09a7932, 0x5ba68e32,
0x055a4a59, 0x743775c7, 0x4f43768e, 0x60e8468b, 0x31870f5e, 0xf383644f, 0xbab68cc3, 0x9032de1c,
0x3c82ca9c, 0xfb8d5f52, 0x245f6792, 0xa680f1c3, 0xd8281103, 0xdef98d83, 0x4487a49c, 0xcdd3d2b5,
0x20e94e63, 0x358d5acf, 0xf2855933, 0x57b49142, 0xc8b04afe, 0x7d1ac0e2, 0x6bd15851, 0x50f9f271,
0x36d71327, 0xfa107867, 0x589ac42f, 0x03153a42, 0x74a801e3, 0x6e751ef3, 0x9f43b5aa, 0x08cf1684,
0x77368310, 0xecc26d04, 0x68a8a310, 0xb945f67a, 0x7da6dd93, 0xaf1fc83c, 0xdd77a83b, 0x94b0c96a,
0xda610abd, 0xd7ae9f26, 0x0dfd49c3, 0x9fc89f33, 0x866ebcb1, 0xe00528f1, 0x0623009e, 0xac3a5738,
0x29375795, 0xff4a9d67, 0xe2e974ba, 0x62761be0, 0xf86eaaf3, 0xfeab9672, 0xb98b16c4, 0x831a978a,
0x7072fe18, 0x3da79d4a, 0xb667e350, 0xb3b7a37b, 0xf9b79e98, 0x122e1fe5, 0xcf801e18, 0xa59ae89e,
0xbf56255d, 0x81fd63d6, 0xc3faed9c, 0x03d39303, 0x9626749e, 0x0ab94c32, 0xe2459c31, 0xa47e6d4e,
0x6930c3f1, 0x577cd80c, 0xe888e78a, 0x14fd1522, 0x00fcac74, 0xed2131f4, 0x0f84a6d9, 0x37b3d4cb,
0x1db3542a, 0x8b5cb8f1, 0x1ce32835, 0xb13e141c, 0x24178f13, 0xbe806c09, 0xbbd274fa, 0x9d0ee159,
0x439bf08e, 0xb5251554, 0xf1b91fdf, 0x43b8bf5f, 0x1e11c46b, 0xff136358, 0x344c5e19, 0xe7be64aa,
0x6ae4de37, 0xa154f23b, 0xfba97273, 0x6a222d94, 0xff57d6eb, 0x8aba76f5, 0x3426d68a, 0x74d5e508,
0x3e5e0d1d, 0xb4619da3, 0x20031bf0, 0x4a750a4a, 0x8f1d33fb, 0xda3e8f4a, 0x9cb2055a, 0x7d885bc8,
0x93088d36, 0x5311833e, 0xdcdcf9f5, 0x7648b6f5, 0xcd672966, 0x0354e72d, 0x0a4717ec, 0x73e1cc95,
0x9efea9c4, 0x7b75b0d0, 0x5b4efba4, 0x793cc5c6, 0x0aae6678, 0xa9750495, 0xcf6f40dd, 0x44af12e4,
0x71225f91, 0x337bb6b5, 0xd0e644b1, 0xdee2ec19, 0xecbff905, 0x15f4b15a, 0x7d299430, 0xa7513d43,
0x50fa7790, 0xd08704f4, 0x187af7cd, 0xf73f15f4, 0xd26c5373, 0x27b932cd, 0xfdb5c2ba, 0xffa6c6f4,
0xce350060, 0xd04aa41b, 0xb3943b47, 0x1d5cbda7, 0x784d036c, 0xfc94883b, 0xba962841, 0xa993902a,
0x241f73ab, 0x5abbb7d1, 0x9646f6e6, 0xf2569058, 0x0e671a76, 0x1f956cb7, 0x0283deed, 0xb6531f3f,
0x5584581c, 0x68d73bdd, 0x198988a8, 0xaa19796b, 0x99d44be7, 0x8f644bd9, 0x079ffe14, 0x50dd5b90,
0xf595d37b, 0x44eedab3, 0x5ffb2655, 0x659835f0, 0x02fdb15b, 0x0b5d8706, 0x8f65152b, 0x7b20c48a,
0x901c8332, 0xdc1f8b99, 0x59e05ddb, 0xcda35c11, 0x6971b221, 0x07ff1417, 0x5044c66f, 0x0817cf08,
0x8d7a80c2, 0x1403d495, 0x54aa091f, 0x5a2d6845, 0x7c8d4b46, 0x4041a26c, 0x001bc795, 0x546fbf53,
0x7cb3d93f, 0x7ba8f713, 0x52670e61, 0x245984c5, 0xd7a615f7, 0x6658f129, 0xf4a53c5f, 0xffdc489c,
0x866aa730, 0x5a89c5af, 0xf353b9ab, 0x23ac597d, 0xc5aede41, 0xce53ad24, 0xcf6217e0, 0x8c0ce45e,
0xf2acf883, 0x390893c0, 0xf62a2f43, 0xf0260878, 0x5fd07e4b, 0xf55eb430, 0x93256130, 0x8e2f95e1,
0xb9d3e893, 0xa2a90b12, 0x3861aec8, 0xf52cc495, 0xc2d5b4bd, 0xdd80647f, 0xa543f4b2, 0x4f93a6d8,
0x429e6b8f, 0xf48b2e7d, 0xc8a0aa43, 0x08a6bf7c, 0xde8b168c, 0x7043b53a, 0x58564c18, 0x0da75752,
0x97534b9f, 0xa2933018, 0xc7320482, 0x570d2e27, 0xa40f4d10, 0xa80a6d0a, 0x3bebe91a, 0x0abfdd73,
0x08c7376e, 0xcfd0e97b, 0xff6df31c, 0xbfa9a06b, 0xc752becc, 0x174c1e4a, 0xff0700b0, 0xbeac59b9,
0x687fd48f, 0xe07564bb, 0xaf35b6ad, 0x3a18b954, 0x7abc6a11, 0xb4706bad, 0xff65e660, 0x30e26547,
0xeddb4f99, 0x479fa542, 0xa7a5ff90, 0xa0ee739a, 0x7ae58cbe, 0x46ffd2ef, 0xb99a5855, 0x30ee7493,
0x1bb9b73a, 0xd29a76f8, 0x02474c06, 0x7b9d3bf6, 0x1a3e58ed, 0x1f403403, 0xc2b3d878, 0x536a092a,
0xcda35b5f, 0x3597b8e6, 0xe67b3748, 0x734cb7b3, 0x36468f79, 0xc7046a7c, 0xd2c933c4, 0x35ef9cba,
0x5e5ca563, 0xcf44d58b, 0xac27007e, 0xb46ccacf, 0x96f73013, 0xfd22289b, 0xd8374b97, 0x1a5f5ace,
0xad020e0b, 0x71e852d2, 0xe193bc88, 0x11d938d7, 0x246f4a91, 0x1f8d50b5, 0xafb31f7a, 0x456003b3,
0x04e88a1c, 0x6520e269, 0xefa8da6d, 0xe6f60bb8, 0x9314fbd5, 0xa4a3743c, 0x132c4026, 0x17b229db,
0xcd2edcd5, 0xe3afe0d6, 0x68205816, 0xda969f35, 0xe3e289ae, 0xee85a80a, 0xbe2a10b2, 0x9a6ab2fc,
0x20555ddf, 0x94d8034f, 0xb16cadf7, 0x85153d6f, 0x9b378ad5, 0x385db55c, 0x8be8dde8, 0xbf914839,
0xa12c720d, 0x660f4f24, 0x43217ce0, 0xa04ace80, 0x26691a51, 0xd5233a2b, 0x775f915a, 0xf2e4e26a,
0xf31aca5b, 0x280d79d1, 0xc203f9b9, 0x8f22eabb, 0x99b4141f, 0x7529bef1, 0x1dbf0eb8, 0x7682baf8,
0xfd738a15, 0x25e408f7, 0x2439adf5, 0x0e59e24b, 0xccfef2be, 0xc67f0105, 0x6c951fd4, 0x7bc2ba52,
0xfb0fb0f9, 0xcf4cb388, 0xd2b170f4, 0x66236143, 0x8807ec4e, 0x138055ea, 0x63894a31, 0x977972e6,
0xd711fde3, 0xc2762c39, 0x1808a921, 0xca0083b7, 0x9a77bef6, 0x3205639d, 0x416dda9b, 0xf51950b2,
0x368a216b, 0x7744e490, 0x50733d71, 0x3e55fa09, 0x2fbad000, 0xa0ccea2d, 0xe7863c95, 0xb3d5c2c5,
0xbbad3a78, 0x87c6d7eb, 0xb7525d7f, 0x0c0f67a6, 0x9075446f, 0x3ad20758, 0xeb4facb7, 0x1a5e46ba,
0xb634acf4, 0x908c5863, 0x35a56967, 0x174515c6, 0x7f863d00, 0xd417a6b0, 0x99fc9dda, 0x540d7ba2,
0xadeb0bb7, 0x2438a967, 0x005fa86a, 0x82fd5afa, 0x0179d942, 0x643115d2, 0xabf01503, 0x79bb3384,
0x627c8cbd, 0x3df35194, 0x9456476a, 0xc0f47cd8, 0xa49c4a9f, 0x38b12a44, 0x79ee8bf6, 0x467a22ad,
0x2a5ca6c6, 0x33641a41, 0xb7ba5007, 0xdb4683a8, 0x40d763dd, 0x39daead1, 0x638bd55e, 0xd9142bcb,
0x3638a1de, 0xddba18bc, 0x775497c0, 0xe9ede9a0, 0x46e17d71, 0x02000d36, 0x18afa1dd, 0x6e23a0d1,
0xdefb309d, 0x390e6de1, 0x4667c167, 0x17ec888c, 0x2cdec071, 0x41cabc12, 0x6a534adf, 0x26f923f8,
0xe68bba11, 0x141b5b4d, 0x38b624af, 0xc6a40e89, 0x33df0097, 0x124efa19, 0x45291378, 0xe0ba3110,
0x28f44e66, 0xc01fcf9a, 0x65bcbae0, 0xd4e138c1, 0x10c0706c, 0x5718375d, 0x8aa461c6, 0x8a6ce40a,
0x22ad4846, 0xa5d72622, 0xc6170ad5, 0x6547bcad, 0x4e5cb097, 0x15bba0d5, 0x99a317fa, 0x4c0698be,
0x8cee8b39, 0xe7f3028d, 0x1796cf4e, 0x05fe33b9, 0xd0f1a5f6, 0x4cdc944c, 0xefd59500, 0xd2378a9e,
0x42c21c4c, 0x938466af, 0xbf93efc4, 0xd8e03f96, 0xca516688, 0xdb0a6a55, 0xf52b6986, 0x08674061,
0x98b7a1d4, 0xc40784db, 0x9f16cacb, 0xc314da32, 0x200f3bb6, 0x55565817, 0xcd5dcad8, 0xffb329d7,
0x267db957, 0x220b229a, 0x7e9f5927, 0x7e84f39d, 0xcdba1f91, 0x07d81eda, 0x1d658908, 0x4ff56f41,
0x97f2b729, 0xb9c87530, 0x50da78cf, 0xedfdddc4, 0x9dadd894, 0xa53312c3, 0xcc2435d7, 0xdae770a0,
0x51a06107, 0xf07208db, 0x836080c7, 0xc62d02ac, 0xebad869f, 0xe9c6ba8c, 0xb4c5b805, 0x307825b9,
0x6df62278, 0x58623c82, 0x03c0833b, 0xa591a31a, 0xd2bcf861, 0xb31bbedd, 0xdaa5d2d2, 0x83e9cc27,
0x912f7c25, 0x2b4d3286, 0xcb196bec, 0x2d6cd753, 0x29eec655, 0x95e9255d, 0x7c66a8fb, 0x5e772ab6,
0x3c4de6e5, 0x3f660623, 0xe61785e7, 0x373932c8, 0x753ea99c, 0x8b4389a1, 0x45345607, 0xb814c688,
0x9927fa71, 0xe9990bd6, 0xc32fc44f, 0xeb1903c9, 0x88a249ad, 0x0e28e4b3, 0x200e8363, 0xf6dde270,
0xb2c59db1, 0x54f83fff, 0x8b44dad9, 0x2ea2f91a, 0x9413776e, 0x0c10f976, 0xccbd6680, 0x9a4670bf,
0x04bd6988, 0xe1b98edf, 0x19a721ab, 0x377bf209, 0x0c0bfb3f, 0xc2b37928, 0xa08893d4, 0xc33b3dbd,
0x297d7057, 0x4a464f31, 0xc448ae1b, 0xa92d11a9, 0x02059add, 0xd672662d, 0x309cb4a7, 0x136f9367,
0x4be0ea24, 0xb479b520, 0x65aeb867, 0xfea3d064, 0x999ac287, 0xc9956c3a, 0x3dad2b70, 0xb3fcf60d,
0x3de47646, 0xa26ba456, 0x26e6fac6, 0xd4c25295, 0xc94dc89f, 0x73ffc37f, 0xe2a1ad6c, 0x36397b68,
0xd03a6f20, 0xb741aea2, 0xdbed7ba7, 0x3a3f0ed5, 0x095ab976, 0xea2f7898, 0x7bb3f706, 0xb567e3e1,
0x5660643c, 0x87d682cc, 0x0229acb8, 0x22a05582, 0xd819b664, 0x8d49aabf, 0xb08aab1a, 0xc8f5aded,
0xf167600c, 0x023551ee, 0x7b0080ef, 0x60251db0, 0xfb59e2ff, 0xda209242, 0x4c391940, 0x5828b07d,
0xd0c024c2, 0x3064f276, 0xa80e89ac, 0x9561dc29, 0xc42cd07f, 0x66a801c7, 0x80e68b66, 0x740ea78e,
0x854f7723, 0xfbb353db, 0x62dda745, 0x5dcd69da, 0xb0e6b221, 0xdd8b9625, 0x730934e8, 0xda0878b9,
0xe6a46c2a, 0x09392564, 0x656f8e64, 0xc4aba2a4, 0xf6d40c8d, 0xc3aa5925, 0x2a776965, 0x2f73628b,
0x9edc2d84, 0x42daea29, 0x3c38f1ed, 0x75d7537c, 0x718b5996, 0xb382e614, 0x341293f6, 0xa6abea18,
0x1c8d37b1, 0x4c5507ea, 0x34655a40, 0x53df034e, 0xd5d279a6, 0xb7d5200c, 0xb82cd5eb, 0x2db4df58,
0xd79106ee, 0x01968417, 0x22ddaf3d, 0xb807952a, 0x2bf3c5ad, 0x163698b5, 0x707ff7d4, 0xb8e3738d,
0x1baeb275, 0x813c48b5, 0xee8ddca5, 0x571c35bd, 0x023b050b, 0x5cc0d792, 0x9748f20b, 0xf0b064b5,
0x980a6f08, 0x7f889654, 0x9468531f, 0x0a2a92a7, 0xefde53a4, 0xc75784a8, 0xad11046e, 0x8daddc92,
0x30852c2d, 0x9cc94f74, 0x418cc095, 0xf48dc2ee, 0xd134f3d2, 0xfea624a6, 0x5a2b8f09, 0xe3751aac,
0xbc20da6a, 0x33a5ce00, 0x7607d1e2, 0x576be69f, 0xaadb07a5, 0x2bf7f96c, 0x49c3b304, 0xcbe8a563,
0xe6eed45a, 0xad73664b, 0x98b7a678, 0x3f4e41e6, 0x193d394f, 0x207f26d4, 0xb20f5920, 0x9eeadaaf,
0x3ad3f8c5, 0x01a13b8b, 0x4481f4c2, 0x415497ba, 0xea96c286, 0xb63bc6eb, 0x8032ae08, 0x093e3184,
0x5dc66779, 0x6b992fd6, 0xce9e5037, 0xbdb78f58, 0x41e92a8f, 0xfdae4873, 0x7a7129c1, 0x6fc8f931,
0x7ce27673, 0x484ae2dc, 0xde0b9a7c, 0x645b1db2, 0xef195a94, 0x9b6895b8, 0x7dfee290, 0x8a28f57b,
0xfc9c5412, 0x6d036b75, 0xde9de836, 0xfa492eaa, 0x9cde6306, 0x03bb0532, 0x12106395, 0x7896fb77,
0x25537502, 0xa2c9d478, 0x762108aa, 0xa6782a21, 0x7397d8a6, 0x2a6bd4fa, 0x3c6a3d0b, 0x8e6150b7,
0xde5ef639, 0x79d1a7d9, 0x3d9819f0, 0x0619c03b, 0x5fc6b565, 0x648ccd33, 0x3ef309f9, 0x5bb4392f,
0x3d1dfba7, 0x71162e9a, 0xd53e8781, 0xc50044fb, 0xe873a1f4, 0xb0858c4b, 0xeef9db9a, 0x0163c36d,
0x6f250daf, 0xc1cb4111, 0x7738a7db, 0xd9d20f06, 0x757acb65, 0x8c9f109e, 0x8de4e70e, 0x37101a96,
0x59fcad8b, 0x9fb163f1, 0xf2223f1a, 0x48213643, 0x7bc8fb93, 0xebda1191, 0x49285414, 0x6621874b,
0x95a3028a, 0x94360053, 0x61569c95, 0xab489c89, 0x2c39a5cc, 0x2b109ade, 0xce6ae59e, 0xa7bf17a4,
0xfe2735e3, 0x0160c575, 0x8c4717d1, 0xf4e8c9a2, 0x05b3017a, 0x023851b4, 0x65434362, 0x8818cf83,
0x3983869d, 0xc67ef8e4, 0xe7bc2c4a, 0x76b74ce6, 0x23517d64, 0xea2fbb96, 0x3b4b094f, 0x4b7c92c4,
0x5efb151c, 0x0eaad0be, 0x82d2e54b, 0xf7f3175e, 0x7fb23e6a, 0xa2131c0b, 0xa8c0a612, 0x98e2b482,
0x5f60ce35, 0x90dbfd93, 0x428dd144, 0x8c42b364, 0x2cb80a7c, 0xef306a21, 0x32aaa4a1, 0x3f779864,
0x818faace, 0xaa4c64dc, 0x73faa6da, 0x70e4aa2a, 0x60597b4c, 0xdca739be, 0x398c0a31, 0x4f2b6682,
0x4ba590d1, 0xec4ee9b6, 0xb6c395c4, 0xa78b2892, 0x3467907e, 0x1f7f05e7, 0x7063b941, 0x93afc5ca,
0x0b53a797, 0x69df0f8a, 0xd5c03b8b, 0xbf80071b, 0x5854eaa4, 0x07025cf6, 0x5a6fbd41, 0x10cbfdba,
0xf451d0ac, 0x4b15d5a0, 0xed6c9fe3, 0x2b814c0c, 0x660dbb4d, 0xd34b4b7e, 0x904e90ef, 0xf33fa031,
0xedd50356, 0xc3251157, 0xca65e921, 0xabd3dda5, 0xd107ee66, 0x77382a98, 0xf1e972e5, 0x0f63283f,
0xef65c20f, 0xa22c4c5c, 0x2a44baf7, 0x8a3dc37a, 0xc5b79304, 0xc692775e, 0xa816c745, 0xe5792228,
0x454cdcf4, 0x55489a7a, 0xcea78207, 0x1ac739df, 0x140b1d90, 0xeafc331e, 0xe7ec19ea, 0x68579c45,
0x01f892cb, 0xa1bcf7c1, 0xd9b61dda, 0xffafd217, 0x8bfd6096, 0x4f1d69a1, 0xd689664f, 0x9e49793b,
0x2cb44ab6, 0x7bc6443d, 0xa860ba8f, 0x927bc6af, 0x98a1aaf2, 0x8204401a, 0x67c6dbd4, 0x341a3915,
0x95afde1a, 0xf23c45e9, 0xfc29fdcf, 0x32da17d0, 0x8f346b20, 0xc2f36c3e, 0x8a034280, 0x9ff9de19,
0xbb7c5b99, 0x4282619d, 0xf05bee16, 0x5a4cd051, 0x8c7877ec, 0x0ecb339b, 0x41689d73, 0x3f55fd38,
0x4454b7c0, 0x29e57fb2, 0xf44fd75d, 0x89d9929c, 0xa5d31d5e, 0x5398b048, 0x2bfe0289, 0x00998987,
0xd46d144c, 0xb917a6d7, 0xb895d528, 0xed988a4e, 0xb7afefdd, 0x4dee4c69, 0x560ccc74, 0xd108d43e,
0xae0e6fb9, 0x6a4a9061, 0x9890c060, 0x0ef51d7f, 0x260e48ea, 0x6c9a289d, 0x7849a74e, 0x6d8c0c61,
0xb52fc228, 0x7b4c9db5, 0xbc925ed5, 0x3c15b90e, 0xdec489dd, 0x63e60772, 0x8ddd1ac6, 0x96e76632,
0x38e65d44, 0x08996b89, 0x1b450dae, 0x216f2df8, 0x31aa10a2, 0x4cbb4124, 0x27fb8ab5, 0xae7a0106,
0xca925ede, 0x9017819f, 0xaa030a09, 0x13580386, 0x65233376, 0xcd137d6c, 0xdd2fd42f, 0xe7d81d19,
0xe9747bcd, 0x1d7829a1, 0xb1f9f4ec, 0xb0a44cbc, 0x4a86a9ac, 0x2fb9b0fc, 0xa865eb0b, 0x97f2f202,
0x510457dc, 0x9c04cf59, 0x3c8f43b5, 0xbc5978c2, 0x9243853a, 0x16a79f01, 0x1c42b7ba, 0x8b6a55d4,
0xfac9d6e5, 0x230714f8, 0x68e7e4f0, 0x87b35e29, 0x51899c06, 0xf5297317, 0x9102eaef, 0xd9ac5d50,
0x5d5f45e4, 0xdbd8e13f, 0xba167f6f, 0x4269e679, 0x1c0d86ae, 0xa7f88ad4, 0x9fcb6d58, 0x5ff50b14,
0x6f9d6f4a, 0x393c4e1e, 0xd9e4258b, 0xe7196b8e, 0xeeed71c4, 0xb6db404e, 0x431aacc7, 0x38204d64,
0x7fb6c142, 0x964580c8, 0x06ac166b, 0x11525d6c, 0x8e7afc49, 0x3b72cccf, 0x750dc09b, 0x0f656b18,
0x1a6ca55d, 0xc59bea8b, 0x6e1b34df, 0xceb07a52, 0x7ae492fb, 0x56432898, 0xeb9cb88f, 0xcbb3f209,
0x0e8c5721, 0xae24861a, 0xd225b885, 0xfaee35ea, 0x48908007, 0xe7441205, 0x7e2f8614, 0x0722bcab,
0xd380c315, 0x9a2e3a8e, 0x15e2d981, 0x7df6a77e, 0xb87d864c, 0x2f0f24ec, 0x24e9a7be, 0xf14ee690,
0x731655aa, 0x90b79802, 0x0b827087, 0x3a05efb6, 0xaaa9c34b, 0xe3b8e168, 0x15b8ba0c, 0x52781e24,
0x49c69cde, 0xc159a8ef, 0x90880b6c, 0xd3c5e9c3, 0x7f801f94, 0xabc7e98c, 0xc4063b5c, 0x1da73a1c,
0xaa1aa595, 0x50777770, 0xb3536d3f, 0x853c25d2, 0x4314a071, 0x364936a7, 0x0d495d15, 0x13688144,
0x35bfb42d, 0x8ad30fa6, 0x0a7dc879, 0xbe956435, 0x7499caec, 0xedcc27d9, 0x312291ba, 0x6d358681,
0xf7bd09c7, 0x52c5cc59, 0xf0c2b520, 0xca9136cc, 0xff0504de, 0x0e0e5969, 0x9d84491e, 0x7fd46203,
0x7e50f755, 0x29fd1c8e, 0xa80c9ef6, 0xafc8a98f, 0xc76c02c6, 0xe2c25665, 0x36a1a53c, 0x29e749f8,
0xf1297e2a, 0x4469abac, 0x3d9a4fe5, 0x19a431c8, 0xdbd4b37c, 0x092fea0a, 0xb06f9333, 0xf3b07ef9,
0x4638f5fc, 0x61fe4c3c, 0xc1f6f1dd, 0x37254b73, 0xf9953e18, 0x47df1505, 0x532c74f8, 0xc711c197,
0x96488578, 0xa46aabd1, 0x0d797f38, 0x9fe94ac1, 0x8fa81f8c, 0x47dd5b29, 0xc812103f, 0xb80eb034,
0x469a9151, 0xf3e9eb69, 0x311863a1, 0xc4a2defc, 0xb7f16fca, 0x0d9ed944, 0x2d01ce93, 0xace35079,
0x99d68545, 0xbd569429, 0xdd7b1489, 0x36c7eabe, 0xa30ea606, 0x4dfc7e3d, 0xf683ee84, 0xaa4f7938,
0x08a1bf82, 0x5a749c6f, 0xd3d92aff, 0xe50aaea7, 0xcd5a128a, 0x6959cfe6, 0x6ee073f7, 0xd30eb46d,
0x33e89d4b, 0x5fae4e6e, 0x1a92475e, 0x639f1ec2, 0x92af5dc5, 0x602c4326, 0x630d0385, 0x0cfa82d4,
0x5b116c5e, 0x23bf6eb9, 0x4730ac1f, 0xe8d24fab, 0xc8182b7c, 0x1b966bb4, 0x36b8c259, 0xf2bb8fae,
0x8c4aa6d6, 0xab2898d2, 0x919b97a3, 0x54f87ad5, 0x5bfa3fc8, 0xabd178d5, 0xc18e2b15, 0x341da612,
0xcaf65e21, 0xb7e603b3, 0x8ceaf425, 0xd78d63e1, 0x3718c1f0, 0x76ca1592, 0xac25c4d9, 0xa6222c2a,
0x24b247d3, 0x3f58f379, 0xb837815d, 0xe745d4b2, 0x92950e80, 0x86ca4eb9, 0x3cbeed18, 0xecfe82a6,
0xc3f83512, 0xc513b35f, 0xd0f4faef, 0x885d2853, 0x81f64a13, 0x1b5819ca, 0xf01195ef, 0x712de6de,
0xeee45337, 0xd15f243f, 0x462d62a6, 0xbef8d660, 0xc2f5defe, 0x0d75e6b9, 0x14138636, 0x0964b4aa,
0x5cc1168c, 0xa91e27cc, 0x4a99bff2, 0x969690fd, 0xd3fbae0a, 0x4b8b8622, 0x8e7c3f0c, 0x6a29f452,
0x63d9af77, 0xb2a0da57, 0x17cecfe2, 0x6a23ab53, 0x1cf16062, 0xc11437cb, 0x7a90afcd, 0x2d7d6885,
0xa342a3f9, 0xfb721c8a, 0x1cef3b85, 0x31fa22fb, 0x9ca03b8f, 0xb4cd091e, 0x41bfa6e4, 0xc50654ce,
0xe989c72e, 0x70ed1bd5, 0x65dcf8b9, 0xf975e03b, 0x83846c7f, 0x2d64df9a, 0xe0fa64c4, 0x55a59e2e,
0x7c1cd805, 0xe4106601, 0xe4cfe66f, 0xdb619a90, 0xe1e82c36, 0x15e3a81d, 0xaf5e65c4, 0x62478a5f,
0x54ba0f13, 0x280bf828, 0x08146c9f, 0x9061eb0c, 0xb7d087da, 0xca8ec7f9, 0xfffbba00, 0x2c66fa2d,
0x147091bb, 0xe5c88f41, 0x73688700, 0x563de9df, 0x060ecf84, 0xd81fb126, 0x5fcc8492, 0xeaf5bec2,
0xe3b87141, 0x913bf72d, 0xee26dc27, 0x9892661f, 0xc692d608, 0xe568e72f, 0xa4064e6d, 0xb8fd8521,
0xc820a681, 0xed760e59, 0x537e643c, 0x2f1e8b6e, 0xc22fb22b, 0x3ee79150, 0xe4569d0f, 0x88e0f198,
0x536cf47a, 0xf785c490, 0x37a436d6, 0x83523a0f, 0xafee1a98, 0x0751cc3d, 0x873b17bc, 0x30d66204,
0x52c364d1, 0x06c799a4, 0xa39faa81, 0x382372b4, 0x8f0e0840, 0xd83be9c6, 0xe22f8b3e, 0xc0bcbabd,
0x092e749c, 0x99d5ee44, 0x1f8ff9c7, 0xa10be901, 0x996c8f44, 0x73403fee, 0x75577ddd, 0x67d738b8,
0x4a2de995, 0x41bd8f63, 0xde90ec81, 0xda792b54, 0xde07bb2f, 0xadd68686, 0xc67e72f0, 0x90a6bb5f,
0x256f5cf0, 0x7a4f610a, 0xc1daa775, 0xa4361d79, 0x255a0e15, 0x600b72df, 0xbdcb5dcd, 0x33268e04,
0xe56abceb, 0x09dbd8d5, 0x203c46e5, 0xf3544ba7, 0x4c2a17d3, 0xc9d82142, 0xb487156b, 0x657849fc,
0x4547daf3, 0x8ba9d2cb, 0x2a4da80b, 0x6092df55, 0x2c907811, 0xb42e20d1, 0x54895d7a, 0xb3969880,
0x8deeaa17, 0x62ed8dcd, 0x55cfaf0f, 0x19a37877, 0xa3b4f04a, 0x61abccf4, 0xef57e114, 0xddf89a01,
0x50602500, 0x5e41da45, 0xdf12dc8c, 0x2c92b674, 0x77441a7a, 0x04686a60, 0x0967ed47, 0x5eb735a8,
0x273279ee, 0xa8e1a708, 0x33586d0f, 0x9c9d979c, 0x54ead8d8, 0x5b5fb4d0, 0x22c6d245, 0xc62cd238,
0x25a3f73c, 0x1cfd7438, 0x5efe3268, 0xacd9b70c, 0xea5db41b, 0x1fb68916, 0x53653dfe, 0x409a5e0d,
0x8a38bad6, 0x025432a8, 0x39bea800, 0xdf61f30c, 0xd397f214, 0xe956b4ff, 0x84684518, 0xb6f8de1f,
0x9367ea6a, 0x4245736e, 0xc9062113, 0x18ba22aa, 0x90cc43df, 0xf625f69b, 0xe66f956d, 0x66afc7fa,
0xad107a2b, 0x0d7d7eca, 0xa014d204, 0x3778955b, 0x6375fa1d, 0x4260030c, 0xdfb0c8c9, 0x99336916,
0xcf4784cf, 0xaea80610, 0xdee57929, 0x85c8d1ec, 0xf6cfb398, 0xf46e825f, 0x96233ac4, 0x5a7407d3,
0x5e904638, 0x3d0c5492, 0xc47c1195, 0x5c36c467, 0x2585f750, 0x92e6c095, 0x8595fb25, 0xfa440a87,
0x40aca851, 0xd6682543, 0xab837530, 0x925c06fa, 0x8cc94555, 0xd6e9c8c3, 0xad34d9ad, 0x9e3307d0,
0x9b03d8fb, 0x1623c9c7, 0x0a9869a2, 0x917950bf, 0x5acee365, 0xf931d78f, 0x2a05d5ac, 0xd7bdcdaa,
0x02da1d57, 0xa7433e6f, 0xecb87ba4, 0xfc7e472c, 0xc9b037a7, 0x3e55a0ab, 0x63452fc6, 0x35f268e9,
0x038fb8c6, 0xad39d13e, 0xdd86bcce, 0xa5221321, 0x6f5625c6, 0xfd8fa734, 0x607a7198, 0xb3a612bc,
0x72d374c4, 0xeea8a6a2, 0x7182d16e, 0xd4c2f825, 0x8f464fb5, 0x3e3cfcae, 0x95fed6de, 0x54388289,
0x311fa65e, 0xeb32e476, 0x70ba57e9, 0xa680af8d, 0x8ee3bc76, 0x63937a78, 0x44f9e702, 0x260c543e,
0x05025436, 0x66aaa09f, 0x31a8c7a3, 0xd07221ce, 0x2fb029bf, 0x7ab1ea02, 0xa4c8f135, 0x7ec9d92b,
0x85f0df32, 0x56a1045c, 0x4ac35e5d, 0xec65688b, 0xf77bf1eb, 0x4b7f32df, 0xa74f7e01, 0x5176b859,
0xb5bc91f6, 0x3d855b7c, 0x9a653ee5, 0xfbaae146, 0xfcfd774b, 0x50db5778, 0xf93d2dc6, 0x4c9d9cd9,
0xe37ea181, 0x157c3440, 0x7b7daec7, 0xc0efe691, 0xfca326e4, 0x082547b4, 0x3a15509b, 0x1fe04ce4,
0x5a663583, 0x2bbffa0a, 0xc15a7130, 0x35d23de0, 0xd0a3a653, 0x3ca723bd, 0x65fa5082, 0xfaaa8a0c,
0x85c46170, 0x0ead4b45, 0xcc9fabf6, 0x955d5639, 0x907a66fd, 0x64d698e8, 0x263992c4, 0x74324382,
0xeeda21cf, 0x3c0cb894, 0xfe5b7887, 0x9e717c6a, 0x2031935f, 0x40a652cd, 0x26b98c09, 0xedeb5633,
0xc8ce1b07, 0x4aca2062, 0x1e45534b, 0x63eea923, 0x185517a8, 0x8223098a, 0x950ff2fa, 0x2102a115,
0x50239569, 0x1d53db9e, 0xaa503faf, 0x9e1f8df0, 0x922fec7a, 0x5ca619fe, 0x53963f96, 0x6bc46df4,
0xfff37193, 0xd3832aaa, 0x9a61c34f, 0x26335c54, 0x7b98cd53, 0x3dfe8b1a, 0xc874776e, 0x421653b0,
0x31c27308, 0xce7dcb31, 0x3d3014f1, 0x83ae9840, 0x0ff41a46, 0xf29857d2, 0x6ed74eea, 0xc1a37d26,
0xc1f0b97a, 0x55fde681, 0xdcc2c6bc, 0xf4df3955, 0xe6e0b290, 0x852fe14a, 0x0d70d247, 0x64f9c7ab,
0xc1f61a5c, 0xa78f3f8a, 0x9b932b07, 0xe09f1837, 0x35038156, 0xfcd88fe6, 0x71139afc, 0x7ecd2f6b,
0x9842716b, 0x2383fb1f, 0x8e57ee9f, 0xcdd21c66, 0xa4bb112d, 0x181ed042, 0x229e0b36, 0xea50de6a,
0xd1c91f2e, 0xd5aebaed, 0xeb56cdce, 0x88295aba, 0xd6284235, 0xee8b49b9, 0xf291a653, 0xeec96e52,
0xc0640ddc, 0x344494bb, 0x27ceaf58, 0xb667c9ce, 0x52d6d025, 0x1e9af30e, 0x0baad63c, 0xe022d6d6,
0x8d9df6ee, 0xf0f7bbc7, 0x737da614, 0x2638ebb6, 0x2e98a490, 0x395233e0, 0x9e896d00, 0xfc58e8fb,
0xadfbc198, 0x3fd444ec, 0x488e1747, 0x7ae53a84, 0xce501a60, 0x00db331f, 0x41201501, 0xdb9036c6,
0x14129c00, 0x33fed87a, 0xeca6c45b, 0x18e3dbc7, 0x0f5516e2, 0x613feeb8, 0x19ecd7cd, 0x7d5ce768,
0xd957a6e0, 0xd5ca7df3, 0x29731c6e, 0xb3ca1658, 0x52a34129, 0x0010c824, 0x31e193ce, 0x51e221b9,
0x755ad012, 0x5c19c7ba, 0xc7eff482, 0xf83e7e2f, 0x351cba69, 0x3aafdd19, 0x7fe9230c, 0xe2ef2057,
0xb79a1b2c, 0x179b3ac3, 0xc8960260, 0x5b042d46, 0xaa7831ab, 0xff5f71b2, 0x1ccd0828, 0x016d91fa,
0x7ca2c01e, 0x9268c541, 0x4d5a23a9, 0xc8825ced, 0xc493fb8d, 0xfd9de9ef, 0x5cd37515, 0x8ef8719a,
0x1cfd2ce6, 0x034b4bd0, 0x7c7d6dbf, 0x4dade7cf, 0xf756d66b, 0xeb09c8f1, 0xdd3dec3b, 0xf0f77453,
0xce2f6db8, 0x503b808b, 0x47f5d0cc, 0x9874ab25, 0x5202906b, 0x5203f404, 0xb06dc274, 0x7a86589b,
0xe0a37226, 0x9beed89a, 0xb3e9be7e, 0xd9e99114, 0xc4493b6a, 0x91a063bd, 0x72fe0dbf, 0x2f683bc5,
0xf2d31649, 0x77b2a0cc, 0x82bbaae8, 0x317b62d3, 0xe6550746, 0xa1eaf358, 0xf85724e1, 0x40f8e355,
0x0fcb960f, 0x99e6dd6d, 0x1cee1cbf, 0x6a20ebdc, 0x6d3e25d4, 0xa0441c54, 0x17871f41, 0xee6d4a31,
0x0caab3bd, 0xa3aa58ca, 0x5388acee, 0x5ff98d8a, 0x10197fbd, 0xa079d2b4, 0x6fab96f5, 0x2a898682,
0xb52e442e, 0xebd5703b, 0x3ff76af1, 0x5f1b5fbe, 0x0ca5fe46, 0x297e6c5c, 0xadb3981f, 0x4e8d07ae,
0x11f9de0b, 0xcfdd0afc, 0x99efd88f, 0x42040ec3, 0x0fe15653, 0x074fd3a8, 0xb9b43eed, 0x1c521e70
};
PRIVATE void ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	cl_uint keys_opencl_divider = 8 * (num_passwords_loaded == 1 ? 2 : 1);
	cl_uint sha256_empy_hash[] = {0x3cc244af, 0x7c9d7e7b, 0x9d2579b4, 0x9daa992a, 0xa98c2030, 0x4418ce34, 0x8511bf70, 0x1c71eb3c};

	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		unsigned char* bin = (unsigned char*)binary_values;

		for (cl_uint i = 0; i < num_passwords_loaded; i++, bin += BINARY_SIZE)
			if (!memcmp(bin, sha256_empy_hash, BINARY_SIZE))
				password_was_found(i, "");

		current_key_lenght = 1;
		report_keys_processed(1);
	}
	// This hack is needed because bug in Nvidia/Intel_CPU OpenCL driver: The compiler do not finish the compilation
	if (current_key_lenght == 1)
	{
		unsigned char key[2];
		key[1] = 0;
		for (cl_uint i = 0; i < num_char_in_charset; i++)
		{
			key[0] = charset[i];
			// Search for a match
			unsigned int A = sha256_one_char[8 * charset[i] + 0];
			unsigned int val = A & size_bit_table;
			if ((bit_table[val >> 5] >> (val & 31)) & 1)
			{
				unsigned int indx = table[A & size_table];
				// Partial match
				while (indx != NO_ELEM)
				{
					unsigned int* bin = ((unsigned int*)binary_values) + indx * 8;

					if (!memcmp(bin,  sha256_one_char + 8 * charset[i], BINARY_SIZE))
						// Total match
						password_was_found(indx, key);

					indx = same_hash_next[indx];
				}
			}
		}

		current_key_lenght = 2;
		report_keys_processed(num_char_in_charset);
	}

	ocl_charset_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_sha256_header, ocl_gen_kernel_with_lenght, sha256_empy_hash, CL_FALSE, keys_opencl_divider);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_sha256(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
{
	char nt_buffer[16][16];
	char buffer_vector_size[16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict table,const __global uint* restrict binary_values,const __global uint* restrict same_hash_next,const __global uint* restrict bit_table");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = num_passwords_loaded > 1 ? 6 : 2;
	}

	// Begin function code
	sprintf(source + strlen(source), "){uint indx;");

	// Convert the key into a nt_buffer
	memset(buffer_vector_size, 1, sizeof(buffer_vector_size));
	ocl_load(source, nt_buffer, buffer_vector_size, lenght, NUM_KEYS_OPENCL, 1);

	sprintf(source + strlen(source), "uint A,B,C,D,E,F,G,H,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");

	ocl_convert_2_big_endian(source, nt_buffer[0], "W0");
	ocl_convert_2_big_endian(source, nt_buffer[1], "W1");
	ocl_convert_2_big_endian(source, nt_buffer[2], "W2");
	ocl_convert_2_big_endian(source, nt_buffer[3], "W3");
	ocl_convert_2_big_endian(source, nt_buffer[4], "W4");
	ocl_convert_2_big_endian(source, nt_buffer[5], "W5");
	ocl_convert_2_big_endian(source, nt_buffer[6], "W6");
	sprintf(source + strlen(source), "W15=0%s;", nt_buffer[7]);

	// Round 1
	sprintf(source + strlen(source),
		"H=0xfc08884dU+W0;D=0x9cbf5a55U+H;"
		"G=R_E(D)+(%uu^(D&%uu))+0x90bb1e3cU+W1;C=0x3c6ef372U+G;G+=R_A(H)+MAJ(H,%uu,%uu);"
		"F=R_E(C)+bs(%uu,D,C)+0x50c6645bU+W2;B=0xbb67ae85U+F;F+=R_A(G)+MAJ(G,H,%uu);"
		"E=R_E(B)+bs(D,C,B)+0x3ac42e24U+W3;A=0x6a09e667U+E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x3956C25BU+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x59F111F1U+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x923F82A4U+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5U;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0xD807AA98U;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0x12835B01U;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x243185BEU;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x550C7DC3U;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x72BE5D74U;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x80DEB1FEU;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x9BDC06A7U;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xC19BF174U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		, 0x9b05688c, 0xca0b3af3, 0x6a09e667, 0xbb67ae85
		, 0x510e527f, 0x6a09e667);

	sprintf(source + strlen(source),
		"W0+=R0(W1);"
		"W1+=R1(W15)+R0(W2);"
		"W2+=R1(W0)+R0(W3);"
		"W3+=R1(W1)+R0(W4);"
		"W4+=R1(W2)+R0(W5);"
		"W5+=R1(W3)+R0(W6);"
		"W6+=R1(W4)+W15;"
		"W7=R1(W5)+W0;"
		"W8=R1(W6)+W1;"
		"W9=R1(W7)+W2;"
		"W10=R1(W8)+W3;"
		"W11=R1(W9)+W4;"
		"W12=R1(W10)+W5;"
		"W13=R1(W11)+W6;"
		"W14=R1(W12)+W7+R0(W15);"
		"W15+=R1(W13)+W8+R0(W0);");

	/* Round 2 */
	sprintf(source + strlen(source),
		"H+=R_E(E)+bs(G,F,E)+0xE49B69C1U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xEFBE4786U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x0FC19DC6U+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x240CA1CCU+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x2DE92C6FU+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x4A7484AAU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x76F988DAU+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0x983E5152U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xA831C66DU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0xB00327C8U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0xBF597FC7U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0xC6E00BF3U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0xD5A79147U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x06CA6351U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x14292967U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x27B70A85U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x2E1B2138U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x4D2C6DFCU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x53380D13U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x650A7354U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x766A0ABBU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x81C2C92EU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x92722C85U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A1U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664BU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A3U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD6990624U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E3585U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0);A+=R_E(F)+bs(H,G,F)+0x106AA070U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
													   													  
	/* Round 4 */									   													  
	sprintf(source + strlen(source),				   													  
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x19A4C116U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x1E376C08U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x2748774CU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x391C0CB3U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4AU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4FU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x682E6FF3U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);"
		"W9+=R1(W7)+W2+R0(W10);"
		"W2=W11+R1(W9)+W4+R0(W12);"
		"W1=W13+R1(W2)+W6+R0(W14);"
		"W0=W15+R1(W1)+W8+R0(W0);A+=W0;");

	// Match
	if (num_passwords_loaded == 1)
	{
		unsigned int* bin = (unsigned int*)binary_values;

			if (found_param_3)
				sprintf(output_3, "output[3u]=%s;", found_param_3);

			sprintf(source + strlen(source),
			"if(A==%uu)"
			"{"
				"A-=W0;"
				"W10+=R1(W8)+W3+R0(W11);"
				"W12+=R1(W10)+W5+R0(W13);"
				"W14+=R1(W12)+W7+R0(W15);"

				"H+=R_E(E)+bs(G,F,E)+0x748F82EEU+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
				"G+=R_E(D)+bs(F,E,D)+0x78A5636FU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
				"F+=R_E(C)+bs(E,D,C)+0x84C87814U+W10;B+=F;F+=MAJ(G,H,A);"
				"E+=R_E(B)+bs(D,C,B)+0x8CC70208U+W2;A+=E;"
				"D+=R_E(A)+bs(C,B,A)+0x90BEFFFAU+W12;H+=D;"
				"C+=R_E(H)+bs(B,A,H)+0xA4506CEBU+W1;G+=C;"
				"B+=bs(A,H,G)+W14;"

				"if(B==%uu&&C==%uu&&D==%uu&&E==%uu&&F==%uu&&G==%uu&&H==%uu)"
				"{"
					"output[0]=1u;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
					"%s"
				"}"
			"}"
			, bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7], output_3);
	}
	else
	{
		if (found_param_3)
			sprintf(output_3, "output[3u*found+3u]=%s;", found_param_3);

		sprintf(source + strlen(source),
			"indx=A&SIZE_BIT_TABLE;"
			"if((bit_table[indx>>5u]>>(indx&31u))&1u)"
			"{"
				"indx=table[A & SIZE_TABLE];"

				"while(indx!=0xffffffff)"
				//"if(indx!=0xffffffff)"
				"{"
					"if(A==binary_values[indx*8u])"
					"{"
						"uint aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"uint ww14=W14+R1(W6)+W7+R0(W15);"
						
						"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"
						
						"hh+=R_E(ee)+bs(gg,ff,ee)+0x748F82EEU+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
						"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]&&"
						   "ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]&&"
						   "hh==binary_values[indx*8u+7u])"
					    "{"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=get_global_id(0);"
							"output[%iu*found+2]=indx;"
							"%s"
						"}", found_multiplier, found_multiplier, output_3);

	strcat(source, "}"
					"indx=same_hash_next[indx];"
				"}"
			"}");
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
#ifdef ANDROID
	ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_sha256_header, ocl_gen_kernel_sha256, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_utf8_le);
#else
	ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_sha256_header, ocl_gen_kernel_sha256, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
#endif
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_sha256_header, ocl_gen_kernel_sha256, kernels2common + PHRASES_INDEX_IN_KERNELS, 64/*consider 32 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_sha256_header, ocl_gen_kernel_sha256, RULE_UTF8_LE_INDEX, 2);
}
#endif

PRIVATE int bench_values[] = { 1, 10, 100, 1000, 10000, 65536, 100000, 1000000 };
Format raw_sha256_format = {
	"Raw-SHA256",
	"Raw SHA-256 format.",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	7,
	bench_values,
	LENGHT(bench_values),
	get_binary,
	is_valid,
	add_hash_from_line,
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
	{{PROTOCOL_CHARSET_OCL, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
#endif
};