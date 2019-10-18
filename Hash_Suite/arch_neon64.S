// This file is part of Hash Suite password cracker,
// Copyright (c) 2019 by Alain Espinosa. See LICENSE.

	.text
	.align	2
	.global	crypt_ntlm_neon_kernel_asm
	.type	crypt_ntlm_neon_kernel_asm, %function
crypt_ntlm_neon_kernel_asm:
  ret
  
/////////////////////////////////////////////////////////////////////////////////////////////////
// MD5
/////////////////////////////////////////////////////////////////////////////////////////////////
	.text
	.align	2
	.global	crypt_md5_neon_kernel_asm
	.type	crypt_md5_neon_kernel_asm, %function
crypt_md5_neon_kernel_asm:
  ret
  
  
	.text
	.align	2
	.global	md5_one_block_neon
	.type	md5_one_block_neon, %function
md5_one_block_neon:
  ret
  
/////////////////////////////////////////////////////////////////////////////////////////////////
// SHA1
/////////////////////////////////////////////////////////////////////////////////////////////////
	.text
	.align	2
	.global	crypt_sha1_neon_kernel_asm
	.type	crypt_sha1_neon_kernel_asm, %function
crypt_sha1_neon_kernel_asm:
  ret

/////////////////////////////////////////////////////////////////////////////////////////////////
// DCC
/////////////////////////////////////////////////////////////////////////////////////////////////
	.text
	.align	2
	.global	dcc_ntlm_part_neon
	.type	dcc_ntlm_part_neon, %function
dcc_ntlm_part_neon:
  ret

#define dcc_salt_part_neon_body(idx) \
.text;\
.align	2;\
.global	dcc_salt_part_neon ## idx;\
.type	dcc_salt_part_neon ## idx, %function;\
dcc_salt_part_neon ## idx:\
  ret

// Funtions by salt_lenght
dcc_salt_part_neon_body(13)
dcc_salt_part_neon_body(12)
dcc_salt_part_neon_body(11)
dcc_salt_part_neon_body(10)
dcc_salt_part_neon_body(9)
dcc_salt_part_neon_body(8)
dcc_salt_part_neon_body(7)
dcc_salt_part_neon_body(6)
dcc_salt_part_neon_body(5)
dcc_salt_part_neon_body(4)

/////////////////////////////////////////////////////////////////////////////////////////////////
// DCC2 format
/////////////////////////////////////////////////////////////////////////////////////////////////

	.text
	.align	2
	.global	sha1_process_sha1_neon
	.type	sha1_process_sha1_neon, %function
sha1_process_sha1_neon:
  ret
  
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SHA256 format
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	.text
	.align	2
	.global	crypt_sha256_neon_kernel_asm
	.type	crypt_sha256_neon_kernel_asm, %function
crypt_sha256_neon_kernel_asm:
  ret
  
/////////////////////////////////////////////////////////////////////////////////////////////////
// SHA512 format
/////////////////////////////////////////////////////////////////////////////////////////////////

	.text
	.align	2
	.global	crypt_sha512_neon_kernel_asm
	.type	crypt_sha512_neon_kernel_asm, %function
crypt_sha512_neon_kernel_asm:
  ret


/////////////////////////////////////////////////////////////////////////////////////////////////
// LM format
/////////////////////////////////////////////////////////////////////////////////////////////////

// Sboxs
	.text
	.align	2
	.global	s1
	.type	s1, %function
s1:
	ret
	
	.text
	.align	2
	.global	s2
	.type	s2, %function
s2:
	ret

	.text
	.align	2
	.global	s3
	.type	s3, %function
s3:
	ret

	.text
	.align	2
	.global	s4
	.type	s4, %function
s4:
	ret

	.text
	.align	2
	.global	s5
	.type	s5, %function
s5:
	ret

	.text
	.align	2
	.global	s6
	.type	s6, %function
s6:
	ret

	.text
	.align	2
	.global	s7
	.type	s7, %function
s7:
	ret

	.text
	.align	2
	.global	s8
	.type	s8, %function
s8:
	ret


	.text
	.align	2
	.global	lm_eval_neon_kernel
	.type	lm_eval_neon_kernel, %function
lm_eval_neon_kernel:
  ret


// Charset
 	.text
	.align	2
	.global	memset_uint_neon
	.type	memset_uint_neon, %function
memset_uint_neon:
	ret
