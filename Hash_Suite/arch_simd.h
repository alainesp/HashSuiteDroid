// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2015 by Alain Espinosa

#include "system.h"

#ifdef HS_X86

// mmintrin.h  : MMX    intrinsics
// xmmintrin.h : SSE    intrinsics
// emmintrin.h : SSE2   intrinsics
// pmmintrin.h : SSE3   intrinsics
// tmmintrin.h : SSSE3  intrinsics
// smmintrin.h : SSE4.1 intrinsics
// nmmintrin.h : SSE4.2 intrinsics

// wmmintrin.h : Intel(R) AES and PCLMULQDQ intrinsics
// ammintrin.h : Definitions for AMD-specific intrinsics

// imminitrin.h : AVX2 intrinsics
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <emmintrin.h>

#define SSE2_WORD	__m128i

#define SSE2_AND(a,b)	_mm_and_si128(a,b)
#define SSE2_OR(a,b)	_mm_or_si128(a,b)
#define SSE2_XOR(a,b)	_mm_xor_si128(a,b)
#define SSE2_NOT(a)		_mm_xor_si128(SSE2_ALL_ONES, a)
#define SSE2_ANDN(a,b)	_mm_andnot_si128(b,a)
#define SSE2_ADD(a,b)	_mm_add_epi32(a,b)

#define SSE2_ALL_ONES			_mm_set1_epi32(0xFFFFFFFFU)
#define SSE2_ZERO				_mm_setzero_si128()
#define SSE2_CONST(u32_const)	_mm_set1_epi32(u32_const)

#define SSE2_SL(elem,shift)		_mm_slli_epi32(elem,shift)
#define SSE2_SR(elem,shift)		_mm_srli_epi32(elem,shift)
#define SSE2_ROTATE(a,rot)		SSE2_OR(SSE2_SL(a, rot), SSE2_SR(a, 32-rot))

#define SSE2_3XOR(a,b,c)		SSE2_XOR(SSE2_XOR(a,b),c)
#define SSE2_4XOR(a,b,c,d)		SSE2_XOR(SSE2_XOR(a,b),SSE2_XOR(c,d))
#define SSE2_3ADD(a,b,c)		SSE2_ADD(SSE2_ADD(a,b),c)
#define SSE2_4ADD(a,b,c,d)		SSE2_ADD(SSE2_ADD(a,b),SSE2_ADD(c,d))
#define SSE2_5ADD(a,b,c,d,e)	SSE2_ADD(SSE2_ADD(SSE2_ADD(a,b),SSE2_ADD(c,d)),e)

// 64bits
#define SSE2_CONST64(u64_const)	_mm_set1_epi64x(u64_const)
#define SSE2_ADD64(a,b)			_mm_add_epi64(a,b)
#define SSE2_3ADD64(a,b,c)		SSE2_ADD64(SSE2_ADD64(a,b),c)
#define SSE2_4ADD64(a,b,c,d)	SSE2_ADD64(SSE2_ADD64(a,b),SSE2_ADD64(c,d))
#define SSE2_5ADD64(a,b,c,d,e)	SSE2_ADD64(SSE2_ADD64(SSE2_ADD64(a,b),SSE2_ADD64(c,d)),e)

#define SSE2_SL64(elem,shift)	_mm_slli_epi64(elem,shift)
#define SSE2_SR64(elem,shift)	_mm_srli_epi64(elem,shift)
#define SSE2_ROTATE64(a,rot)	SSE2_OR(SSE2_SL64(a, rot), SSE2_SR64(a, 64-rot))

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// V128
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define V128_WORD				SSE2_WORD

#define V128_LOAD(ptr)			_mm_load_si128(ptr)
#define V128_STORE(ptr,value)	_mm_store_si128(ptr, value)

#define V128_AND(a,b)			SSE2_AND(a,b)
#define V128_XOR(a,b)			SSE2_XOR(a,b)
#define V128_OR(a,b)			SSE2_OR(a,b)
#define V128_ADD(a,b)			SSE2_ADD(a,b)

#define V128_SL(a,shift)		SSE2_SL(a,shift)
#define V128_SR(a,shift)		SSE2_SR(a,shift)
#define V128_ROTATE(a,rot)		SSE2_ROTATE(a,rot)		

#define V128_CONST(u32_const)	_mm_set1_epi32(u32_const)
#define V128_ALL_ONES			V128_CONST(0xffffffff)
#define V128_ZERO				_mm_setzero_si128()

#define V128_INIT_MASK(mask)	V128_WORD mask = _mm_set_epi32(0, 0, 0, 1)
#define V128_NEXT_MASK(mask)	mask = (i==63) ? _mm_set_epi32(0, 1, 0, 0) : _mm_slli_epi64(mask, 1)

#define CPU_CAP_V128			CPU_CAP_SSE2

// 64bits
#define V128_CONST64(u64_const)	_mm_set1_epi64x(u64_const)
#define V128_ADD64(a,b)			SSE2_ADD64(a,b)			
#define V128_3ADD64(a,b,c)		SSE2_3ADD64(a,b,c)		
#define V128_4ADD64(a,b,c,d)	SSE2_4ADD64(a,b,c,d)	
#define V128_5ADD64(a,b,c,d,e)	SSE2_5ADD64(a,b,c,d,e)	

#define V128_SL64(elem,shift)	SSE2_SL64(elem,shift)	
#define V128_SR64(elem,shift)	SSE2_SR64(elem,shift)	
#define V128_ROTATE64(a,rot)	SSE2_ROTATE64(a,rot)	

#endif

#define V128_BIT_LENGHT	128
#define V128_3XOR(a,b,c)		V128_XOR(V128_XOR(a,b),c)
#define V128_3ADD(a,b,c)		V128_ADD(V128_ADD(a,b),c)
#define V128_4ADD(a,b,c,d)		V128_ADD(V128_ADD(a,b),V128_ADD(c,d))
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
#include <arm_neon.h>

#define V128_WORD uint32x4_t

#define V128_LOAD(ptr)			vld1q_u32(ptr)
#define V128_STORE(ptr,value)	vst1q_u32(ptr, value)

#define V128_AND(a,b)			vandq_u32(a,b)
#define V128_XOR(a,b)			veorq_u32(a,b)
#define V128_OR(a,b)			vorrq_u32(a,b)
#define V128_ADD(a,b)			vaddq_u32(a,b)

#define V128_SL(a,shift)		vshlq_n_u32(a,shift)
#define V128_SR(a,shift)		vshrq_n_u32(a,shift)
#define V128_SL64(a,shift)		vshlq_n_u64(a,shift)
#define V128_SR64(a,shift)		vshrq_n_u64(a,shift)
#define V128_ROTATE(a,rot)		vorrq_u32(vshlq_n_u32(a, rot), vshrq_n_u32(a, 32-rot))

#define V128_CONST(u32_const)	vdupq_n_u32(u32_const)
#define V128_CONST64(u64_const)	vdupq_n_u64(u64_const)

#define V128_ALL_ONES	V128_CONST(0xffffffff)
#define V128_ZERO		V128_CONST(0x0)

#define V128_INIT_MASK(mask)	V128_WORD mask = vdupq_n_u32(0);mask = vsetq_lane_u32(1, mask, 0)
#define V128_NEXT_MASK(mask)	switch (i){\
									case 31:\
										mask = vsetq_lane_u32(0, mask, 0);\
										mask = vsetq_lane_u32(1, mask, 1);\
										break;\
									case 63:\
										mask = vsetq_lane_u32(0, mask, 1);\
										mask = vsetq_lane_u32(1, mask, 2);\
										break;\
									case 95:\
										mask = vsetq_lane_u32(0, mask, 2);\
										mask = vsetq_lane_u32(1, mask, 3);\
										break;\
									default:\
										mask = vaddq_u32(mask, mask);\
										break;\
								}

#define CPU_CAP_V128			CPU_CAP_NEON
#endif