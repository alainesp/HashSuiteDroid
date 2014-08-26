// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa. See LICENSE.

#define ROTATE(reg1,reg2,rot,t1,t2)	\
    vshr.u32 t1  , reg1, #(32-rot);\
	vshr.u32 t2  , reg2, #(32-rot);\
	vshl.u32 reg1, reg1, #(rot);\
	vshl.u32 reg2, reg2, #(rot);\
	vorr.u32 reg1, reg1, t1;\
	vorr.u32 reg2, reg2, t2;

#define LOAD_NT_BUFFER(a1,a2,index)	\
	add nt_buffer, nt_buffer_base, #(4*index*NT_NUM_KEYS);\
	vld1.u32 {t3,t4}, [nt_buffer:128];\
	vadd.u32 a1, a1, t3;\
	vadd.u32 a2, a2, t4;

#define LOAD_NT_BUFFER_0(a1,a2)	\
	vld1.u32 {t3,t4}, [nt_buffer_base:128];\
	vadd.u32 a1, a1, t3;\
	vadd.u32 a2, a2, t4;

#define LOAD_NT_BUFFER_14(a1,a2)	\
	vadd.u32 a1, a1, t5;\
	vadd.u32 a2, a2, t6;

#define LOAD_NT_BUFFER_1(a1,a2)		LOAD_NT_BUFFER(a1,a2,1)
#define LOAD_NT_BUFFER_2(a1,a2)		LOAD_NT_BUFFER(a1,a2,2)
#define LOAD_NT_BUFFER_3(a1,a2)		LOAD_NT_BUFFER(a1,a2,3)
#define LOAD_NT_BUFFER_4(a1,a2)		LOAD_NT_BUFFER(a1,a2,4)
#define LOAD_NT_BUFFER_5(a1,a2)		LOAD_NT_BUFFER(a1,a2,5)
#define LOAD_NT_BUFFER_6(a1,a2)		LOAD_NT_BUFFER(a1,a2,6)
#define LOAD_NT_BUFFER_7(a1,a2)		LOAD_NT_BUFFER(a1,a2,7)
#define LOAD_NT_BUFFER_8(a1,a2)		LOAD_NT_BUFFER(a1,a2,8)
#define LOAD_NT_BUFFER_9(a1,a2)		LOAD_NT_BUFFER(a1,a2,9)
#define LOAD_NT_BUFFER_10(a1,a2)	LOAD_NT_BUFFER(a1,a2,10)
#define LOAD_NT_BUFFER_11(a1,a2)	LOAD_NT_BUFFER(a1,a2,11)
#define LOAD_NT_BUFFER_12(a1,a2)	LOAD_NT_BUFFER(a1,a2,12)
#define LOAD_NT_BUFFER_13(a1,a2)	LOAD_NT_BUFFER(a1,a2,13)
#define LOAD_NT_BUFFER_15(a1,a2)
 
#define STEP1(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,NT_NUM_KEYS)	\
	LOAD_NT_BUFFER_ ## index (a1,a2)\
	vmov.u32 t1, b1;\
	vmov.u32 t2, b2;\
	vbsl t1, c1, d1;\
	vbsl t2, c2, d2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1, a2, rot,t1,t2)


#define STEP2(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,NT_NUM_KEYS,sqrt_2)	\
	LOAD_NT_BUFFER_ ## index (a1,a2)\
	vorr.u32 t1, c1, d1;\
	vorr.u32 t2, c2, d2;\
	vand.u32 t3, c1, d1;\
	vand.u32 t4, c2, d2;\
	vand.u32 t1, t1, b1;\
	vand.u32 t2, t2, b2;\
	vadd.u32 a1, a1, sqrt_2;\
	vadd.u32 a2, a2, sqrt_2;\
	vorr.u32 t1, t1, t3;\
	vorr.u32 t2, t2, t4;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1, a2, rot,t1,t2)

 #define STEP3(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,NT_NUM_KEYS,sqrt_3)	\
	LOAD_NT_BUFFER_ ## index (a1,a2)\
	veor.u32 t1, d1, c1;\
	veor.u32 t2, d2, c2;\
	vadd.u32 a1, a1, sqrt_3;\
	vadd.u32 a2, a2, sqrt_3;\
	veor.u32 t1, t1, b1;\
	veor.u32 t2, t2, b2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1, a2, rot,t1,t2)


#define nt_buffer_base r0
#define table_ptr r1
#define size_bit_table_reg r2
#define nt_buffer r3
#define i r4

#define reg_a1 q0
#define reg_a2 q1
#define reg_b1 q2
#define reg_b2 q3
#define reg_c1 q4
#define reg_c2 q5
#define reg_d1 q6
#define reg_d2 q7

#define t1 q8
#define t1_0 d16[0]
#define t1_1 d16[1]
#define t1_2 d17[0]
#define t1_3 d17[1]

#define t2 q9
#define t2_0 d18[0]
#define t2_1 d18[1]
#define t2_2 d19[0]
#define t2_3 d19[1]

#define t3 q10
#define t4 q11
#define sqrt_2 q12
#define sqrt_3 q13

#define t5 q14
#define t5_0 d28[0]
#define t5_1 d28[1]
#define t5_2 d29[0]
#define t5_3 d29[1]

#define t6 q15
#define t6_0 d30[0]
#define t6_1 d30[1]
#define t6_2 d31[0]
#define t6_3 d31[1]

#define NT_NUM_KEYS 128

// Store a 32-bit constant into a register.
// eg: SET_REG r1, 0x11223344
// Recommended for ARMv6+ because the number is stored inside the instruction
//.macro SET_REG reg,val
//	movw	\reg, #:lower16:\val
//	movt	\reg, #:upper16:\val
//.endm

#define SET_REG(reg,val)	\
	movw	reg, #(val & 0xffff);\
	movt	reg, #(val >> 16)

 
	.text
	.align	2
	.global	crypt_ntlm_neon_kernel_asm
	.type	crypt_ntlm_neon_kernel_asm, %function
crypt_ntlm_neon_kernel_asm:
  vpush {q4,q5,q6,q7}
  push	{r4,r5,r6,r7}
  push	{r8,r9,r10,r11}

  SET_REG(r7,0x5a827999)
  SET_REG(r8,0x6ed9eba1)
  vdup.u32 sqrt_2, r7
  vdup.u32 sqrt_3, r8
  
  SET_REG(r5,0x98badcfe)
  SET_REG(r6,0x10325476)
  SET_REG(r7,0xefcdab89)

  mov i, #0	// i=0
while1:
  // Round 1
  vmov.u32 t1, #0xffffffff //Put all 1 in a
  
  add nt_buffer, nt_buffer_base, #(4*14*NT_NUM_KEYS);
  vld1.u32 {t5,t6}, [nt_buffer:128];

  vdup.u32 reg_b1, r7
  vdup.u32 reg_b2, r7
  vdup.u32 reg_c1, r5
  vdup.u32 reg_c2, r5
  vld1.u32 {t2,t3}, [nt_buffer_base:128]
  vdup.u32 reg_d1, r6
  vdup.u32 reg_d2, r6

  vadd.u32 reg_a1, t1, t2// First step
  vadd.u32 reg_a2, t1, t3
  vshl.u32 reg_a1, reg_a1, #3
  vshl.u32 reg_a2, reg_a2, #3
  
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 1 , 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 2 , 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 3 , 19, NT_NUM_KEYS)
                                                                                           
  STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 4 , 3 , NT_NUM_KEYS)
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 5 , 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6 , 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 7 , 19, NT_NUM_KEYS)
                                                                                           
  STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8 , 3 , NT_NUM_KEYS)
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 9 , 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 10, 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 11, 19, NT_NUM_KEYS)
                                                                                           
  STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 12, 3 , NT_NUM_KEYS)
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 13, 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 14, 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 19, NT_NUM_KEYS)
// Round 2
  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 4 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8 , 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 12, 13, NT_NUM_KEYS,sqrt_2)
                                                                                                  
  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 5 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 9 , 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 13, 13, NT_NUM_KEYS,sqrt_2)
	                                                                                              
  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 2 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 6 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 10, 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 14, 13, NT_NUM_KEYS,sqrt_2)
                                                                                                  
  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 3 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 7 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 11, 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 13, NT_NUM_KEYS,sqrt_2)
// Round 3
  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8 , 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 4 , 11, NT_NUM_KEYS,sqrt_3)
  STEP3(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 12, 15, NT_NUM_KEYS,sqrt_3)
                                                                                                  
  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 2 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 10, 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6 , 11, NT_NUM_KEYS,sqrt_3)
  STEP3(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 14, 15, NT_NUM_KEYS,sqrt_3)
                                                                                                  
  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 9 , 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 5 , 11, NT_NUM_KEYS,sqrt_3)
  
  // Save a, c, d
  add nt_buffer, nt_buffer_base, #(16*4*NT_NUM_KEYS+0*4*NT_NUM_KEYS)
  vst1.u32 {reg_a1,reg_a2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(16*4*NT_NUM_KEYS+3*4*NT_NUM_KEYS)
  vst1.u32 {reg_d1,reg_d2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(16*4*NT_NUM_KEYS+2*4*NT_NUM_KEYS)
  vst1.u32 {reg_c1,reg_c2}, [nt_buffer:128]
  
  add nt_buffer, nt_buffer_base, #(4*13*NT_NUM_KEYS)
  vld1.u32 {t3,t4}, [nt_buffer:128]
  vadd.u32 reg_b1, reg_b1, t3
  vadd.u32 reg_b2, reg_b2, t4
  veor.u32 t1, reg_a1, reg_d1
  veor.u32 t2, reg_a2, reg_d2
  veor.u32 t1, t1, reg_c1
  veor.u32 t2, t2, reg_c2
  vadd.u32 reg_b1, reg_b1, t1
  vadd.u32 reg_b2, reg_b2, t2
  
  // Save b
  add nt_buffer, nt_buffer_base, #(16*4*NT_NUM_KEYS+1*4*NT_NUM_KEYS)
  vst1.u32 {reg_b1,reg_b2}, [nt_buffer:128]
  
  // Table look-up---------------------------------------------------------
  vdup.u32 t5, size_bit_table_reg
  vmov.u32 t6, #31// Create C31

  vand.u32 t1, reg_b1, t5// and SIZE_BIT_TABLE
  vand.u32 t2, reg_b2, t5
  vand.u32 t3, t1, t6// mod 32
  vand.u32 t4, t2, t6
  vshr.u32 t1, t1, #(5-2) // div 32 and later mul 4 to address dword
  vshr.u32 t2, t2, #(5-2)
  vbic.u32 t1, t1, #3// ...	   later mul 4 to address dword
  vbic.u32 t2, t2, #3
  vneg.s32 t3, t3// shift right need negative number
  vneg.s32 t4, t4

  //Table look-up is not vectorizable, shift out one data element to look up table one by one
  vmov.u32 r8 , t1_0// get first index
  vmov.u32 r9, t2_0
  ldr r10, [table_ptr, r8]
  ldr r11, [table_ptr, r9]
  vmov.u32 t5_0, r10
  vmov.u32 t6_0, r11

  vmov.u32 r8, t1_1// get 2nd index
  vmov.u32 r9, t2_1
  ldr r10, [table_ptr, r8]
  ldr r11, [table_ptr, r9]
  vmov.u32 t5_1, r10
  vmov.u32 t6_1, r11

  vmov.u32 r8, t1_2// get 3rd index
  vmov.u32 r9, t2_2
  ldr r10, [table_ptr, r8]
  ldr r11, [table_ptr, r9]
  vmov.u32 t5_2, r10
  vmov.u32 t6_2, r11

  vmov.u32 r8, t1_3// get fourth index
  vmov.u32 r9, t2_3
  ldr r10, [table_ptr, r8]
  ldr r11, [table_ptr, r9]
  vmov.u32 t5_3, r10
  vmov.u32 t6_3, r11
  //end of scalar part
  vshl.u32 t5, t5, t3
  vmov.u32 t1, #1// Create ONE
  vshl.u32 t6, t6, t4
  vand.u32 t5, t5, t1// and ONE
  vand.u32 t6, t6, t1// and ONE
  // Save indexs
  add nt_buffer, nt_buffer_base, #(16*4*NT_NUM_KEYS+4*4*NT_NUM_KEYS)//indexes
  vst1.u32 {t5,t6}, [nt_buffer:128]
  // ----------------------------------------------------------------------------

  add i,i,#1
  add nt_buffer_base, nt_buffer_base, #(2*16)
  cmp i, #(NT_NUM_KEYS/(16/2))
  blo while1
	
  pop  {r8,r9,r10,r11}
  pop  {r4,r5,r6,r7}
  vpop {q4,q5,q6,q7}
  bx lr

/////////////////////////////////////////////////////////////////////////////////////////////////
// DCC
/////////////////////////////////////////////////////////////////////////////////////////////////
#define STEP1_DCC(a1,b1,c1,d1,a2,b2,c2,d2,rot,NT_NUM_KEYS,t1,t2,init_value) \
	vadd.u32 a1, a1, init_value;\
	vadd.u32 a2, a2, init_value;\
	vmov.u32 t1, b1;\
	vmov.u32 t2, b2;\
	vbsl t1, c1, d1;\
	vbsl t2, c2, d2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1,a2,rot,t1,t2)

#undef nt_buffer
#undef NT_NUM_KEYS
#define nt_buffer_base	r0
#define crypt_result	r1
#define nt_buffer		r2
#define NT_NUM_KEYS		64

	.text
	.align	2
	.global	dcc_ntlm_part_neon
	.type	dcc_ntlm_part_neon, %function
dcc_ntlm_part_neon:
  vpush {q4,q5,q6,q7}
  push	{r4,r5}

  SET_REG(r2,0x5a827999)
  SET_REG(r3,0x6ed9eba1)
  vdup.u32 sqrt_2, r2
  vdup.u32 sqrt_3, r3

  SET_REG(r5,0x98badcfe)
  SET_REG(r4,0x10325476)
  SET_REG(r3,0xefcdab89)

  // Round 1
  vmov.u32 t1, #0xffffffff //Put all 1 in a

  add nt_buffer, nt_buffer_base, #(4*14*NT_NUM_KEYS);
  vld1.u32 {t5,t6}, [nt_buffer:128];

  vdup.u32 reg_b1, r3
  vdup.u32 reg_b2, r3
  vdup.u32 reg_c1, r5
  vdup.u32 reg_c2, r5
  vld1.u32 {t2,t3}, [nt_buffer_base:128]
  vdup.u32 reg_d1, r4
  vdup.u32 reg_d2, r4

  vadd.u32 reg_a1, t1, t2// First step
  vadd.u32 reg_a2, t1, t3
  vshl.u32 reg_a1, reg_a1, #3
  vshl.u32 reg_a2, reg_a2, #3

  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 1 , 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 2 , 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 3 , 19, NT_NUM_KEYS)

  STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 4 , 3 , NT_NUM_KEYS)
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 5 , 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6 , 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 7 , 19, NT_NUM_KEYS)

  STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8 , 3 , NT_NUM_KEYS)
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 9 , 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 10, 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 11, 19, NT_NUM_KEYS)

  STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 12, 3 , NT_NUM_KEYS)
  STEP1(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 13, 7 , NT_NUM_KEYS)
  STEP1(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 14, 11, NT_NUM_KEYS)
  STEP1(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 19, NT_NUM_KEYS)
// Round 2
  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 4 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8 , 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 12, 13, NT_NUM_KEYS,sqrt_2)

  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 5 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 9 , 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 13, 13, NT_NUM_KEYS,sqrt_2)

  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 2 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 6 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 10, 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 14, 13, NT_NUM_KEYS,sqrt_2)

  STEP2(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 3 , 3 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 7 , 5 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 11, 9 , NT_NUM_KEYS,sqrt_2)
  STEP2(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 13, NT_NUM_KEYS,sqrt_2)
// Round 3
  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8 , 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 4 , 11, NT_NUM_KEYS,sqrt_3)
  STEP3(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 12, 15, NT_NUM_KEYS,sqrt_3)

  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 2 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 10, 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6 , 11, NT_NUM_KEYS,sqrt_3)
  STEP3(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 14, 15, NT_NUM_KEYS,sqrt_3)

  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 9 , 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 5 , 11, NT_NUM_KEYS,sqrt_3)
  STEP3(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 13, 15, NT_NUM_KEYS,sqrt_3)

  STEP3(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 3 , 3 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 11, 9 , NT_NUM_KEYS,sqrt_3)
  STEP3(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 7 , 11, NT_NUM_KEYS,sqrt_3)
  STEP3(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 15, NT_NUM_KEYS,sqrt_3)

//LOAD const_init_*
  vdup.u32 t2, r3
  vdup.u32 t3, r5
  vdup.u32 t4, r4
  SET_REG(r3,0x67452301)
  vdup.u32 t1, r3

  vadd.u32 reg_a1, reg_a1, t1
  vadd.u32 reg_a2, reg_a2, t1
  vadd.u32 reg_b1, reg_b1, t2
  vadd.u32 reg_b2, reg_b2, t2
  vadd.u32 reg_c1, reg_c1, t3
  vadd.u32 reg_c2, reg_c2, t3
  vadd.u32 reg_d1, reg_d1, t4
  vadd.u32 reg_d2, reg_d2, t4

  vst1.u32 {reg_a1,reg_a2}, [crypt_result:128]!
  vst1.u32 {reg_b1,reg_b2}, [crypt_result:128]!
  vst1.u32 {reg_c1,reg_c2}, [crypt_result:128]!
  vst1.u32 {reg_d1,reg_d2}, [crypt_result:128]!

  // Round 1
  vmov.u32 t1, #0xffffffff //Put all 1 in a

  vadd.u32 reg_a1, t1, reg_a1// First step
  vadd.u32 reg_a2, t1, reg_a2
  ROTATE(reg_a1,reg_a2,3,t1,sqrt_2)

  // interchange b and d
  STEP1_DCC(reg_b1, reg_a1, t2, t3, reg_b2, reg_a2, t2, t3, 7 , NT_NUM_KEYS,t1,sqrt_2,t4)
  STEP1_DCC(reg_c1, reg_b1, reg_a1, t2, reg_c2, reg_b2, reg_a2, t2, 11, NT_NUM_KEYS,t1,sqrt_2,t3)
  STEP1_DCC(reg_d1, reg_c1, reg_b1, reg_a1, reg_d2, reg_c2, reg_b2, reg_a2, 19, NT_NUM_KEYS,t1,sqrt_2,t2)

  vst1.u32 {reg_a1,reg_a2}, [crypt_result:128]!
  vst1.u32 {reg_d1,reg_d2}, [crypt_result:128]!
  vst1.u32 {reg_c1,reg_c2}, [crypt_result:128]!
  vst1.u32 {reg_b1,reg_b2}, [crypt_result:128]!

  pop  {r4,r5}
  vpop {q4,q5,q6,q7}
  bx lr


#define DCC_LOAD_CRYPT(a1,a2,index) \
	add nt_buffer, crypt_result, #(index*2*16);\
	vld1.u32 {t3,t4}, [nt_buffer:128];\
	vadd.u32 a1, a1, t3;\
	vadd.u32 a2, a2, t4;

#define DCC_LOAD_NT_BUFFER(a1,a2,index) \
	ldr r3, [nt_buffer_base, #(4*(index-4))];\
	vdup.u32 t3, r3;\
	vadd.u32 a1, a1, t3;\
	vadd.u32 a2, a2, t3;

#define LOAD_DCC_0(a1,a2)	vld1.u32 {t3,t4}, [crypt_result:128];\
							vadd.u32 a1, a1, t3;\
							vadd.u32 a2, a2, t4;
#define LOAD_DCC_1(a1,a2)	DCC_LOAD_CRYPT(a1,a2,1)
#define LOAD_DCC_2(a1,a2)	DCC_LOAD_CRYPT(a1,a2,2)
#define LOAD_DCC_3(a1,a2)	DCC_LOAD_CRYPT(a1,a2,3)

#define LOAD_DCC_4(a1,a2)	vadd.u32 a1, a1, t5;\
							vadd.u32 a2, a2, t5;
#define LOAD_DCC_5(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,5)
#define LOAD_DCC_6(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,6)
#define LOAD_DCC_7(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,7)
#define LOAD_DCC_8(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,8)
#define LOAD_DCC_9(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,9)
#define LOAD_DCC_10(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,10)
#define LOAD_DCC_11(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,11)
#define LOAD_DCC_12(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,12)
#define LOAD_DCC_13(a1,a2)	DCC_LOAD_NT_BUFFER(a1,a2,13)
#define LOAD_DCC_14(a1,a2)	vadd.u32 a1, a1, t6;\
							vadd.u32 a2, a2, t6;
#define LOAD_DCC_15(a1,a2)

#define STEP1_DCC_SALT(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,t1,t2)	\
    LOAD_DCC_ ## index (a1,a2)\
	vmov.u32 t1, b1;\
	vmov.u32 t2, b2;\
	vbsl t1, c1, d1;\
	vbsl t2, c2, d2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1,a2,rot,t1,t2)

#define STEP2_DCC_SALT(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,sqrt_2,t1,t2,t3,t4) \
	LOAD_DCC_ ## index (a1,a2)\
	vorr.u32 t1, c1, d1;\
	vorr.u32 t2, c2, d2;\
	vand.u32 t3, c1, d1;\
	vand.u32 t4, c2, d2;\
	vand.u32 t1, t1, b1;\
	vand.u32 t2, t2, b2;\
	vadd.u32 a1, a1, sqrt_2;\
	vadd.u32 a2, a2, sqrt_2;\
	vorr.u32 t1, t1, t3;\
	vorr.u32 t2, t2, t4;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1,a2,rot,t1,t2)

#define STEP3_DCC_SALT(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,sqrt_3,t1,t2) \
	LOAD_DCC_ ## index (a1,a2)\
	veor.u32 t1, d1, c1;\
	veor.u32 t2, d2, c2;\
	vadd.u32 a1, a1, sqrt_3;\
	vadd.u32 a2, a2, sqrt_3;\
	veor.u32 t1, t1, b1;\
	veor.u32 t2, t2, b2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1,a2,rot,t1,t2)

#define dcc_salt_part_neon_body(idx) \
.text;\
.align	2;\
.global	dcc_salt_part_neon ## idx;\
.type	dcc_salt_part_neon ## idx, %function;\
dcc_salt_part_neon ## idx:\
  vpush {q4,q5,q6,q7};\
\
  SET_REG(r2,0x5a827999);\
  SET_REG(r3,0x6ed9eba1);\
  vdup.u32 sqrt_2, r2;\
  vdup.u32 sqrt_3, r3;\
\
 /* Round 1*/\
  add nt_buffer, crypt_result, #(8*16);\
  vld1.u32 {reg_a1,reg_a2}, [nt_buffer:128]!;\
  vld1.u32 {reg_b1,reg_b2}, [nt_buffer:128]!;\
  vld1.u32 {reg_c1,reg_c2}, [nt_buffer:128]!;\
  vld1.u32 {reg_d1,reg_d2}, [nt_buffer:128]!;\
\
  ldr r2, [nt_buffer_base];\
  ldr r3, [nt_buffer_base, #(4*(14-4))];\
  vdup.u32 t5, r2;\
  vdup.u32 t6, r3;\
\
  STEP1_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 4 , 3 ,t1,t2);\
  STEP1_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 5 , 7 ,t1,t2);\
  STEP1_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6 , 11,t1,t2);\
  STEP1_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 7 , 19,t1,t2);\
\
  STEP1_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8 , 3 ,t1,t2);\
  STEP1_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 9 , 7 ,t1,t2);\
  STEP1_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 10, 11,t1,t2);\
  STEP1_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 11, 19,t1,t2);\
\
  STEP1_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 12, 3 ,t1,t2);\
  STEP1_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 13, 7 ,t1,t2);\
  STEP1_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 14, 11,t1,t2);\
  STEP1_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 19,t1,t2);\
/* Round 2*/\
  STEP2_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0 , 3 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 4 , 5 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8 , 9 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 12, 13,sqrt_2,t1,t2,t3,t4);\
\
  STEP2_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1 , 3 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 5 , 5 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 9 , 9 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 13, 13,sqrt_2,t1,t2,t3,t4);\
\
  STEP2_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 2 , 3 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 6 , 5 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 10, 9 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 14, 13,sqrt_2,t1,t2,t3,t4);\
\
  STEP2_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 3 , 3 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 7 , 5 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 11, 9 ,sqrt_2,t1,t2,t3,t4);\
  STEP2_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 15, 13,sqrt_2,t1,t2,t3,t4);\
/* Round 3*/\
  STEP3_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0 , 3 ,sqrt_3,t1,t2);\
  STEP3_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8 , 9 ,sqrt_3,t1,t2);\
  STEP3_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 4 , 11,sqrt_3,t1,t2);\
  STEP3_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 12, 15,sqrt_3,t1,t2);\
\
  STEP3_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 2 , 3 ,sqrt_3,t1,t2);\
  STEP3_DCC_SALT(reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 10, 9 ,sqrt_3,t1,t2);\
  STEP3_DCC_SALT(reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6 , 11,sqrt_3,t1,t2);\
  STEP3_DCC_SALT(reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 14, 15,sqrt_3,t1,t2);\
\
  STEP3_DCC_SALT(reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1 , 3 ,sqrt_3,t1,t2);\
  LOAD_DCC_9(reg_d1,reg_d2);\
  veor.u32 t1, reg_c1, reg_b1;\
  veor.u32 t2, reg_c2, reg_b2;\
  veor.u32 t1, t1, reg_a1;\
  veor.u32 t2, t2, reg_a2;\
  vadd.u32 reg_d1, reg_d1, t1;\
  vadd.u32 reg_d2, reg_d2, t2;\
\
  add crypt_result, crypt_result, #(16*16);\
  vst1.u32 {reg_a1,reg_a2}, [crypt_result:128]!;\
  vst1.u32 {reg_b1,reg_b2}, [crypt_result:128]!;\
  vst1.u32 {reg_c1,reg_c2}, [crypt_result:128]!;\
  vst1.u32 {reg_d1,reg_d2}, [crypt_result:128]!;\
\
  vpop {q4,q5,q6,q7};\
  bx lr

// Funtions by salt_lenght
dcc_salt_part_neon_body(13)

#undef LOAD_DCC_13
#define LOAD_DCC_13(a1,a2)
dcc_salt_part_neon_body(12)

#undef LOAD_DCC_12
#define LOAD_DCC_12(a1,a2)
dcc_salt_part_neon_body(11)

#undef LOAD_DCC_11
#define LOAD_DCC_11(a1,a2)
dcc_salt_part_neon_body(10)

#undef LOAD_DCC_10
#define LOAD_DCC_10(a1,a2)
dcc_salt_part_neon_body(9)

#undef LOAD_DCC_9
#define LOAD_DCC_9(a1,a2)
dcc_salt_part_neon_body(8)

#undef LOAD_DCC_8
#define LOAD_DCC_8(a1,a2)
dcc_salt_part_neon_body(7)

#undef LOAD_DCC_7
#define LOAD_DCC_7(a1,a2)
dcc_salt_part_neon_body(6)

#undef LOAD_DCC_6
#define LOAD_DCC_6(a1,a2)
dcc_salt_part_neon_body(5)

#undef LOAD_DCC_5
#define LOAD_DCC_5(a1,a2)
dcc_salt_part_neon_body(4)


/////////////////////////////////////////////////////////////////////////////////////////////////
// LM format
/////////////////////////////////////////////////////////////////////////////////////////////////
#define first_k r4
#define first_c r5
#define p_out	r6
#undef i
#define i		r7
#define first_c_ptr r0
#define first_k_ptr	r1

// Repeats
#define MAX_REPEAT 8// If change this change also SET_0 and SET_FFFFFFFF
#define SET_0	\
vst1.u32 {q0,q1}, [first_c_ptr:128]!;\
vst1.u32 {q0,q1}, [first_c_ptr:128]!;\
vst1.u32 {q0,q1}, [first_c_ptr:128]!;\
vst1.u32 {q0,q1}, [first_c_ptr:128]!;
#define SET_FFFFFFFF	\
vst1.u32 {q2,q3}, [first_c_ptr:128]!;\
vst1.u32 {q2,q3}, [first_c_ptr:128]!;\
vst1.u32 {q2,q3}, [first_c_ptr:128]!;\
vst1.u32 {q2,q3}, [first_c_ptr:128]!;

// Sboxs
	.text
	.align	2
	.global	s1
	.type	s1, %function
s1:
	veor q0, q14, q9
	vorr q2, q12, q15
	vand q0, q10, q0
	veor q3, q10, q12
	veor q1, q13, q0
	vand q4, q2, q3
	veor q6, q1, q9
	veor q8, q13, q4
	veor q7, q14, q15
	vand q6, q8, q6
	veor q12, q12, q9
	veor q5, q12, q7
	vorr q4, q15, q4
	vand q5, q1, q5
	vorr q0, q12, q0
	veor q4, q5, q4
	vorr q15, q10, q15
	veor q5, q6, q9
	vorr q12, q4, q15
	vand q5, q4, q5
	veor q8, q8, q9
	veor q15, q15, q9
	vand q8, q14, q8
	vand q15, q13, q15
	veor q3, q3, q9
	veor q13, q12, q8
	veor q15, q8, q15
	vand q3, q7, q3
	vand q4, q2, q4
	vorr q15, q15, q3
	veor q3, q1, q12
	veor q12, q2, q12
	vand q0, q3, q0
	vorr q12, q15, q12
	veor q3, q0, q9
	veor q0, q7, q0
	veor q4, q3, q4
	vorr q0, q8, q0
	vorr q14, q14, q1
	veor q3, q11, q9
	veor q0, q2, q0
	vand q3, q13, q3
	veor q10, q10, q0
	veor q3, q3, q4
	vorr q6, q6, q11
	veor q4, q4, q10
	
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q0}, [first_c_ptr:128]
	veor q0, q0, q3
	vst1.u32 {q0}, [first_c_ptr:128]

	veor q6, q6, q4
	veor q2, q10, q12
	vorr q4, q7, q4
	vand q10, q5, q10
	veor q4, q2, q4
	
	vld1.u32 {q0}, [p_out:128]
	veor q0, q0, q6
	vst1.u32 {q0}, [p_out:128]

	veor q2, q2, q9
	vorr q6, q5, q11
	vand q2, q14, q2
	veor q4, q6, q4
	veor q10, q2, q10
	
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q0}, [first_c_ptr:128]
	veor q0, q0, q4
	vst1.u32 {q0}, [first_c_ptr:128]

	vorr q11, q10, q11
	veor q11, q11, q15
	
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q0}, [first_c_ptr:128]
	veor q0, q0, q11
	vst1.u32 {q0}, [first_c_ptr:128]

	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr
	
	.text
	.align	2
	.global	s2
	.type	s2, %function
s2:
	veor q0, q11, q14
	veor q7, q10, q9
	vorr q1, q7, q15
	vand q1, q14, q1
	vorr q2, q11, q1
	veor q3, q15, q9
	vand q3, q0, q3
	vand q4, q10, q0
	veor q14, q14, q4
	veor q5, q3, q9
	vand q5, q14, q5
	vorr q5, q5, q13
	vand q4, q12, q15
	veor q1, q1, q3
	vand q1, q2, q1
	veor q3, q1, q9
	vorr q3, q3, q4
	vand q6, q12, q1
	veor q10, q6, q7
	veor q15, q15, q0
	veor q7, q15, q9
	vorr q7, q7, q4
	vand q11, q11, q7//q7
	veor q7, q7, q9
	veor q7, q10, q7
	vand q3, q13, q3
	veor q3, q3, q7
	veor q14, q14, q11
	veor q6, q6, q11//q11
	
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q11}, [first_c_ptr:128]
	veor q11, q11, q3
	vst1.u32 {q11}, [first_c_ptr:128]

	veor q14, q14, q9
	vand q3, q10, q14
	veor q12, q12, q15
	veor q3, q3, q12
	veor q10, q13, q9
	vand q10, q2, q10
	veor q10, q10, q3
	
	vld1.u32 {q11}, [p_out:128]
	veor q11, q11, q10
	vst1.u32 {q11}, [p_out:128]

	vorr q12, q12, q6
	veor q2, q2, q7
	vorr q4, q4, q2
	veor q6, q12, q4
	veor q1, q1, q7//q8
	veor q1, q3, q1
	vand q1, q4, q1//q4
	vand q12, q0, q12//q0
	veor q12, q1, q12//q1
	vorr q3, q12, q13
	veor q6, q3, q6
	
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q11}, [first_c_ptr:128]
	veor q11, q11, q6
	vst1.u32 {q11}, [first_c_ptr:128]

	vand q14, q12, q14//q12
	vorr q15, q15, q2//q2
	veor q14, q14, q15//q15
	veor q5, q5, q14//q14
	
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q11}, [first_c_ptr:128]
	veor q11, q11, q5
	vst1.u32 {q11}, [first_c_ptr:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

	.text
	.align	2
	.global	s3
	.type	s3, %function
s3:
	veor q0, q11, q9// repeted below
	vand q0, q10, q0
	veor q1, q12, q15
	vorr q2, q0, q1
	veor q3, q13, q15
	veor q4, q10, q9
	vand q4, q3, q4
	veor q5, q2, q4
	veor q6, q11, q1
	veor q7, q15, q9
	vand q7, q6, q7
	veor q2, q2, q7
	veor q7, q5, q9
	vorr q7, q7, q2
	vand q1, q1, q3
	vand q3, q15, q5
	vorr q3, q13, q3
	vand q3, q10, q3
	veor q3, q6, q3
	veor q8, q10, q13
	vorr q4, q4, q8
	veor q8, q2, q8
	vorr q8, q12, q8
	veor q1, q1, q9
	vand q1, q8, q1
	veor q8, q4, q9
	vand q8, q3, q8
	vand q15, q13, q15
	vorr q12, q11, q12
	veor q11, q11, q9
	vand q11, q15, q11
	veor q11, q8, q11//q8
	vand q2, q2, q11
	vorr q15, q6, q15
	veor q2, q2, q9
	vand q15, q15, q2//q2
	vand q7, q14, q7
	veor q2, q14, q9
	vand q2, q5, q2
	veor q2, q2, q3
	veor q10, q10, q15
	
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q15}, [first_c_ptr:128]
	veor q15, q15, q2
	vst1.u32 {q15}, [first_c_ptr:128]

	vand q1, q1, q14
	veor q1, q1, q10
		
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q15}, [first_c_ptr:128]
	veor q15, q15, q1
	vst1.u32 {q15}, [first_c_ptr:128]

	veor q5, q5, q9
	vorr q12, q12, q5
	veor q12, q6, q12//q6
	veor q4, q4, q12
	veor q4, q7, q4//q7---------
		
	vld1.u32 {q15}, [p_out:128]
	veor q15, q15, q4
	vst1.u32 {q15}, [p_out:128]

	vand q13, q13, q5//q5
	veor q13, q3, q13//q3
	vorr q13, q12, q13//q12
	veor q10, q0, q10//q0
	veor q13, q13, q10//q10
	vorr q14, q11, q14//q3
	veor q14, q14, q13//q13
		
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q15}, [first_c_ptr:128]
	veor q15, q15, q14
	vst1.u32 {q15}, [first_c_ptr:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

	.text
	.align	2
	.global	s4
	.type	s4, %function
s4:
	veor q10, q10, q12//q10
	veor q12, q12, q14//q12
	veor q1, q11, q9
	veor q0, q1, q13
	vand q1, q12, q1
	veor q2, q13, q1
	vorr q13, q11, q13//q13
	veor q13, q14, q13
	vorr q1, q14, q1//q14
	veor q13, q13, q9
	vand q13, q12, q13
	vorr q3, q10, q2
	veor q14, q13, q9
	vand q14, q3, q14
	veor q11, q11, q14//q11
	vand q2, q2, q11
	veor q3, q12, q9//q12
	vorr q3, q3, q2
	veor q10, q10, q11
	vand q3, q10, q3
	veor q3, q13, q3//q13
	veor q1, q10, q1//q10
	vand q10, q1, q0
	veor q10, q14, q10
	veor q13, q3, q9
	vand q13, q15, q13
	veor q13, q13, q10
		
	vld1.u32 {q12}, [p_out:128]
	veor q12, q12, q13
	vst1.u32 {q12}, [p_out:128]

	veor q10, q10, q9
	vorr q14, q11, q15
	vand q11, q11, q15
	veor q15, q15, q9
	vand q15, q3, q15//q15
	veor q15, q15, q10
			
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q12}, [first_c_ptr:128]
	veor q12, q12, q15
	vst1.u32 {q12}, [first_c_ptr:128]

	veor q10, q3, q10//q3
	vand q0, q10, q0//q6
	vorr q0, q2, q0//q2
	veor q0, q1, q0//q1
	veor q14, q14, q0
			
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q12}, [first_c_ptr:128]
	veor q12, q12, q14
	vst1.u32 {q12}, [first_c_ptr:128]

	veor q0, q11, q0
			
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q12}, [first_c_ptr:128]
	veor q12, q12, q0
	vst1.u32 {q12}, [first_c_ptr:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

	.text
	.align	2
	.global	s5
	.type	s5, %function
s5:
	vorr q0, q10, q12
	veor q1, q15, q9
	vand q1, q0, q1
	veor q2, q13, q9
	vand q2, q1, q2
	veor q1, q10, q1
	veor q2, q12, q2
	veor q12, q12, q1//q12
	vorr q4, q13, q12
	vand q5, q14, q2
	vorr q12, q10, q12
	veor q5, q5, q12
	veor q5, q13, q5
	veor q15, q15, q5//q15
	vorr q8, q1, q15
	veor q0, q10, q0
	veor q10, q10, q9
	vand q10, q8, q10
	vand q3, q13, q12
	veor q3, q1, q3
	veor q7, q2, q10
	vand q8, q14, q8
	veor q14, q14, q4
	veor q10, q10, q14
	veor q3, q3, q8
	vorr q10, q3, q10
	vand q12, q2, q12
	veor q6, q2, q9
	vorr q6, q6, q8
	vand q10, q10, q6
	vand q15, q15, q10
	veor q0, q10, q0
	veor q10, q10, q9
	vand q10, q4, q10
	veor q15, q14, q15
	vorr q12, q15, q12
	veor q12, q8, q12//q8
	vand q12, q12, q11
	veor q12, q12, q3//q3
			
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q6}, [first_c_ptr:128]
	veor q6, q6, q12
	vst1.u32 {q6}, [first_c_ptr:128]

	vand q13, q13, q15//q13
	veor q0, q0, q13
	vorr q10, q10, q11
	veor q10, q10, q0
				
	vld1.u32 {q6}, [p_out:128]
	veor q6, q6, q10
	vst1.u32 {q6}, [p_out:128]

	veor q2, q4, q2
	veor q0, q0, q9
	vand q0, q2, q0
	veor q1, q1, q15
	veor q0, q0, q1
	vand q4, q4, q11//q11
	veor q11, q11, q9
	veor q1, q14, q9
	vorr q7, q1, q7
	vand q7, q11, q7
	veor q5, q7, q5//q7
				
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q6}, [first_c_ptr:128]
	veor q6, q6, q5
	vst1.u32 {q6}, [first_c_ptr:128]

	veor q0, q4, q0
				
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q6}, [first_c_ptr:128]
	veor q6, q6, q0
	vst1.u32 {q6}, [first_c_ptr:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

	.text
	.align	2
	.global	s6
	.type	s6, %function
s6:
	veor q0, q11, q14
	vorr q1, q11, q15
	vand q1, q10, q1
	veor q0, q0, q1
	veor q2, q15, q0
	vand q3, q10, q2
	veor q2, q2, q9
	vand q2, q14, q2
	veor q4, q11, q3
	veor q3, q15, q3
	veor q5, q10, q12
	vorr q6, q4, q5
	vorr q4, q2, q4
	vorr q5, q11, q5
	veor q11, q11, q6
	veor q6, q0, q6
	veor q11, q11, q9
	vand q8, q15, q11
	veor q8, q12, q8
	vand q12, q12, q6
	veor q15, q15, q9
	vand q15, q12, q15
	veor q7, q10, q8
	vorr q10, q10, q6
	vand q10, q4, q10
	veor q4, q15, q4
	veor q11, q5, q11
	veor q5, q4, q5
	veor q10, q8, q10
	veor q15, q15, q9
	vand q15, q10, q15
	veor q0, q0, q10
	veor q0, q0, q9
	vand q0, q14, q0
	veor q0, q0, q11
	veor q11, q12, q11
	veor q12, q12, q9
	vand q12, q14, q12//q14
	vorr q12, q8, q12//q8
	vand q4, q4, q13
	veor q4, q4, q6//q6
				
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q14}, [first_c_ptr:128]
	veor q14, q14, q4
	vst1.u32 {q14}, [first_c_ptr:128]

	vorr q2, q2, q13
	veor q2, q2, q15//q15
					
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q14}, [first_c_ptr:128]
	veor q14, q14, q2
	vst1.u32 {q14}, [first_c_ptr:128]

	vorr q1, q1, q12
	veor q1, q5, q1//q5
	veor q13, q13, q9
	vand q0, q0, q13//q0
	veor q1, q0, q1
					
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q14}, [first_c_ptr:128]
	veor q14, q14, q1
	vst1.u32 {q14}, [first_c_ptr:128]

	vand q3, q3, q7
	veor q3, q3, q11//q11
	vand q13, q12, q13//q13
	veor q3, q13, q3
					
	vld1.u32 {q14}, [p_out:128]
	veor q14, q14, q3
	vst1.u32 {q14}, [p_out:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

	.text
	.align	2
	.global	s7
	.type	s7, %function
s7:
	veor q0, q13, q14
	veor q1, q12, q0
	vand q2, q15, q1
	vand q3, q13, q0
	veor q4, q11, q3
	vand q5, q2, q4
	vand q6, q15, q3
	veor q6, q12, q6
	vorr q7, q4, q6
	veor q0, q15, q0
	veor q7, q7, q0
	veor q5, q5, q9
	vand q5, q10, q5
	veor q5, q5, q7
	vorr q3, q3, q7
					
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q7}, [first_c_ptr:128]
	veor q7, q7, q5
	vst1.u32 {q7}, [first_c_ptr:128]

	veor q7, q1, q9
	vand q7, q14, q7
	vorr q5, q4, q7
	veor q6, q2, q6
	veor q5, q5, q6
	veor q2, q2, q0
	veor q13, q13, q9
	vorr q13, q13, q2
	vand q13, q4, q13
	veor q6, q14, q6
	veor q13, q13, q6
	vand q12, q12, q13
	vorr q3, q3, q12
	veor q0, q0, q9
	vand q0, q1, q0//q1
	veor q0, q3, q0//q3
	veor q2, q10, q9
	vand q2, q0, q2
	veor q2, q2, q5
						
	vld1.u32 {q1}, [p_out:128]
	veor q1, q1, q2
	vst1.u32 {q1}, [p_out:128]

	vorr q4, q13, q0
	vand q15, q15, q4//q4
	vand q11, q11, q15
	veor q5, q5, q0
	veor q11, q11, q5
	vorr q12, q12, q11
	veor q12, q15, q12
	veor q14, q14, q5//q5
	vorr q12, q12, q14//q14
	vand q6, q12, q10
	veor q13, q6, q13//q6
							
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q1}, [first_c_ptr:128]
	veor q1, q1, q13
	vst1.u32 {q1}, [first_c_ptr:128]

	veor q12, q15, q12//q15
	vorr q12, q7, q12//q7
	veor q0, q0, q9
	veor q12, q12, q0//q0
	veor q10, q10, q9
	vand q10, q12, q10//q12
	veor q10, q10, q11//q11
							
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q1}, [first_c_ptr:128]
	veor q1, q1, q10
	vst1.u32 {q1}, [first_c_ptr:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

	.text
	.align	2
	.global	s8
	.type	s8, %function
s8:
	veor q6, q12, q9
	vorr q0, q6, q11
	vand q1, q14, q6
	veor q1, q13, q1
	vand q2, q10, q1
	veor q1, q1, q9
	vand q3, q11, q1
	vorr q4, q10, q3
	veor q5, q4, q9
	vand q5, q12, q5
	vand q12, q11, q6//q12
	veor q12, q14, q12
	vand q4, q4, q12
	veor q1, q4, q1
	veor q1, q1, q5
	veor q6, q0, q9
	veor q6, q6, q1
	vand q0, q2, q0
	vorr q2, q2, q4
	vorr q5, q0, q15
	veor q5, q5, q6
	veor q6, q10, q6
	vand q4, q14, q6
	veor q6, q14, q6//q14
							
	add first_c_ptr, p_out, #(1*16*MAX_REPEAT)
	vld1.u32 {q14}, [first_c_ptr:128]
	veor q14, q14, q5
	vst1.u32 {q14}, [first_c_ptr:128]

	veor q1, q11, q1
	veor q4, q4, q1
	veor q3, q3, q4
	veor q4, q2, q4
	vorr q4, q11, q4//q11
	veor q4, q4, q6//q6
	vand q2, q2, q15
	veor q2, q2, q4
								
	add first_c_ptr, p_out, #(2*16*MAX_REPEAT)
	vld1.u32 {q14}, [first_c_ptr:128]
	veor q14, q14, q2
	vst1.u32 {q14}, [first_c_ptr:128]

	veor q12, q12, q3//q12
	vorr q1, q13, q1
	veor q1, q12, q1
	veor q10, q10, q1//q10
	veor q1, q0, q1
	vand q10, q10, q15
	veor q10, q10, q3
								
	add first_c_ptr, p_out, #(3*16*MAX_REPEAT)
	vld1.u32 {q14}, [first_c_ptr:128]
	veor q14, q14, q10
	vst1.u32 {q14}, [first_c_ptr:128]
	
	veor q13, q13, q9
	vand q13, q12, q13//q13
	vand q4, q4, q13//q13
	veor q4, q4, q1
	vorr q4, q4, q15//q15
	veor q4, q4, q3
								
	vld1.u32 {q14}, [p_out:128]
	veor q14, q14, q4
	vst1.u32 {q14}, [p_out:128]
	
	add p_out, p_out, #(4*16*MAX_REPEAT)
	bx lr

#define LM_CALL_STEP(fun,c1,k1,c2,k2,c3,k3,c4,k4,c5,k5,c6,k6) \
	add r0, first_c, #(c1*16*MAX_REPEAT);\
	add r1, first_c, #(c2*16*MAX_REPEAT);\
	add r2, first_c, #(c3*16*MAX_REPEAT);\
	add r3, first_c, #(c4*16*MAX_REPEAT);\
	vld1.u32 {q10}, [r0:128];\
	vld1.u32 {q11}, [r1:128];\
	vld1.u32 {q12}, [r2:128];\
	vld1.u32 {q13}, [r3:128];\
\
	add r0, first_c, #(c5*16*MAX_REPEAT);\
	add r1, first_c, #(c6*16*MAX_REPEAT);\
	add r2, first_k, #(k1*16*MAX_REPEAT);\
	add r3, first_k, #(k2*16*MAX_REPEAT);\
	vld1.u32 {q14}, [r0:128];\
	vld1.u32 {q15}, [r1:128];\
	vld1.u32 {q0}, [r2:128];\
	vld1.u32 {q1}, [r3:128];\
\
	add r0, first_k, #(k3*16*MAX_REPEAT);\
	add r1, first_k, #(k4*16*MAX_REPEAT);\
	add r2, first_k, #(k5*16*MAX_REPEAT);\
	add r3, first_k, #(k6*16*MAX_REPEAT);\
	vld1.u32 {q2}, [r0:128];\
	vld1.u32 {q3}, [r1:128];\
	vld1.u32 {q4}, [r2:128];\
	vld1.u32 {q5}, [r3:128];\
\
    veor.u32 q10, q10, q0;\
    veor.u32 q11, q11, q1;\
    veor.u32 q12, q12, q2;\
    veor.u32 q13, q13, q3;\
    veor.u32 q14, q14, q4;\
    veor.u32 q15, q15, q5;\
\
	bl fun


	.text
	.align	2
	.global	lm_eval_neon_kernel
	.type	lm_eval_neon_kernel, %function
lm_eval_neon_kernel:
  vpush {q4,q5,q6,q7}
  push	{r4,r5,r6,r7}
  push  {lr}

  mov first_k, r0
  mov first_c, r1
  
  // Initialize cs
  vmov.u32 q9, #0xffffffff
  vmov.u32 q0, #0
  vmov.u32 q1, #0
  vmov.u32 q2, #0xffffffff //Put all 1
  vmov.u32 q3, #0xffffffff
  mov first_c_ptr, first_c
  
  SET_0
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_0
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_0
  SET_0
  SET_0
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0
  SET_0
  SET_0
  SET_FFFFFFFF
  SET_0
  SET_0

  mov i, #0	// i=0
init_while:
    mov p_out, first_c//1
	LM_CALL_STEP(s1, 56, 47, 47, 11, 38, 26, 51, 3 , 52, 13, 60, 41)
	LM_CALL_STEP(s2, 52, 27, 60, 6 , 43, 54, 59, 48, 48, 39, 32, 19)
	LM_CALL_STEP(s3, 48, 53, 32, 25, 46, 33, 54, 34, 57, 17, 36, 5 )
	LM_CALL_STEP(s4, 57, 4 , 36, 55, 49, 24, 62, 32, 41, 40, 33, 20)
	LM_CALL_STEP(s5, 41, 36, 33, 31, 39, 21, 55, 8 , 45, 23, 63, 52)
	LM_CALL_STEP(s6, 45, 14, 63, 29, 58, 51, 34, 9 , 40, 35, 50, 30)
	LM_CALL_STEP(s7, 40, 2 , 50, 37, 44, 22, 61, 0 , 37, 42, 53, 38)
	LM_CALL_STEP(s8, 37, 16, 53, 43, 42, 44, 35, 1 , 56, 7 , 47, 28)
	//2
	LM_CALL_STEP(s1, 24, 54, 15, 18, 6 , 33, 19, 10, 20, 20, 28, 48)
	LM_CALL_STEP(s2, 20, 34, 28, 13, 11, 4 , 27, 55, 16, 46, 0 , 26)
	LM_CALL_STEP(s3, 16, 3 , 0 , 32, 14, 40, 22, 41, 25, 24, 4 , 12)
	LM_CALL_STEP(s4, 25, 11, 4 , 5 , 17, 6 , 30, 39, 9 , 47, 1 , 27)
	LM_CALL_STEP(s5, 9 , 43, 1 , 38, 7 , 28, 23, 15, 13, 30, 31, 0 )
	LM_CALL_STEP(s6, 13, 21, 31, 36, 26, 31, 2 , 16, 8 , 42, 18, 37)
	LM_CALL_STEP(s7, 8 , 9 , 18, 44, 12, 29, 29, 7 , 5 , 49, 21, 45)
	LM_CALL_STEP(s8, 5 , 23, 21, 50, 10, 51, 3 , 8 , 24, 14, 15, 35)
	mov p_out, first_c//3
	LM_CALL_STEP(s1, 56, 11, 47, 32, 38, 47, 51, 24, 52, 34, 60, 5 )
	LM_CALL_STEP(s2, 52, 48, 60, 27, 43, 18, 59, 12, 48, 3 , 32, 40)
	LM_CALL_STEP(s3, 48, 17, 32, 46, 46, 54, 54, 55, 57, 13, 36, 26)
	LM_CALL_STEP(s4, 57, 25, 36, 19, 49, 20, 62, 53, 41, 4 , 33, 41)
	LM_CALL_STEP(s5, 41, 2 , 33, 52, 39, 42, 55, 29, 45, 44, 63, 14)
	LM_CALL_STEP(s6, 45, 35, 63, 50, 58, 45, 34, 30, 40, 1 , 50, 51)
	LM_CALL_STEP(s7, 40, 23, 50, 31, 44, 43, 61, 21, 37, 8 , 53, 0 )
	LM_CALL_STEP(s8, 37, 37, 53, 9 , 42, 38, 35, 22, 56, 28, 47, 49)
	//4
	LM_CALL_STEP(s1, 24, 25, 15, 46, 6 , 4 , 19, 13, 20, 48, 28, 19)
	LM_CALL_STEP(s2, 20, 5 , 28, 41, 11, 32, 27, 26, 16, 17, 0 , 54)
	LM_CALL_STEP(s3, 16, 6 , 0 , 3 , 14, 11, 22, 12, 25, 27, 4 , 40)
	LM_CALL_STEP(s4, 25, 39, 4 , 33, 17, 34, 30, 10, 9 , 18, 1 , 55)
	LM_CALL_STEP(s5, 9 , 16, 1 , 7 , 7 , 1 , 23, 43, 13, 31, 31, 28)
	LM_CALL_STEP(s6, 13, 49, 31, 9 , 26, 0 , 2 , 44, 8 , 15, 18, 38)
	LM_CALL_STEP(s7, 8 , 37, 18, 45, 12, 2 , 29, 35, 5 , 22, 21, 14)
	LM_CALL_STEP(s8, 5 , 51, 21, 23, 10, 52, 3 , 36, 24, 42, 15, 8 )
	mov p_out, first_c//5
	LM_CALL_STEP(s1, 56, 39, 47, 3 , 38, 18, 51, 27, 52, 5 , 60, 33)
	LM_CALL_STEP(s2, 52, 19, 60, 55, 43, 46, 59, 40, 48, 6 , 32, 11)
	LM_CALL_STEP(s3, 48, 20, 32, 17, 46, 25, 54, 26, 57, 41, 36, 54)
	LM_CALL_STEP(s4, 57, 53, 36, 47, 49, 48, 62, 24, 41, 32, 33, 12)
	LM_CALL_STEP(s5, 41, 30, 33, 21, 39, 15, 55, 2 , 45, 45, 63, 42)
	LM_CALL_STEP(s6, 45, 8 , 63, 23, 58, 14, 34, 31, 40, 29, 50, 52)
	LM_CALL_STEP(s7, 40, 51, 50, 0 , 44, 16, 61, 49, 37, 36, 53, 28)
	LM_CALL_STEP(s8, 37, 38, 53, 37, 42, 7 , 35, 50, 56, 1 , 47, 22)
	//6
	LM_CALL_STEP(s1, 24, 53, 15, 17, 6 , 32, 19, 41, 20, 19, 28, 47)
	LM_CALL_STEP(s2, 20, 33, 28, 12, 11, 3 , 27, 54, 16, 20, 0 , 25)
	LM_CALL_STEP(s3, 16, 34, 0 , 6 , 14, 39, 22, 40, 25, 55, 4 , 11)
	LM_CALL_STEP(s4, 25, 10, 4 , 4 , 17, 5 , 30, 13, 9 , 46, 1 , 26)
	LM_CALL_STEP(s5, 9 , 44, 1 , 35, 7 , 29, 23, 16, 13, 0 , 31, 1 )
	LM_CALL_STEP(s6, 13, 22, 31, 37, 26, 28, 2 , 45, 8 , 43, 18, 7 )
	LM_CALL_STEP(s7, 8 , 38, 18, 14, 12, 30, 29, 8 , 5 , 50, 21, 42)
	LM_CALL_STEP(s8, 5 , 52, 21, 51, 10, 21, 3 , 9 , 24, 15, 15, 36)
	mov p_out, first_c//7
	LM_CALL_STEP(s1, 56, 10, 47, 6 , 38, 46, 51, 55, 52, 33, 60, 4 )
	LM_CALL_STEP(s2, 52, 47, 60, 26, 43, 17, 59, 11, 48, 34, 32, 39)
	LM_CALL_STEP(s3, 48, 48, 32, 20, 46, 53, 54, 54, 57, 12, 36, 25)
	LM_CALL_STEP(s4, 57, 24, 36, 18, 49, 19, 62, 27, 41, 3 , 33, 40)
	LM_CALL_STEP(s5, 41, 31, 33, 49, 39, 43, 55, 30, 45, 14, 63, 15)
	LM_CALL_STEP(s6, 45, 36, 63, 51, 58, 42, 34, 0 , 40, 2 , 50, 21)
	LM_CALL_STEP(s7, 40, 52, 50, 28, 44, 44, 61, 22, 37, 9 , 53, 1 )
	LM_CALL_STEP(s8, 37, 7 , 53, 38, 42, 35, 35, 23, 56, 29, 47, 50)
	//8
	LM_CALL_STEP(s1, 24, 24, 15, 20, 6 , 3 , 19, 12, 20, 47, 28, 18)
	LM_CALL_STEP(s2, 20, 4 , 28, 40, 11, 6 , 27, 25, 16, 48, 0 , 53)
	LM_CALL_STEP(s3, 16, 5 , 0 , 34, 14, 10, 22, 11, 25, 26, 4 , 39)
	LM_CALL_STEP(s4, 25, 13, 4 , 32, 17, 33, 30, 41, 9 , 17, 1 , 54)
	LM_CALL_STEP(s5, 9 , 45, 1 , 8 , 7 , 2 , 23, 44, 13, 28, 31, 29)
	LM_CALL_STEP(s6, 13, 50, 31, 38, 26, 1 , 2 , 14, 8 , 16, 18, 35)
	LM_CALL_STEP(s7, 8 , 7 , 18, 42, 12, 31, 29, 36, 5 , 23, 21, 15)
	LM_CALL_STEP(s8, 5 , 21, 21, 52, 10, 49, 3 , 37, 24, 43, 15, 9 )
	mov p_out, first_c//9
	LM_CALL_STEP(s1, 56, 6 , 47, 27, 38, 10, 51, 19, 52, 54, 60, 25)
	LM_CALL_STEP(s2, 52, 11, 60, 47, 43, 13, 59, 32, 48, 55, 32, 3 )
	LM_CALL_STEP(s3, 48, 12, 32, 41, 46, 17, 54, 18, 57, 33, 36, 46)
	LM_CALL_STEP(s4, 57, 20, 36, 39, 49, 40, 62, 48, 41, 24, 33, 4 )
	LM_CALL_STEP(s5, 41, 52, 33, 15, 39, 9 , 55, 51, 45, 35, 63, 36)
	LM_CALL_STEP(s6, 45, 2 , 63, 45, 58, 8 , 34, 21, 40, 23, 50, 42)
	LM_CALL_STEP(s7, 40, 14, 50, 49, 44, 38, 61, 43, 37, 30, 53, 22)
	LM_CALL_STEP(s8, 37, 28, 53, 0 , 42, 1 , 35, 44, 56, 50, 47, 16)
	//10
	LM_CALL_STEP(s1, 24, 20, 15, 41, 6 , 24, 19, 33, 20, 11, 28, 39)
	LM_CALL_STEP(s2, 20, 25, 28, 4 , 11, 27, 27, 46, 16, 12, 0 , 17)
	LM_CALL_STEP(s3, 16, 26, 0 , 55, 14, 6 , 22, 32, 25, 47, 4 , 3 )
	LM_CALL_STEP(s4, 25, 34, 4 , 53, 17, 54, 30, 5 , 9 , 13, 1 , 18)
	LM_CALL_STEP(s5, 9 , 7 , 1 , 29, 7 , 23, 23, 38, 13, 49, 31, 50)
	LM_CALL_STEP(s6, 13, 16, 31, 0 , 26, 22, 2 , 35, 8 , 37, 18, 1 )
	LM_CALL_STEP(s7, 8 , 28, 18, 8 , 12, 52, 29, 2 , 5 , 44, 21, 36)
	LM_CALL_STEP(s8, 5 , 42, 21, 14, 10, 15, 3 , 31, 24, 9 , 15, 30)
	mov p_out, first_c//11
	LM_CALL_STEP(s1, 56, 34, 47, 55, 38, 13, 51, 47, 52, 25, 60, 53)
	LM_CALL_STEP(s2, 52, 39, 60, 18, 43, 41, 59, 3 , 48, 26, 32, 6 )
	LM_CALL_STEP(s3, 48, 40, 32, 12, 46, 20, 54, 46, 57, 4 , 36, 17)
	LM_CALL_STEP(s4, 57, 48, 36, 10, 49, 11, 62, 19, 41, 27, 33, 32)
	LM_CALL_STEP(s5, 41, 21, 33, 43, 39, 37, 55, 52, 45, 8 , 63, 9 )
	LM_CALL_STEP(s6, 45, 30, 63, 14, 58, 36, 34, 49, 40, 51, 50, 15)
	LM_CALL_STEP(s7, 40, 42, 50, 22, 44, 7 , 61, 16, 37, 31, 53, 50)
	LM_CALL_STEP(s8, 37, 1 , 53, 28, 42, 29, 35, 45, 56, 23, 47, 44)
	//12
	LM_CALL_STEP(s1, 24, 48, 15, 12, 6 , 27, 19, 4 , 20, 39, 28, 10)
	LM_CALL_STEP(s2, 20, 53, 28, 32, 11, 55, 27, 17, 16, 40, 0 , 20)
	LM_CALL_STEP(s3, 16, 54, 0 , 26, 14, 34, 22, 3 , 25, 18, 4 , 6 )
	LM_CALL_STEP(s4, 25, 5 , 4 , 24, 17, 25, 30, 33, 9 , 41, 1 , 46)
	LM_CALL_STEP(s5, 9 , 35, 1 , 2 , 7 , 51, 23, 7 , 13, 22, 31, 23)
	LM_CALL_STEP(s6, 13, 44, 31, 28, 26, 50, 2 , 8 , 8 , 38, 18, 29)
	LM_CALL_STEP(s7, 8 , 1 , 18, 36, 12, 21, 29, 30, 5 , 45, 21, 9 )
	LM_CALL_STEP(s8, 5 , 15, 21, 42, 10, 43, 3 , 0 , 24, 37, 15, 31)
	mov p_out, first_c//13
	LM_CALL_STEP(s1, 56, 5 , 47, 26, 38, 41, 51, 18, 52, 53, 60, 24)
	LM_CALL_STEP(s2, 52, 10, 60, 46, 43, 12, 59, 6 , 48, 54, 32, 34)
	LM_CALL_STEP(s3, 48, 11, 32, 40, 46, 48, 54, 17, 57, 32, 36, 20)
	LM_CALL_STEP(s4, 57, 19, 36, 13, 49, 39, 62, 47, 41, 55, 33, 3 )
	LM_CALL_STEP(s5, 41, 49, 33, 16, 39, 38, 55, 21, 45, 36, 63, 37)
	LM_CALL_STEP(s6, 45, 31, 63, 42, 58, 9 , 34, 22, 40, 52, 50, 43)
	LM_CALL_STEP(s7, 40, 15, 50, 50, 44, 35, 61, 44, 37, 0 , 53, 23)
	LM_CALL_STEP(s8, 37, 29, 53, 1 , 42, 2 , 35, 14, 56, 51, 47, 45)
	//14
	LM_CALL_STEP(s1, 24, 19, 15, 40, 6 , 55, 19, 32, 20, 10, 28, 13)
	LM_CALL_STEP(s2, 20, 24, 28, 3 , 11, 26, 27, 20, 16, 11, 0 , 48)
	LM_CALL_STEP(s3, 16, 25, 0 , 54, 14, 5 , 22, 6 , 25, 46, 4 , 34)
	LM_CALL_STEP(s4, 25, 33, 4 , 27, 17, 53, 30, 4 , 9 , 12, 1 , 17)
	LM_CALL_STEP(s5, 9 , 8 , 1 , 30, 7 , 52, 23, 35, 13, 50, 31, 51)
	LM_CALL_STEP(s6, 13, 45, 31, 1 , 26, 23, 2 , 36, 8 , 7 , 18, 2 )
	LM_CALL_STEP(s7, 8 , 29, 18, 9 , 12, 49, 29, 31, 5 , 14, 21, 37)
	LM_CALL_STEP(s8, 5 , 43, 21, 15, 10, 16, 3 , 28, 24, 38, 15, 0 )
	mov p_out, first_c//15
	LM_CALL_STEP(s1, 56, 33, 47, 54, 38, 12, 51, 46, 52, 24, 60, 27)
	LM_CALL_STEP(s2, 52, 13, 60, 17, 43, 40, 59, 34, 48, 25, 32, 5 )

  add i, i, #1
  add first_k, first_k, #16
  add first_c, first_c, #16
  cmp i, #(MAX_REPEAT)
  blo init_while

  pop {lr}
  pop  {r4,r5,r6,r7}
  vpop {q4,q5,q6,q7}
  bx lr


// Charset
#define buffer r0
#define value r1
#define size r2

 	.text
	.align	2
	.global	memset_uint_neon
	.type	memset_uint_neon, %function
memset_uint_neon:
	vdup.u32 q0, value
	vmov q1, q0

while:
	vst1.u32 {q0,q1}, [buffer:128]!
	vst1.u32 {q0,q1}, [buffer:128]!
	sub size, size, #16
	cmp size, #0
	bgt while

	bx lr
