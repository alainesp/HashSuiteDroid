// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2015 by Alain Espinosa. See LICENSE.

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
	veor.u32 t1, c1, d1;\
	veor.u32 t2, c2, d2;\
	vbsl t1, b1, c1;\
	vbsl t2, b2, c2;\
	vadd.u32 a1, a1, sqrt_2;\
	vadd.u32 a2, a2, sqrt_2;\
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
#define t7 q12
#define t8 q13

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
#define REG_BYTE_SIZE 16

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

#define TABLE_LOOKUP(reg_val1,reg_val2,INDEXS_POS) \
  vdup.u32 t5, size_bit_table_reg;\
  vmov.u32 t6, #31;\
\
  vand.u32 t1, reg_val1, t5;\
  vand.u32 t2, reg_val2, t5;\
  vand.u32 t3, t1, t6;\
  vand.u32 t4, t2, t6;\
  vshr.u32 t1, t1, #(5-2);\
  vshr.u32 t2, t2, #(5-2);\
  vbic.u32 t1, t1, #3;\
  vbic.u32 t2, t2, #3;\
  vneg.s32 t3, t3;\
  vneg.s32 t4, t4;\
\
  vmov.u32 r12, t1_0;\
  vmov.u32 r9 , t2_0;\
  ldr r12, [table_ptr, r12];\
  ldr r9 , [table_ptr, r9];\
  vmov.u32 t5_0, r12;\
  vmov.u32 t6_0, r9;\
\
  vmov.u32 r12, t1_1;\
  vmov.u32 r9 , t2_1;\
  ldr r12, [table_ptr, r12];\
  ldr r9 , [table_ptr, r9];\
  vmov.u32 t5_1, r12;\
  vmov.u32 t6_1, r9;\
\
  vmov.u32 r12, t1_2;\
  vmov.u32 r9 , t2_2;\
  ldr r12, [table_ptr, r12];\
  ldr r9 , [table_ptr, r9];\
  vmov.u32 t5_2, r12;\
  vmov.u32 t6_2, r9;\
\
  vmov.u32 r12, t1_3;\
  vmov.u32 r9 , t2_3;\
  ldr r12, [table_ptr, r12];\
  ldr r9 , [table_ptr, r9];\
  vmov.u32 t5_3, r12;\
  vmov.u32 t6_3, r9;\
\
  vshl.u32 t5, t5, t3;\
  vmov.u32 t1, #1;\
  vshl.u32 t6, t6, t4;\
  vand.u32 t5, t5, t1;\
  vand.u32 t6, t6, t1;\
\
  add nt_buffer, nt_buffer_base, #(INDEXS_POS*4*NT_NUM_KEYS);\
  vst1.u32 {t5,t6}, [nt_buffer:128];
 
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
  
  // Table look-up
  TABLE_LOOKUP(reg_b1,reg_b2,20)

  add i,i,#1
  add nt_buffer_base, nt_buffer_base, #(2*16)
  cmp i, #(NT_NUM_KEYS/(16/2))
  blo while1
	
  pop  {r8,r9,r10,r11}
  pop  {r4,r5,r6,r7}
  vpop {q4,q5,q6,q7}
  bx lr
  
/////////////////////////////////////////////////////////////////////////////////////////////////
// MD5
/////////////////////////////////////////////////////////////////////////////////////////////////
#define MD5_LOAD_CONST(t_const,const_val) \
	SET_REG(r5,const_val);\
	vdup.u32 t_const, r5;

#define MD5_LOAD_BUFFER(a1,a2,index,t_const,const_val,t1,t2)	\
	add nt_buffer, nt_buffer_base, #(4*index*NT_NUM_KEYS);\
	vld1.u32 {t1,t2}, [nt_buffer:128];\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	MD5_LOAD_CONST(t_const,const_val)

#define MD5_LOAD_BUFFER_0(a1,a2,t_const,const_val,t1,t2)	\
	vld1.u32 {t1,t2}, [nt_buffer_base:128];\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	MD5_LOAD_CONST(t_const,const_val)

#define MD5_LOAD_BUFFER_6(a1,a2,t_const,const_val,t1,t2)	\
	vadd.u32 a1, a1, t7;\
	vadd.u32 a2, a2, t8;\
	MD5_LOAD_CONST(t_const,const_val)
	
#define MD5_LOAD_BUFFER_7(a1,a2,t_const,const_val,t1,t2)	\
	vadd.u32 a1, a1, t5;\
	vadd.u32 a2, a2, t6;\
	MD5_LOAD_CONST(t_const,const_val)

#define MD5_LOAD_BUFFER_1(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_BUFFER(a1,a2,1,t_const,const_val,t1,t2)
#define MD5_LOAD_BUFFER_2(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_BUFFER(a1,a2,2,t_const,const_val,t1,t2)
#define MD5_LOAD_BUFFER_3(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_BUFFER(a1,a2,3,t_const,const_val,t1,t2)
#define MD5_LOAD_BUFFER_4(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_BUFFER(a1,a2,4,t_const,const_val,t1,t2)
#define MD5_LOAD_BUFFER_5(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_BUFFER(a1,a2,5,t_const,const_val,t1,t2)

#define MD5_LOAD_BUFFER_8(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_9(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_10(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_11(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_12(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_13(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_14(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)
#define MD5_LOAD_BUFFER_15(a1,a2,t_const,const_val,t1,t2)		MD5_LOAD_CONST(t_const,const_val)

#define MD5_STEP1(a1,b1,c1,d1,a2,b2,c2,d2,b1_sum,b2_sum,index,rot,t1,t2,t_const,const_val) \
	MD5_LOAD_BUFFER_ ## index (a1,a2,t_const,const_val,t1,t2)\
	vmov.u32 t1, b1;\
	vmov.u32 t2, b2;\
	vbsl t1, c1, d1;\
	vbsl t2, c2, d2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	vadd.u32 a1, a1, t_const;\
	vadd.u32 a2, a2, t_const;\
	ROTATE(a1, a2, rot,t1,t2);\
	vadd.u32 a1, a1, b1_sum;\
	vadd.u32 a2, a2, b2_sum
	
#define MD5_STEP3(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,t1,t2,t_const,const_val) \
	MD5_LOAD_BUFFER_ ## index (a1,a2,t_const,const_val,t1,t2)\
	veor.u32 t1, d1, c1;\
	veor.u32 t2, d2, c2;\
	vadd.u32 a1, a1, t_const;\
	vadd.u32 a2, a2, t_const;\
	veor.u32 t1, t1, b1;\
	veor.u32 t2, t2, b2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1, a2, rot,t1,t2);\
	vadd.u32 a1, a1, b1;\
	vadd.u32 a2, a2, b2

#define MD5_STEP4(a1,b1,c1,d1,a2,b2,c2,d2,index,rot,t1,t2,t_const,const_val) \
	MD5_LOAD_BUFFER_ ## index (a1,a2,t_const,const_val,t1,t2)\
	vorn.u32 t1, b1, d1;\
	vorn.u32 t2, b2, d2;\
	vadd.u32 a1, a1, t_const;\
	vadd.u32 a2, a2, t_const;\
	veor.u32 t1, t1, c1;\
	veor.u32 t2, t2, c2;\
	vadd.u32 a1, a1, t1;\
	vadd.u32 a2, a2, t2;\
	ROTATE(a1, a2, rot,t1,t2);\
	vadd.u32 a1, a1, b1;\
	vadd.u32 a2, a2, b2

	.text
	.align	2
	.global	crypt_md5_neon_kernel_asm
	.type	crypt_md5_neon_kernel_asm, %function
crypt_md5_neon_kernel_asm:
  vpush {q4,q5,q6,q7}
  push	{r4,r5,r6,r7}
  push	{r8,r9,r10,r11}
  
  SET_REG(r6,0xefcdab89)
  SET_REG(r7,0x98badcfe)
  
  mov i, #0	// i=0
md5_while1:
  // Round 1
  vdup.u32 t5, r6
  vdup.u32 t6, r7
  SET_REG(r5,0xd76aa477)
  vdup.u32 t7, r5
 
  add nt_buffer, nt_buffer_base, #(4*1*NT_NUM_KEYS);
  vld1.u32 {reg_d1,reg_d2}, [nt_buffer:128];
  add nt_buffer, nt_buffer_base, #(4*2*NT_NUM_KEYS);
  vld1.u32 {reg_c1,reg_c2}, [nt_buffer:128];
  add nt_buffer, nt_buffer_base, #(4*3*NT_NUM_KEYS);
  vld1.u32 {reg_b1,reg_b2}, [nt_buffer:128];
  
  vld1.u32 {reg_a1,reg_a2}, [nt_buffer_base:128]// First step
  vadd.u32 reg_a1, reg_a1, t7
  vadd.u32 reg_a2, reg_a2, t7

  ROTATE(reg_a1,reg_a2,7,t1,t2)
  vadd.u32 reg_a1, reg_a1, t5
  vadd.u32 reg_a2, reg_a2, t5
  
  MD5_STEP1( reg_d1, reg_a1, 	t5, 	t6, reg_d2, reg_a2, 	t5, 	t6, reg_a1, reg_a2, 8 , 12,t1,t2,t3,0xf8fa0bcc)
  MD5_STEP1( reg_c1, reg_d1, reg_a1, 	t5, reg_c2, reg_d2, reg_a2, 	t5, reg_d1, reg_d2, 8 , 17,t1,t2,t3,0xbcdb4dd9)
  MD5_STEP1( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, reg_c1, reg_c2, 8 , 22,t1,t2,t3,0xb18b7a77)
  
  add nt_buffer, nt_buffer_base, #(4*7*NT_NUM_KEYS);
  vld1.u32 {t5,t6}, [nt_buffer:128];
  add nt_buffer, nt_buffer_base, #(4*6*NT_NUM_KEYS);
  vld1.u32 {t7,t8}, [nt_buffer:128];

  MD5_STEP1( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, reg_b1, reg_b2, 4 , 7 ,t1,t2,t3,0xf57c0faf)
  MD5_STEP1( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, reg_a1, reg_a2, 5 , 12,t1,t2,t3,0x4787c62a)
  MD5_STEP1( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, reg_d1, reg_d2, 6 , 17,t1,t2,t3,0xa8304613)
  MD5_STEP1( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, reg_c1, reg_c2, 8 , 22,t1,t2,t3,0xfd469501)

  MD5_STEP1( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, reg_b1, reg_b2, 8 , 7 ,t1,t2,t3,0x698098d8)
  MD5_STEP1( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, reg_a1, reg_a2, 9 , 12,t1,t2,t3,0x8b44f7af)
  MD5_STEP1( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, reg_d1, reg_d2, 10, 17,t1,t2,t3,0xffff5bb1)
  MD5_STEP1( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, reg_c1, reg_c2, 11, 22,t1,t2,t3,0x895cd7be)

  MD5_STEP1( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, reg_b1, reg_b2, 12, 7 ,t1,t2,t3,0x6b901122)
  MD5_STEP1( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, reg_a1, reg_a2, 13, 12,t1,t2,t3,0xfd987193)
  MD5_STEP1( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, reg_d1, reg_d2, 7 , 17,t1,t2,t3,0xa679438e)
  MD5_STEP1( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, reg_c1, reg_c2, 15, 22,t1,t2,t3,0x49b40821)
  
  // Round 2
  MD5_STEP1( reg_a1, reg_d1, reg_b1, reg_c1, reg_a2, reg_d2, reg_b2, reg_c2, reg_b1, reg_b2, 1, 5 ,t1,t2,t3,0xf61e2562)
  MD5_STEP1( reg_d1, reg_c1, reg_a1, reg_b1, reg_d2, reg_c2, reg_a2, reg_b2, reg_a1, reg_a2, 6, 9 ,t1,t2,t3,0xc040b340)
  MD5_STEP1( reg_c1, reg_b1, reg_d1, reg_a1, reg_c2, reg_b2, reg_d2, reg_a2, reg_d1, reg_d2, 8, 14,t1,t2,t3,0x265e5a51)
  MD5_STEP1( reg_b1, reg_a1, reg_c1, reg_d1, reg_b2, reg_a2, reg_c2, reg_d2, reg_c1, reg_c2, 0, 20,t1,t2,t3,0xe9b6c7aa)

  MD5_STEP1( reg_a1, reg_d1, reg_b1, reg_c1, reg_a2, reg_d2, reg_b2, reg_c2, reg_b1, reg_b2, 5, 5 ,t1,t2,t3,0xd62f105d)
  MD5_STEP1( reg_d1, reg_c1, reg_a1, reg_b1, reg_d2, reg_c2, reg_a2, reg_b2, reg_a1, reg_a2, 8, 9 ,t1,t2,t3,0x02441453)
  MD5_STEP1( reg_c1, reg_b1, reg_d1, reg_a1, reg_c2, reg_b2, reg_d2, reg_a2, reg_d1, reg_d2, 8, 14,t1,t2,t3,0xd8a1e681)
  MD5_STEP1( reg_b1, reg_a1, reg_c1, reg_d1, reg_b2, reg_a2, reg_c2, reg_d2, reg_c1, reg_c2, 4, 20,t1,t2,t3,0xe7d3fbc8)

  MD5_STEP1( reg_a1, reg_d1, reg_b1, reg_c1, reg_a2, reg_d2, reg_b2, reg_c2, reg_b1, reg_b2, 8, 5 ,t1,t2,t3,0x21e1cde6)
  MD5_STEP1( reg_d1, reg_c1, reg_a1, reg_b1, reg_d2, reg_c2, reg_a2, reg_b2, reg_a1, reg_a2, 7, 9 ,t1,t2,t3,0xc33707d6)
  MD5_STEP1( reg_c1, reg_b1, reg_d1, reg_a1, reg_c2, reg_b2, reg_d2, reg_a2, reg_d1, reg_d2, 3, 14,t1,t2,t3,0xf4d50d87)
  MD5_STEP1( reg_b1, reg_a1, reg_c1, reg_d1, reg_b2, reg_a2, reg_c2, reg_d2, reg_c1, reg_c2, 8, 20,t1,t2,t3,0x455a14ed)

  MD5_STEP1( reg_a1, reg_d1, reg_b1, reg_c1, reg_a2, reg_d2, reg_b2, reg_c2, reg_b1, reg_b2, 8, 5 ,t1,t2,t3,0xa9e3e905)
  MD5_STEP1( reg_d1, reg_c1, reg_a1, reg_b1, reg_d2, reg_c2, reg_a2, reg_b2, reg_a1, reg_a2, 2, 9 ,t1,t2,t3,0xfcefa3f8)
  MD5_STEP1( reg_c1, reg_b1, reg_d1, reg_a1, reg_c2, reg_b2, reg_d2, reg_a2, reg_d1, reg_d2, 8, 14,t1,t2,t3,0x676f02d9)
  MD5_STEP1( reg_b1, reg_a1, reg_c1, reg_d1, reg_b2, reg_a2, reg_c2, reg_d2, reg_c1, reg_c2, 8, 20,t1,t2,t3,0x8d2a4c8a)
  
// Round 3
  MD5_STEP3( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 5, 4 ,t1,t2,t3,0xfffa3942)
  MD5_STEP3( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8, 11,t1,t2,t3,0x8771f681)
  MD5_STEP3( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8, 16,t1,t2,t3,0x6d9d6122)
  MD5_STEP3( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 7, 23,t1,t2,t3,0xfde5380c)

  MD5_STEP3( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 1, 4 ,t1,t2,t3,0xa4beea44)
  MD5_STEP3( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 4, 11,t1,t2,t3,0x4bdecfa9)
  MD5_STEP3( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8, 16,t1,t2,t3,0xf6bb4b60)
  MD5_STEP3( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 8, 23,t1,t2,t3,0xbebfbc70)

  MD5_STEP3( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8, 4 ,t1,t2,t3,0x289b7ec6)
  MD5_STEP3( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 0, 11,t1,t2,t3,0xeaa127fa)
  MD5_STEP3( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 3, 16,t1,t2,t3,0xd4ef3085)
  MD5_STEP3( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 6, 23,t1,t2,t3,0x04881d05)

  MD5_STEP3( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8, 4 ,t1,t2,t3,0xd9d4d039)
  MD5_STEP3( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8, 11,t1,t2,t3,0xe6db99e5)
  MD5_STEP3( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8, 16,t1,t2,t3,0x1fa27cf8)
  MD5_STEP3( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 2, 23,t1,t2,t3,0xc4ac5665)
// Round 4
  MD5_STEP4( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 0, 6 ,t1,t2,t3,0xf4292244)
  MD5_STEP4( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8, 10,t1,t2,t3,0x432aff97)
  MD5_STEP4( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 7, 15,t1,t2,t3,0xab9423a7)
  MD5_STEP4( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 5, 21,t1,t2,t3,0xfc93a039)

  MD5_STEP4( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8, 6 ,t1,t2,t3,0x655b59c3)
  MD5_STEP4( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 3, 10,t1,t2,t3,0x8f0ccc92)
  MD5_STEP4( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 8, 15,t1,t2,t3,0xffeff47d)
  MD5_STEP4( reg_b1, reg_c1, reg_d1, reg_a1, reg_b2, reg_c2, reg_d2, reg_a2, 1, 21,t1,t2,t3,0x85845dd1)

  MD5_STEP4( reg_a1, reg_b1, reg_c1, reg_d1, reg_a2, reg_b2, reg_c2, reg_d2, 8, 6 ,t1,t2,t3,0x6fa87e4f)
  MD5_STEP4( reg_d1, reg_a1, reg_b1, reg_c1, reg_d2, reg_a2, reg_b2, reg_c2, 8, 10,t1,t2,t3,0xfe2ce6e0)
  MD5_STEP4( reg_c1, reg_d1, reg_a1, reg_b1, reg_c2, reg_d2, reg_a2, reg_b2, 6, 15,t1,t2,t3,0xa3014314)
  add nt_buffer, nt_buffer_base, #(4*2*NT_NUM_KEYS)
  vld1.u32 {t1,t2}, [nt_buffer:128]
  vadd.u32 reg_c1, reg_c1, t1
  vadd.u32 reg_c2, reg_c2, t2
  
  // Save a, c, d, b
   add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+1*4*NT_NUM_KEYS)
  vst1.u32 {reg_b1,reg_b2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+0*4*NT_NUM_KEYS)
  vst1.u32 {reg_a1,reg_a2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+3*4*NT_NUM_KEYS)
  vst1.u32 {reg_d1,reg_d2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+2*4*NT_NUM_KEYS)
  vst1.u32 {reg_c1,reg_c2}, [nt_buffer:128]
  
  // Table look-up
  TABLE_LOOKUP(reg_c1,reg_c2,12)
  
  add i,i,#1
  add nt_buffer_base, nt_buffer_base, #(2*REG_BYTE_SIZE)
  cmp i, #(NT_NUM_KEYS/(REG_BYTE_SIZE/2))
  blo md5_while1
	
  pop  {r8,r9,r10,r11}
  pop  {r4,r5,r6,r7}
  vpop {q4,q5,q6,q7}
  bx lr
  
/////////////////////////////////////////////////////////////////////////////////////////////////
// SHA1
/////////////////////////////////////////////////////////////////////////////////////////////////
#undef t7
#undef t8
#define reg_e1 q12
#define reg_e2 q13
#define step_const q15

#define ROTATE_1(reg1,reg2,t1,t2)	\
    vshr.u32 t1  , reg1, #(31);\
	vshr.u32 t2  , reg2, #(31);\
	vadd.u32 reg1, reg1, reg1;\
	vadd.u32 reg2, reg2, reg2;\
	vorr.u32 reg1, reg1, t1;\
	vorr.u32 reg2, reg2, t2;
	
#define DCC2_ROTATE_5(reg1,reg2,t1,t2,t3,t4) \
    vshr.u32 t1, reg1, #(32-5);\
	vshr.u32 t3, reg2, #(32-5);\
	vshl.u32 t2, reg1, #(5);\
	vshl.u32 t4, reg2, #(5);\
	vorr.u32 t1, t2, t1;\
	vorr.u32 t3, t4, t3;

	
#define CVT_BIG_ENDIAN_AND_CALCULATE_W(t00,t01,t10,t11,t20,t21,t30,t31,t40,t41,t50,t51,t60,t61,tmp0,tmp1) \
	vld1.u32 {t00,t01}, [nt_buffer_base:128];\
	vrev32.u8 t00,t00;\
	vrev32.u8 t01,t01;\
	vst1.u32 {t00,t01}, [nt_buffer_base:128];\
\
	add nt_buffer, nt_buffer_base, #(1*4*NT_NUM_KEYS);\
	vld1.u32 {t10,t11}, [nt_buffer:128];\
	vrev32.u8 t10,t10;\
	vrev32.u8 t11,t11;\
	vst1.u32 {t10,t11}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(2*4*NT_NUM_KEYS);\
	vld1.u32 {t20,t21}, [nt_buffer:128];\
	vrev32.u8 t20,t20;\
	vrev32.u8 t21,t21;\
	vst1.u32 {t20,t21}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(3*4*NT_NUM_KEYS);\
	vld1.u32 {t30,t31}, [nt_buffer:128];\
	vrev32.u8 t30,t30;\
	vrev32.u8 t31,t31;\
	vst1.u32 {t30,t31}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(4*4*NT_NUM_KEYS);\
	vld1.u32 {t40,t41}, [nt_buffer:128];\
	vrev32.u8 t40,t40;\
	vrev32.u8 t41,t41;\
	vst1.u32 {t40,t41}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(5*4*NT_NUM_KEYS);\
	vld1.u32 {t50,t51}, [nt_buffer:128];\
	vrev32.u8 t50,t50;\
	vrev32.u8 t51,t51;\
	vst1.u32 {t50,t51}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(6*4*NT_NUM_KEYS);\
	vld1.u32 {t60,t61}, [nt_buffer:128];\
	vrev32.u8 t60,t60;\
	vrev32.u8 t61,t61;\
	vst1.u32 {t60,t61}, [nt_buffer:128];\
\
	veor.u32 t00,t00,t20;\
	veor.u32 t01,t01,t21;\
	ROTATE_1(t00,t01,tmp0,tmp1);\
	veor.u32 t10,t10,t30;\
	veor.u32 t11,t11,t31;\
	ROTATE_1(t10,t11,tmp0,tmp1)\
	veor.u32 t20,t20,t40;\
	veor.u32 t21,t21,t41;\
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t20,t20,tmp0;\
	veor.u32 t21,t21,tmp1;\
	ROTATE_1(t20,t21,tmp0,tmp1);\
	veor.u32 t30,t30,t00;\
	veor.u32 t31,t31,t01;\
	veor.u32 t30,t30,t50;\
	veor.u32 t31,t31,t51;\
	ROTATE_1(t30,t31,tmp0,tmp1);\
	veor.u32 t40,t40,t10;\
	veor.u32 t41,t41,t11;\
	veor.u32 t40,t40,t60;\
	veor.u32 t41,t41,t61;\
	ROTATE_1(t40,t41,tmp0,tmp1);\
	veor.u32 t50,t50,t20;\
	veor.u32 t51,t51,t21;\
	ROTATE_1(t50,t51,tmp0,tmp1);\
	veor.u32 t60,t60,t30;\
	veor.u32 t61,t61,t31;\
	ROTATE_1(t60,t61,tmp0,tmp1);\
\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+0*4*NT_NUM_KEYS);\
	vst1.u32 {t00,t01}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+1*4*NT_NUM_KEYS);\
	vst1.u32 {t10,t11}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+2*4*NT_NUM_KEYS);\
	vst1.u32 {t20,t21}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+3*4*NT_NUM_KEYS);\
	vst1.u32 {t30,t31}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+4*4*NT_NUM_KEYS);\
	vst1.u32 {t40,t41}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+5*4*NT_NUM_KEYS);\
	vst1.u32 {t50,t51}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+6*4*NT_NUM_KEYS);\
	vst1.u32 {t60,t61}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t40,t40,tmp0;\
	veor.u32 t41,t41,tmp1;\
	ROTATE_1(t40,t41,tmp0,tmp1);\
	veor.u32 t00,t00,t50;\
	veor.u32 t01,t01,t51;\
	ROTATE_1(t00,t01,tmp0,tmp1);\
	veor.u32 t10,t10,t60;\
	veor.u32 t11,t11,t61;\
	ROTATE_1(t10,t11,tmp0,tmp1);\
	veor.u32 t20,t20,t40;\
	veor.u32 t21,t21,t41;\
	ROTATE_1(t20,t21,tmp0,tmp1);\
	veor.u32 t30,t30,t00;\
	veor.u32 t31,t31,t01;\
	ROTATE_1(t30,t31,tmp0,tmp1);\
\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+7*4*NT_NUM_KEYS);\
	vst1.u32 {t40,t41}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+8*4*NT_NUM_KEYS);\
	vst1.u32 {t00,t01}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+9*4*NT_NUM_KEYS);\
	vst1.u32 {t10,t11}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+10*4*NT_NUM_KEYS);\
	vst1.u32 {t20,t21}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+11*4*NT_NUM_KEYS);\
	vst1.u32 {t30,t31}, [nt_buffer:128];\
\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+4*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t10,t10,tmp0;\
	veor.u32 t11,t11,tmp1;\
	ROTATE_1(t10,t11,tmp0,tmp1);\
\
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t50,t50,tmp0;\
	veor.u32 t51,t51,tmp1;\
	veor.u32 t50,t50,t20;\
	veor.u32 t51,t51,t21;\
	ROTATE_1(t50,t51,tmp0,tmp1);\
\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+0*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t60,t60,tmp0;\
	veor.u32 t61,t61,tmp1;\
	veor.u32 t60,t60,t30;\
	veor.u32 t61,t61,t31;\
	ROTATE_1(t60,t61,tmp0,tmp1);\
\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+1*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t40,t40,tmp0;\
	veor.u32 t41,t41,tmp1;\
	veor.u32 t40,t40,t10;\
	veor.u32 t41,t41,t11;\
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS);\
	vld1.u32 {tmp0,tmp1}, [nt_buffer:128];\
	veor.u32 t40,t40,tmp0;\
	veor.u32 t41,t41,tmp1;\
	ROTATE_1(t40,t41,tmp0,tmp1);\
\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+12*4*NT_NUM_KEYS);\
	vst1.u32 {t10,t11}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+13*4*NT_NUM_KEYS);\
	vst1.u32 {t50,t51}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+14*4*NT_NUM_KEYS);\
	vst1.u32 {t60,t61}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+15*4*NT_NUM_KEYS);\
	vst1.u32 {t40,t41}, [nt_buffer:128]
	
#define DCC2_STEP1(reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,step_const) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	vmov.u32 t1, reg_b1;\
	vmov.u32 t2, reg_b2;\
	vbsl t1, reg_c1, reg_d1;\
	vbsl t2, reg_c2, reg_d2;\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
	ROTATE(reg_b1, reg_b2, 30, t1, t2)
	
#define SHA1_STEP2(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,index) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_c1, reg_d1;\
	veor.u32 t2, reg_c2, reg_d2;\
	veor.u32 t1, t1, reg_b1;\
	veor.u32 t2, t2, reg_b2;\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+index*4*NT_NUM_KEYS);\
	vld1.u32 {t3,t4}, [nt_buffer:128];\
	vadd.u32 reg_e1, reg_e1, t3;\
	vadd.u32 reg_e2, reg_e2, t4;\
\
	ROTATE(reg_b1, reg_b2, 30, t1, t2)
	
#define SHA1_R(t1,t2,t3,t4,w0,w1,w2,w3) \
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+w1*4*NT_NUM_KEYS);\
	vld1.u32 {t1,t2}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+w2*4*NT_NUM_KEYS);\
	vld1.u32 {t3,t4}, [nt_buffer:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+w3*4*NT_NUM_KEYS);\
	vld1.u32 {t3,t4}, [nt_buffer:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+w0*4*NT_NUM_KEYS);\
	vld1.u32 {t3,t4}, [nt_buffer:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	ROTATE_1(t1, t2, t3, t4)\
	vst1.u32 {t1,t2}, [nt_buffer:128];

#define SHA1_STEP3(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,w0,w1,w2,w3) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_d1, reg_c1;\
	veor.u32 t2, reg_d2, reg_c2;\
	vbsl t1, reg_b1, reg_c1;\
	vbsl t2, reg_b2, reg_c2;\
\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
	ROTATE(reg_b1, reg_b2, 30, t1, t2)\
	SHA1_R(t1,t2,t3,t4,w0,w1,w2,w3)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;
	
#define SHA1_STEP4(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,w0,w1,w2,w3) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_c1, reg_d1;\
	veor.u32 t2, reg_c2, reg_d2;\
	veor.u32 t1, t1, reg_b1;\
	veor.u32 t2, t2, reg_b2;\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
    ROTATE(reg_b1, reg_b2, 30, t1, t2)\
\
	SHA1_R(t1,t2,t3,t4,w0,w1,w2,w3)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;
	
#define SHA1_STEP4_NO_ROT(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,w0,w1,w2,w3) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_c1, reg_d1;\
	veor.u32 t2, reg_c2, reg_d2;\
	veor.u32 t1, t1, reg_b1;\
	veor.u32 t2, t2, reg_b2;\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
	SHA1_R(t1,t2,t3,t4,w0,w1,w2,w3)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;
	

	.text
	.align	2
	.global	crypt_sha1_neon_kernel_asm
	.type	crypt_sha1_neon_kernel_asm, %function
crypt_sha1_neon_kernel_asm:
  vpush {q4,q5,q6,q7}
  push	{r4,r5,r6,r7}
  push	{r8,r9,r10,r11}
  
  mov i, #0	// i=0
sha1_while1:
	CVT_BIG_ENDIAN_AND_CALCULATE_W(reg_a1,reg_a2,reg_b1,reg_b2,reg_c1,reg_c2,reg_d1,reg_d2,reg_e1,reg_e2,t1,t2,t3,t4,t5,t6)
  
	// Load state
	vld1.u32 {reg_e1,reg_e2}, [nt_buffer_base:128]
	add nt_buffer, nt_buffer_base, #(1*4*NT_NUM_KEYS)
	vld1.u32 {reg_d1,reg_d2}, [nt_buffer:128]
	add nt_buffer, nt_buffer_base, #(2*4*NT_NUM_KEYS)
	vld1.u32 {reg_c1,reg_c2}, [nt_buffer:128]
	add nt_buffer, nt_buffer_base, #(3*4*NT_NUM_KEYS)
	vld1.u32 {reg_b1,reg_b2}, [nt_buffer:128]
	add nt_buffer, nt_buffer_base, #(4*4*NT_NUM_KEYS)
	vld1.u32 {reg_a1,reg_a2}, [nt_buffer:128]
	
	//Step 1
	SET_REG(r5,0x9fb498b3)
	vdup.u32 t1, r5
	SET_REG(r5,0x66b0cd0d)
	vdup.u32 t2, r5
	vadd.u32 reg_e1, reg_e1, t1
	vadd.u32 reg_e2, reg_e2, t1
	//Step 2
	vadd.u32 reg_d1, reg_d1, t2
	vadd.u32 reg_d2, reg_d2, t2
	DCC2_ROTATE_5(reg_e1,reg_e2,t3,t4,t5,step_const)
	vadd.u32 reg_d1, reg_d1, t3
	vadd.u32 reg_d2, reg_d2, t5
	//Step 3
	SET_REG(r5,0xf33d5697)
	vdup.u32 step_const, r5
	vadd.u32 reg_c1, reg_c1, step_const
	vadd.u32 reg_c2, reg_c2, step_const
	DCC2_ROTATE_5(reg_d1,reg_d2,t1,t2,t3,t4)
	vadd.u32 reg_c1, reg_c1, t1
	vadd.u32 reg_c2, reg_c2, t3
	
	SET_REG(r5,0x22222222)
	vdup.u32 t2, r5
	SET_REG(r5,0x7bf36ae2)
	vdup.u32 t5, r5
	vand.u32 t4, reg_e1, t2
	vand.u32 t2, reg_e2, t2
	veor.u32 t4, t4, t5
	veor.u32 t2, t2, t5
	vadd.u32 reg_c1, reg_c1, t4
	vadd.u32 reg_c2, reg_c2, t2
	ROTATE(reg_e1,reg_e2,30,t1,t2)
	//Step 4
	SET_REG(r5,0xd675e47b)
	vdup.u32 step_const, r5
	SET_REG(r5,0x59d148c0)
	vdup.u32 t5, r5
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, t5, reg_b2, reg_c2, reg_d2, reg_e2, t5, t1, t2, t3, t4,step_const)
	SET_REG(r5,0xb453c259)
	vdup.u32 step_const, r5
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	//Step 5
	SET_REG(r5,0x5a827999)
	vdup.u32 step_const, r5
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(5*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_e1, reg_e1, t1
	vadd.u32 reg_e2, reg_e2, t2
	//Step 6
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(6*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_d1, reg_d1, t1
	vadd.u32 reg_d2, reg_d2, t2
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_e1, reg_e1, t1
	vadd.u32 reg_e2, reg_e2, t2
	// Recalculate W
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+0*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_d1, reg_d1, t1
	vadd.u32 reg_d2, reg_d2, t2
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+1*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_c1, reg_c1, t1
	vadd.u32 reg_c2, reg_c2, t2
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+2*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_b1, reg_b1, t1
	vadd.u32 reg_b2, reg_b2, t2
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+3*4*NT_NUM_KEYS)
	vld1.u32 {t1,t2}, [nt_buffer:128]
	vadd.u32 reg_a1, reg_a1, t1
	vadd.u32 reg_a2, reg_a2, t2
	
	//Round 2
	SET_REG(r5,0x6ed9eba1)
	vdup.u32 step_const, r5
	SHA1_STEP2(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 4 )
	SHA1_STEP2(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 5 )
	SHA1_STEP2(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 6 )
	SHA1_STEP2(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 7 )
	SHA1_STEP2(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 8 )
	SHA1_STEP2(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 9 )
	SHA1_STEP2(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 10)
	SHA1_STEP2(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 11)
	SHA1_STEP2(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 12)
	SHA1_STEP2(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 13)
	SHA1_STEP2(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 14)
	SHA1_STEP2(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 15)
	SHA1_STEP4(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 0, 13, 8 , 2)
	SHA1_STEP4(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 1, 14, 9 , 3)
	SHA1_STEP4(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 2, 15, 10, 4)
	SHA1_STEP4(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 3, 0 , 11, 5)
	SHA1_STEP4(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 4, 1 , 12, 6)
	SHA1_STEP4(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 5, 2 , 13, 7)
	SHA1_STEP4(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 6, 3 , 14, 8)
	SHA1_STEP4(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 7, 4 , 15, 9)
	
	//Round 3
	SET_REG(r5,0x8F1BBCDC)
	vdup.u32 step_const, r5
	SHA1_STEP3(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 8 , 5 , 0 , 10)
    SHA1_STEP3(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 9 , 6 , 1 , 11)
    SHA1_STEP3(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 10, 7 , 2 , 12)
    SHA1_STEP3(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 11, 8 , 3 , 13)
    SHA1_STEP3(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 12, 9 , 4 , 14)
    SHA1_STEP3(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 13, 10, 5 , 15)
    SHA1_STEP3(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 14, 11, 6 , 0 )
    SHA1_STEP3(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 15, 12, 7 , 1 )
    SHA1_STEP3(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 0 , 13, 8 , 2 )
    SHA1_STEP3(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 1 , 14, 9 , 3 )
    SHA1_STEP3(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 2 , 15, 10, 4 )
    SHA1_STEP3(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 3 , 0 , 11, 5 )
    SHA1_STEP3(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 4 , 1 , 12, 6 )
    SHA1_STEP3(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 5 , 2 , 13, 7 )
    SHA1_STEP3(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 6 , 3 , 14, 8 )
    SHA1_STEP3(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 7 , 4 , 15, 9 )
    SHA1_STEP3(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 8 , 5 , 0 , 10)
    SHA1_STEP3(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 9 , 6 , 1 , 11)
    SHA1_STEP3(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 10, 7 , 2 , 12)
    SHA1_STEP3(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 11, 8 , 3 , 13)
	
	//Round 4
	SET_REG(r5,0xCA62C1D6)
	vdup.u32 step_const, r5
	SHA1_STEP4(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 12, 9 , 4 , 14 )
    SHA1_STEP4(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 13, 10, 5 , 15 )
    SHA1_STEP4(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 14, 11, 6 , 0  )
    SHA1_STEP4(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 15, 12, 7 , 1  )
    SHA1_STEP4(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 0 , 13, 8 , 2  )
    SHA1_STEP4(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 1 , 14, 9 , 3  )
    SHA1_STEP4(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 2 , 15, 10, 4  )
    SHA1_STEP4(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 3 , 0 , 11, 5  )
    SHA1_STEP4(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 4 , 1 , 12, 6  )
    SHA1_STEP4(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 5 , 2 , 13, 7  )
    SHA1_STEP4(step_const,reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 6 , 3 , 14, 8  )
    SHA1_STEP4(step_const,reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 7 , 4 , 15, 9  )
    SHA1_STEP4(step_const,reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 8 , 5 , 0 , 10 )
    SHA1_STEP4(step_const,reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 9 , 6 , 1 , 11 )
    SHA1_STEP4_NO_ROT(step_const,reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 10, 7 , 2 , 12)
	
	SHA1_R(t1,t2,t3,t4,12, 9, 4, 14)
	SHA1_R(t1,t2,t3,t4,15, 12, 7, 1)
	ROTATE(reg_a1,reg_a2,30,t3,t4)
	vadd.u32 reg_a1, reg_a1, t1
	vadd.u32 reg_a2, reg_a2, t2
	
  // Save a, c, d, b, e
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+4*4*NT_NUM_KEYS)
  vst1.u32 {reg_b1,reg_b2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+2*4*NT_NUM_KEYS)
  vst1.u32 {reg_a1,reg_a2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+16*4*NT_NUM_KEYS)
  vst1.u32 {reg_d1,reg_d2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+9*4*NT_NUM_KEYS)
  vst1.u32 {reg_c1,reg_c2}, [nt_buffer:128]
  add nt_buffer, nt_buffer_base, #(8*4*NT_NUM_KEYS+17*4*NT_NUM_KEYS)
  vst1.u32 {reg_e1,reg_e2}, [nt_buffer:128]
  
  // Table look-up
  TABLE_LOOKUP(reg_a1,reg_a2,26)
  
  add i,i,#1
  add nt_buffer_base, nt_buffer_base, #(2*REG_BYTE_SIZE)
  cmp i, #(NT_NUM_KEYS/(REG_BYTE_SIZE/2))
  blo sha1_while1
	
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
	veor.u32 t1, c1, d1;\
	veor.u32 t2, c2, d2;\
	vbsl t1, b1, c1;\
	vbsl t2, b2, c2;\
	vadd.u32 a1, a1, sqrt_2;\
	vadd.u32 a2, a2, sqrt_2;\
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
// DCC2 format
/////////////////////////////////////////////////////////////////////////////////////////////////
#define dcc2_state r0
#define sha1_hash r1
#define W r2
#define tmp_ptr r3
#define tmp_ptr0 r3
#define tmp_ptr1 r4

#define DCC2_ADD(reg1,reg2,w_ptr,index1,index2) \
	add tmp_ptr, w_ptr, #(index1*REG_BYTE_SIZE);\
	vld1.u32 {t1}, [tmp_ptr:128];\
	vadd.u32 reg1, reg1, t1;\
\
	add tmp_ptr, w_ptr, #(index2*REG_BYTE_SIZE);\
	vld1.u32 {t1}, [tmp_ptr:128];\
	vadd.u32 reg2, reg2, t1;
	
#define DCC2_STEP2(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,index) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_c1, reg_d1;\
	veor.u32 t2, reg_c2, reg_d2;\
	veor.u32 t1, t1, reg_b1;\
	veor.u32 t2, t2, reg_b2;\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
	add tmp_ptr, W, #(index*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr:128];\
	add tmp_ptr, W, #((index+16)*REG_BYTE_SIZE);\
	vld1.u32 {t4}, [tmp_ptr:128];\
	vadd.u32 reg_e1, reg_e1, t3;\
	vadd.u32 reg_e2, reg_e2, t4;\
\
	ROTATE(reg_b1, reg_b2, 30, t1, t2)

#define DCC2_STEP3(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,w0,w1,w2,w3) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_d1, reg_c1;\
	veor.u32 t2, reg_d2, reg_c2;\
	vbsl t1, reg_b1, reg_c1;\
	vbsl t2, reg_b2, reg_c2;\
\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
	ROTATE(reg_b1, reg_b2, 30, t1, t2)\
\
	add tmp_ptr0, W, #(w1*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w1+16)*REG_BYTE_SIZE);\
	vld1.u32 {t1}, [tmp_ptr0:128];\
	vld1.u32 {t2}, [tmp_ptr1:128];\
\
	add tmp_ptr0, W, #(w2*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w2+16)*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr0:128];\
	vld1.u32 {t4}, [tmp_ptr1:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	add tmp_ptr0, W, #(w3*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w3+16)*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr0:128];\
	vld1.u32 {t4}, [tmp_ptr1:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	add tmp_ptr0, W, #(w0*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w0+16)*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr0:128];\
	vld1.u32 {t4}, [tmp_ptr1:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	ROTATE_1(t1, t2, t3, t4)\
	vst1.u32 {t1}, [tmp_ptr0:128];\
	vst1.u32 {t2}, [tmp_ptr1:128];\
\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;
	
#define DCC2_STEP4(step_const,reg_e1,reg_a1,reg_b1,reg_c1,reg_d1,reg_e2,reg_a2,reg_b2,reg_c2,reg_d2,t1,t2,t3,t4,w0,w1,w2,w3) \
	DCC2_ROTATE_5(reg_a1,reg_a2,t1,t2,t3,t4)\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t3;\
\
	veor.u32 t1, reg_c1, reg_d1;\
	veor.u32 t2, reg_c2, reg_d2;\
	veor.u32 t1, t1, reg_b1;\
	veor.u32 t2, t2, reg_b2;\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;\
	vadd.u32 reg_e1, reg_e1, step_const;\
	vadd.u32 reg_e2, reg_e2, step_const;\
\
    ROTATE(reg_b1, reg_b2, 30, t1, t2)\
\
	add tmp_ptr0, W, #(w1*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w1+16)*REG_BYTE_SIZE);\
	vld1.u32 {t1}, [tmp_ptr0:128];\
	vld1.u32 {t2}, [tmp_ptr1:128];\
\
	add tmp_ptr0, W, #(w2*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w2+16)*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr0:128];\
	vld1.u32 {t4}, [tmp_ptr1:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	add tmp_ptr0, W, #(w3*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w3+16)*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr0:128];\
	vld1.u32 {t4}, [tmp_ptr1:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	add tmp_ptr0, W, #(w0*REG_BYTE_SIZE);\
	add tmp_ptr1, W, #((w0+16)*REG_BYTE_SIZE);\
	vld1.u32 {t3}, [tmp_ptr0:128];\
	vld1.u32 {t4}, [tmp_ptr1:128];\
	veor.u32 t1, t1, t3;\
	veor.u32 t2, t2, t4;\
\
	ROTATE_1(t1, t2, t3, t4)\
	vst1.u32 {t1}, [tmp_ptr0:128];\
	vst1.u32 {t2}, [tmp_ptr1:128];\
\
	vadd.u32 reg_e1, reg_e1, t1;\
	vadd.u32 reg_e2, reg_e2, t2;

	.text
	.align	2
	.global	sha1_process_sha1_neon
	.type	sha1_process_sha1_neon, %function
sha1_process_sha1_neon:
  vpush {q4,q5,q6,q7}
  push	{r4,r5}

	// Calculate all Qs
	mov tmp_ptr, sha1_hash
	vld1.u32 {reg_a1}, [tmp_ptr:128]!
	vld1.u32 {reg_b1}, [tmp_ptr:128]!
	vld1.u32 {reg_c1}, [tmp_ptr:128]!
	vld1.u32 {reg_d1}, [tmp_ptr:128]!
	vld1.u32 {reg_e1}, [tmp_ptr:128]!
	vld1.u32 {reg_a2}, [tmp_ptr:128]!
	vld1.u32 {reg_b2}, [tmp_ptr:128]!
	vld1.u32 {reg_c2}, [tmp_ptr:128]!
	vld1.u32 {reg_d2}, [tmp_ptr:128]!
	vld1.u32 {reg_e2}, [tmp_ptr:128]!
	
	// Q0
	veor.u32 reg_a1, reg_a1, reg_c1
	veor.u32 reg_a2, reg_a2, reg_c2
	ROTATE_1(reg_a1, reg_a2, t1, t2)
	add tmp_ptr0, W, #((0+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((0+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_a1}, [tmp_ptr0:128]
	vst1.u32 {reg_a2}, [tmp_ptr1:128]
	// Q1
	veor.u32 reg_b1, reg_b1, reg_d1
	veor.u32 reg_b2, reg_b2, reg_d2
	ROTATE_1(reg_b1, reg_b2, t1, t2)
	
	add tmp_ptr0, W, #((1+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((1+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_b1}, [tmp_ptr0:128]
	vst1.u32 {reg_b2}, [tmp_ptr1:128]
	// Q2
	SET_REG(r5,0x000002A0)
	vdup.u32 t3, r5
	vmov.u32 t5, #0x80000000
	veor.u32 reg_c1, reg_c1, reg_e1
	veor.u32 reg_c2, reg_c2, reg_e2
	veor.u32 reg_c1, reg_c1, t3
	veor.u32 reg_c2, reg_c2, t3
	ROTATE_1(reg_c1, reg_c2, t1, t2)
	add tmp_ptr0, W, #((2+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((2+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_c1}, [tmp_ptr0:128]
	vst1.u32 {reg_c2}, [tmp_ptr1:128]
	// Q3
	veor.u32 reg_d1, reg_d1, t5
	veor.u32 reg_d2, reg_d2, t5
	veor.u32 reg_d1, reg_d1, reg_a1
	veor.u32 reg_d2, reg_d2, reg_a2
	ROTATE_1(reg_d1, reg_d2, t1, t2)
	add tmp_ptr0, W, #((3+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((3+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_d1}, [tmp_ptr0:128]
	vst1.u32 {reg_d2}, [tmp_ptr1:128]
	// Q4
	veor.u32 reg_e1, reg_e1, reg_b1
	veor.u32 reg_e2, reg_e2, reg_b2
	ROTATE_1(reg_e1, reg_e2, t1, t2)
	add tmp_ptr0, W, #((4+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((4+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_e1}, [tmp_ptr0:128]
	vst1.u32 {reg_e2}, [tmp_ptr1:128]
	// Q5
	veor.u32 step_const, reg_c2, t5
	veor.u32 t5, reg_c1, t5
	ROTATE_1(t5, step_const, t1, t2)
	add tmp_ptr0, W, #((5+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((5+1*16)*REG_BYTE_SIZE)
	vst1.u32 {t5}, [tmp_ptr0:128]
	vst1.u32 {step_const}, [tmp_ptr1:128]
	// Q6
	vshr.u32 t3, reg_d1, #31
	vshr.u32 t4, reg_d2, #31
	vadd.u32 t1, reg_d1, reg_d1
	vadd.u32 t2, reg_d2, reg_d2
	vorr.u32   t3, t3, t1
	vorr.u32   t4, t4, t2
	add tmp_ptr0, W, #((6+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((6+1*16)*REG_BYTE_SIZE)
	vst1.u32 {t3}, [tmp_ptr0:128]
	vst1.u32 {t4}, [tmp_ptr1:128]
	// Q8
	veor.u32 t5, t5, reg_a1
	veor.u32 step_const, step_const, reg_a2
	ROTATE_1(t5, step_const, t1, t2)
	add tmp_ptr0, W, #((8+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((8+1*16)*REG_BYTE_SIZE)
	vst1.u32 {t5}, [tmp_ptr0:128]
	vst1.u32 {step_const}, [tmp_ptr1:128]
	// Q11
	veor.u32 reg_d1, t5, reg_d1
	veor.u32 reg_d2, step_const, reg_d2
	ROTATE_1(reg_d1, reg_d2, t1, t2)
	add tmp_ptr0, W, #((11+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((11+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_d1}, [tmp_ptr0:128]
	vst1.u32 {reg_d2}, [tmp_ptr1:128]
	// Q14
	SET_REG(r5,0x000002A0)
	vdup.u32 t5, r5
	veor.u32 reg_d1, reg_d1, t3
	veor.u32 reg_d2, reg_d2, t4
	veor.u32 reg_d1, reg_d1, reg_a1
	veor.u32 reg_d2, reg_d2, reg_a2
	ROTATE_1(reg_d1, reg_d2, t1, t2)
	add tmp_ptr0, W, #((14+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((14+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_d1}, [tmp_ptr0:128]
	vst1.u32 {reg_d2}, [tmp_ptr1:128]
	// Q7
	veor.u32 reg_a1, reg_e1, t5
	veor.u32 reg_a2, reg_e2, t5
	ROTATE_1(reg_a1, reg_a2, t1, t2)
	add tmp_ptr0, W, #((7+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((7+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_a1}, [tmp_ptr0:128]
	vst1.u32 {reg_a2}, [tmp_ptr1:128]
	// Q9
	veor.u32 reg_d1, t3, reg_b1
	veor.u32 reg_d2, t4, reg_b2
	ROTATE_1(reg_d1, reg_d2, t1, t2)
	add tmp_ptr0, W, #((9+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((9+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_d1}, [tmp_ptr0:128]
	vst1.u32 {reg_d2}, [tmp_ptr1:128]
	// Q10
	veor.u32 reg_c1, reg_a1, reg_c1
	veor.u32 reg_c2, reg_a2, reg_c2
	ROTATE_1(reg_c1, reg_c2, t1, t2)
	add tmp_ptr0, W, #((10+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((10+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_c1}, [tmp_ptr0:128]
	vst1.u32 {reg_c2}, [tmp_ptr1:128]
	// Q12
	veor.u32 reg_e1, reg_d1, reg_e1
	veor.u32 reg_e2, reg_d2, reg_e2
	ROTATE_1(reg_e1, reg_e2, t1, t2)
	add tmp_ptr0, W, #((12+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((12+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_e1}, [tmp_ptr0:128]
	vst1.u32 {reg_e2}, [tmp_ptr1:128]
	// Q13
	add tmp_ptr0, W, #((5+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((5+1*16)*REG_BYTE_SIZE)
	vld1.u32 {t1}, [tmp_ptr0:128]
	vld1.u32 {t2}, [tmp_ptr1:128]
	veor.u32 reg_c1, reg_c1, t1
	veor.u32 reg_c2, reg_c2, t2
	veor.u32 reg_c1, reg_c1, t5
	veor.u32 reg_c2, reg_c2, t5
	ROTATE_1(reg_c1, reg_c2, t1, t2)
	add tmp_ptr0, W, #((13+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((13+1*16)*REG_BYTE_SIZE)
	vst1.u32 {reg_c1}, [tmp_ptr0:128]
	vst1.u32 {reg_c2}, [tmp_ptr1:128]
	// Q15
	veor.u32 step_const, t5, reg_b2
	veor.u32 t5, t5, reg_b1
	veor.u32 reg_e1, reg_e1, reg_a1
	veor.u32 reg_e2, reg_e2, reg_a2
	veor.u32 t5, t5, reg_e1
	veor.u32 step_const, step_const, reg_e2
	ROTATE_1(t5, step_const, t1, t2)
	add tmp_ptr0, W, #((15+0*16)*REG_BYTE_SIZE)
	add tmp_ptr1, W, #((15+1*16)*REG_BYTE_SIZE)
	vst1.u32 {t5}, [tmp_ptr0:128]
	vst1.u32 {step_const}, [tmp_ptr1:128]
  
	// Load state
	mov tmp_ptr, dcc2_state
	vld1.u32 {reg_a1}, [tmp_ptr:128]!
	vld1.u32 {reg_b1}, [tmp_ptr:128]!
	vld1.u32 {reg_c1}, [tmp_ptr:128]!
	vld1.u32 {reg_d1}, [tmp_ptr:128]!
	vld1.u32 {reg_e1}, [tmp_ptr:128]!
	vld1.u32 {reg_a2}, [tmp_ptr:128]!
	vld1.u32 {reg_b2}, [tmp_ptr:128]!
	vld1.u32 {reg_c2}, [tmp_ptr:128]!
	vld1.u32 {reg_d2}, [tmp_ptr:128]!
	vld1.u32 {reg_e2}, [tmp_ptr:128]!

	SET_REG(r5,0x5a827999)
	vdup.u32 step_const, r5
	// Step1
	DCC2_ADD(reg_e1, reg_e2, sha1_hash, 0, 5)
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_d1, reg_d2, sha1_hash, 1, 6)
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_c1, reg_c2, sha1_hash, 2, 7)
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_b1, reg_b2, sha1_hash, 3, 8)
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_a1, reg_a2, sha1_hash, 4, 9)
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	vmov.u32 t1, #0x80000000
	vadd.u32 reg_e1, reg_e1, t1
	vadd.u32 reg_e2, reg_e2, t1
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	SET_REG(r5,0x000002A0)
	vdup.u32 t1, r5
	vadd.u32 reg_e1, reg_e1, t1
	vadd.u32 reg_e2, reg_e2, t1
	DCC2_STEP1(reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_d1, reg_d2, W, 0, 16)
	DCC2_STEP1(reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_c1, reg_c2, W, 1, 17)
	DCC2_STEP1(reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_b1, reg_b2, W, 2, 18)
	DCC2_STEP1(reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4,step_const)
	DCC2_ADD(reg_a1, reg_a2, W, 3, 19)
	DCC2_STEP1(reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4,step_const)
	
	// Step2
	SET_REG(r5,0x6ed9eba1)
	vdup.u32 step_const, r5
	DCC2_STEP2(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 4 )
	DCC2_STEP2(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 5 )
	DCC2_STEP2(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 6 )
	DCC2_STEP2(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 7 )
	DCC2_STEP2(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 8 )
	DCC2_STEP2(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 9 )
	DCC2_STEP2(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 10)
	DCC2_STEP2(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 11)
	DCC2_STEP2(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 12)
	DCC2_STEP2(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 13)
	DCC2_STEP2(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 14)
	DCC2_STEP2(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 15)
	DCC2_STEP4(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 0, 13, 8 , 2)
	DCC2_STEP4(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 1, 14, 9 , 3)
	DCC2_STEP4(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 2, 15, 10, 4)
	DCC2_STEP4(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 3, 0 , 11, 5)
	DCC2_STEP4(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 4, 1 , 12, 6)
	DCC2_STEP4(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 5, 2 , 13, 7)
	DCC2_STEP4(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 6, 3 , 14, 8)
	DCC2_STEP4(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 7, 4 , 15, 9)
	
	// Step3
	SET_REG(r5,0x8F1BBCDC)
	vdup.u32 step_const, r5
	DCC2_STEP3(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 8 , 5 , 0 , 10)
    DCC2_STEP3(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 9 , 6 , 1 , 11)
    DCC2_STEP3(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 10, 7 , 2 , 12)
    DCC2_STEP3(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 11, 8 , 3 , 13)
    DCC2_STEP3(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 12, 9 , 4 , 14)
    DCC2_STEP3(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 13, 10, 5 , 15)
    DCC2_STEP3(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 14, 11, 6 , 0 )
    DCC2_STEP3(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 15, 12, 7 , 1 )
    DCC2_STEP3(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 0 , 13, 8 , 2 )
    DCC2_STEP3(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 1 , 14, 9 , 3 )
    DCC2_STEP3(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 2 , 15, 10, 4 )
    DCC2_STEP3(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 3 , 0 , 11, 5 )
    DCC2_STEP3(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 4 , 1 , 12, 6 )
    DCC2_STEP3(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 5 , 2 , 13, 7 )
    DCC2_STEP3(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 6 , 3 , 14, 8 )
    DCC2_STEP3(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 7 , 4 , 15, 9 )
    DCC2_STEP3(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 8 , 5 , 0 , 10)
    DCC2_STEP3(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 9 , 6 , 1 , 11)
    DCC2_STEP3(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 10, 7 , 2 , 12)
    DCC2_STEP3(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 11, 8 , 3 , 13)
	
	// Step4
	SET_REG(r5,0xCA62C1D6)
	vdup.u32 step_const, r5
	DCC2_STEP4(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 12, 9 , 4 , 14)
    DCC2_STEP4(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 13, 10, 5 , 15)
    DCC2_STEP4(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 14, 11, 6 , 0 )
    DCC2_STEP4(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 15, 12, 7 , 1 )
    DCC2_STEP4(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 0 , 13, 8 , 2 )
    DCC2_STEP4(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 1 , 14, 9 , 3 )
    DCC2_STEP4(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 2 , 15, 10, 4 )
    DCC2_STEP4(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 3 , 0 , 11, 5 )
    DCC2_STEP4(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 4 , 1 , 12, 6 )
    DCC2_STEP4(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 5 , 2 , 13, 7 )
    DCC2_STEP4(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 6 , 3 , 14, 8 )
    DCC2_STEP4(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 7 , 4 , 15, 9 )
    DCC2_STEP4(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 8 , 5 , 0 , 10)
    DCC2_STEP4(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 9 , 6 , 1 , 11)
    DCC2_STEP4(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 10, 7 , 2 , 12)
    DCC2_STEP4(step_const, reg_e1, reg_a1, reg_b1, reg_c1, reg_d1, reg_e2, reg_a2, reg_b2, reg_c2, reg_d2, t1, t2, t3, t4, 11, 8 , 3 , 13)
    DCC2_STEP4(step_const, reg_d1, reg_e1, reg_a1, reg_b1, reg_c1, reg_d2, reg_e2, reg_a2, reg_b2, reg_c2, t1, t2, t3, t4, 12, 9 , 4 , 14)
    DCC2_STEP4(step_const, reg_c1, reg_d1, reg_e1, reg_a1, reg_b1, reg_c2, reg_d2, reg_e2, reg_a2, reg_b2, t1, t2, t3, t4, 13, 10, 5 , 15)
    DCC2_STEP4(step_const, reg_b1, reg_c1, reg_d1, reg_e1, reg_a1, reg_b2, reg_c2, reg_d2, reg_e2, reg_a2, t1, t2, t3, t4, 14, 11, 6 , 0 )
    DCC2_STEP4(step_const, reg_a1, reg_b1, reg_c1, reg_d1, reg_e1, reg_a2, reg_b2, reg_c2, reg_d2, reg_e2, t1, t2, t3, t4, 15, 12, 7 , 1 )
  
    mov tmp_ptr, dcc2_state
	vld1.u32 {t1,t2}, [tmp_ptr:128]!
	vld1.u32 {t3,t4}, [tmp_ptr:128]!
	vadd.u32 reg_a1, reg_a1, t1
	vadd.u32 reg_b1, reg_b1, t2
	vadd.u32 reg_c1, reg_c1, t3
	vadd.u32 reg_d1, reg_d1, t4
	vld1.u32 {t1,t2}, [tmp_ptr:128]!
	vld1.u32 {t3,t4}, [tmp_ptr:128]!
	vadd.u32 reg_e1, reg_e1, t1
	vadd.u32 reg_a2, reg_a2, t2
	vadd.u32 reg_b2, reg_b2, t3
	vadd.u32 reg_c2, reg_c2, t4
	vld1.u32 {t1,t2}, [tmp_ptr:128]!
	vadd.u32 reg_d2, reg_d2, t1 
	vadd.u32 reg_e2, reg_e2, t2
	
	mov tmp_ptr, sha1_hash
	vst1.u32 {reg_a1}, [tmp_ptr:128]!
	vst1.u32 {reg_b1}, [tmp_ptr:128]!
	vst1.u32 {reg_c1}, [tmp_ptr:128]!
	vst1.u32 {reg_d1}, [tmp_ptr:128]!
	vst1.u32 {reg_e1}, [tmp_ptr:128]!
	vst1.u32 {reg_a2}, [tmp_ptr:128]!
	vst1.u32 {reg_b2}, [tmp_ptr:128]!
	vst1.u32 {reg_c2}, [tmp_ptr:128]!
	vst1.u32 {reg_d2}, [tmp_ptr:128]!
	vst1.u32 {reg_e2}, [tmp_ptr:128]!
	
  pop  {r4,r5}
  vpop {q4,q5,q6,q7}
  bx lr
  
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SHA256 format
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7) \
	MD5_LOAD_CONST(t7,const);\
\
	vshr.u32 t0, reg_e, #(32-26);\
	vshr.u32 t1, reg_e, #(32-21);\
	vshr.u32 t2, reg_e, #(32-7);\
\
	vmov t6, reg_e;\
	vbsl t6, reg_f, reg_g;\
\
	vshl.u32 t3, reg_e, #26;\
	vshl.u32 t4, reg_e, #21;\
	vshl.u32 t5, reg_e, #7;\
\
	vorr   t0, t3, t0;\
	vorr   t1, t4, t1;\
	vorr   t2, t5, t2;\
	vadd.u32 reg_h,reg_h,t7;\
\
	veor.u32 t0,t0,t1;\
	vadd.u32 reg_h,reg_h,t6;\
	veor.u32 t0,t0,t2;\
\
	vadd.u32 reg_h,reg_h,t0;\
\
	vadd.u32 reg_d,reg_h,reg_d;\
\
	vshr.u32 t0, reg_a, #(32-30);\
	vshr.u32 t1, reg_a, #(32-19);\
	vshr.u32 t2, reg_a, #(32-10);\
\
	vshl.u32 t3, reg_a, #30;\
	vshl.u32 t4, reg_a, #19;\
	vshl.u32 t5, reg_a, #10;\
\
	veor t6, reg_b, reg_c;\
	vbsl t6, reg_a, reg_b;\
\
	vorr   t0, t3, t0;\
	vorr   t1, t4, t1;\
	vorr   t2, t5, t2;\
	veor.u32 t0,t0,t1;\
	veor.u32 t0,t0,t2;\
	vadd.u32 reg_h,reg_h,t6;\
	vadd.u32 reg_h,reg_h,t0;

#define SHA256_ROUNDW(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA256_RW_1SUM0_SAME(w_index0,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u32 reg_h,reg_h,t6;\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA256_ROUNDW_316(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA256_RW_1SUM0_316(w_index0,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u32 reg_h,reg_h,t6;\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA256_ROUNDW_416(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA256_RW_1SUM0_416(w_index0,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u32 reg_h,reg_h,t6;\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA256_ROUNDW1416(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA256_RW_1SUM01416(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u32 reg_h,reg_h,t6;\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA256_ROUNDW_116(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA256_RW_1SUM0_116(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u32 reg_h,reg_h,t6;\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA256_RW_1SUM0_316(r_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer,nt_buffer_base,#((8+r1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t6},[nt_buffer:128];\
	add nt_buffer,nt_buffer_base,#((8+r0_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t7},[nt_buffer:128];\
\
	vshr.u32 t0, t6, #(32-15);\
	vshr.u32 t1, t6, #(32-13);\
	vshr.u32 t2, t6, #10;\
\
	vshl.u32 t3, t6, #15;\
	vshl.u32 t6, t6, #13;\
	vshr.u32 t4, t7, #(32-25);\
	vshr.u32 t5, t7, #(32-14);\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
\
	vshr.u32 t1, t7, #3;\
	vshl.u32 t3, t7, #25;\
\
	veor t6,t0,t6;\
	vshl.u32 t7, t7, #14;\
	vorr   t4, t3, t4;\
	vorr   t7, t7, t5;\
\
	veor t6,t6,t2;\
	veor t7,t4,t7;\
\
	veor t7,t7,t1;\
	vadd.u32 t6,t7,t6;\
\
	add nt_buffer, nt_buffer_base, #((8+r_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u32 t6,t6,t0;\
	vst1.u32 {t6},[nt_buffer:128];
	
#define SHA256_RW_1SUM0_416(r_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer,nt_buffer_base,#((8+r1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t6},[nt_buffer:128];\
\
	vshr.u32 t0, t6, #(32-15);\
	vshr.u32 t1, t6, #(32-13);\
	vshr.u32 t2, t6, #10;\
\
	vshl.u32 t3, t6, #15;\
	vshl.u32 t6, t6, #13;\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
\
	veor t6,t0,t6;\
	veor t6,t6,t2;\
\
	add nt_buffer,nt_buffer_base,#((8+rsum1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u32 t6,t6,t0;\
	add nt_buffer,nt_buffer_base,#((8+r_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t2},[nt_buffer:128];\
	vadd.u32 t6,t6,t2;\
\
	vst1.u32 {t6},[nt_buffer:128];

#define SHA256_RW_1SUM01416(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer,nt_buffer_base,#((8+r1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t6},[nt_buffer:128];\
\
	vshr.u32 t0, t6, #(32-15);\
	vshr.u32 t1, t6, #(32-13);\
	vshr.u32 t2, t6, #10;\
\
	vshl.u32 t3, t6, #15;\
	vshl.u32 t6, t6, #13;\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
\
	veor t6,t0,t6;\
	veor t6,t6,t2;\
\
	add nt_buffer,nt_buffer_base,#((8+rsum1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u32 t6,t6,t0;\
	add nt_buffer,nt_buffer_base,#((8+r_index)*4*NT_NUM_KEYS);\
	vst1.u32 {t6},[nt_buffer:128];

#define SHA256_RW_1SUM0_116(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer,nt_buffer_base,#((8+r1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t6},[nt_buffer:128];\
	add nt_buffer,nt_buffer_base,#((8+r0_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t7},[nt_buffer:128];\
\
	vshr.u32 t0, t6, #(32-15);\
	vshr.u32 t1, t6, #(32-13);\
	vshr.u32 t2, t6, #10;\
\
	vshl.u32 t3, t6, #15;\
	vshl.u32 t6, t6, #13;\
	vshr.u32 t4, t7, #(32-25);\
	vshr.u32 t5, t7, #(32-14);\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
	vshr.u32 t1, t7, #3;\
	vshl.u32 t3, t7, #25;\
\
	veor t6,t0,t6;\
	vshl.u32 t7, t7, #14;\
	vorr   t4, t3, t4;\
	vorr   t7, t7, t5;\
	veor t6,t6,t2;\
\
	veor t7,t4,t7;\
\
	add nt_buffer,nt_buffer_base,#((8+rsum1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u32 t6,t6,t0;\
	veor t7,t7,t1;\
	vadd.u32 t6,t7,t6;\
\
	add nt_buffer,nt_buffer_base,#((8+r_index)*4*NT_NUM_KEYS);\
	vst1.u32 {t6},[nt_buffer:128];

#define SHA256_RW_1SUM0_SAME(r_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer,nt_buffer_base,#((8+r1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t6},[nt_buffer:128];\
	add nt_buffer,nt_buffer_base,#((8+r0_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t7},[nt_buffer:128];\
\
	vshr.u32 t0, t6, #(32-15);\
	vshr.u32 t1, t6, #(32-13);\
	vshr.u32 t2, t6, #10;\
\
	vshl.u32 t3, t6, #15;\
	vshl.u32 t6, t6, #13;\
	vshr.u32 t4, t7, #(32-25);\
	vshr.u32 t5, t7, #(32-14);\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
	vshr.u32 t1, t7, #3;\
	vshl.u32 t3, t7, #25;\
\
	veor t6,t0,t6;\
	vshl.u32 t7, t7, #14;\
	vorr   t4, t3, t4;\
	vorr   t7, t7, t5;\
	veor t6,t6,t2;\
\
	veor t7,t4,t7;\
	add nt_buffer,nt_buffer_base,#((8+rsum1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u32 t6,t6,t0;\
\
	veor t7,t7,t1;\
	vadd.u32 t6,t7,t6;\
	add nt_buffer,nt_buffer_base,#((8+r_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t2},[nt_buffer:128];\
	vadd.u32 t6,t6,t2;\
	vst1.u32 {t6},[nt_buffer:128];
	
#define SHA256_RW_1SUM0(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer,nt_buffer_base,#((8+r1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t6},[nt_buffer:128];\
	add nt_buffer,nt_buffer_base,#((8+r0_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t7},[nt_buffer:128];\
\
	vshr.u32 t0, t6, #(32-15);\
	vshr.u32 t1, t6, #(32-13);\
	vshr.u32 t2, t6, #10;\
\
	vshl.u32 t3, t6, #15;\
	vshl.u32 t6, t6, #13;\
	vshr.u32 t4, t7, #(32-25);\
	vshr.u32 t5, t7, #(32-14);\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
	vshr.u32 t1, t7, #3;\
	vshl.u32 t3, t7, #25;\
\
	veor t6,t0,t6;\
	vshl.u32 t7, t7, #14;\
	vorr   t4, t3, t4;\
	vorr   t7, t7, t5;\
	veor t6,t6,t2;\
\
	veor t7,t4,t7;\
	add nt_buffer,nt_buffer_base,#((8+rsum1_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u32 t6,t6,t0;\
\
	veor t7,t7,t1;\
	vadd.u32 t6,t7,t6;\
	add nt_buffer,nt_buffer_base,#((8+rsum0_index)*4*NT_NUM_KEYS);\
	vld1.u32 {t2},[nt_buffer:128];\
	vadd.u32 t6,t6,t2;\
\
	add nt_buffer,nt_buffer_base,#((8+r_index)*4*NT_NUM_KEYS);\
	vst1.u32 {t6},[nt_buffer:128];


#define CRYPT_SHA256_AVX_KERNEL_ASM_BODY(NT_NUM_KEYS,reg_a,reg_b,reg_c,reg_d,reg_e,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const) \
	mov i, #0;\
sha256_while1:\
	/* Convert to Big-Endian*/\
	/* Load                 */\
	mov nt_buffer, nt_buffer_base;             vld1.u32 {reg_h}, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {reg_g}, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {t2   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {t3   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {t4   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {t5   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {t6   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer, #1*4*NT_NUM_KEYS;vld1.u32 {t1   }, [nt_buffer:128];\
	/* Shuffle bytes*/\
	vrev32.u8 reg_h, reg_h;\
	vrev32.u8 reg_g, reg_g;\
	vrev32.u8 t2   , t2   ;\
	vrev32.u8 t3   , t3   ;\
	vrev32.u8 t4   , t4   ;\
	vrev32.u8 t5   , t5   ;\
	vrev32.u8 t6   , t6   ;\
	/* Write to W*/\
	add nt_buffer, nt_buffer_base, #((8+0 )*4*NT_NUM_KEYS);vst1.u32 {reg_h}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+1 )*4*NT_NUM_KEYS);vst1.u32 {reg_g}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+2 )*4*NT_NUM_KEYS);vst1.u32 {t2   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+3 )*4*NT_NUM_KEYS);vst1.u32 {t3   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+4 )*4*NT_NUM_KEYS);vst1.u32 {t4   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+5 )*4*NT_NUM_KEYS);vst1.u32 {t5   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+6 )*4*NT_NUM_KEYS);vst1.u32 {t6   }, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+15)*4*NT_NUM_KEYS);vst1.u32 {t1   }, [nt_buffer:128];\
\
	/*Step 1: H  = 0xfc08884d + W[0 * NT_NUM_KEYS]; D=0x9cbf5a55+H;*/\
	MD5_LOAD_CONST(step_const,0xfc08884d);\
	MD5_LOAD_CONST(t6   ,0x9cbf5a55);\
	MD5_LOAD_CONST(reg_a,0x6a09e667);\
	MD5_LOAD_CONST(reg_b,0xbb67ae85);\
	vadd.u32 reg_h, reg_h, step_const;\
	MD5_LOAD_CONST(reg_c,0x3c6ef372);\
	MD5_LOAD_CONST(reg_e,0x510e527f);\
	MD5_LOAD_CONST(reg_f,0x9b05688c);\
	vadd.u32 reg_d, reg_h, t6;\
\
	SHA256_ROUND1(reg_g,reg_d,reg_f,reg_e,0x90bb1e3c ,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((8+2)*4*NT_NUM_KEYS);\
	vld1.u32 {reg_f}, [nt_buffer:128];\
	SHA256_ROUND1(reg_f,reg_c,reg_e,reg_d,0x50c6645b ,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((8+3)*4*NT_NUM_KEYS);\
	vld1.u32 {reg_e}, [nt_buffer:128];\
	SHA256_ROUND1(reg_e,reg_b,reg_d,reg_c,0x3ac42e24 ,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((8+4)*4*NT_NUM_KEYS);\
	vld1.u32 {t0}, [nt_buffer:128];\
	vadd.u32 reg_d,reg_d,t0;\
	SHA256_ROUND1(reg_d,reg_a,reg_c,reg_b,0x3956C25B ,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((8+5)*4*NT_NUM_KEYS);\
	vld1.u32 {t0}, [nt_buffer:128];\
	vadd.u32 reg_c,reg_c,t0;\
	SHA256_ROUND1(reg_c,reg_h,reg_b,reg_a,0x59F111F1 ,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((8+6)*4*NT_NUM_KEYS);\
	vld1.u32 {t0}, [nt_buffer:128];\
	vadd.u32 reg_b,reg_b,t0;\
	SHA256_ROUND1(reg_b,reg_g,reg_a,reg_h,0x923F82A4,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_a,reg_f,reg_h,reg_g,0xAB1C5ED5,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,0xD807AA98,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_g,reg_d,reg_f,reg_e,0x12835B01,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_f,reg_c,reg_e,reg_d,0x243185BE,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_e,reg_b,reg_d,reg_c,0x550C7DC3,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_d,reg_a,reg_c,reg_b,0x72BE5D74,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_c,reg_h,reg_b,reg_a,0x80DEB1FE,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUND1(reg_b,reg_g,reg_a,reg_h,0x9BDC06A7,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS);\
	vld1.u32 {t0}, [nt_buffer:128];\
	vadd.u32 reg_a,reg_a,t0;\
	SHA256_ROUND1(reg_a,reg_f,reg_h,reg_g,0xC19BF174,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const);\
\
	add nt_buffer, nt_buffer_base, #((8+1)*4*NT_NUM_KEYS);\
	vld1.u32 {t5}, [nt_buffer:128];\
	vshr.u32 t0, t5, #(32-25);\
	vshr.u32 t1, t5, #(32-14);\
	vshr.u32 t2, t5, #3;\
	vshl.u32 t3, t5, #25;\
	vshl.u32 t4, t5, #14;\
	vorr  t0, t3, t0;\
	vorr  t1, t4, t1;\
	veor  t0, t0, t1;\
	veor  t0, t0, t2;\
	add nt_buffer, nt_buffer_base, #((8+0)*4*NT_NUM_KEYS);\
	vld1.u32 {t6}, [nt_buffer:128];\
	vadd.u32 t0, t0, t6;\
	vst1.u32 {t0}, [nt_buffer:128];\
	vadd.u32 reg_h, reg_h, t0;\
	SHA256_ROUND1(reg_h,reg_e,reg_g,reg_f,0xE49B69C1,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA256_ROUNDW_316(reg_g,reg_d,reg_f,reg_e,0xEFBE4786,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,  1, 15, 16,  2,NT_NUM_KEYS);\
	SHA256_ROUNDW_316(reg_f,reg_c,reg_e,reg_d,0x0FC19DC6,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,  2, 0 , 16,  3,NT_NUM_KEYS);\
	SHA256_ROUNDW_316(reg_e,reg_b,reg_d,reg_c,0x240CA1CC,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,  3, 1 , 16,  4,NT_NUM_KEYS);\
	SHA256_ROUNDW_316(reg_d,reg_a,reg_c,reg_b,0x2DE92C6F,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 ,  4, 2 , 16,  5,NT_NUM_KEYS);\
	SHA256_ROUNDW_316(reg_c,reg_h,reg_b,reg_a,0x4A7484AA,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 ,  5, 3 , 16,  6,NT_NUM_KEYS);\
	SHA256_ROUNDW_416(reg_b,reg_g,reg_a,reg_h,0x5CB0A9DC,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 ,  6, 4 , 15, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_a,reg_f,reg_h,reg_g,0x76F988DA,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 , 16, 5 ,  0, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_h,reg_e,reg_g,reg_f,0x983E5152,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,8 , 16, 6 ,  1, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_g,reg_d,reg_f,reg_e,0xA831C66D,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,9 , 16, 7 ,  2, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_f,reg_c,reg_e,reg_d,0xB00327C8,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,10, 16, 8 ,  3, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_e,reg_b,reg_d,reg_c,0xBF597FC7,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,11, 16, 9 ,  4, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_d,reg_a,reg_c,reg_b,0xC6E00BF3,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,12, 16, 10,  5, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW1416(reg_c,reg_h,reg_b,reg_a,0xD5A79147,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,13, 16, 11,  6, 16,NT_NUM_KEYS);\
	SHA256_ROUNDW_116(reg_b,reg_g,reg_a,reg_h,0x06CA6351,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,14, 16, 12,  7, 15,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_a,reg_f,reg_h,reg_g,0x14292967,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,15, 15, 13,  8, 0 ,NT_NUM_KEYS);\
\
	SHA256_ROUNDW(reg_h,reg_e,reg_g,reg_f,0x27B70A85,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,0 ,0 ,14,9 ,1 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_g,reg_d,reg_f,reg_e,0x2E1B2138,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,1 ,15,10,2 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_f,reg_c,reg_e,reg_d,0x4D2C6DFC,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,2 ,0 ,11,3 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_e,reg_b,reg_d,reg_c,0x53380D13,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,3 ,1 ,12,4 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_d,reg_a,reg_c,reg_b,0x650A7354,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 ,4 ,2 ,13,5 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_c,reg_h,reg_b,reg_a,0x766A0ABB,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 ,5 ,3 ,14,6 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_b,reg_g,reg_a,reg_h,0x81C2C92E,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 ,6 ,4 ,15,7 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_a,reg_f,reg_h,reg_g,0x92722C85,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 ,7 ,5 ,0 ,8 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_h,reg_e,reg_g,reg_f,0xA2BFE8A1,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,8 ,8 ,6 ,1 ,9 ,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_g,reg_d,reg_f,reg_e,0xA81A664B,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,9 ,9 ,7 ,2 ,10,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_f,reg_c,reg_e,reg_d,0xC24B8B70,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,10,10,8 ,3 ,11,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_e,reg_b,reg_d,reg_c,0xC76C51A3,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,11,11,9 ,4 ,12,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_d,reg_a,reg_c,reg_b,0xD192E819,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,12,12,10,5 ,13,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_c,reg_h,reg_b,reg_a,0xD6990624,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,13,13,11,6 ,14,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_b,reg_g,reg_a,reg_h,0xF40E3585,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,14,14,12,7 ,15,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_a,reg_f,reg_h,reg_g,0x106AA070,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,15,15,13,8 ,0 ,NT_NUM_KEYS);\
\
	SHA256_ROUNDW(reg_h,reg_e,reg_g,reg_f,0x19A4C116,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,0 ,0 ,14,9 ,1,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_g,reg_d,reg_f,reg_e,0x1E376C08,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,1 ,15,10,2,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_f,reg_c,reg_e,reg_d,0x2748774C,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,2 ,0 ,11,3,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_e,reg_b,reg_d,reg_c,0x34B0BCB5,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,3 ,1 ,12,4,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_d,reg_a,reg_c,reg_b,0x391C0CB3,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 ,4 ,2 ,13,5,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_c,reg_h,reg_b,reg_a,0x4ED8AA4A,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 ,5 ,3 ,14,6,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_b,reg_g,reg_a,reg_h,0x5B9CCA4F,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 ,6 ,4 ,15,7,NT_NUM_KEYS);\
	SHA256_ROUNDW(reg_a,reg_f,reg_h,reg_g,0x682E6FF3,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 ,7 ,5 ,0 ,8,NT_NUM_KEYS);\
	SHA256_RW_1SUM0(8,8 ,6,1,9 ,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA256_RW_1SUM0(9,9 ,7,2,10,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA256_RW_1SUM0(2,11,9,4,12,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA256_RW_1SUM0(1,13,2,6,14,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA256_RW_1SUM0(0,15,1,8,0 ,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	add nt_buffer, nt_buffer_base, #((8+0)*4*NT_NUM_KEYS);\
	vld1.u32 {t5}, [nt_buffer:128];\
	vadd.u32 reg_a,reg_a,t5;\
\
	add nt_buffer, nt_buffer_base, #((8+4 )*4*NT_NUM_KEYS); vst1.u32 {reg_a}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+16)*4*NT_NUM_KEYS); vst1.u32 {reg_b}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+17)*4*NT_NUM_KEYS); vst1.u32 {reg_c}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+18)*4*NT_NUM_KEYS); vst1.u32 {reg_d}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+19)*4*NT_NUM_KEYS); vst1.u32 {reg_e}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+20)*4*NT_NUM_KEYS); vst1.u32 {reg_f}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+21)*4*NT_NUM_KEYS); vst1.u32 {reg_g}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((8+22)*4*NT_NUM_KEYS); vst1.u32 {reg_h}, [nt_buffer:128];\
\
	add i,i,#1;\
	add nt_buffer_base, nt_buffer_base, #16;\
	cmp i, #(NT_NUM_KEYS/4);\
	blo sha256_while1;

#undef nt_buffer
#undef NT_NUM_KEYS
#define nt_buffer_base r0
#define table_ptr r1
#define size_bit_table_reg r2
#define nt_buffer r3
#define i r4
#define NT_NUM_KEYS 128
	
	.text
	.align	2
	.global	crypt_sha256_neon_kernel_asm
	.type	crypt_sha256_neon_kernel_asm, %function
crypt_sha256_neon_kernel_asm:
  vpush {q4,q5,q6,q7}
  push	{r4,r5}
  
  CRYPT_SHA256_AVX_KERNEL_ASM_BODY(128,q0,q1,q2,q3,q4,q5,q6,q7,q8,q9,q10,q11,q12,q13,q14,q15)
  
  sub nt_buffer_base, nt_buffer_base, #(4*NT_NUM_KEYS)
  add r5, nt_buffer_base, #((8+4 )*4*NT_NUM_KEYS)
  mov i, #0
sha256_while_table_lookup:
	vld1.u32 {q0,q1}, [r5:128]!
	
	TABLE_LOOKUP(q0,q1,14)

	add i,i,#1
	add nt_buffer_base, nt_buffer_base, #(16*2)
	cmp i, #(NT_NUM_KEYS/8)
	blo sha256_while_table_lookup
  
  pop  {r4,r5}
  vpop {q4,q5,q6,q7}
  bx lr
  
/////////////////////////////////////////////////////////////////////////////////////////////////
// SHA512 format
/////////////////////////////////////////////////////////////////////////////////////////////////
#undef nt_buffer
#define sha512_const_array r3
#define nt_buffer r5

#define SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const_index,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7) \
	add nt_buffer, sha512_const_array, #(const_index*16);\
	vld1.u32 {t7}, [nt_buffer:128];\
\
	vshr.u64 t0, reg_e, #(64-50);\
	vshr.u64 t1, reg_e, #(64-46);\
	vshr.u64 t2, reg_e, #(64-23);\
\
	vmov t6, reg_e;\
	vbsl t6, reg_f, reg_g;\
\
	vshl.u64 t3, reg_e, #50;\
	vshl.u64 t4, reg_e, #46;\
	vshl.u64 t5, reg_e, #23;\
\
	vorr   t0, t3, t0;\
	vorr   t1, t4, t1;\
	vorr   t2, t5, t2;\
	vadd.u64 reg_h,reg_h,t7;\
\
	veor t0,t0,t1;\
	vadd.u64 reg_h,reg_h,t6;\
	veor t0,t0,t2;\
\
	vadd.u64 reg_h,reg_h,t0;\
/* D += H*/\
	vadd.u64 reg_d,reg_h,reg_d;\
/* H += R_A(A) + ((A & B) | (C & (A | B)));*/\
	vshr.u64 t0, reg_a, #(64-36);\
	vshr.u64 t1, reg_a, #(64-30);\
	vshr.u64 t2, reg_a, #(64-25);\
\
	vshl.u64 t3, reg_a, #36;\
	vshl.u64 t4, reg_a, #30;\
	vshl.u64 t5, reg_a, #25;\
\
	vorr t0, t3, t0;\
	veor t6, reg_b, reg_c;\
	vorr t1, t4, t1;\
	vbsl t6, reg_a, reg_b;\
\
	vorr t2, t5, t2;\
	veor t0, t0, t1;\
	veor t0, t0, t2;\
	vadd.u64 reg_h,reg_h,t6;\
	vadd.u64 reg_h,reg_h,t0;


#define SHA512_ROUNDW(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA512_RW_1SUM0(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u64 reg_h,reg_h,t6;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA512_ROUNDW_316(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA512_RW_1SUM0_316(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u64 reg_h,reg_h,t6;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA512_ROUNDW3416(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA512_RW_1SUM03416(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u64 reg_h,reg_h,t6;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA512_ROUND13416(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA512_RW_1SUM013416(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u64 reg_h,reg_h,t6;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA512_ROUNDW1416(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA512_RW_1SUM01416(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u64 reg_h,reg_h,t6;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);
	
#define SHA512_ROUNDW116(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7,w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,NT_NUM_KEYS) \
	SHA512_RW_1SUM0116(w_index0,w_index1,w_index_r1,w_index_sum,w_index_r0,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS);\
	vadd.u64 reg_h,reg_h,t6;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,const,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,t7);


#define SHA512_RW_1SUM0_316(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer, nt_buffer_base, #((4+r1_index)*8*NT_NUM_KEYS); vld1.u64 {t6}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+r0_index)*8*NT_NUM_KEYS); vld1.u64 {t7}, [nt_buffer:128];\
\
	vshr.u64 t0, t6, #(64-45);\
	vshr.u64 t1, t6, #(64-3);\
	vshr.u64 t2, t6, #6;\
\
	vshl.u64 t3, t6, #45;\
	vshl.u64 t6, t6, #3;\
	vshr.u64 t4, t7, #(64-63);\
	vshr.u64 t5, t7, #(64-56);\
\
	vorr t0, t3, t0;\
	vorr t6, t6, t1;\
	vshr.u64 t1, t7, #7;\
	vshl.u64 t3, t7, #63;\
\
	veor t6,t0,t6;\
	vshl.u64 t7, t7, #56;\
	vorr t4, t3, t4;\
	vorr t7, t7, t5;\
	veor t6,t6,t2;\
\
	veor t7,t4,t7;\
	veor t7,t7,t1;\
	vadd.u64 t6,t7,t6;\
\
	add nt_buffer, nt_buffer_base, #((4+rsum0_index)*8*NT_NUM_KEYS); vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 t6,t6,t0;\
	add nt_buffer, nt_buffer_base, #((4+r_index)*8*NT_NUM_KEYS); vst1.u64 {t6}, [nt_buffer:128];

#define SHA512_RW_1SUM03416(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer, nt_buffer_base, #((4+r1_index)*8*NT_NUM_KEYS); vld1.u64 {t6}, [nt_buffer:128];\
\
	vshr.u64 t0, t6, #(64-45);\
	vshr.u64 t1, t6, #(64-3);\
	vshr.u64 t2, t6, #6;\
\
	vshl.u64 t3, t6, #45;\
	vshl.u64 t6, t6, #3;\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
\
	veor t6,t0,t6;\
	veor t6,t6,t2;\
\
	add nt_buffer, nt_buffer_base, #((4+rsum0_index)*8*NT_NUM_KEYS); vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 t6,t6,t0;\
	add nt_buffer, nt_buffer_base, #((4+r_index)*8*NT_NUM_KEYS); vst1.u64 {t6}, [nt_buffer:128];

#define SHA512_RW_1SUM013416(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer, nt_buffer_base, #((4+r1_index)*8*NT_NUM_KEYS); vld1.u64 {t6}, [nt_buffer:128];\
\
	vshr.u64 t0, t6, #(64-45);\
	vshr.u64 t1, t6, #(64-3);\
	vshr.u64 t2, t6, #6;\
\
	vshl.u64 t3, t6, #45;\
	vshl.u64 t6, t6, #3;\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
\
	veor t6,t0,t6;\
	veor t6,t6,t2;\
\
	add nt_buffer, nt_buffer_base, #((4+r_index)*8*NT_NUM_KEYS); vst1.u64 {t6}, [nt_buffer:128];	

#define SHA512_RW_1SUM01416(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer, nt_buffer_base, #((4+r1_index)*8*NT_NUM_KEYS); vld1.u64 {t6}, [nt_buffer:128];\
\
	vshr.u64 t0, t6, #(64-45);\
	vshr.u64 t1, t6, #(64-3);\
	vshr.u64 t2, t6, #6;\
\
	vshl.u64 t3, t6, #45;\
	vshl.u64 t6, t6, #3;\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
\
	veor t6,t0,t6;\
	veor t6,t6,t2;\
\
	add nt_buffer, nt_buffer_base, #((4+rsum1_index)*8*NT_NUM_KEYS); vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 t6,t6,t0;\
	add nt_buffer, nt_buffer_base, #((4+r_index)*8*NT_NUM_KEYS); vst1.u64 {t6}, [nt_buffer:128];
	
#define SHA512_RW_1SUM0116(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer, nt_buffer_base, #((4+r1_index)*8*NT_NUM_KEYS); vld1.u64 {t6}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+r0_index)*8*NT_NUM_KEYS); vld1.u64 {t7}, [nt_buffer:128];\
\
	vshr.u64 t0, t6, #(64-45);\
	vshr.u64 t1, t6, #(64-3);\
	vshr.u64 t2, t6, #6;\
\
	vshl.u64 t3, t6, #45;\
	vshl.u64 t6, t6, #3;\
	vshr.u64 t4, t7, #(64-63);\
	vshr.u64 t5, t7, #(64-56);\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
	vshr.u64 t1, t7, #7;\
	vshl.u64 t3, t7, #63;\
\
	veor t6,t0,t6;\
	vshl.u64 t7, t7, #56;\
	vorr   t4, t3, t4;\
	vorr   t7, t7, t5;\
	veor t6,t6,t2;\
	veor t7,t4,t7;\
\
	add nt_buffer, nt_buffer_base, #((4+rsum1_index)*8*NT_NUM_KEYS); vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 t6,t6,t0;\
\
	veor t7,t7,t1;\
	vadd.u64 t6,t7,t6;\
	add nt_buffer, nt_buffer_base, #((4+r_index)*8*NT_NUM_KEYS); vst1.u64 {t6}, [nt_buffer:128];
	
#define SHA512_RW_1SUM0(r_index,rsum0_index,r1_index,rsum1_index,r0_index,t0,t1,t2,t3,t4,t5,t6,t7,NT_NUM_KEYS) \
	add nt_buffer, nt_buffer_base, #((4+r1_index)*8*NT_NUM_KEYS); vld1.u64 {t6}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+r0_index)*8*NT_NUM_KEYS); vld1.u64 {t7}, [nt_buffer:128];\
\
	vshr.u64 t0, t6, #(64-45);\
	vshr.u64 t1, t6, #(64-3);\
	vshr.u64 t2, t6, #6;\
\
	vshl.u64 t3, t6, #45;\
	vshl.u64 t6, t6, #3;\
	vshr.u64 t4, t7, #(64-63);\
	vshr.u64 t5, t7, #(64-56);\
\
	vorr   t0, t3, t0;\
	vorr   t6, t6, t1;\
	vshr.u64 t1, t7, #7;\
	vshl.u64 t3, t7, #63;\
\
	veor t6,t0,t6;\
	vshl.u64 t7, t7, #56;\
	vorr   t4, t3, t4;\
	vorr   t7, t7, t5;\
\
	veor t6,t6,t2;\
	veor t7,t4,t7;\
	add nt_buffer, nt_buffer_base, #((4+rsum1_index)*8*NT_NUM_KEYS); vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 t6,t6,t0;\
\
	veor t7,t7,t1;\
	vadd.u64 t6,t7,t6;\
	add nt_buffer, nt_buffer_base, #((4+rsum0_index)*8*NT_NUM_KEYS); vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 t6,t6,t0;\
	add nt_buffer, nt_buffer_base, #((4+r_index)*8*NT_NUM_KEYS); vst1.u64 {t6}, [nt_buffer:128];


#define SHA512_CONVERT_ENDIAN(NT_NUM_KEYS,t0,t1,t2,t3,t4,t5,t6,t7,t8,t9) \
	mov i, #0;\
	add r6, nt_buffer_base, #(4*8*NT_NUM_KEYS);\
sha512_while_endian:\
	/* Load*/\
	add nt_buffer, nt_buffer_base, #(0*4*NT_NUM_KEYS); vld1.u32 {t1}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(1*4*NT_NUM_KEYS); vld1.u32 {t0}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(2*4*NT_NUM_KEYS); vld1.u32 {t3}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(3*4*NT_NUM_KEYS); vld1.u32 {t2}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(4*4*NT_NUM_KEYS); vld1.u32 {t5}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(5*4*NT_NUM_KEYS); vld1.u32 {t4}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(6*4*NT_NUM_KEYS); vld1.u32 {t7}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #(7*4*NT_NUM_KEYS); vld1.u32 {t8}, [nt_buffer:128];\
\
	/* Shuffle bytes*/\
	vrev32.u8 t0, t0;\
	vrev32.u8 t1, t1;\
	vrev32.u8 t2, t2;\
	vrev32.u8 t3, t3;\
	vrev32.u8 t4, t4;\
	vrev32.u8 t5, t5;\
	vrev32.u8 t7, t7;\
\
	/* Interleave dword*/\
	vmov.u64 t6, #0;\
	vmov.u64 t9, #0;\
	vzip.u32 t0, t1;\
	vzip.u32 t2, t3;\
	vzip.u32 t4, t5;\
	vzip.u32 t6, t7;\
	vzip.u32 t8, t9;\
\
	/* Write to W*/\
	add nt_buffer, r6, #(0 *8*NT_NUM_KEYS); vst1.u64 {t0,t1}, [nt_buffer:128];\
	add nt_buffer, r6, #(1 *8*NT_NUM_KEYS); vst1.u64 {t2,t3}, [nt_buffer:128];\
	add nt_buffer, r6, #(2 *8*NT_NUM_KEYS); vst1.u64 {t4,t5}, [nt_buffer:128];\
	add nt_buffer, r6, #(3 *8*NT_NUM_KEYS); vst1.u64 {t6,t7}, [nt_buffer:128];\
	add nt_buffer, r6, #(15*8*NT_NUM_KEYS); vst1.u64 {t8,t9}, [nt_buffer:128];\
\
	add i, #1;\
    add nt_buffer_base, #16;\
	add r6, #(2*16);\
    cmp i, #(NT_NUM_KEYS/4);\
    blo sha512_while_endian;


#define CRYPT_SHA512_AVX_KERNEL_ASM_BODY(NT_NUM_KEYS,reg_a,reg_b,reg_c,reg_d,reg_e,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const) \
	mov i, #0;\
sha512_while1:\
	add nt_buffer, nt_buffer_base, #((4+0 )*8*NT_NUM_KEYS); vld1.u32 {reg_h}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+1 )*8*NT_NUM_KEYS); vld1.u32 {reg_g}, [nt_buffer:128];\
\
	/*Step 1: H  = 0xfc08884d + W[0 * NT_NUM_KEYS]; D=0x9cbf5a55+H;*/\
	add nt_buffer, sha512_const_array, #(0 *16); vld1.u32 {step_const}, [nt_buffer:128];\
	add nt_buffer, sha512_const_array, #(75*16); vld1.u32 {t6}, [nt_buffer:128];\
	add nt_buffer, sha512_const_array, #(72*16); vld1.u32 {reg_a}, [nt_buffer:128];\
	add nt_buffer, sha512_const_array, #(77*16); vld1.u32 {reg_b}, [nt_buffer:128];\
	vadd.u64 reg_h, reg_h, step_const;\
	add nt_buffer, sha512_const_array, #(76*16); vld1.u32 {reg_c}, [nt_buffer:128];\
	add nt_buffer, sha512_const_array, #(73*16); vld1.u32 {reg_e}, [nt_buffer:128];\
	add nt_buffer, sha512_const_array, #(74*16); vld1.u32 {reg_f}, [nt_buffer:128];\
	vadd.u64 reg_d, reg_h, t6;\
\
	/*Step 2*/\
	SHA512_ROUND1(reg_g,reg_d,reg_f,reg_e,1 ,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((4+2)*8*NT_NUM_KEYS);\
	vld1.u32 {reg_f},[nt_buffer:128];\
	SHA512_ROUND1(reg_f,reg_c,reg_e,reg_d,2 ,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((4+3)*8*NT_NUM_KEYS);\
	vld1.u32 {reg_e},[nt_buffer:128];\
	SHA512_ROUND1(reg_e,reg_b,reg_d,reg_c,3 ,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_d,reg_a,reg_c,reg_b,4 ,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_c,reg_h,reg_b,reg_a,5 ,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_b,reg_g,reg_a,reg_h,6 ,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_a,reg_f,reg_h,reg_g,7 ,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,8 ,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_g,reg_d,reg_f,reg_e,9 ,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_f,reg_c,reg_e,reg_d,10,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_e,reg_b,reg_d,reg_c,11,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_d,reg_a,reg_c,reg_b,12,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_c,reg_h,reg_b,reg_a,13,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUND1(reg_b,reg_g,reg_a,reg_h,14,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const);\
	add nt_buffer, nt_buffer_base, #((4+15)*8*NT_NUM_KEYS);\
	vld1.u32 {t0},[nt_buffer:128];\
	vadd.u64 reg_a,reg_a,t0;\
	SHA512_ROUND1(reg_a,reg_f,reg_h,reg_g,15,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const);\
\
	/* Recalculate W*/\
	/*W[ 0 * NT_NUM_KEYS] +=					                               R0(W[1  * NT_NUM_KEYS]);*/\
	add nt_buffer, nt_buffer_base, #((4+1)*8*NT_NUM_KEYS);vld1.u64 {t5},[nt_buffer:128];\
	vshr.u64 t0, t5, #(64-63);\
	vshr.u64 t1, t5, #(64-56);\
	vshr.u64 t2, t5, #7;\
	vshl.u64 t3, t5, #63;\
	vshl.u64 t4, t5, #56;\
	vorr  t0, t3, t0;\
	vorr  t1, t4, t1;\
	veor  t0, t0, t1;\
	veor  t0, t0, t2;\
	add nt_buffer, nt_buffer_base, #((4+0)*8*NT_NUM_KEYS);vld1.u64 {t5},[nt_buffer:128];\
	vadd.u64 t0, t0, t5;\
	vst1.u64 {t0}, [nt_buffer:128];\
	/*Round 2*/\
	vadd.u64 reg_h, reg_h, t0;\
	SHA512_ROUND1(reg_h,reg_e,reg_g,reg_f,16,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const);\
	SHA512_ROUNDW_316(reg_g,reg_d,reg_f,reg_e,17,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,  1, 15, 16,  2,NT_NUM_KEYS);\
	SHA512_ROUNDW_316(reg_f,reg_c,reg_e,reg_d,18,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,  2, 0 , 16,  3,NT_NUM_KEYS);\
	SHA512_ROUNDW3416(reg_e,reg_b,reg_d,reg_c,19,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,  3, 1 , 16, 16,NT_NUM_KEYS);\
	SHA512_ROUND13416(reg_d,reg_a,reg_c,reg_b,20,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 , 16, 2 , 16, 16,NT_NUM_KEYS);\
	SHA512_ROUND13416(reg_c,reg_h,reg_b,reg_a,21,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 , 16, 3 , 16, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_b,reg_g,reg_a,reg_h,22,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 , 16, 4 , 15, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_a,reg_f,reg_h,reg_g,23,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 , 16, 5 ,  0, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_h,reg_e,reg_g,reg_f,24,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,8 , 16, 6 ,  1, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_g,reg_d,reg_f,reg_e,25,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,9 , 16, 7 ,  2, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_f,reg_c,reg_e,reg_d,26,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,10, 16, 8 ,  3, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_e,reg_b,reg_d,reg_c,27,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,11, 16, 9 ,  4, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_d,reg_a,reg_c,reg_b,28,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,12, 16, 10,  5, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW1416(reg_c,reg_h,reg_b,reg_a,29,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,13, 16, 11,  6, 16,NT_NUM_KEYS);\
	SHA512_ROUNDW116(reg_b,reg_g,reg_a,reg_h,30,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,14, 16, 12,  7, 15,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_a,reg_f,reg_h,reg_g,31,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,15, 15, 13,  8, 0 ,NT_NUM_KEYS);\
\
	/*Round 3*/\
	SHA512_ROUNDW(reg_h,reg_e,reg_g,reg_f,32,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,0 ,0 ,14,9 ,1 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_g,reg_d,reg_f,reg_e,33,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,1 ,15,10,2 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_f,reg_c,reg_e,reg_d,34,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,2 ,0 ,11,3 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_e,reg_b,reg_d,reg_c,35,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,3 ,1 ,12,4 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_d,reg_a,reg_c,reg_b,36,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 ,4 ,2 ,13,5 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_c,reg_h,reg_b,reg_a,37,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 ,5 ,3 ,14,6 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_b,reg_g,reg_a,reg_h,38,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 ,6 ,4 ,15,7 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_a,reg_f,reg_h,reg_g,39,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 ,7 ,5 ,0 ,8 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_h,reg_e,reg_g,reg_f,40,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,8 ,8 ,6 ,1 ,9 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_g,reg_d,reg_f,reg_e,41,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,9 ,9 ,7 ,2 ,10,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_f,reg_c,reg_e,reg_d,42,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,10,10,8 ,3 ,11,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_e,reg_b,reg_d,reg_c,43,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,11,11,9 ,4 ,12,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_d,reg_a,reg_c,reg_b,44,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,12,12,10,5 ,13,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_c,reg_h,reg_b,reg_a,45,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,13,13,11,6 ,14,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_b,reg_g,reg_a,reg_h,46,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,14,14,12,7 ,15,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_a,reg_f,reg_h,reg_g,47,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,15,15,13,8 ,0 ,NT_NUM_KEYS);\
\
	/*Round 4*/\
	SHA512_ROUNDW(reg_h,reg_e,reg_g,reg_f,48,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,0 ,0 ,14,9 ,1 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_g,reg_d,reg_f,reg_e,49,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,1 ,15,10,2 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_f,reg_c,reg_e,reg_d,50,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,2 ,0 ,11,3 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_e,reg_b,reg_d,reg_c,51,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,3 ,1 ,12,4 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_d,reg_a,reg_c,reg_b,52,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 ,4 ,2 ,13,5 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_c,reg_h,reg_b,reg_a,53,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 ,5 ,3 ,14,6 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_b,reg_g,reg_a,reg_h,54,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 ,6 ,4 ,15,7 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_a,reg_f,reg_h,reg_g,55,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 ,7 ,5 ,0 ,8 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_h,reg_e,reg_g,reg_f,56,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,8 ,8 ,6 ,1 ,9 ,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_g,reg_d,reg_f,reg_e,57,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,9 ,9 ,7 ,2 ,10,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_f,reg_c,reg_e,reg_d,58,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,10,10,8 ,3 ,11,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_e,reg_b,reg_d,reg_c,59,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,11,11,9 ,4 ,12,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_d,reg_a,reg_c,reg_b,60,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,12,12,10,5 ,13,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_c,reg_h,reg_b,reg_a,61,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,13,13,11,6 ,14,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_b,reg_g,reg_a,reg_h,62,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,14,14,12,7 ,15,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_a,reg_f,reg_h,reg_g,63,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,15,15,13,8 ,0 ,NT_NUM_KEYS);\
\
	/*Round 5*/\
	SHA512_ROUNDW(reg_h,reg_e,reg_g,reg_f,64,reg_d,reg_a,reg_b,reg_c,t0,t1,t2,t3,t4,t5,t6,step_const,0 ,0 ,14,9 ,1,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_g,reg_d,reg_f,reg_e,65,reg_c,reg_h,reg_a,reg_b,t0,t1,t2,t3,t4,t5,t6,step_const,1 ,1 ,15,10,2,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_f,reg_c,reg_e,reg_d,66,reg_b,reg_g,reg_h,reg_a,t0,t1,t2,t3,t4,t5,t6,step_const,2 ,2 ,0 ,11,3,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_e,reg_b,reg_d,reg_c,67,reg_a,reg_f,reg_g,reg_h,t0,t1,t2,t3,t4,t5,t6,step_const,3 ,3 ,1 ,12,4,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_d,reg_a,reg_c,reg_b,68,reg_h,reg_e,reg_f,reg_g,t0,t1,t2,t3,t4,t5,t6,step_const,4 ,4 ,2 ,13,5,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_c,reg_h,reg_b,reg_a,69,reg_g,reg_d,reg_e,reg_f,t0,t1,t2,t3,t4,t5,t6,step_const,5 ,5 ,3 ,14,6,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_b,reg_g,reg_a,reg_h,70,reg_f,reg_c,reg_d,reg_e,t0,t1,t2,t3,t4,t5,t6,step_const,6 ,6 ,4 ,15,7,NT_NUM_KEYS);\
	SHA512_ROUNDW(reg_a,reg_f,reg_h,reg_g,71,reg_e,reg_b,reg_c,reg_d,t0,t1,t2,t3,t4,t5,t6,step_const,7 ,7 ,5 ,0 ,8,NT_NUM_KEYS);\
	SHA512_RW_1SUM0(8,8 ,6,1,9 ,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA512_RW_1SUM0(9,9 ,7,2,10,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA512_RW_1SUM0(2,11,9,4,12,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA512_RW_1SUM0(1,13,2,6,14,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	SHA512_RW_1SUM0(0,15,1,8,0 ,t0,t1,t2,t3,t4,t5,t6,step_const,NT_NUM_KEYS);\
	add nt_buffer, nt_buffer_base, #((4+0)*8*NT_NUM_KEYS);\
	vld1.u64 {t0}, [nt_buffer:128];\
	vadd.u64 reg_a,reg_a,t0;\
\
	add nt_buffer, nt_buffer_base, #((4+4 )*8*NT_NUM_KEYS); vst1.u32 {reg_a}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+6 )*8*NT_NUM_KEYS); vst1.u32 {reg_b}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+16)*8*NT_NUM_KEYS); vst1.u32 {reg_c}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+17)*8*NT_NUM_KEYS); vst1.u32 {reg_d}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+18)*8*NT_NUM_KEYS); vst1.u32 {reg_e}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+19)*8*NT_NUM_KEYS); vst1.u32 {reg_f}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+20)*8*NT_NUM_KEYS); vst1.u32 {reg_g}, [nt_buffer:128];\
	add nt_buffer, nt_buffer_base, #((4+21)*8*NT_NUM_KEYS); vst1.u32 {reg_h}, [nt_buffer:128];\
\
	add i, #1;\
    add nt_buffer_base, #16;\
    cmp i, #(NT_NUM_KEYS/2);\
    blo sha512_while1;

	.text
	.align	2
	.global	crypt_sha512_neon_kernel_asm
	.type	crypt_sha512_neon_kernel_asm, %function
crypt_sha512_neon_kernel_asm:
  vpush {q4,q5,q6,q7}
  push	{r4,r5,r6}

  SHA512_CONVERT_ENDIAN(128,q0,q1,q2,q3,q4,q5,q6,q7,q8,q9)
  sub nt_buffer_base, nt_buffer_base, #(4*NT_NUM_KEYS)
  CRYPT_SHA512_AVX_KERNEL_ASM_BODY(128,q0,q1,q2,q3,q4,q5,q6,q7,q8,q9,q10,q11,q12,q13,q14,q15)
  
  pop  {r4,r5,r6}
  vpop {q4,q5,q6,q7}
  bx lr


#undef NT_NUM_KEYS
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
	//vmov q1, q0

while:
	//vst1.u32 {q0,q1}, [buffer:128]!
	//vst1.u32 {q0,q1}, [buffer:128]!
	//sub size, size, #16
	vst1.u32 {q0}, [buffer:128]!
	sub size, size, #4
	
	cmp size, #0
	bgt while

	bx lr
