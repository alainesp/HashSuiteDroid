// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#include "common.h"
#include <stdio.h>

#ifdef _WIN32
	#include <windows.h>
#else
	#include <pthread.h>
#endif

PUBLIC int64_t num_keys_served_from_save;
PUBLIC int64_t num_keys_served_from_start;
PUBLIC int64_t num_key_space;

PUBLIC unsigned int max_lenght;
PUBLIC unsigned int min_lenght;
PUBLIC unsigned int current_key_lenght;

PUBLIC void* thread_params = NULL;
PUBLIC unsigned int num_thread_params = 0;

// Mutex for thread-safe access
PUBLIC HS_MUTEX key_provider_mutex;

PUBLIC int64_t get_num_keys_served()
{
	return num_keys_served_from_save + num_keys_served_from_start;
}
PRIVATE void do_nothing(){}
PRIVATE void do_nothing_save_resume_arg(char* resume)
{
	resume[0] = 0;
}
PRIVATE void do_nothing_description(const char* provider_param, char* description, int min_lenght, int max_lenght)
{

}
////////////////////////////////////////////////////////////////////////////////////
// Charset mode
////////////////////////////////////////////////////////////////////////////////////
PUBLIC unsigned char charset[256];
PUBLIC unsigned int num_char_in_charset;
PUBLIC unsigned char current_key[MAX_KEY_LENGHT];

PRIVATE __forceinline void COPY_GENERATE_KEY_PROTOCOL_NTLM_CHARSET(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int index)
{
	unsigned int j = 0;

	for(; j < current_key_lenght/2; j++)
		nt_buffer[j*NUM_KEYS+index] = ((unsigned int)charset[current_key[2*j]]) | ((unsigned int)charset[current_key[2*j+1]]) << 16;

	nt_buffer[j*NUM_KEYS+index] = (current_key_lenght & 1) ? ((unsigned int)charset[current_key[2*j]]) | 0x800000 : 0x80;
	nt_buffer[14*NUM_KEYS+index] = current_key_lenght << 4;

	num_keys_served_from_save++;
}
PRIVATE __forceinline void COPY_GENERATE_KEY_PROTOCOL_NTLM_KEY(unsigned int* nt_buffer, const unsigned char* key, unsigned int NUM_KEYS, unsigned int index)
{
	unsigned int j = 0;

	for(; j < current_key_lenght/2; j++)	
		nt_buffer[j*NUM_KEYS+index] = ((unsigned int)key[2*j]) | ((unsigned int)key[2*j+1]) << 16;
												
	nt_buffer[j*NUM_KEYS+index] = (current_key_lenght & 1) ? ((unsigned int)key[2*j]) | 0x800000 : 0x80;
	nt_buffer[14*NUM_KEYS+index] = current_key_lenght << 4;	
												
	for(j++; j < 14; j++)						
		nt_buffer[j*NUM_KEYS+index] = 0;

	num_keys_served_from_save++;
}

PRIVATE __forceinline void next_key_charset()
{
	int index = 0;

	while(++current_key[index] == num_char_in_charset)
	{
		current_key[index] = 0;

		if(++index == current_key_lenght)
		{
			current_key_lenght++;
			break;
		}	
	}
}

// Copy only non repetitive characters
PRIVATE int strcpy_no_repetide(unsigned char* dst, char* src)
{
	int j;
	int is_repetide;
	int dst_pos, src_pos;
	int src_lenght = (int)strlen(src);

	for(src_pos = 0, dst_pos = 0; src_pos < src_lenght; src_pos++)
	{
		is_repetide = FALSE;

		for(j = src_pos + 1; j < src_lenght; j++)
			if(src[src_pos] == src[j])
			{
				is_repetide = TRUE;
				break;
			}

		if(!is_repetide)
		{
			dst[dst_pos] = src[src_pos];
			dst_pos++;
		}
	}

	// null terminate
	dst[dst_pos] = 0;

	return dst_pos;
} 
// param: charset
PRIVATE void charset_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index)
{
	int64_t pow_num;
	unsigned int i, j;

	num_keys_served_from_save = 0;
	memset(current_key, 0, sizeof(current_key));

	current_key_lenght = pmin_lenght;
	max_lenght = pmax_lenght;

	if(format_index == LM_INDEX)
		_strupr(param);

	num_char_in_charset = strcpy_no_repetide(charset, param);

	if(!num_char_in_charset)
	{
		current_key_lenght = 0;
		max_lenght = 0;
	}

	// Resume
	if(resume_arg && strlen(resume_arg))
	{
		current_key_lenght = (unsigned int)strlen(resume_arg);

		for(i = 0; i < current_key_lenght; i++)
			for(j = 0; j < num_char_in_charset; j++)
				if(resume_arg[i] == charset[j])
				{
					current_key[i] = j;
					break;
				}
	}

	// Calculate the key-space
	num_key_space = 0;
	pow_num = 1;

	// Take into account resume attacks
	for(i = 0; i < current_key_lenght ; i++, pow_num *= num_char_in_charset)
		num_key_space -= current_key[i] * pow_num;
	
	for(i = current_key_lenght; i <= max_lenght ; i++, pow_num *= num_char_in_charset)
	{
		num_key_space += pow_num;
		// Protects against integer overflow
		if(num_key_space > 0xFFFFFFFFFFFFFFF || pow_num > 0xFFFFFFFFFFFFFFF)
		{
			num_key_space = KEY_SPACE_UNKNOW;
			break;
		}
	}
}
PRIVATE void charset_save_resume_arg(char* resume_arg)
{
	unsigned int save_key_lenght = UINT_MAX;
	unsigned int old_index = 0;
	unsigned char* buffer = (unsigned char*)thread_params;
	resume_arg[0] = 0;

	if (thread_params)
	{
		unsigned int i, j;
		HS_ENTER_MUTEX(&key_provider_mutex);

		// Find the most old saved data
		for (i = 0; i < num_thread_params; i++)
		{
			unsigned int thread_key_lenght = ((unsigned int*)thread_params)[8 * i + 7];
			if (thread_key_lenght < save_key_lenght)
			{
				save_key_lenght = thread_key_lenght;
				old_index = i;
			}
			if (thread_key_lenght == save_key_lenght)
				for (j = thread_key_lenght - 1; j < thread_key_lenght; j--)
				{
					if (buffer[32 * i + j] < buffer[32 * old_index + j])
					{
						old_index = i;
						break;
					}
					if (buffer[32 * i + j] > buffer[32 * old_index + j])
						break;
				}
		}

		// Save current candidate
		for (i = 0; i < save_key_lenght; i++)
			resume_arg[i] = charset[buffer[32 * old_index + i]];

		resume_arg[save_key_lenght] = 0;

		HS_LEAVE_MUTEX(&key_provider_mutex);
	}
	else
	{
		unsigned int i;
		// Save current candidate
		for (i = 0; i < current_key_lenght; i++)
			resume_arg[i] = charset[current_key[i]];

		resume_arg[current_key_lenght] = 0;
	}
}

#ifdef ANDROID
typedef void MEMSET_UINT_DEC(unsigned int* buffer, unsigned int value, unsigned int size);

void memset_uint_neon(unsigned int* buffer, unsigned int value, unsigned int size);
PRIVATE void memset_uint_c_code(unsigned int* buffer, unsigned int value, unsigned int size)
{
	unsigned int i = 0;
	for (; i < size; i++)
		buffer[i] = value;
}
#else
PRIVATE void memset_uint(unsigned int* buffer, unsigned int value, unsigned int size)
{
	unsigned int i = 0;
	for (; i < size; i++)
		buffer[i] = value;
}
#endif

PRIVATE int charset_gen_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id)
{
	unsigned int i;
	unsigned int current_key_lenght1;
	int my_max_number = max_number;
	unsigned char current_key1[MAX_KEY_LENGHT];
	unsigned char* current_save = ((unsigned char*)thread_params) + 32 * thread_id;
#ifdef ANDROID
	MEMSET_UINT_DEC* memset_uint = current_cpu.capabilites[CPU_CAP_NEON] ? memset_uint_neon : memset_uint_c_code;
#endif

	HS_ENTER_MUTEX(&key_provider_mutex);

	if(current_key_lenght > max_lenght)
	{
		HS_LEAVE_MUTEX(&key_provider_mutex);
		return 0;
	}
	else
	{
		// Copy all
		current_key_lenght1 = current_key_lenght;
		((unsigned int*)current_save)[7] = current_key_lenght1;
		memcpy(current_save, current_key, current_key_lenght);
		memcpy(current_key1, current_key, max_lenght);
		num_keys_served_from_save += max_number;

		// Calculate final current_key with new algorithm
		if(!current_key_lenght)
		{
			current_key_lenght++;
			my_max_number--;
		}
		// Sum
		i = 0;
		while(my_max_number)
		{
			current_key[i] += my_max_number%num_char_in_charset;
			my_max_number /= num_char_in_charset;

			if(current_key[i] >= num_char_in_charset)
			{
				my_max_number++;
				current_key[i] -= num_char_in_charset;
			}

			// Increase length
			if(my_max_number && ++i == current_key_lenght)
			{
				current_key_lenght++;
				my_max_number--;
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);

	// If only change first 2 chars --> optimized version
	if(current_key_lenght1 <= max_lenght && current_key_lenght1 > 2 && (num_char_in_charset-current_key1[0]-1+(num_char_in_charset-current_key1[1]-1)*num_char_in_charset) > max_number)
	{
		unsigned int j = 1, key_0, key_1;
		unsigned int tmp;

		for(; j < current_key_lenght1/2; j++)
		{
			tmp = ((unsigned int)charset[current_key1[2*j]]) | ((unsigned int)charset[current_key1[2*j+1]]) << 16;
			memset_uint(nt_buffer+j*max_number, tmp, max_number);
			//for(i = 0; i < max_number; i++)
			//	nt_buffer[j*max_number+i] = tmp;
		}

		tmp = (current_key_lenght1 & 1) ? ((unsigned int)charset[current_key1[2*j]]) | 0x800000 : 0x80;
		memset_uint(nt_buffer+j*max_number, tmp, max_number);
		//i = j * max_number;
		//j = i + max_number;
		//for(; i < j; i++) nt_buffer[i] = tmp;

		tmp = current_key_lenght1 << 4;
		memset_uint(nt_buffer+14*max_number, tmp, max_number);
		//i = 14 * max_number;
		//j = i + max_number;
		//for(; i < j; i++) nt_buffer[i] = tmp;

		key_0 = current_key1[0];
		key_1 = current_key1[1];
		i = 0;
		j = max_number;
		for(; i < j; i++)
		{
			nt_buffer[i] = ((unsigned int)charset[key_0]) | ((unsigned int)charset[key_1]) << 16;
			// Next key
			if(++key_0 == num_char_in_charset)
			{
				key_0 = 0;
				key_1++;	
			}
		}
	}
	else
		for(i = 0; i < max_number; i++)					
		{
			unsigned int j = 0;
			// Copy key to nt_buffer
			for(; j < current_key_lenght1/2; j++)
				nt_buffer[j*max_number+i] = ((unsigned int)charset[current_key1[2*j]]) | ((unsigned int)charset[current_key1[2*j+1]]) << 16;

			nt_buffer[j*max_number+i] = (current_key_lenght1 & 1) ? ((unsigned int)charset[current_key1[2*j]]) | 0x800000 : 0x80;
			nt_buffer[14*max_number+i] = current_key_lenght1 << 4;

			// Next key
			if(current_key_lenght1) //if length > 0 
			{
				j = 0;
				while(++current_key1[j] == num_char_in_charset)
				{
					current_key1[j] = 0;

					if(++j == current_key_lenght1)
					{
						current_key_lenght1++;
						break;
					}	
				}
			}
			else// if length == 0
				current_key_lenght1++;
		}

	return 1;
}
PRIVATE int charset_gen_utf8_lm(unsigned char* keys, unsigned int max_number, int thread_id)
{
	unsigned int i = 0, j;
	int result = 1;
	unsigned char* current_save = ((unsigned char*)thread_params) + 32 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);

	((unsigned int*)current_save)[7] = current_key_lenght;
	memcpy(current_save, current_key, current_key_lenght);

	for(; i < max_number; i++, keys+=8)
	{
		// All keys generated
		if(current_key_lenght > max_lenght)
		{
			result = i;	break;
		}

		num_keys_served_from_save++;
		// Copy key
		for(j = 0; j < current_key_lenght; j++)
			keys[j] = charset[current_key[j]];

		// Next key
		if(current_key_lenght) //if length > 0 
			next_key_charset();
		else// if length == 0
			current_key_lenght++;
		
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;
}
PRIVATE int charset_gen_opencl(unsigned int* nt_buffer, unsigned int max_number, int thread_id)
{
	int result = 1;
	unsigned char* current_save = ((unsigned char*)thread_params) + 32 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);

	if(current_key_lenght > max_lenght)
		result = 0;
	else
	{
		unsigned int index = 0;
		num_keys_served_from_save += max_number*num_char_in_charset;

		// Ensure begin with aligned key at character 0
		num_keys_served_from_save -= current_key[0];
		current_key[0] = 0;

		// Copy all
		((unsigned int*)current_save)[7] = current_key_lenght;
		memcpy(current_save, current_key, current_key_lenght);
		memcpy(nt_buffer, current_key, sizeof(current_key));
		nt_buffer[8] = current_key_lenght;
		nt_buffer[9] = max_number;

		// Calculate final current_key with new algorithm
		while(max_number)// Sum
		{
			if(++index >= current_key_lenght)
			{
				// Calculate how much we exceed
				unsigned int pow = num_char_in_charset;
				unsigned int exceed_served = 0;
				for(index = 1; index < current_key_lenght; index++, pow*=num_char_in_charset)
					exceed_served += current_key[index]*pow;

				exceed_served += (max_number-1)*pow;
				num_keys_served_from_save -= exceed_served;
				nt_buffer[9] -= exceed_served/num_char_in_charset;
				// Support only one length in each call
				current_key_lenght++;
				memset(current_key, 0, current_key_lenght);
				break;
			}
			max_number += current_key[index];
			current_key[index] = max_number%num_char_in_charset;
			max_number /= num_char_in_charset;
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);
	return result;
}
PRIVATE int charset_gen_opencl_no_aligned(unsigned int* nt_buffer, unsigned int max_number, int thread_id)
{
	int result = 1;
	unsigned char* current_save = ((unsigned char*)thread_params) + 32 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);

	if(current_key_lenght > max_lenght)
		result = 0;
	else if(!current_key_lenght)
	{
		num_keys_served_from_save++;
		nt_buffer[8] = 0;
		nt_buffer[9] = 1;
		current_key_lenght++;
	}
	else
	{
		unsigned int index = 0;
		num_keys_served_from_save += max_number;

		// Copy all
		((unsigned int*)current_save)[7] = current_key_lenght;
		memcpy(current_save, current_key, current_key_lenght);
		memcpy(nt_buffer, current_key, sizeof(current_key));
		nt_buffer[8] = current_key_lenght;
		nt_buffer[9] = max_number;

		// Calculate final current_key with new algorithm
		while(max_number)// Sum
		{
			max_number += current_key[index];
			current_key[index] = max_number%num_char_in_charset;
			max_number /= num_char_in_charset;

			if(max_number && ++index >= current_key_lenght)
			{
				// Calculate how much we exceed
				unsigned int pow = 1;
				unsigned int exceed_served = 0;
				for(index = 0; index < current_key_lenght; index++, pow*=num_char_in_charset)
					exceed_served += current_key[index]*pow;

				exceed_served += (max_number-1)*pow;
				num_keys_served_from_save -= exceed_served;
				nt_buffer[9] -= exceed_served;
				// Support only one length in each call
				current_key_lenght++;
				memset(current_key, 0, current_key_lenght);
				break;
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);
	return result;
}

PRIVATE void charset_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght)
{
	int is_lower = FALSE;
	int is_upper = FALSE;
	int is_digit = FALSE;
	int is_simbol = FALSE;

	const char* charset_ptr = provider_param;

	for(; *charset_ptr; charset_ptr++)
	{
		if(isdigit(*charset_ptr))
			is_digit = TRUE;
		else if(isupper(*charset_ptr))
			is_upper = TRUE;
		else if(islower(*charset_ptr))
			is_lower = TRUE;
		else if(*charset_ptr >= 32 && *charset_ptr <= 126)
			is_simbol = TRUE;
	}

	sprintf(description, " %i-%i [%s%s%s%s]", min_lenght, max_lenght,
		is_lower?"L":"", is_upper?"U":"", is_digit?"D":"", is_simbol?"S":"");
}

////////////////////////////////////////////////////////////////////////////////////
// Wordlist mode
// See wordlist.c
////////////////////////////////////////////////////////////////////////////////////
void wordlist_resume(int pmin_lenght, int pmax_lenght, char* params, const char* resume_arg, int format_index);
void wordlist_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght);
void wordlist_save_resume_arg(char* resume_arg);
int wordlist_generate_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id);
int wordlist_generate_utf8_lm(unsigned char* keys, unsigned int max_number, int thread_id);
int wordlist_generate_utf8(unsigned char* keys, unsigned int max_number, int thread_id);

void sentence_resume(int pmin_lenght, int pmax_lenght, char* params, const char* resume_arg, int format_index);
int sentence_generate_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id);
int sentence_generate_utf8(unsigned char* keys, unsigned int max_number, int thread_id);
int sentence_generate_ocl(int* current_sentence1, unsigned int max_number, int thread_id);
void sentence_save_resume_arg(char* resume_arg);
void sentence_finish();
void sentence_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght);

////////////////////////////////////////////////////////////////////////////////////
// Keyboard mode
////////////////////////////////////////////////////////////////////////////////////
typedef struct ContextKey
{
	unsigned char near_keys[7];
	int num_near_keys;
}
ContextKey;
PRIVATE ContextKey keyboard_context[48];

PRIVATE unsigned char near_key_indexs[MAX_KEY_LENGHT];

PRIVATE int64_t num_key_space_by_lenght[] = {
	1ll, 48ll, 268ll, 1582ll, 9504ll, 57524ll, 349458ll, 2127706ll, 12974632ll, 79209438ll, 484005476ll,
	2959654272ll, 18109003598ll, 110858566206ll, 678941194544ll// TODO: calculate key-space for lengths greater than that
};

PRIVATE void add_near_key(int index, int near_index)
{
	keyboard_context[index].near_keys[keyboard_context[index].num_near_keys] = near_index;
	keyboard_context[index].num_near_keys++;
}
/*
		----------------------------------------------------------
	0	|`   1   2   3   4   5   6   7   8   9   0   -   =        |
	13	|      q   w   e   r   t   y   u   i   o   p   [   ]   \  |
	26	|        a   s   d   f   g   h   j   k   l   ;   '        |
	37	|      \   z   x   c   v   b   n   m   ,   .   /          |
	48	----------------------------------------------------------
*/
PRIVATE void add_near_in_col(int min_index, int max_index, int near_index)
{
	int i;
	for(i = min_index; i < max_index + 1; i++)
		add_near_key(i, near_index + (i - min_index));
}
PRIVATE void fill_keyboard_context()
{
	int i;

	// No near keys
	memset(keyboard_context, 0, sizeof(keyboard_context));

	// Rows
	for(i = 0; i < LENGHT(keyboard_context); i++)
	{
		add_near_key(i, i);        // Key are near same key
		if(i != 12 && i != 25 && i != 36 && i != 47)
			add_near_key(i, i + 1);// Next in row
		if(i != 0 && i != 13 && i != 26 && i != 37)
			add_near_key(i, i - 1);// Prev in row
	}
	// Columns
	// Down Next
	add_near_in_col(1, 12, 13);
	add_near_in_col(13, 23, 26);
	add_near_in_col(26, 35, 38);
	// Down Prev
	add_near_in_col(2, 12, 13);
	add_near_in_col(14, 24, 26);
	add_near_in_col(26, 36, 37);
	// Up Next
	add_near_in_col(13, 23, 2);
	add_near_in_col(26, 36, 14);
	add_near_in_col(37, 47, 26);
	// Up Prev
	add_near_in_col(13, 24, 1);
	add_near_in_col(26, 36, 13);
	add_near_in_col(38, 47, 26);
}
PRIVATE void keyboard_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index)
{
	unsigned int i;
	num_keys_served_from_save = 0;

	// At least 2 characters
	current_key_lenght = __max(2, pmin_lenght);
	max_lenght = __max(2, pmax_lenght);

	strcpy(charset, param);
	if(format_index == LM_INDEX)
		_strupr(charset);

	memset(near_key_indexs, 0, sizeof(near_key_indexs));

	fill_keyboard_context();

	current_key[0] = 0;
	for(i = 1; i < current_key_lenght; i++)
		current_key[i] = keyboard_context[current_key[i-1]].near_keys[near_key_indexs[i-1]];

	if(resume_arg && strlen(resume_arg))
	{
		int j;
		current_key_lenght = (unsigned int)strlen(resume_arg);

		for(i = 0; i < current_key_lenght; i++)
			for(j = 0; j < LENGHT(keyboard_context); j++)
				if(resume_arg[i] == charset[j])
				{
					current_key[i] = j;
					break;
				}
			
		for(; i < current_key_lenght-1; i++)
			for(j = 0; j < keyboard_context[i].num_near_keys; j++)
				if(keyboard_context[i].near_keys[j] == current_key[i+1])
				{
					near_key_indexs[i] = j;
					break;
				}
	}

	// Fill key-space from pre-calculate table
	if(max_lenght >= LENGHT(num_key_space_by_lenght))
		num_key_space = KEY_SPACE_UNKNOW;
	else
	{
		num_key_space = 0;

		for(i = current_key_lenght; i <= max_lenght ;i++)
			num_key_space += num_key_space_by_lenght[i];
	}
}
PRIVATE __forceinline void NEXT_KEY_KEYBOARD()
{
	int index = current_key_lenght - 2;
	unsigned int j;

	while(++near_key_indexs[index] == keyboard_context[current_key[index]].num_near_keys)
	{
		near_key_indexs[index] = 0;
		index--;

		if(index < 0)
		{
			if(++current_key[0] == LENGHT(keyboard_context))
			{
				current_key_lenght++;
				current_key[0] = 0;
			}
			index = 0;
			break;
		}
	}

	for(j = index + 1; j < current_key_lenght; j++)
		current_key[j] = keyboard_context[current_key[j-1]].near_keys[near_key_indexs[j-1]];
}

PRIVATE int keyboard_generate_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id)
{
	int result = 1;
	unsigned int* save_key = ((unsigned int*)thread_params) + 8 * thread_id;
	unsigned int i;

	HS_ENTER_MUTEX(&key_provider_mutex);
	memcpy(save_key, current_key, current_key_lenght);
	save_key[7] = current_key_lenght;

	for (i = 0; i < max_number; i++)
	{
		// All keys generated
		if (current_key_lenght > max_lenght)
		{
			result = i;	break;
		}

		COPY_GENERATE_KEY_PROTOCOL_NTLM_CHARSET(nt_buffer, max_number, i);

		// Next key
		NEXT_KEY_KEYBOARD();
	}
												
	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;								
}
PRIVATE int keyboard_generate_utf8_lm(unsigned char* keys, unsigned int max_number, int thread_id)
{
	unsigned int i = 0, j;
	int result = 1;
	unsigned int* save_key = ((unsigned int*)thread_params) + 8 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);
	memcpy(save_key, current_key, current_key_lenght);
	save_key[7] = current_key_lenght;

	for(; i < max_number; i++, keys+=8)
	{
		// All keys generated
		if(current_key_lenght > max_lenght)
		{
			result = i;	break;
		}

		num_keys_served_from_save++;
		// Copy key
		for(j = 0; j < current_key_lenght; j++)
			keys[j] = charset[current_key[j]];

		keys[current_key_lenght] = 0;

		// Next key
		NEXT_KEY_KEYBOARD();
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;
}
PRIVATE int keyboard_generate_utf8(unsigned char* keys, unsigned int max_number, int thread_id)
{
	unsigned int i = 0, j;
	unsigned int* save_key = ((unsigned int*)thread_params) + 8 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);
	memcpy(save_key, current_key, current_key_lenght);
	save_key[7] = current_key_lenght;

	for(; i < max_number; i++, keys += MAX_KEY_LENGHT)
	{
		// All keys generated
		if(current_key_lenght > max_lenght)
			break;

		num_keys_served_from_save++;
		// Copy key
		for(j = 0; j < current_key_lenght; j++)
			keys[j] = charset[current_key[j]];

		keys[current_key_lenght] = 0;

		// Next key
		NEXT_KEY_KEYBOARD();
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return i;
}
PRIVATE void keyboard_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght)
{
	sqlite3_stmt* find_layout;

	// Calculate key_space
	sqlite3_prepare_v2(db, "SELECT Name FROM Keyboard WHERE Chars == ?1;", -1, &find_layout, NULL);
	sqlite3_bind_text(find_layout, 1, provider_param, -1, SQLITE_STATIC);
	sqlite3_step(find_layout);
	sprintf(description, " [%s]", sqlite3_column_text(find_layout, 0));
	sqlite3_finalize(find_layout);
}

////////////////////////////////////////////////////////////////////////////////////
// Database info mode
////////////////////////////////////////////////////////////////////////////////////
PRIVATE sqlite3_stmt* select_info;
PRIVATE int more_rows;

PRIVATE void db_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index)
{
	sqlite3_stmt* count_key_space;
	max_lenght = pmax_lenght;
	min_lenght = pmin_lenght;

	more_rows = TRUE;

	// Calculate key_space
	sqlite3_prepare_v2(db, "SELECT count(*) FROM (SELECT UserName FROM Account UNION SELECT ClearText FROM FindHash);", -1, &count_key_space, NULL);
	sqlite3_step(count_key_space);
	num_key_space =  sqlite3_column_int(count_key_space, 0);
	sqlite3_finalize(count_key_space);

	sqlite3_prepare_v2(db, "SELECT UserName FROM Account UNION SELECT ClearText FROM FindHash;", -1, &select_info, NULL);
}
PRIVATE int db_generate_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id)
{
	int result = 1;
	unsigned int i;

	HS_ENTER_MUTEX(&key_provider_mutex);

	for (i = 0; i < max_number; i++)
	{
		const unsigned char* key;

		// All keys generated
		if (!more_rows || sqlite3_step(select_info) != SQLITE_ROW)
		{
			result = i;
			more_rows = FALSE;
			break;
		}
		key = sqlite3_column_text(select_info, 0);
		current_key_lenght = (unsigned int)strlen(key);

		// Skip short or long keys
		if (current_key_lenght < min_lenght || current_key_lenght > max_lenght)
		{
			i--;
			continue;
		}

		COPY_GENERATE_KEY_PROTOCOL_NTLM_KEY(nt_buffer, key, max_number, i);
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);
	return result;
}
PRIVATE int db_generate_utf8_lm(unsigned char* keys, unsigned int max_number, int thread_id)
{
	unsigned int i = 0;
	int result = 1;
	unsigned char key[8];

	memset(keys, 0, max_number*8);

	HS_ENTER_MUTEX(&key_provider_mutex);

	for(; i < max_number; i++, keys+=8)
	{
		// All keys generated
		if(!more_rows || sqlite3_step(select_info) != SQLITE_ROW)
		{
			result = i;
			more_rows = FALSE;
			break;
		}
		strncpy(key, sqlite3_column_text(select_info, 0), 7);
		key[7] = 0;
		current_key_lenght = (unsigned int)strlen(key);

		num_keys_served_from_save++;
		strncpy(keys, _strupr(key), max_lenght);
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;
}
PRIVATE int db_generate_utf8(unsigned char* keys, unsigned int max_number, int thread_id)
{
	unsigned int i = 0;

	HS_ENTER_MUTEX(&key_provider_mutex);

	for(; i < max_number; i++, keys+=MAX_KEY_LENGHT, num_keys_served_from_save++)
	{
		// All keys generated
		if(!more_rows || sqlite3_step(select_info) != SQLITE_ROW)
		{
			more_rows = FALSE;
			break;
		}
		strcpy(keys, sqlite3_column_text(select_info, 0));
		keys[MAX_KEY_LENGHT-1] = 0;
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return i;
}
PRIVATE void db_finish()
{
	sqlite3_finalize(select_info);
}

////////////////////////////////////////////////////////////////////////////////////
// LM2NTLM mode
////////////////////////////////////////////////////////////////////////////////////
PRIVATE sqlite3_stmt* select_lm_keys;
PRIVATE int need_key_from_db;

PRIVATE void lm2ntlm_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index)
{
	more_rows = TRUE;
	need_key_from_db = TRUE;

	sqlite3_prepare_v2(db, "SELECT DISTINCT (FindHash1.ClearText || FindHash2.ClearText) AS ClearText FROM AccountLM INNER JOIN FindHash AS FindHash1 ON FindHash1.ID==AccountLM.LM1 INNER JOIN FindHash AS FindHash2 ON FindHash2.ID==AccountLM.LM2;", -1, &select_lm_keys, NULL);

	num_key_space = KEY_SPACE_UNKNOW;
}
PRIVATE int lm2ntlm_generate_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id)
{
	int result = 1;
	unsigned int i, index;

	HS_ENTER_MUTEX(&key_provider_mutex);

	for (i = 0; i < max_number; i++)
	{
		if (need_key_from_db)
		{
			// All keys generated
			if (!more_rows || sqlite3_step(select_lm_keys) != SQLITE_ROW)
			{
				result = i;
				more_rows = FALSE;
				num_key_space = get_num_keys_served();
				break;
			}

			need_key_from_db = FALSE;

			strcpy(current_key, sqlite3_column_text(select_lm_keys, 0));
			current_key_lenght = (unsigned int)strlen(current_key);
		}

		COPY_GENERATE_KEY_PROTOCOL_NTLM_KEY(nt_buffer, current_key, max_number, i);

		// New key
		index = 0;
		while (index < current_key_lenght && !isalpha(current_key[index]))
			index++;

		while (index < current_key_lenght)
		{
			if (isupper(current_key[index]))
			{
				current_key[index] = tolower(current_key[index]);
				break;
			}
			else
			{
				current_key[index] = toupper(current_key[index]);

				index++;
				while (index < current_key_lenght && !isalpha(current_key[index]))
					index++;
			}
		}

		if (index >= current_key_lenght)
			need_key_from_db = TRUE;
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);
	return result;
}

PRIVATE int lm2ntlm_generate_utf8(unsigned char* keys, unsigned int max_number, int thread_id)
{												
	unsigned int i = 0;														

	HS_ENTER_MUTEX(&key_provider_mutex);	

	for(; i < max_number; i++, keys+=MAX_KEY_LENGHT, num_keys_served_from_save++)					
	{
		if(need_key_from_db)
		{
			// All keys generated
			if(!more_rows || sqlite3_step(select_lm_keys) != SQLITE_ROW)
			{
				more_rows = FALSE;
				num_key_space = get_num_keys_served();
				break;
			}

			need_key_from_db = FALSE;

			strcpy(current_key, sqlite3_column_text(select_lm_keys, 0));
			current_key_lenght = (unsigned int)strlen(current_key);
		}

		strcpy(keys, current_key);

		// New key
		{
			unsigned int index = 0;
			while(index < current_key_lenght && !isalpha(current_key[index]))
				index++;

			while(index < current_key_lenght)
			{
				if(isupper(current_key[index]))
				{
					current_key[index] = tolower(current_key[index]);
					break;
				}
				else
				{
					current_key[index] = toupper(current_key[index]);

					index++;
					while(index < current_key_lenght && !isalpha(current_key[index]))
						index++;
				}
			}

			if(index >= current_key_lenght)
				need_key_from_db = TRUE;
		}
	}											

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return i;								
}
PRIVATE void lm2ntlm_finish()
{
	sqlite3_finalize(select_lm_keys);
}
////////////////////////////////////////////////////////////////////////////////////
// Fast LM mode
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include <emmintrin.h>
#define SSE2_WORD		__m128i
#define SSE2_OR(a,b)	_mm_or_si128(a,b)
#define SSE2_ALL_ONES	_mm_set1_epi32(0xFFFFFFFFU)
#define SSE2_ZERO		_mm_setzero_si128()
#define SET_MASK(mask)	SSE2_WORD mask = _mm_set_epi32(0, 0, 0, 1);
#define NEXT_MAST(mask)	mask = (i==63) ? _mm_set_epi32(0, 1, 0, 0) : _mm_slli_epi64(mask, 1);
#endif

#ifdef HS_ARM
#include <arm_neon.h>
#define SSE2_WORD		uint64x2_t
#define SSE2_OR(a,b)	vorrq_u64(a,b)
#define SSE2_ALL_ONES	vdupq_n_u64(0xFFFFFFFFFFFFFFFFll)
#define SSE2_ZERO		vdupq_n_u64(0x0)
#define SET_MASK(mask)	SSE2_WORD mask = vdupq_n_u64(0);mask = vsetq_lane_u64(1, mask, 0);
#define NEXT_MAST(mask)	if(i==63){mask = vsetq_lane_u64(0, mask, 0);mask = vsetq_lane_u64(1, mask, 1);}else mask = vaddq_u64(mask, mask);
#endif

#define SSE2_BIT_LENGHT	128
PRIVATE SSE2_WORD lm_keys[56];
PRIVATE int num_iter_first;
PRIVATE int max_iter_first;

PRIVATE void CONVERT_CHAR_TO_LM_CHAR(int index)
{
	unsigned char char_to_convert = charset[current_key[index]];	

	lm_keys[55 - index*8 - 7] = (char_to_convert &  1 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 6] = (char_to_convert &  2 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 5] = (char_to_convert &  4 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 4] = (char_to_convert &  8 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 3] = (char_to_convert & 16 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 2] = (char_to_convert & 32 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 1] = (char_to_convert & 64 ) ? SSE2_ALL_ONES : SSE2_ZERO;	
	lm_keys[55 - index*8 - 0] = (char_to_convert & 128) ? SSE2_ALL_ONES : SSE2_ZERO;
}

PRIVATE void next_iter_first()
{
	SET_MASK(_mask);
	unsigned int i, j;

	if(num_iter_first >= max_iter_first)
	{
		current_key_lenght++;
		if(current_key_lenght > max_lenght)
			return;

		memset(current_key, 0, sizeof(current_key));
		num_iter_first = 0;
		CONVERT_CHAR_TO_LM_CHAR(current_key_lenght-3);
	}
	// Next in the last 2 chars
	memset(lm_keys + 8*(7-current_key_lenght), 0, 2*8*sizeof(SSE2_WORD));

	for(i = 0; i < SSE2_BIT_LENGHT; i++)
	{
		int index = current_key_lenght-2;

		for (j = 8*current_key_lenght-16; j < 8*current_key_lenght; j++)
			if ( (charset[current_key[j/8]] & (128 >> (j % 8))) )
				lm_keys[55 - j] = SSE2_OR(lm_keys[55 - j], _mask);

		NEXT_MAST(_mask)
		
		// next key
		while(++current_key[index] == num_char_in_charset)
		{
			current_key[index] = 0;
			index++;
		}
	}

	num_iter_first++;
}
PRIVATE void fast_lm_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index)
{
	unsigned int i;
	int64_t pow_num;

	charset_resume(pmin_lenght, pmax_lenght, param, resume_arg, format_index);

	max_iter_first = num_char_in_charset*num_char_in_charset/SSE2_BIT_LENGHT;
	memset(lm_keys, 0, sizeof(lm_keys));

	// Resume
	if(resume_arg && strlen(resume_arg))
	{
		int rest;

		num_iter_first = (num_char_in_charset*current_key[current_key_lenght-1]+current_key[current_key_lenght-2])/SSE2_BIT_LENGHT - 1;

		current_key[current_key_lenght-1] -= SSE2_BIT_LENGHT/num_char_in_charset;
		rest = current_key[current_key_lenght-2] - SSE2_BIT_LENGHT%num_char_in_charset;

		if(rest < 0)
		{
			current_key[current_key_lenght-1]--;
			current_key[current_key_lenght-2] = (num_char_in_charset+rest)%num_char_in_charset;
		}
		else
			current_key[current_key_lenght-2] = rest;
	}
	else
		num_iter_first = 0;
		
	next_iter_first();

	for(i = 0; i < current_key_lenght-2; i++)
		CONVERT_CHAR_TO_LM_CHAR(i);

	// Calculate key_space of current length
	num_key_space = 0;
	pow_num		  = SSE2_BIT_LENGHT;

	// Take into account resume attacks
	for(i = 0; i < current_key_lenght-2 ; i++, pow_num *= num_char_in_charset)
		num_key_space -= current_key[i] * pow_num ;

	num_key_space -= pow_num * (num_iter_first-1);
	pow_num *= max_iter_first;

	// Key_space of length greater than
	for(i = current_key_lenght; i <= max_lenght; i++, pow_num*=num_char_in_charset)
		num_key_space += pow_num;
}
PRIVATE int fast_lm_generate(SSE2_WORD* keys, unsigned int max_number, int thread_id)
{
	int result = 1, i;
	int num_repeat = max_number/SSE2_BIT_LENGHT;
	unsigned char* current_save = ((unsigned char*)thread_params) + 32 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);
	memcpy(current_save, current_key, current_key_lenght);
	((unsigned int*)current_save)[7] = current_key_lenght;

	for(i = 0; i < num_repeat; i++)
	{
		int j;
		// All keys generated
		if(current_key_lenght > max_lenght)
		{
			result = 0; goto end;
		}

		// Copy keys values
		for(j = 0; j < 56; j++)
			keys[i+j*num_repeat] = lm_keys[j];

		num_keys_served_from_save += SSE2_BIT_LENGHT;

		// Next
		{
			int index = 0;
			current_key[index]++;
			CONVERT_CHAR_TO_LM_CHAR(index);

			while(current_key[index] == num_char_in_charset)
			{
				current_key[index] = 0;
				CONVERT_CHAR_TO_LM_CHAR(index);

				if(++index == current_key_lenght-2)
				{
					next_iter_first();
					break;
				}

				current_key[index]++;
				CONVERT_CHAR_TO_LM_CHAR(index);
			}
		}
	}

end:
	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;
}
PRIVATE int fast_lm_opencl_generate(unsigned int* lm_param, unsigned int max_number, int thread_id)
{
	int result = 1;
	unsigned int i, j, pow, index = 0;
	unsigned char* current_save = ((unsigned char*)thread_params) + 32 * thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);

	memcpy(current_save, current_key, current_key_lenght);
	((unsigned int*)current_save)[7] = current_key_lenght;

	if(current_key_lenght > max_lenght)
		result = 0;
	else
	{
		num_keys_served_from_save += SSE2_BIT_LENGHT*max_number;

		// Copy all
		lm_param[0] = 0;
		pow = 1;
		for(i = 0; i < current_key_lenght-2; i++, pow *= num_char_in_charset)
			lm_param[0] += current_key[i] * pow;// Current key
		lm_param[1] = num_iter_first-1;// Last character position
		lm_param[2] = current_key_lenght;// Password length
		lm_param[3] = max_number;// Number of 32 bits keys to try

		// Calculate final current_key with new algorithm
		while(max_number)
		{
			// Normal
			if(index < current_key_lenght-2)
			{
				max_number += current_key[index];
				current_key[index] = max_number%num_char_in_charset;
				max_number /= num_char_in_charset;
				CONVERT_CHAR_TO_LM_CHAR(index);// Maintain CPU synchronization
				index++;
			}
			else// if change last characters
			{
				SET_MASK(_mask);
				num_iter_first += max_number;

				if(num_iter_first > max_iter_first)// Next length
				{
					// Calculate how much we exceed
					unsigned int pow = 1;
					unsigned int exceed_served = 0;
					for(i = 0; i < current_key_lenght-2; i++, pow*=num_char_in_charset)
						exceed_served += current_key[i]*pow;

					exceed_served += (num_iter_first-max_iter_first-1)*pow;
					num_keys_served_from_save -= exceed_served*SSE2_BIT_LENGHT;
					lm_param[3] -= exceed_served;
					// Support only one length in each call
					num_iter_first = 1;
					current_key_lenght++;
					memset(current_key, 0, current_key_lenght);
					if(current_key_lenght < 8)
						for (i = 0; i < current_key_lenght-2; i++)
							CONVERT_CHAR_TO_LM_CHAR(i);
				}
				max_number = 0;// Finish cycle
				// Maintain CPU synchronization
				if(current_key_lenght < 8)
				{
					// Calculate index of last characters(-1)
					current_key[current_key_lenght-2] = ((num_iter_first-1)*SSE2_BIT_LENGHT)%num_char_in_charset;
					current_key[current_key_lenght-1] = ((num_iter_first-1)*SSE2_BIT_LENGHT)/num_char_in_charset;

					// Put data of Last 2 chars
					memset(lm_keys + 8*(7-current_key_lenght), 0, 2*8*sizeof(SSE2_WORD));
					for(i = 0; i < SSE2_BIT_LENGHT; i++)
					{
						int index = current_key_lenght-2;

						for (j = 8*current_key_lenght-16; j < 8*current_key_lenght; j++)
							if ( (charset[current_key[j/8]] & (128 >> (j % 8))) )
								lm_keys[55 - j] = SSE2_OR(lm_keys[55 - j], _mask);

						NEXT_MAST(_mask)

						// next key
						while(++current_key[index] == num_char_in_charset)
						{
							current_key[index] = 0;
							index++;
						}
					}
				}
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;
}

PUBLIC void introduce_fast_lm(AttackData** batch, int* num_attack_in_batch)
{
	int i, lenght, num_keys_not_try;
	AttackData data = (*batch)[0];

#ifdef HS_X86
	if(current_cpu.capabilites[CPU_CAP_SSE2]
#endif
#ifdef HS_ARM
	if(current_cpu.capabilites[CPU_CAP_NEON]
#endif
		&& data.format_index == LM_INDEX && data.provider_index == CHARSET_INDEX && data.max_lenght >= key_providers[FAST_LM_INDEX].min_size)
	{
		charset_resume(data.min_lenght, data.max_lenght, data.params, NULL, data.format_index);

		num_keys_not_try = num_char_in_charset*num_char_in_charset - (num_char_in_charset*num_char_in_charset/SSE2_BIT_LENGHT)*SSE2_BIT_LENGHT;
	
		if(num_char_in_charset < 12)// 12*12 > 128
			return;

		// Calculate number of attack parts
		if(num_keys_not_try)
			num_attack_in_batch[0] = 2 + data.max_lenght - __max(data.min_lenght, key_providers[FAST_LM_INDEX].min_size);
		else
			num_attack_in_batch[0] = 1;

		if(data.min_lenght < key_providers[FAST_LM_INDEX].min_size)
			num_attack_in_batch[0]++;

		// Create and initialize
		free(*batch);
		*batch = (AttackData*)malloc( sizeof(AttackData) * num_attack_in_batch[0]);
		for(i = 0; i < num_attack_in_batch[0] ; i++)
			(*batch)[i] = data;

		i = 0;
		// Charset small
		if(data.min_lenght < key_providers[FAST_LM_INDEX].min_size)
		{
			(*batch)[i].max_lenght = key_providers[FAST_LM_INDEX].min_size - 1;
			i++;
		}
		// Fast lm
		(*batch)[i].min_lenght = __max(data.min_lenght, key_providers[FAST_LM_INDEX].min_size);
		(*batch)[i].provider_index = FAST_LM_INDEX;
		i++;
		// Charset Rest
		if(num_keys_not_try)
			for(lenght = __max(data.min_lenght, key_providers[FAST_LM_INDEX].min_size); lenght <= data.max_lenght; lenght++, i++)
			{
				(*batch)[i].min_lenght = lenght;
				(*batch)[i].max_lenght = lenght;

				charset_resume(lenght, lenght, data.params, NULL, data.format_index);

				current_key[lenght-1] = num_char_in_charset-1-num_keys_not_try/num_char_in_charset;
				current_key[lenght-2] = (num_char_in_charset-num_keys_not_try%num_char_in_charset)%num_char_in_charset;

				charset_save_resume_arg((*batch)[i].resume_arg);
			}
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////

PUBLIC void register_key_providers(int db_already_initialize)
{
	int i = 0;

	// Mutex for thread-safe access
	HS_CREATE_MUTEX(&key_provider_mutex);

	if (!db_already_initialize)
	{
		sqlite3_stmt* insert;
		// KeyProvider in database
		sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO KeyProvider (ID, Name, Description) VALUES (?, ?, ?);", -1, &insert, NULL);

		for (; i < num_key_providers; i++)
		{
			// Ensures all KeyProvider are in the db
			sqlite3_reset(insert);
			sqlite3_bind_int64(insert, 1, key_providers[i].db_id);
			sqlite3_bind_text(insert, 2, key_providers[i].name, -1, SQLITE_STATIC);
			sqlite3_bind_text(insert, 3, key_providers[i].description, -1, SQLITE_STATIC);
			sqlite3_step(insert);
		}

		sqlite3_finalize(insert);
	}
}

//TODO: delete this
void rules_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index);
int rules_generate_ntlm(unsigned int* nt_buffer, unsigned int max_number, int thread_id);
void rules_finish();
void rules_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght);

PUBLIC KeyProvider key_providers[] = {
	{
		"Charset" , "Fast generation of keys.", 1, 
		{{PROTOCOL_NTLM, charset_gen_ntlm}, {PROTOCOL_UTF8_LM, charset_gen_utf8_lm}, {PROTOCOL_CHARSET_OCL, charset_gen_opencl}, {PROTOCOL_CHARSET_OCL_NO_ALIGNED, charset_gen_opencl_no_aligned}},
		charset_save_resume_arg , charset_resume , do_nothing, charset_get_description, 0, 6, TRUE, FALSE, MAX_KEY_LENGHT
	},
	{
		"Wordlist", "Read keys from a file." , 2,
		{{PROTOCOL_NTLM, wordlist_generate_ntlm}, {PROTOCOL_UTF8_LM, wordlist_generate_utf8_lm}, {PROTOCOL_UTF8, wordlist_generate_utf8}, {PROTOCOL_UTF8, wordlist_generate_utf8}},
		wordlist_save_resume_arg, wordlist_resume, NULL, wordlist_get_description, 1, MAX_KEY_LENGHT, TRUE, TRUE, sizeof(fpos_t)
	},
	{
		"Keyboard", "Generate combination of adjacent keys in keyboard." , 3,
		{{PROTOCOL_NTLM, keyboard_generate_ntlm}, {PROTOCOL_UTF8_LM, keyboard_generate_utf8_lm}, {PROTOCOL_UTF8, keyboard_generate_utf8}, {PROTOCOL_UTF8, keyboard_generate_utf8}},
		charset_save_resume_arg, keyboard_resume, do_nothing, keyboard_get_description, 2, 10, TRUE, FALSE, MAX_KEY_LENGHT
	},
	{
		"Phrases" , "Generate phrases combining words from a wordlist.", 9,
		{{PROTOCOL_NTLM, sentence_generate_ntlm}, {PROTOCOL_PHRASES_OPENCL, sentence_generate_ocl}, {PROTOCOL_UTF8, sentence_generate_utf8}, {PROTOCOL_UTF8, sentence_generate_utf8}},
		sentence_save_resume_arg, sentence_resume, sentence_finish, sentence_get_description, 2, 4, TRUE, FALSE, MAX_KEY_LENGHT*sizeof(unsigned int)
	},
	{
		"DB Info" , "Tries usernames and passwords found.", 5, 
		{{PROTOCOL_NTLM, db_generate_ntlm}, {PROTOCOL_UTF8_LM, db_generate_utf8_lm}, {PROTOCOL_UTF8, db_generate_utf8}, {PROTOCOL_UTF8, db_generate_utf8}},
		do_nothing_save_resume_arg, db_resume, db_finish, do_nothing_description, 1, MAX_KEY_LENGHT, TRUE, TRUE, 0
	},
	{
		"LM2NT" , "Found NTLM passwords using LM passwords and correcting case.", 6, 
		{{PROTOCOL_NTLM, lm2ntlm_generate_ntlm}, {PROTOCOL_NTLM, lm2ntlm_generate_ntlm}, {PROTOCOL_UTF8, lm2ntlm_generate_utf8}, {PROTOCOL_UTF8, lm2ntlm_generate_utf8}},
		do_nothing_save_resume_arg, lm2ntlm_resume, lm2ntlm_finish, do_nothing_description, 0, MAX_KEY_LENGHT, TRUE, FALSE, 0
	},
	//////////////////////////////////////////////////////////////////////////////////////////////
	// Down are the 'private' key_providers: This key_providers do not show to user directly
	//////////////////////////////////////////////////////////////////////////////////////////////
	{
		"FastLM" , "Very fast generation of LM keys.", 7, 
		{{PROTOCOL_FAST_LM, fast_lm_generate}, {PROTOCOL_FAST_LM_OPENCL, fast_lm_opencl_generate}, {PROTOCOL_FAST_LM, fast_lm_generate}, {PROTOCOL_FAST_LM, fast_lm_generate}},
		charset_save_resume_arg, fast_lm_resume, do_nothing, charset_get_description, 4, 7, FALSE, FALSE, MAX_KEY_LENGHT
	},
	{
		"Rules" , "Apply rules.", 8, 
		{{PROTOCOL_NTLM, rules_generate_ntlm}, {PROTOCOL_NTLM, rules_generate_ntlm}, {PROTOCOL_RULES_OPENCL, rules_generate_ntlm}, {PROTOCOL_RULES_OPENCL, rules_generate_ntlm}},
		NULL, rules_resume, rules_finish, rules_get_description, 0, 27, FALSE, FALSE, 0
	}
	// TODO: Mask or KnowForce, characters Added, Subset, From STDIN, Distributed, ...
};
PUBLIC int num_key_providers = LENGHT(key_providers);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
#include "attack.h"
PUBLIC void ocl_rule_simple_copy(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	strcpy(nt_buffer[0 ], "+nt_buffer[0 ]");
	strcpy(nt_buffer[1 ], "+nt_buffer[1 ]");
	strcpy(nt_buffer[2 ], "+nt_buffer[2 ]");
	strcpy(nt_buffer[3 ], "+nt_buffer[3 ]");
	strcpy(nt_buffer[4 ], "+nt_buffer[4 ]");
	strcpy(nt_buffer[5 ], "+nt_buffer[5 ]");
	strcpy(nt_buffer[6 ], "+nt_buffer[6 ]");
	strcpy(nt_buffer[7 ], "+nt_buffer[7 ]");
	strcpy(nt_buffer[8 ], "+nt_buffer[8 ]");
	strcpy(nt_buffer[9 ], "+nt_buffer[9 ]");
	strcpy(nt_buffer[10], "+nt_buffer[10]");
	strcpy(nt_buffer[11], "+nt_buffer[11]");
	strcpy(nt_buffer[12], "+nt_buffer[12]");
	strcpy(nt_buffer[13], "+nt_buffer[13]");
	strcpy(nt_buffer[14], "+nt_len"       );

	// Total number of keys
	sprintf(source + strlen(source),
		"indx=get_global_id(0);"
		"uint nt_buffer[14];"
		"uint nt_len = keys[indx+7*%uu];"
		"c = (nt_len >> 6) + 1;", NUM_KEYS_OPENCL);

	for (unsigned int i = 2; i < 14; i++)
		sprintf(source + strlen(source), "nt_buffer[%u] = 0;", i);

	sprintf(source + strlen(source),
		"for(uint i = 0; i < c; i++){"
			"a = keys[indx+i*%uu];"
			"nt_buffer[2*i  ] = GET_1(a);"
			"nt_buffer[2*i+1] = GET_2(a);"
		"}", NUM_KEYS_OPENCL);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_charset_2_common(char* source, unsigned int NUM_KEYS_OPENCL)
{
	unsigned int i;
	DivisionParams div_param = get_div_params(num_char_in_charset);

	sprintf(source+strlen(source),	"#define GLOBAL_SIZE %uu\n"
									"__constant uchar charset[]={", NUM_KEYS_OPENCL);
	// Fill charset
	for(i = 0; i < num_char_in_charset; i++)
		sprintf(source+strlen(source), "%s%uU", i?",":"", (unsigned int)charset[i%num_char_in_charset]);
	strcat(source, "};\n");

	// Define the kernel to process the keys from charset into a "fast-to-use" format
	sprintf(source+strlen(source), "\n__kernel void process_key(__constant uchar* current_key,__global uint* restrict out_keys)"
									"{"
										// Global data
										"uint idx=get_global_id(0);"
										"uint max_number=idx;"
										"uint key_lenght=current_key[0];"
										"uint buffer=0;"

										"for(uint i=0;i<key_lenght;i++)"
										"{"
											"max_number+=current_key[i+1];");
// Perform division
if(div_param.magic)	sprintf(source+strlen(source), "uint div=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
else				sprintf(source+strlen(source), "uint div=max_number>>%iU;", (int)div_param.shift);// Power of two division
											

	sprintf(source+strlen(source),			"buffer|=((uint)charset[max_number-%uu*div])<<(8u*(i&3));"
											"max_number=div;"
											"if((i&3u)==3u)"
											"{"
												"out_keys[mad_sat(i/4u,GLOBAL_SIZE,idx)]=buffer;"
												"buffer=0u;"
											"}"
										"}"
										// Padding
										"buffer|=0x80<<(8u*(key_lenght&3));"
										"out_keys[mad_sat(key_lenght/4u,GLOBAL_SIZE,idx)]=buffer;"

										// Manage the length
										"out_keys[7u*GLOBAL_SIZE+idx]=key_lenght<<4u;"
									"}\n", num_char_in_charset);
}
PRIVATE void ocl_charset_setup_proccessed_keys_params(OpenCL_Param* param, GPUDevice* gpu)
{
	// Create memory objects
	create_opencl_mem(param, GPU_TO_PROCESS_KEY	, CL_MEM_READ_ONLY, MAX_KEY_LENGHT, NULL);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 0, sizeof(cl_mem), (void*) &param->mems[GPU_TO_PROCESS_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 1, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
}
PRIVATE size_t ocl_charset_process_buffer(unsigned int* buffer, int fill_result, OpenCL_Param* param, int* num_keys_filled)
{
	size_t num_work_items;
	unsigned char key_param[MAX_KEY_LENGHT];

	*num_keys_filled = buffer[9];
	num_work_items = (((unsigned int)(*num_keys_filled)) + (param->max_work_group_size-1)) & ~(param->max_work_group_size-1);// Convert to multiple of work_group_size

	// key_lenght
	key_param[0] = buffer[8];
	memcpy(key_param+1, buffer, key_param[0]);

	// TODO: Check if there is some problem
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_TO_PROCESS_KEY], CL_FALSE, 0, key_param[0]+1, key_param, 0, NULL, NULL);
	// Process key
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_PROCESS_KEY_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
	pclFinish(param->queue);

	return num_work_items;
}
PRIVATE void ocl_charset_get_key(unsigned char* buffer, unsigned char* out_key, unsigned int key_index, size_t num_work_items)
{
	unsigned int max_number = key_index, i;
	unsigned int key_lenght = ((unsigned int*)buffer)[8];
	// Calculate final current_key with new algorithm
	for(i = 0; i < key_lenght; i++)
	{
		max_number += buffer[i];
		out_key[i] = charset[max_number%num_char_in_charset];
		max_number /= num_char_in_charset;
	}
	out_key[key_lenght] = 0;
}
PRIVATE size_t ocl_charset_get_buffer_size(OpenCL_Param* param)
{
	return (MAX_KEY_LENGHT+2*sizeof(unsigned int));
}

PUBLIC void ocl_charset_process_found(OpenCL_Param* param, cl_uint* num_found, int is_consecutive, unsigned char* buffer, cl_uint key_lenght)
{
	unsigned char key[MAX_KEY_LENGHT];

	pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 4, 2*sizeof(cl_uint)*num_found[0], param->output, 0, NULL, NULL);
	// Iterate all found passwords
	for(unsigned int i = 0; i < num_found[0]; i++)
	{
		unsigned int max_number = param->output[2*i];

		// Extract key
		key[0] = is_consecutive ? (is_consecutive + max_number%num_char_in_charset) : charset[max_number%num_char_in_charset];
		max_number /= num_char_in_charset;

		// Calculate final current_key with new algorithm
		for(unsigned int j = 1; j < key_lenght; j++)
		{
			max_number += buffer[j];
			// Extract key
			key[j] = charset[max_number%num_char_in_charset];
			max_number /= num_char_in_charset;
		}
		key[key_lenght] = 0;

		password_was_found(param->output[2*i+1], key);
	}
	num_found[0] = 0;
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, sizeof(cl_uint), num_found, 0, NULL, NULL);
}
PUBLIC void ocl_common_process_found(OpenCL_Param* param, cl_uint* num_found, ocl_get_key* get_key, void* buffer, size_t num_work_items)
{
	unsigned char key[MAX_KEY_LENGHT];

	pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 4, 2 * sizeof(cl_uint)*num_found[0], param->output, 0, NULL, NULL);
	// Iterate all found passwords
	for (unsigned int i = 0; i < num_found[0]; i++)
	{
		get_key(buffer, key, param->output[2 * i], num_work_items);
		password_was_found(param->output[2 * i + 1], key);
	}

	num_found[0] = 0;
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, sizeof(cl_uint), num_found, 0, NULL, NULL);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE size_t ocl_utf8_get_buffer_size(OpenCL_Param* param)
{
	return MAX_KEY_LENGHT*param->NUM_KEYS_OPENCL;
}
PRIVATE size_t ocl_utf8_process_buffer(void* buffer, int fill_result, OpenCL_Param* param, int* num_keys_filled)
{
	size_t num_work_items;

	*num_keys_filled = fill_result;
	num_work_items = (((unsigned int)(*num_keys_filled)) + (param->max_work_group_size-1)) & ~(param->max_work_group_size-1);// Convert to multiple of work_group_size

	// TODO: Check if there is some problem
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_TO_PROCESS_KEY], CL_FALSE, 0, MAX_KEY_LENGHT*fill_result, buffer, 0, NULL, NULL);
	// Process key
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_PROCESS_KEY_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	return num_work_items;
}
PRIVATE void ocl_utf8_get_key(unsigned char* buffer, unsigned char* out_key, unsigned int key_index, size_t num_work_items)
{
	strcpy(out_key, buffer+MAX_KEY_LENGHT*key_index);
}
PRIVATE void ocl_gen_kernel_UTF8_2_common(char* source, unsigned int NUM_KEYS_OPENCL)
{
	sprintf(source+strlen(source),	"#define haszero(v) (((v)-0x01010101UL)&~(v)&0x80808080UL)\n"
									"#define GLOBAL_SIZE %uu\n", NUM_KEYS_OPENCL);

	// Define the kernel to process the keys from UTF8 into a "fast-to-use" format
	sprintf(source+strlen(source), "\n__kernel void process_key(const __global uint* restrict keys,__global uint* restrict out_keys)"
									"{"
										// Global data
										"uint idx=get_global_id(0);"
									
										// Get first 4-char
										"uint key_chars=keys[idx*8];"
										"uint key_index=0;"

										// Cycle until end of string
										"while(!haszero(key_chars))"
										"{"
											"out_keys[mad_sat(key_index,GLOBAL_SIZE,idx)]=key_chars;"
											"key_index++;"
											"key_chars=keys[mad_sat(idx,8u,key_index)];"
										"}"
										// Manage the end of string
										// TODO: Make this portable to big-endian
										"uint size_part=0;"
										"if((key_chars&0x00FF0000)==0)size_part=8;"
										"if((key_chars&0x0000FF00)==0)size_part=16;"
										"if((key_chars&0x000000FF)==0)size_part=24;"

										"out_keys[mad_sat(key_index,GLOBAL_SIZE,idx)]=(key_chars&(0x00FFFFFF>>size_part))+(0x80000000>>size_part);"
										// Manage the length
										"out_keys[7u*GLOBAL_SIZE+idx]=(key_index<<6)+(48-(size_part<<1));"
									"}\n");
}
PRIVATE void ocl_utf8_setup_proccessed_keys_params(OpenCL_Param* param, GPUDevice* gpu)
{
	// Create memory objects
	create_opencl_mem(param, GPU_TO_PROCESS_KEY	, CL_MEM_READ_ONLY, MAX_KEY_LENGHT*param->NUM_KEYS_OPENCL, NULL);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 0, sizeof(cl_mem), (void*) &param->mems[GPU_TO_PROCESS_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 1, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define WORD_POS_MASK		0x07ffffff
#define GET_WORD_POS(x)		(word_pos[(x)] & WORD_POS_MASK)
#define GET_WORD_LEN(x)		(word_pos[(x)] >> 27)

extern unsigned int* word_pos;
extern unsigned char* words;
extern unsigned int num_words;

PRIVATE size_t ocl_phrases_get_buffer_size(OpenCL_Param* param)
{
	return (MAX_KEY_LENGHT+2)*sizeof(unsigned int);
}
PRIVATE size_t ocl_phrases_process_buffer(unsigned int* sentence, int fill_result, OpenCL_Param* param, int* num_keys_filled)
{
	size_t num_work_items;

	*num_keys_filled = sentence[0];
	num_work_items = (((unsigned int)(*num_keys_filled)) + (param->max_work_group_size-1)) & ~(param->max_work_group_size-1);// Convert to multiple of work_group_size
	num_work_items /= 2;

	// TODO: Check if there is some problem
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_TO_PROCESS_KEY], CL_FALSE, 0, (sentence[1]+1)*sizeof(cl_uint), sentence+1, 0, NULL, NULL);
	// Process key
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_PROCESS_KEY_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	return num_work_items*2;
}
PRIVATE void ocl_phrases_get_key(unsigned int* sentence, unsigned char* out_key, unsigned int key_index, size_t num_work_items)
{
	unsigned int j, max_number = key_index;
	unsigned int found_sentence[MAX_KEY_LENGHT];
	int key_lenght = 0, is_space = 0;
	if(max_number >= num_work_items/2)
	{
		is_space = 1;
		max_number -= (unsigned int)(num_work_items/2);
	}
	// Calculate final current_sentence with new algorithm
	for(j = sentence[1] - 1; j < sentence[1]; j--)
	{
		max_number += sentence[2+j];
		found_sentence[j] = max_number%num_words;
		max_number /= num_words;
	}
				
	// Create the sentence
	for(j = 0; j < sentence[1]; j++)
	{
		unsigned int word_pos_j = GET_WORD_POS(found_sentence[j]);
		unsigned int len =	GET_WORD_LEN(found_sentence[j]);
		int use_space = j ? is_space : 0;

		if( (key_lenght+len+use_space) <= 27)
		{
			memcpy(out_key + key_lenght, " ", use_space);
			memcpy(out_key + key_lenght + use_space, words + word_pos_j, len);
			key_lenght += len + use_space;
		}
	}
	out_key[key_lenght] = 0;
}
PRIVATE void ocl_gen_kernel_phrases_2_common(char* source, unsigned int NUM_KEYS_OPENCL)
{
	sprintf(source+strlen(source),	"#define num_words %uu\n"
									"#define GLOBAL_SIZE %uu\n", num_words, NUM_KEYS_OPENCL);

	char key_lenght[16];
	// Define the kernel to process the keys from phrases into a "fast-to-use" format
	sprintf(source + strlen(source), "\n__kernel void process_key(__constant uint* keys,__global uint* restrict out_keys, const __global uint* restrict words, const __global uint* restrict word_pos)"
									"{"
									// Global data
									"uint out_idx=get_global_id(0);"
									"uint max_number=out_idx;"
									"uint current_sentence[%u];"
									"uint i;", max_lenght);

	if (current_key_lenght == max_lenght)
	{
		for (unsigned int i = max_lenght - 1; i < max_lenght; i--)
			sprintf(source + strlen(source),
									"max_number+=keys[%uu];"
									"current_sentence[%uu]=word_pos[max_number%%num_words];"
									"max_number/=num_words;", i + 1, i);
		sprintf(key_lenght, "%uu", max_lenght);
	}
	else
	{
		sprintf(source + strlen(source),
									"uint key_lenght=keys[0];"
									// Modify current_sentence to take into account work-item index
									"i=key_lenght-1;"
									"for(;i<key_lenght;i--)"
									"{"
										"max_number+=keys[i+1];"
										"current_sentence[i]=word_pos[max_number%%num_words];"
										"max_number/=num_words;"
									"}");
		strcpy(key_lenght, "key_lenght");
	}

	sprintf(source + strlen(source),// First word----------------------------------------
									"uint word_pos_j=current_sentence[0];"
									"uint len=word_pos_j>>27;"
									"word_pos_j&=0x07ffffff;"

									"uint total_len=len;"
									"uint buffer=0;"
									"uint chars_in_buffer=0;"
									// Body part of the string to copy
									"for(i=0;i<len/4;i++)"
									"{"
										"uint qword_copy=words[word_pos_j+i];"
										"out_keys[out_idx]=qword_copy;"
										"out_keys[out_idx+get_global_size(0)]=qword_copy;"
										"out_idx+=GLOBAL_SIZE;"
									"}"
									// Last part
									"len&=3;"
									"if(len)"
									"{"
										"buffer=words[word_pos_j+i];"
										"chars_in_buffer=len;"
									"}"
									// end of first word---------------------------------------------------
									"uint buffer_sp=buffer,total_len_sp=total_len,chars_in_buffer_sp=chars_in_buffer,out_idx_sp=out_idx+get_global_size(0);"

									// Common copy
									"for(max_number=1;max_number<%s;max_number++)"
									"{"
										"word_pos_j=current_sentence[max_number];"

										"len=word_pos_j>>27;"
										"word_pos_j&=0x07ffffff;"

										"if((total_len_sp+len)<27)"
										"{"
											// Put space
											"total_len_sp++;"
											"buffer_sp|=' '<<(8*chars_in_buffer_sp);"
											"chars_in_buffer_sp++;"
											"if(chars_in_buffer_sp>=4)"
											"{"
												"out_keys[out_idx_sp]=buffer_sp;"
												"out_idx_sp+=GLOBAL_SIZE;"
												"chars_in_buffer_sp=0;"
												"buffer_sp=0;"
											"}"

											// Body part of the string to copy
											"for(i=0;i<len/4;i++)"
											"{"
												"uint qword_copy=words[word_pos_j+i];"
												"buffer|=qword_copy<<(8*chars_in_buffer);"
												"buffer_sp|=qword_copy<<(8*chars_in_buffer_sp);"
												"out_keys[out_idx]=buffer;"
												"out_keys[out_idx_sp]=buffer_sp;"
												"out_idx+=GLOBAL_SIZE;"
												"out_idx_sp+=GLOBAL_SIZE;"
												"buffer=chars_in_buffer?(qword_copy>>(8*(4-chars_in_buffer))):0;"
												"buffer_sp=chars_in_buffer_sp?(qword_copy>>(8*(4-chars_in_buffer_sp))):0;"
											"}"
											"total_len+=len;"
											"total_len_sp+=len;"
											// Last part of the string to copy
											"len&=3;"
											"if(len)"
											"{"
												"uint qword_copy=words[word_pos_j+i];"
												"buffer|=qword_copy<<(8*chars_in_buffer);"
												"buffer_sp|=qword_copy<<(8*chars_in_buffer_sp);"
												"chars_in_buffer+=len;"
												"chars_in_buffer_sp+=len;"
												"if(chars_in_buffer>=4)"
												"{"
													"out_keys[out_idx]=buffer;"
													"out_idx+=GLOBAL_SIZE;"
													"chars_in_buffer-=4;"
													"buffer=chars_in_buffer?(qword_copy>>(8*(len-chars_in_buffer))):0;"
												"}"
												"if(chars_in_buffer_sp>=4)"
												"{"
													"out_keys[out_idx_sp]=buffer_sp;"
													"out_idx_sp+=GLOBAL_SIZE;"
													"chars_in_buffer_sp-=4;"
													"buffer_sp=chars_in_buffer_sp?(qword_copy>>(8*(len-chars_in_buffer_sp))):0;"
												"}"
											"}"
										"}"
										"else break;"
									"}"
									// Here only is the normal (without spaces)
									"for(;max_number<%s;max_number++)"
									"{"
										"if((total_len+len)<=27)"
										"{"
											"for(i=0;i<len/4;i++)"
											"{"
												"uint qword_copy=words[word_pos_j+i];"
												"buffer|=qword_copy<<(8*chars_in_buffer);"
												"out_keys[out_idx]=buffer;"
												"out_idx+=GLOBAL_SIZE;"
												"buffer=chars_in_buffer?(qword_copy>>(8*(4-chars_in_buffer))):0;"
											"}"
											"total_len+=len;"
											"len&=3;"
											"if(len)"
											"{"
												"uint qword_copy=words[word_pos_j+i];"
												"buffer|=qword_copy<<(8*chars_in_buffer);"
												"chars_in_buffer+=len;"
												"if(chars_in_buffer>=4)"
												"{"
													"out_keys[out_idx]=buffer;"
													"out_idx+=GLOBAL_SIZE;"
													"chars_in_buffer-=4;"
													"buffer=chars_in_buffer?(qword_copy>>(8*(len-chars_in_buffer))):0;"
												"}"
											"}"

											"if((max_number+1)<%s)"
											"{"
												"word_pos_j=current_sentence[max_number+1];"
												"len=word_pos_j>>27;"
												"word_pos_j&=0x07ffffff;"
											"}"
										"}"
										"else break;"
									"}"
									// Put padding
									"buffer|=0x80<<(8*chars_in_buffer);"
									"buffer_sp|=0x80<<(8*chars_in_buffer_sp);"
									"out_keys[out_idx]=buffer;"
									"out_keys[out_idx_sp]=buffer_sp;"
									// Put length
									"out_idx=get_global_id(0);"
									"out_keys[7u*GLOBAL_SIZE+out_idx]=total_len<<4;"
									"out_keys[7u*GLOBAL_SIZE+out_idx+get_global_size(0)]=total_len_sp<<4;"
								"}\n", key_lenght, key_lenght, key_lenght);
}
PRIVATE void ocl_phrases_setup_proccessed_keys_params(OpenCL_Param* param, GPUDevice* gpu)
{
	// The size is: (position of last element) + (length of last element) + a plus to ensure correct read by uint
	unsigned int size_words = GET_WORD_POS(num_words-1) + GET_WORD_LEN(num_words-1) + 4;

	// Create words aligned to 4 bytes
	unsigned int size_new_word = size_words + 3 * num_words;
	unsigned char* new_words   = (unsigned char*)malloc(size_new_word);
	unsigned int* new_word_pos = (unsigned int*)malloc(num_words*sizeof(cl_uint));
	unsigned int new_pos = 0;
	memset(new_words, 0, size_new_word);
	for (unsigned int i = 0; i < num_words; i++)
	{
		unsigned int len = GET_WORD_LEN(i);
		memcpy(new_words+new_pos, words + GET_WORD_POS(i), len);
		new_word_pos[i] = new_pos/4 + (len<<27);
		new_pos += ((len+3)/4)*4;
		// If bigger than GPU memory
		if (new_pos >= gpu->global_memory_size)
		{
			num_words = i;
			new_pos -= ((len+3)/4)*4;
			break;
		}
	}
	size_new_word = new_pos;

	// Params needed
	create_opencl_mem(param, GPU_WORDS	  , CL_MEM_READ_ONLY, size_new_word, NULL);
	create_opencl_mem(param, GPU_WORDS_POS, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_words, NULL);
	// Write to gpu memory
	cl_write_buffer(param, GPU_WORDS	, size_new_word, new_words);
	cl_write_buffer(param, GPU_WORDS_POS, sizeof(cl_uint)*num_words, new_word_pos);
	pclFinish(param->queue);

	free(new_words);
	free(new_word_pos);
	// Create memory objects
	create_opencl_mem(param, GPU_TO_PROCESS_KEY, CL_MEM_READ_ONLY, (MAX_KEY_LENGHT+1)*sizeof(cl_uint), NULL);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 0, sizeof(cl_mem), (void*) &param->mems[GPU_TO_PROCESS_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 1, sizeof(cl_mem), (void*) &param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 2, sizeof(cl_mem), (void*) &param->mems[GPU_WORDS]);
	pclSetKernelArg(param->kernels[KERNEL_PROCESS_KEY_INDEX], 3, sizeof(cl_mem), (void*) &param->mems[GPU_WORDS_POS]);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PUBLIC void ocl_gen_kernel_common_2_ordered(char* source, unsigned int NUM_KEYS_OPENCL, unsigned int max_key_lenght)
{
	unsigned int i, gpu_key_buffer_lenght;

	sprintf(source + strlen(source),"#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n"
									"#pragma OPENCL EXTENSION cl_khr_local_int32_base_atomics : enable\n"
									"__constant uint pos_by_lenght[]={");

	for (i = 0, gpu_key_buffer_lenght = 32; i <= max_key_lenght; i++)
	{
		sprintf(source + strlen(source), "%s%uu", i ? "," : "", gpu_key_buffer_lenght);
		gpu_key_buffer_lenght += (i + 3) / 4 * NUM_KEYS_OPENCL;
	}
	strcat(source, "};\n");

	// Define the kernel to process the keys from common into a format ordered by lenght
	sprintf(source + strlen(source), "\n__kernel void common2ordered(__global uint* restrict keys,__global uint* restrict out_keys)"
		"{"
			// Global data
			"uint idx=get_global_id(0);"
			"uint lenght=min(27u,(uint)(keys[%uu+idx]>>4u));"
			// Needed by local atomics
			"uint lidx=get_local_id(0);"
			"__local uint lpos_by_lenght[28];"
			// Initialize
			"if(lidx<28)"
				"lpos_by_lenght[lidx]=0;"
			"barrier(CLK_LOCAL_MEM_FENCE);"
			// Increment count
			"uint pos_out=atom_inc(lpos_by_lenght+lenght);"
			"barrier(CLK_LOCAL_MEM_FENCE);"
			// Update global memory
			"if(lidx<28 && lpos_by_lenght[lidx])"
				"lpos_by_lenght[lidx]=atom_add(out_keys+lidx,lpos_by_lenght[lidx])+pos_by_lenght[lidx];"
			"barrier(CLK_LOCAL_MEM_FENCE);"
			// Find position
			"pos_out+=lpos_by_lenght[lenght];"
			// All __local code is to improves performance of below line
			//"uint pos_out=atom_inc(out_keys+lenght)+pos_by_lenght[lenght];"

			// Copy
			"lenght=(lenght+3)/4;"
			"for(uint pos=0;pos<lenght;pos++)"
				"out_keys[mad_sat(pos,%uu,pos_out)]=keys[mad_sat(pos,%uu,idx)];"
		"}\n", 7u*NUM_KEYS_OPENCL, NUM_KEYS_OPENCL, NUM_KEYS_OPENCL);
}
PUBLIC void ocl_rules_process_found( OpenCL_Param* param, unsigned int* num_found, unsigned int* gpu_num_keys_by_len, unsigned int* gpu_pos_ordered_by_len)
{
	// Keys found
	unsigned char normal_key[MAX_KEY_LENGHT];
	unsigned char rule_key[MAX_KEY_LENGHT];

	pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 4, 3 * sizeof(cl_uint)*num_found[0], param->output, 0, NULL, NULL);

	// Iterate all found passwords
	for (unsigned int i = 0; i < num_found[0]; i++)
	{
		unsigned int key_index = param->output[3 * i];
		unsigned int hash_id = param->output[3 * i + 1];
		unsigned int rule_index = param->output[3 * i + 2] >> 22;
		unsigned int lenght = rule_index >> 5;
		rule_index &= 0x1F;
		if (rule_index < (unsigned int)num_rules && hash_id < num_passwords_loaded && !is_found[hash_id] && key_index < gpu_num_keys_by_len[lenght])
		{
			// Get the cleartext of the original key
			for (unsigned int j = 0; j < (lenght+3)/4; j++)
				pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, 4 * (gpu_pos_ordered_by_len[lenght] + key_index + j*param->NUM_KEYS_OPENCL), sizeof(cl_uint), normal_key + 4 * j, 0, NULL, NULL);

			pclFinish(param->queue);
			normal_key[lenght] = 0;
			// Transform key by the rule
			rules[rule_index].ocl.get_key(rule_key, normal_key, param->output[3 * i + 2] & 0x003FFFFF);
			password_was_found(hash_id, rule_key);
		}
	}

	num_found[0] = 0;
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, sizeof(cl_uint), num_found, 0, NULL, NULL);
}


PUBLIC oclKernel2Common kernels2common[] = {
	{PROTOCOL_CHARSET_OCL_NO_ALIGNED, ocl_gen_kernel_charset_2_common, ocl_charset_setup_proccessed_keys_params , ocl_charset_process_buffer, ocl_charset_get_key, ocl_charset_get_buffer_size},
	{PROTOCOL_PHRASES_OPENCL		, ocl_gen_kernel_phrases_2_common, ocl_phrases_setup_proccessed_keys_params , ocl_phrases_process_buffer, ocl_phrases_get_key, ocl_phrases_get_buffer_size},
	{PROTOCOL_UTF8					, ocl_gen_kernel_UTF8_2_common	 , ocl_utf8_setup_proccessed_keys_params	, ocl_utf8_process_buffer	, ocl_utf8_get_key	 , ocl_utf8_get_buffer_size}
};
PUBLIC unsigned int num_kernels2common = LENGHT(kernels2common);
#endif