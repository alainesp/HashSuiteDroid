// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#include "common.h"

#ifdef _WIN32
	#include <windows.h>
#else
	#include <pthread.h>
#endif

#define rules_nt_buffer				rules_data_buffer
#define RULES_IS_INIT_DATA_INDEX	(16*NUM_KEYS+0)
#define CURRENT_RULE_INDEX			(16*NUM_KEYS+1)
#define nt_buffer_index				rules_data_buffer[16*NUM_KEYS+2]
#define rules_nt_buffer_index		rules_data_buffer[16*NUM_KEYS+3]

#define CHAR_ADDED_INDEX			(16*NUM_KEYS+4 )
#define CHANGE_POS_INDEX			(16*NUM_KEYS+5 )
#define INSERT_POS_INDEX			(16*NUM_KEYS+6 )
#define DIGIT1_INDEX				(16*NUM_KEYS+7 )
#define DIGIT2_INDEX				(16*NUM_KEYS+8 )
#define IS_1900_INDEX				(16*NUM_KEYS+9 )
#define CHAR_ADDED0_INDEX			(16*NUM_KEYS+10)
#define CHAR_ADDED1_INDEX			(16*NUM_KEYS+11)
#define CHAR_ADDED2_INDEX			(16*NUM_KEYS+12)
#define LEET_INDEX0					(16*NUM_KEYS+13)

////////////////////////////////////////////////////////////////////////////////////
// Specific rules
////////////////////////////////////////////////////////////////////////////////////
PRIVATE void rule_copy(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int num_to_copy = __min(NUM_KEYS-rules_nt_buffer_index, NUM_KEYS-nt_buffer_index);
	int i = 0;
	for(; i < 15; i++)
		memcpy(nt_buffer+i*NUM_KEYS+nt_buffer_index, rules_nt_buffer+i*NUM_KEYS+rules_nt_buffer_index, sizeof(unsigned int)*num_to_copy);

	rules_nt_buffer_index += num_to_copy;
	nt_buffer_index += num_to_copy;
}
PRIVATE void rule_lower(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		unsigned int i;
		int need_change = FALSE;
		int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if(_tmp >= 4259840 && _tmp <= 5963775)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(need_change)
		{
			for(; i < 14*NUM_KEYS; i+=NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
	}
}
PRIVATE void rule_upper(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		unsigned int i;
		int need_change = FALSE;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'a' && (_tmp & 0xFF) <= 'z')
			{
				need_change = TRUE;
				_tmp -= 32;
			}
			if(_tmp >= 6356992 && _tmp <= 8060927)
			{
				need_change = TRUE;
				_tmp -= 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(need_change)
		{
			for(; i < 14*NUM_KEYS; i+=NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
	}
}
PRIVATE void rule_capitalize(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		unsigned int i;
		int need_change = FALSE;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
			unsigned int _char = _tmp & 0xFF;

			if(i)
			{
				if(_char >= 'A' && _char <= 'Z')
				{
					need_change = TRUE;
					_tmp += 32;
				}
			}
			else
			{
				// First position -> to-upper
				if(_char >= 'a' && _char <= 'z')
				{
					need_change = TRUE;
					_tmp -= 32;
				}
				else if(_char < 'A' || _char > 'Z')
					break;//need_change = FALSE
			}

			if(_tmp >= 4259840 && _tmp <= 5963775)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(need_change)
		{
			for(; i < 14*NUM_KEYS; i+=NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
	}
}
PRIVATE void rule_duplicate(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		int i;
		int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int lenght_2num_keys = lenght/2*NUM_KEYS;

		if(lenght > 13) continue;

		if(lenght & 1)
		{ 
			unsigned int last_tmp = rules_nt_buffer[lenght_2num_keys+rules_nt_buffer_index] & 0xFF;

			for(i = 0; i < lenght_2num_keys; i+=NUM_KEYS)
			{
				unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
				nt_buffer[i+nt_buffer_index] = _tmp;
				nt_buffer[i+lenght_2num_keys+nt_buffer_index] = (_tmp << 16) | last_tmp;

				last_tmp = _tmp >> 16;
			}

			nt_buffer[i+lenght_2num_keys+nt_buffer_index] = last_tmp | (rules_nt_buffer[i+rules_nt_buffer_index] << 16);
		}
		else
			for(i = 0; i < lenght_2num_keys; i+=NUM_KEYS)
			{
				unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
				nt_buffer[i+nt_buffer_index] = _tmp;
				nt_buffer[i+lenght_2num_keys+nt_buffer_index] = _tmp;
			}

		nt_buffer[lenght*NUM_KEYS+nt_buffer_index] = 0x80;
		lenght_2num_keys = 14*NUM_KEYS+nt_buffer_index;

		for(i = (lenght+1)*NUM_KEYS+nt_buffer_index; i < lenght_2num_keys; i+=NUM_KEYS)
			nt_buffer[i] = 0;

		nt_buffer[lenght_2num_keys] = lenght << 5;
		nt_buffer_index++;
	}
}
PRIVATE void rule_lower_upper_last(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		unsigned int i;
		int need_change = FALSE;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int MAX = (lenght & 1) ? lenght/2*NUM_KEYS : (lenght/2-1)*NUM_KEYS;
		if(!lenght) continue;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if(_tmp >= 4259840 && _tmp <= 5963775)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		// Last letter --> uppercase
		if(lenght & 1)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'a' && (_tmp & 0xFF) <= 'z')
			{
				need_change = TRUE;
				_tmp -= 32;
			}
			else if((_tmp & 0xFF) < 'A' && (_tmp & 0xFF) > 'Z')
				need_change = FALSE;

			nt_buffer[i+nt_buffer_index] = _tmp;
		}
		else
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if(_tmp >= 6356992 && _tmp <= 8060927)
			{
				need_change = TRUE;
				_tmp -= 32 << 16;
			}
			else if(_tmp < 4259840 || _tmp > 5963775)
				need_change = FALSE;

			nt_buffer[i+nt_buffer_index] = _tmp;
			i+=NUM_KEYS;
			nt_buffer[i+nt_buffer_index] = 0x80;
		}

		if(need_change)
		{
			i+=NUM_KEYS;

			for(; i < 14*NUM_KEYS; i+=NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
	}
}
// OpenCL rules
#ifdef HS_OPENCL_SUPPORT
PRIVATE void write_finish_brace(char* source)
{
	strcat(source, "}");
}
PRIVATE void ocl_fill_buffer(char nt_buffer[16][16], unsigned int lenght)
{
	unsigned int i;
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i], "+nt_buffer%u", i);

	if (lenght & 1)
		sprintf(nt_buffer[i], "+nt_buffer%u", i);
	else
		strcpy(nt_buffer[i], "+0x80");

	i++;
	for (; i < 14; i++)
		strcpy(nt_buffer[i], "");

	sprintf(nt_buffer[14], "+%uu", lenght << 4);
}
PRIVATE void ocl_fill_buffer_array(char nt_buffer[16][16], unsigned int lenght)
{
	unsigned int i;
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i], "+nt_buffer[%u]", i);

	if (lenght & 1)
		sprintf(nt_buffer[i], "+nt_buffer[%u]", i);
	else
		strcpy(nt_buffer[i], "+0x80");

	i++;
	for (; i < 14; i++)
		strcpy(nt_buffer[i], "");

	sprintf(nt_buffer[14], "+%uu", lenght << 4);
}
PRIVATE void ocl_rule_copy(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	unsigned int i, gpu_key_buffer_lenght;

	ocl_fill_buffer(nt_buffer, lenght);
	if (!lenght) return;

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i < lenght; i++)
		gpu_key_buffer_lenght += (i + 3) / 4;

	// Total number of keys
	sprintf(source + strlen(source), "indx=get_global_id(0)+%uu;", 32+gpu_key_buffer_lenght*NUM_KEYS_OPENCL);
	// Convert the key into a nt_buffer
	for (i = 0; i < ((lenght + 3) / 4 - 1); i++)
		sprintf(source + strlen(source),
				"a = keys[indx+%uu];"
				"uint nt_buffer%u = GET_1(a);"
				"uint nt_buffer%u = GET_2(a);"
				, i*NUM_KEYS_OPENCL, 2 * i, 2 * i + 1);

	// Last
	sprintf(source + strlen(source),
		"a = keys[indx+%uu];"
		"uint nt_buffer%u = GET_1(a);"
		, i*NUM_KEYS_OPENCL, 2 * i);
	if (lenght % 4 == 3 || lenght % 4 == 0)
		sprintf(source + strlen(source), "uint nt_buffer%u = GET_2(a);", 2 * i + 1);
}
PRIVATE void ocl_rule_copy_array(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL, unsigned int more_buffer)
{
	unsigned int i, gpu_key_buffer_lenght;

	ocl_fill_buffer_array(nt_buffer, lenght);
	if (!lenght) return;

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i < lenght; i++)
		gpu_key_buffer_lenght += (i + 3) / 4;

	// Total number of keys
	sprintf(source + strlen(source),"indx=get_global_id(0)+%uu;"
									"uint nt_buffer[%u];", 32+gpu_key_buffer_lenght*NUM_KEYS_OPENCL, (lenght + 1 + more_buffer) / 2);
	// Convert the key into a nt_buffer
	for (i = 0; i < ((lenght + 3) / 4 - 1); i++)
		sprintf(source + strlen(source),"a = keys[indx+%uu];"
										"nt_buffer[%u] = GET_1(a);"
										"nt_buffer[%u] = GET_2(a);"
										, i*NUM_KEYS_OPENCL, 2 * i, 2 * i + 1);
	// Last
	sprintf(source + strlen(source),"a = keys[indx+%uu];"
									"nt_buffer[%u] = GET_1(a);"
									, i*NUM_KEYS_OPENCL, 2 * i);
	if (lenght % 4 == 3 || lenght % 4 == 0)
		sprintf(source + strlen(source), "nt_buffer[%u] = GET_2(a);", 2 * i + 1);
}
PRIVATE void ocl_rule_lower(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Lowercase
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);
}
PRIVATE void ocl_rule_upper(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Uppercase
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 6356992u) <= 1703935u)"
												"nt_buffer%u -= 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 97u) <= 25u)"
												"nt_buffer%u -= 32;"
												, i / 2, i / 2, i / 2);
}
PRIVATE void ocl_rule_capitalize(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	//Capitalize
	if (lenght)
		sprintf(source + strlen(source),"if(((nt_buffer0 & 0xFF) - 97u) <= 25u)"
											"nt_buffer0 -= 32;");
	// Lowercase
	for (unsigned int i = 1; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);
}
PRIVATE void ocl_rule_duplicate(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	if (lenght > 13)
	{
		strcat(source, "return;");
		return;
	}
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", lenght << 5);
	if (lenght & 1)
	{
		sprintf(source + strlen(source), "nt_buffer%u = (nt_buffer%u & 0xff) | (nt_buffer0 << 16);", lenght / 2, lenght / 2);
		for (unsigned int i = 0; i < lenght / 2; i++)
		{
			sprintf(nt_buffer[lenght / 2 + i + 1], "+nt_buffer%u", lenght / 2 + i + 1);
			sprintf(source + strlen(source), "uint nt_buffer%u = (nt_buffer%u << 16) | (nt_buffer%u >> 16);", lenght / 2 + i + 1, i+1, i);
		}
	}
	else
		for (unsigned int i = 0; i < lenght/2; i++)
			strcpy(nt_buffer[lenght / 2 + i], nt_buffer[i]);

	strcpy(nt_buffer[lenght], "+0x80");
}
PRIVATE void ocl_rule_lower_upper_last(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	unsigned int i;
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Requires length greater than 0
	if (!lenght)
	{
		strcat(source, "return;");
		return;
	}

	// Lowercase
	for (i = 0; i < lenght-1; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);

	// Upper last
	if (i & 1)
		sprintf(source + strlen(source), "if((nt_buffer%u - 6356992u) <= 1703935u)"
											"nt_buffer%u -= 32 << 16;"
											, i / 2, i / 2, i / 2);
	else
		sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 97u) <= 25u)"
												"nt_buffer%u -= 32;"
												, i / 2, i / 2, i / 2);
}
// Get plaintext
PRIVATE void ocl_copy_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
}
PRIVATE void ocl_lower_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
}
PRIVATE void ocl_upper_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strupr(out_key);
}
PRIVATE void ocl_capitalize_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	if(islower(out_key[0]))
		out_key[0] -= 32;
}
PRIVATE void ocl_duplicate_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	strcpy(out_key+strlen(out_key), plain);
}
PRIVATE void ocl_lower_upper_last_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	if( islower(out_key[strlen(out_key)-1]) )
		out_key[strlen(out_key)-1] -= 32;
}
#endif

// Append and prefix stuff
#define MAX_CHAR_ADDED 126/*'~'*/
#define MIN_CHAR_ADDED  32/*' '*/
#define LENGHT_CHAR_ADDED (MAX_CHAR_ADDED-MIN_CHAR_ADDED+1)

PRIVATE void rule_lower_append(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added = rules_data_buffer[CHAR_ADDED_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
				_tmp += 32;
			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(_tmp >= 'A' && _tmp <= 'Z')
				_tmp += 32;

			for(j = i + nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = _tmp | (char_added << 16);

			i += NUM_KEYS;
			MAX += NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}
		else
			for(j = i + nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = char_added | 0x800000;

		i   += NUM_KEYS;
		MAX += NUM_KEYS;
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+1) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_capitalize_append(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added = rules_data_buffer[CHAR_ADDED_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i)
			{
				if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
					_tmp += 32;
			}
			else
			{
				// First position -> to-upper
				if((_tmp & 0xFF) >= 'a' && (_tmp & 0xFF) <= 'z')
					_tmp -= 32;
			}
			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(_tmp >= 'A' && _tmp <= 'Z')
				_tmp += 32;

			for(j = i + nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = _tmp | (char_added << 16);

			i+=NUM_KEYS;
			MAX+=NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}
		else
			for(j = i + nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = char_added | 0x800000;

		i   += NUM_KEYS;
		MAX += NUM_KEYS;
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+1) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_prefix(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added = rules_data_buffer[CHAR_ADDED_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;
		unsigned int MAX_LOWER = (lenght+3)/2*NUM_KEYS;

		if(lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for(i = 0; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
			unsigned int last_tmp;

			if(i)
			{
				last_tmp = (_tmp << 16) | (last_tmp >> 16);
				for(j = i+nt_buffer_index; j < MAX; j++)
					nt_buffer[j] = last_tmp;
			}
			else
			{
				last_tmp = _tmp << 16;
				for(j = nt_buffer_index; j < MAX; j++, char_added++)
					nt_buffer[j] = char_added | last_tmp;
			}

			last_tmp = _tmp;
		}

		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 1) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if(char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_lower_append(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	// Lowercase
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);
	// Append character
	if (lenght & 1)
	{
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
		sprintf(source + strlen(source), "nt_buffer%u = (nt_buffer%u & 0xff) | %uu;", lenght / 2, lenght / 2, MIN_CHAR_ADDED << 16);
	}
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
		sprintf(source + strlen(source), "uint nt_buffer%u = %uu;", lenght / 2, 0x800000 | MIN_CHAR_ADDED);
	}
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, nt_buffer%u+=%uu){", LENGHT_CHAR_ADDED, lenght / 2, 1 << (16 * (lenght & 1)));

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght+1) << 4);
}
PRIVATE void ocl_rule_capitalize_append(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	//Capitalize
	if (lenght)
		sprintf(source + strlen(source),"if(((nt_buffer0 & 0xFF) - 97u) <= 25u)"
											"nt_buffer0 -= 32;");
	// Lowercase
	for (unsigned int i = 1; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);
	// Append character
	if (lenght & 1)
	{
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
		sprintf(source + strlen(source), "nt_buffer%u = (nt_buffer%u & 0xff) | %uu;", lenght / 2, lenght / 2, MIN_CHAR_ADDED << 16);
	}
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
		sprintf(source + strlen(source), "uint nt_buffer%u = %uu;", lenght / 2, 0x800000 | MIN_CHAR_ADDED);
	}
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, nt_buffer%u+=%uu){", LENGHT_CHAR_ADDED, lenght / 2, 1 << (16 * (lenght & 1)));

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 1) << 4);
}
PRIVATE void ocl_rule_prefix(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	// Prefix character
	if (lenght & 1)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
		sprintf(source + strlen(source), "uint nt_buffer%u = 0x80;", lenght / 2);
	}
	// First character
	sprintf(source + strlen(source),
		"uint tmp = nt_buffer0 >> 16;"
		"nt_buffer0 <<= 16;"
		"nt_buffer0 |= %uu;", MIN_CHAR_ADDED);
	// Copy
	for (unsigned int i = 1; i < lenght/2 + 1; i++)
		sprintf(source + strlen(source),
			"a = tmp | (nt_buffer%u << 16);"
			"tmp = nt_buffer%u >> 16;"
			"nt_buffer%u = a;"
			, i, i, i);
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, nt_buffer0++){", LENGHT_CHAR_ADDED);
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 1) << 4);
}
// Get plaintext
PRIVATE void ocl_lower_append_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	out_key[strlen(out_key)+1] = 0;
	out_key[strlen(out_key)] = (unsigned char)(MIN_CHAR_ADDED + param);
}
PRIVATE void ocl_capitalize_append_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	// Capitalize
	if(islower(out_key[0]))
		out_key[0] -= 32;
	// Append
	out_key[strlen(out_key)+1] = 0;
	out_key[strlen(out_key)] = (unsigned char) (MIN_CHAR_ADDED + param);
}
PRIVATE void ocl_prefix_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key+1, plain);
	out_key[0] = (unsigned char)(MIN_CHAR_ADDED + param);
}
#endif

// Less common
PRIVATE void rule_overstrike(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	unsigned int change_pos = rules_data_buffer[CHANGE_POS_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;
		unsigned int MAX_LOWER = (lenght+2)/2*NUM_KEYS;

		if(lenght > 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			change_pos = 0;
			continue;
		}

		// Copy and over-strike
		for(i = 0; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i == change_pos/2*NUM_KEYS)// over-strike
			{
				int shift = 0;
				if(change_pos & 1)
				{
					_tmp &= 0x0000FFFF;
					shift = 16;
				}
				else
					_tmp &= 0xFFFF0000;

				for(j = i+nt_buffer_index; j < MAX; j++, char_added++)
					nt_buffer[j] = _tmp | (char_added << shift);
			}
			else// Copy
			{
				for(j = i+nt_buffer_index; j < MAX; j++)
					nt_buffer[j] = _tmp;
			}
		}

		// Fill with 0
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		// Change
		if(char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			change_pos++;

			if(change_pos >= lenght)
			{
				change_pos = 0;
				rules_nt_buffer_index++;
			}
		}

		// Copy length
		lenght <<= 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHANGE_POS_INDEX] = change_pos;
	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_remove(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int change_pos = rules_data_buffer[CHANGE_POS_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int last_tmp;

		if(lenght == 0)
		{
			change_pos = 0;
			rules_nt_buffer_index++;
			continue;
		}

		// Copy
		for(i = 0; i < change_pos/2*NUM_KEYS; i += NUM_KEYS)
			nt_buffer[i+nt_buffer_index] = rules_nt_buffer[i+rules_nt_buffer_index];

		// Copy
		last_tmp = rules_nt_buffer[i+rules_nt_buffer_index];
		if(change_pos & 1)
			last_tmp <<= 16;
		i += NUM_KEYS;
		// Remove
		for(; i < (lenght+3)/2*NUM_KEYS; i += NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			nt_buffer[i-NUM_KEYS+nt_buffer_index] = (_tmp << 16) | (last_tmp >> 16);

			last_tmp = _tmp;
		}

		i -= NUM_KEYS;
		// Fill with 0
		for(; i < 14*NUM_KEYS; i += NUM_KEYS)
			nt_buffer[i+nt_buffer_index] = 0;

		// Copy length
		nt_buffer[14*NUM_KEYS+nt_buffer_index] = (lenght - 1) << 4;

		change_pos++;
		// Change
		if(change_pos >= lenght)
		{
			change_pos = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index++;
	}

	rules_data_buffer[CHANGE_POS_INDEX] = change_pos;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_overstrike(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy_array(source, nt_buffer, lenght, NUM_KEYS_OPENCL, 0);
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"uint to_sum;"

		"if(param & 1){"
			"nt_buffer[param/2] = %uu | (nt_buffer[param/2] & 0x0000ffff);"
			"to_sum = 1<<16;"
		"}else{"
			"nt_buffer[param/2] = %uu | (nt_buffer[param/2] & 0xffff0000);"
			"to_sum = 1;"
		"}"

		"for(uint i = 0; i < %uu; i++, nt_buffer[param/2]+=to_sum){", MIN_CHAR_ADDED << 16, MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);
}
PRIVATE void ocl_rule_remove(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy_array(source, nt_buffer, lenght, NUM_KEYS_OPENCL, 0);
	// Check lenght
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint nt_buffer[1];uint change_index = 0, char_removed = 0;return;{");
		return;
	}

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght - 1) << 4);

	// Convert the key into a nt_buffer
	sprintf(source + strlen(source), "uint char_removed = nt_buffer[0] & 0x0000ffff;");

	// Remove first character
	for (unsigned int i = 0; i < (lenght-1) / 2; i++)
		sprintf(source + strlen(source), "nt_buffer[%u] = (nt_buffer[%u] >> 16) | (nt_buffer[%u] << 16);", i, i, i+1);

	// Remove character
	if (lenght & 1)
		strcpy(nt_buffer[lenght / 2], "+0x80");
	else
	{
		strcpy(nt_buffer[lenght / 2], "");
		sprintf(source + strlen(source), "nt_buffer[%u] = 0x800000 | (nt_buffer[%u] >> 16);", lenght / 2 - 1, lenght / 2 - 1);
	}

	// Lenght and begin cycle
	sprintf(source + strlen(source), "for(uint change_index = 0; change_index < %uu; change_index++){", lenght);
}
// Get
PRIVATE void ocl_rule_remove_end(char* source)
{
	// End cycle
	sprintf(source+strlen(source),		"uint last_tmp = nt_buffer[change_index/2];"

										"if(change_index & 1){"
											"nt_buffer[change_index/2] = (last_tmp & 0x0000ffff) | char_removed;"
											"char_removed = last_tmp >> 16;"
										"}else{"
											"nt_buffer[change_index/2] = (last_tmp & 0xffff0000) | char_removed;"
											"char_removed = last_tmp << 16;"
										"}"
									"}");
}
PRIVATE void ocl_overstrike_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	out_key[param >> 8] = (unsigned char)(MIN_CHAR_ADDED + (param & 0xff));
}
PRIVATE void ocl_remove_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	size_t len = strlen(plain);
	out_key[0] = 0;
	if (len >= param)
	{
		strcpy(out_key, plain);
		memmove(out_key + param, out_key + param + 1, strlen(out_key) - param);
	}
}
#define OCL_REMOVE_PARAM		"change_index"
#define OCL_OVERSTRIKE_PARAM	"((param << 8) + i)"
#endif

PRIVATE void rule_insert(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	unsigned int insert_pos = rules_data_buffer[INSERT_POS_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;
		unsigned int MAX_LOWER = (lenght+3)/2*NUM_KEYS;
		unsigned int last_tmp;

		if(lenght >= 27 || lenght < 2)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			insert_pos = 1;
			continue;
		}

		// Copy
		for(i = 0; i < insert_pos/2*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = rules_nt_buffer[i+rules_nt_buffer_index];

		// Insert
		last_tmp = rules_nt_buffer[i+rules_nt_buffer_index];

		if(insert_pos & 1)
			for(j = i+nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = (last_tmp & 0x0000FFFF) | (char_added << 16);
		else
			for(j = i+nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = (last_tmp << 16) | char_added;

		i += NUM_KEYS;
		MAX += NUM_KEYS;

		// Copy
		for(; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			last_tmp = (_tmp << 16) | (last_tmp >> 16);
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}

		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		if(char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			insert_pos++;
			if(insert_pos >= lenght)
			{
				insert_pos = 1;
				rules_nt_buffer_index++;
			}
		}

		lenght = (lenght + 1) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[INSERT_POS_INDEX] = insert_pos;
	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_insert(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy_array(source, nt_buffer, lenght, NUM_KEYS_OPENCL, 1);

	// Check lenght
	if (lenght >= 27 || lenght < 2)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 1) << 4);
	// Insert character
	if (lenght & 1)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer[%u]", lenght / 2);
		sprintf(source + strlen(source), "nt_buffer[%u] = 0x800000 | (nt_buffer[%u]>>16);", lenght / 2, lenght / 2 - 1);
	}

	// Begin cycle of insert
	sprintf(source + strlen(source),
		"uint insert_index=(param+1)/2;"
		"uint tmp = nt_buffer[insert_index];"
		"uint to_sum;"

		"if(param & 1){"
			"nt_buffer[insert_index] = %uu | (tmp << 16);"
			"to_sum = 1;"
		"}else{"
			"nt_buffer[insert_index] = %uu | (tmp & 0xffff);"
			"to_sum = 1<<16;"
		"}"
		// Copy the remaining
		"tmp = tmp >> 16;"
		"for (uint i = insert_index+1; i < %uu; i++)"
		"{"
			"a = tmp | (nt_buffer[i] << 16);"
			"tmp = nt_buffer[i] >> 16;"
			"nt_buffer[i] = a;"
		"}"

		"for(uint i = 0; i < %uu; i++, nt_buffer[insert_index]+=to_sum){", MIN_CHAR_ADDED, MIN_CHAR_ADDED << 16, (lenght+1) / 2, LENGHT_CHAR_ADDED);
}
PRIVATE void ocl_insert_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	unsigned int insert_index = param >> 8;
	strcpy(out_key, plain);
	memmove(out_key + insert_index + 1, out_key + insert_index, strlen(out_key) - insert_index + 1);
	out_key[insert_index] = (unsigned char)(MIN_CHAR_ADDED + (param & 0xff));
}
#define OCL_INSERT_PARAM	"(((param+1)<<8)+i)"
#endif

// Append 2 digits
PRIVATE void rule_lower_append_2digits(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((unsigned int)(('9'-digit1)*10+'9'-digit2+1), __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 26)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
				_tmp += 32;
			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(_tmp >= 'A' && _tmp <= 'Z')
				_tmp += 32;

			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = _tmp | (digit1 << 16);
				nt_buffer[j+NUM_KEYS] = digit2 | 0x800000;
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}

			i+=NUM_KEYS;
			MAX+=NUM_KEYS;
		}
		else
		{
			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = digit1 | (digit2 << 16);
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}

			i+=NUM_KEYS;
			MAX+=NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i+=NUM_KEYS;
		MAX+=NUM_KEYS;
		for(; i < 14*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+2) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(digit1 > '9')
		{
			digit1 = '0';
			digit2 = '0';
			rules_nt_buffer_index++;
		}

		nt_buffer_index+=num_to_copy;
	}

	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
PRIVATE void rule_capitalize_append_2digits(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((unsigned int)(('9'-digit1)*10+'9'-digit2+1), __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 26)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i)
			{
				if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
					_tmp += 32;
			}else{// First position -> to-upper
				if((_tmp & 0xFF) >= 'a' && (_tmp & 0xFF) <= 'z')
					_tmp -= 32;
			}

			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(_tmp >= 'A' && _tmp <= 'Z')
				_tmp += 32;

			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = _tmp | (digit1 << 16);
				nt_buffer[j+NUM_KEYS] = digit2 | 0x800000;
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}

			i+=NUM_KEYS;
			MAX+=NUM_KEYS;
		}
		else
		{
			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = digit1 | (digit2 << 16);
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}

			i+=NUM_KEYS;
			MAX+=NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i+=NUM_KEYS;
		MAX+=NUM_KEYS;
		for(; i < 14*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+2) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(digit1 > '9')
		{
			digit1 = '0';
			digit2 = '0';
			rules_nt_buffer_index++;
		}

		nt_buffer_index+=num_to_copy;
	}
	
	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_lower_append_2digits(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	// Lowercase
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);

	sprintf(nt_buffer[(lenght + 1) / 2], "+nt_buffer%u", (lenght + 1) / 2);
	sprintf(source + strlen(source), "uint nt_buffer%u;", (lenght + 1) / 2);
	// Append 2 digits
	if ((lenght & 1) == 0)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Begin cycle
	sprintf(source + strlen(source),
		"for(uint i = 0; i < 100u; i++)"
		"{"
			// Divide by 10
			"a=mul_hi(i,429496730u);"
			"b=mul_hi(a,429496730u);");

	// Last characters
	if (lenght & 1)
		sprintf(source + strlen(source),
			"nt_buffer%u = (nt_buffer%u & 0x0000ffff) | ((48u+a-b*10) << 16);"
			"nt_buffer%u = 0x800030 + i - a*10;", lenght / 2, lenght / 2, (lenght + 1) / 2);
	else
		sprintf(source + strlen(source), "nt_buffer%u = 0x300030 + (i<<16) - a*0x9FFFF - b*10u;", (lenght + 1) / 2);
}
PRIVATE void ocl_rule_capitalize_append_2digits(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	//Capitalize
	if (lenght)
		sprintf(source + strlen(source),"if(((nt_buffer0 & 0xFF) - 97u) <= 25u)"
											"nt_buffer0 -= 32;");
	// Lowercase
	for (unsigned int i = 1; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);

	sprintf(nt_buffer[(lenght + 1) / 2], "+nt_buffer%u", (lenght + 1) / 2);
	sprintf(source + strlen(source), "uint nt_buffer%u;", (lenght + 1) / 2);
	// Append 2 digits
	if ((lenght & 1) == 0)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Begin cycle
	sprintf(source + strlen(source),
		"for(uint i = 0; i < 100u; i++)"
		"{"
			// Divide by 10
			"a=mul_hi(i,429496730u);"
			"b=mul_hi(a,429496730u);");

	// Last characters
	if (lenght & 1)
		sprintf(source + strlen(source),
			"nt_buffer%u = (nt_buffer%u & 0x0000ffff) | (('0'+a-b*10) << 16);"
			"nt_buffer%u = 0x800030 + i - a*10;", lenght / 2, lenght / 2, (lenght + 1) / 2);
	else
		sprintf(source + strlen(source), "nt_buffer%u = 0x300030 + (i<<16) - a*0x9FFFF - b*10u;", (lenght + 1) / 2);
}
// Get plaintext
PRIVATE void ocl_lower_append_2digits_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	out_key[strlen(out_key)+2] = 0;
	out_key[strlen(out_key)+1] = (unsigned char)('0' + param%10);
	out_key[strlen(out_key)] = (unsigned char)('0' + (param/10)%10);
}
PRIVATE void ocl_capitalize_append_2digits_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	// Capitalize
	if(islower(out_key[0]))
		out_key[0] -= 32;
	// Append
	out_key[strlen(out_key)+2] = 0;
	out_key[strlen(out_key)+1] = (unsigned char)('0' + param%10);
	out_key[strlen(out_key)] = (unsigned char)('0' + (param/10)%10);
}
#endif

// Append a year between 1900-2019
PRIVATE void rule_lower_append_year(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];
	int is_1900 = rules_data_buffer[IS_1900_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((unsigned int)(is_1900 ? ('9'-digit1)*10+'9'-digit2+1+20 : ('1'-digit1)*10+'9'-digit2+1), 
							  __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 24)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			is_1900 = TRUE;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
				_tmp += 32;
			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(_tmp >= 'A' && _tmp <= 'Z')
				_tmp += 32;

			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = _tmp | (is_1900 ? ('1' << 16) : ('2' << 16));
				nt_buffer[j+NUM_KEYS] = (is_1900 ? '9' : '0') | (digit1 << 16);
				nt_buffer[j+2*NUM_KEYS] = digit2 | 0x800000;
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
					if(digit1 > '9')
					{
						digit1 = '0';
						is_1900 = FALSE;
					}
				}
			}

			i+=2*NUM_KEYS;
			MAX+=2*NUM_KEYS;
		}
		else
		{
			unsigned int _tmp = is_1900 ? '1' | ('9' << 16) : '2' | ('0' << 16);
			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = _tmp;
				nt_buffer[j+NUM_KEYS] = digit1 | (digit2 << 16);
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
					if(digit1 > '9')
					{
						digit1 = '0';
						is_1900 = FALSE;
						_tmp = '2' | ('0' << 16);
					}
				}
			}

			i+=2*NUM_KEYS;
			MAX+=2*NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i+=NUM_KEYS;
		MAX+=NUM_KEYS;
		for(; i < 14*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+4) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(!is_1900 && digit1 > '1')
		{
			digit1 = '0';
			digit2 = '0';
			is_1900 = TRUE;
			rules_nt_buffer_index++;
		}

		nt_buffer_index+=num_to_copy;
	}

	rules_data_buffer[IS_1900_INDEX] = is_1900;
	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
PRIVATE void rule_capitalize_append_year(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];
	int is_1900 = rules_data_buffer[IS_1900_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((unsigned int)(is_1900 ? ('9'-digit1)*10+'9'-digit2+1+20 : ('1'-digit1)*10+'9'-digit2+1), 
							  __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 24)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			is_1900 = TRUE;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i)
			{
				if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
					_tmp += 32;
			}else{// First position -> to-upper
				if((_tmp & 0xFF) >= 'a' && (_tmp & 0xFF) <= 'z')
					_tmp -= 32;
			}

			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(_tmp >= 'A' && _tmp <= 'Z')
				_tmp += 32;

			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = _tmp | (is_1900 ? ('1' << 16) : ('2' << 16));
				nt_buffer[j+NUM_KEYS] = (is_1900 ? '9' : '0') | (digit1 << 16);
				nt_buffer[j+2*NUM_KEYS] = digit2 | 0x800000;
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
					if(digit1 > '9')
					{
						digit1 = '0';
						is_1900 = FALSE;
					}
				}
			}

			i+=2*NUM_KEYS;
			MAX+=2*NUM_KEYS;
		}
		else
		{
			unsigned int _tmp = is_1900 ? '1' | ('9' << 16) : '2' | ('0' << 16);
			for(j = i + nt_buffer_index; j < MAX; j++,digit2++)
			{
				nt_buffer[j] = _tmp;
				nt_buffer[j+NUM_KEYS] = digit1 | (digit2 << 16);
				if(digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
					if(digit1 > '9')
					{
						digit1 = '0';
						is_1900 = FALSE;
						_tmp = '2' | ('0' << 16);
					}
				}
			}

			i+=2*NUM_KEYS;
			MAX+=2*NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i+=NUM_KEYS;
		MAX+=NUM_KEYS;
		for(; i < 14*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+4) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(!is_1900 && digit1 > '1')
		{
			digit1 = '0';
			digit2 = '0';
			is_1900 = TRUE;
			rules_nt_buffer_index++;
		}

		nt_buffer_index+=num_to_copy;
	}

	rules_data_buffer[IS_1900_INDEX] = is_1900;
	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_lower_append_year(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Lowercase
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 4) << 4);
	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"for(uint i = 0; i < 120u; i++)"
		"{"
			// Divide by 10
			"a=mul_hi(i,429496730u);"
			"b=mul_hi(a,429496730u);");

	// Last characters
	sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
	sprintf(nt_buffer[lenght / 2 + 1], "+nt_buffer%u", lenght / 2 + 1);
	sprintf(nt_buffer[lenght / 2 + 2], "+nt_buffer%u", lenght / 2 + 2);
	if (lenght & 1)
		sprintf(source + strlen(source),
			"nt_buffer%u = (nt_buffer%u & 0xffff) | ((i >= 100u) ? 3276800u : 3211264u);"
			"uint nt_buffer%u = (a<<16) - b*0xA0000 + ((i >= 100u) ? 0x300030 : 0x300039);"
			"uint nt_buffer%u = 0x800030 + i - a*10u;", lenght / 2, lenght / 2, lenght / 2 + 1, lenght / 2 + 2);
	else{
		sprintf(source + strlen(source),
			"uint nt_buffer%u = (i >= 100u) ? 3145778u : 3735601u;"
			"uint nt_buffer%u = 0x300030 + (i<<16) - a*0x9FFFF - b*10u;", lenght / 2, lenght / 2 + 1);
		sprintf(nt_buffer[lenght / 2 + 2], "+0x80");
	}
}
PRIVATE void ocl_rule_capitalize_append_year(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	//Capitalize
	if (lenght)
		sprintf(source + strlen(source),"if(((nt_buffer0 & 0xFF) - 97u) <= 25u)"
											"nt_buffer0 -= 32;");
	// Lowercase
	for (unsigned int i = 1; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u - 4259840u) <= 1703935u)"
												"nt_buffer%u += 32 << 16;"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u & 0xFF) - 65u) <= 25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2, i / 2);

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 4) << 4);
	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"for(uint i = 0; i < 120u; i++)"
		"{"
			// Divide by 10
			"a=mul_hi(i,429496730u);"
			"b=mul_hi(a,429496730u);");

	// Last characters
	sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
	sprintf(nt_buffer[lenght / 2 + 1], "+nt_buffer%u", lenght / 2 + 1);
	sprintf(nt_buffer[lenght / 2 + 2], "+nt_buffer%u", lenght / 2 + 2);
	if (lenght & 1)
		sprintf(source + strlen(source),
			"nt_buffer%u = (nt_buffer%u & 0xffff) | ((i >= 100u) ? 3276800u : 3211264u);"
			"uint nt_buffer%u = (a<<16) - b*0xA0000 + ((i >= 100u) ? 0x300030 : 0x300039);"
			"uint nt_buffer%u = 0x800030 + i - a*10u;", lenght / 2, lenght / 2, lenght / 2 + 1, lenght / 2 + 2);
	else{
		sprintf(source + strlen(source),
			"uint nt_buffer%u = (i >= 100u) ? 3145778u : 3735601u;"
			"uint nt_buffer%u = 0x300030 + (i<<16) - a*0x9FFFF - b*10u;", lenght / 2, lenght / 2 + 1);
		sprintf(nt_buffer[lenght / 2 + 2], "+0x80");
	}
}
// Get
PRIVATE void ocl_lower_append_year_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	// Append
	out_key[strlen(out_key)+4] = 0;
	out_key[strlen(out_key)+3] = '0' + param%10;
	out_key[strlen(out_key)+2] = '0' + (param/10)%10;
	out_key[strlen(out_key)+1] = param >= 100 ? '0' : '9';
	out_key[strlen(out_key)] = param >= 100 ? '2' : '1';
}
PRIVATE void ocl_capitalize_append_year_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	// Capitalize
	if(islower(out_key[0]))
		out_key[0] -= 32;
	// Append
	out_key[strlen(out_key)+4] = 0;
	out_key[strlen(out_key)+3] = '0' + param%10;
	out_key[strlen(out_key)+2] = '0' + (param/10)%10;
	out_key[strlen(out_key)+1] = param >= 100 ? '0' : '9';
	out_key[strlen(out_key)] = param >= 100 ? '2' : '1';
}
#endif

// Prefix a year between 1900-2019
PRIVATE void rule_prefix_year(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];
	int is_1900 = rules_data_buffer[IS_1900_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((unsigned int)(is_1900 ? ('9'-digit1)*10+'9'-digit2+1+20 : ('1'-digit1)*10+'9'-digit2+1), 
							  __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 24)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			is_1900 = TRUE;
			continue;
		}

		// Prefix the year
		for(j = nt_buffer_index; j < MAX; j++, digit2++)
		{
			nt_buffer[j] = is_1900 ? '1' | ('9' << 16) : '2' | ('0' << 16);;
			nt_buffer[j+NUM_KEYS] = digit1 | (digit2 << 16);
			if(digit2 >= '9')
			{
				digit2 = '0' - 1;
				digit1++;
				if(digit1 > '9')
				{
					digit1 = '0';
					is_1900 = FALSE;
				}
			}
		}

		// Copy
		for(i = 0; i < (lenght/2+1)*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j+2*NUM_KEYS] = rules_nt_buffer[i+rules_nt_buffer_index];

		i   += 2*NUM_KEYS;
		MAX += 2*NUM_KEYS;
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+4) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(!is_1900 && digit1 > '1')
		{
			digit1 = '0';
			digit2 = '0';
			is_1900 = TRUE;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[IS_1900_INDEX] = is_1900;
	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_prefix_year(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	unsigned int i;
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Put buffer
	strcpy(nt_buffer[0], "+century");
	strcpy(nt_buffer[1], "+digits");
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i+2], "+nt_buffer%u", i);

	if (lenght & 1)
		sprintf(nt_buffer[i + 2], "+nt_buffer%u", i);
	else
		strcpy(nt_buffer[i + 2], "+0x80");

	sprintf(nt_buffer[14], "+%uu", (lenght+4)<<4);

	// Lenght and begin cycle
	sprintf(source + strlen(source), 
		"for(uint i = 0; i < 120u; i++)"
		"{"
			// "20" and "19" transformed to Unicode
			"uint century = (i >= 100u) ? 3145778u : 3735601u;"
			// Divide by 10
			"a=mul_hi(i,429496730u);"
			"b=mul_hi(a,429496730u);"
			//"uint digits  = ((48 + i - a*10u) << 16) | (48 + a - b*10u);");
			"uint digits  = 0x300030 + (i<<16) - a*0x9FFFF - b*10u;");
}
// Get
PRIVATE void ocl_prefix_year_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key+4, plain);
	// Prefix
	out_key[3] = '0' + param%10;
	out_key[2] = '0' + (param/10)%10;
	out_key[1] = param >= 100 ? '0' : '9';
	out_key[0] = param >= 100 ? '2' : '1';
}
#endif

// Prefix two characters
PRIVATE void rule_prefix_2char(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	unsigned int char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+(MAX_CHAR_ADDED-MIN_CHAR_ADDED+1)*(MAX_CHAR_ADDED-char_added1), 
							  __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 26)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			continue;
		}

		// Prefix 2 char
		for(j = nt_buffer_index; j < MAX; j++, char_added0++)
		{
			nt_buffer[j] = char_added0 | (char_added1 << 16);
			if(char_added0 >= MAX_CHAR_ADDED)
			{
				char_added0 = MIN_CHAR_ADDED-1;
				char_added1++;
			}
		}

		// Copy
		for(i = 0; i < (lenght/2+1)*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j+NUM_KEYS] = rules_nt_buffer[i+rules_nt_buffer_index];

		i   += NUM_KEYS;
		MAX += NUM_KEYS;
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+2) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(char_added1 > MAX_CHAR_ADDED)
		{
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED0_INDEX] = char_added0;
	rules_data_buffer[CHAR_ADDED1_INDEX] = char_added1;
}
PRIVATE void rule_append_2char(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	unsigned int char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+(MAX_CHAR_ADDED-MIN_CHAR_ADDED+1)*(MAX_CHAR_ADDED-char_added1),
			__min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 26)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for(i = 0; i < lenght/2*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = rules_nt_buffer[i+rules_nt_buffer_index];

		if(lenght & 1)
		{
			for(j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = (rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF) | (char_added0 << 16);
				nt_buffer[j+NUM_KEYS] = char_added1 | 0x800000;
				if(char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED-1;
					char_added1++;
				}
			}

			i   += NUM_KEYS;
			MAX += NUM_KEYS;
		}
		else
		{
			for(j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = char_added0 | (char_added1 << 16);
				if(char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED-1;
					char_added1++;
				}
			}

			i   += NUM_KEYS;
			MAX += NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i   += NUM_KEYS;
		MAX += NUM_KEYS;
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+2) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(char_added1 > MAX_CHAR_ADDED)
		{
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED0_INDEX] = char_added0;
	rules_data_buffer[CHAR_ADDED1_INDEX] = char_added1;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_prefix_2char(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	unsigned int i;
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Put buffer
	strcpy(nt_buffer[0], "+chars");
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i + 1], "+nt_buffer%u", i);

	if (lenght & 1)
		sprintf(nt_buffer[i + 1], "+nt_buffer%u", i);
	else
		strcpy(nt_buffer[i + 1], "+0x80");

	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Convert the key into a nt_buffer
	sprintf(source + strlen(source), "uint chars = %uu + (param << 16);", MIN_CHAR_ADDED + (MIN_CHAR_ADDED<<16));
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, chars++){", LENGHT_CHAR_ADDED);
}
PRIVATE void ocl_rule_append_2char(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	sprintf(nt_buffer[(lenght + 1) / 2], "+nt_buffer%u", (lenght + 1) / 2);
	sprintf(source + strlen(source), "uint nt_buffer%u;", (lenght + 1) / 2);
	// Append 2 characters
	if ((lenght & 1) == 0)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Last characters
	if (lenght & 1)
		sprintf(source + strlen(source),
		"nt_buffer%u = (nt_buffer%u & 0x0000ffff) | %uu;"
		"nt_buffer%u = %uu+param;", lenght / 2, lenght / 2, MIN_CHAR_ADDED << 16, (lenght + 1) / 2, 0x800000+MIN_CHAR_ADDED);
	else
		sprintf(source + strlen(source), "nt_buffer%u = (param<<16) + %uu;", (lenght + 1) / 2, (MIN_CHAR_ADDED<<16) + MIN_CHAR_ADDED);

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, nt_buffer%u+=%uu){", LENGHT_CHAR_ADDED, lenght / 2, 1 << (16*(lenght&1)));
}
// Get
PRIVATE void ocl_prefix_2char_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key+2, plain);
	// Prefix
	out_key[1] = MIN_CHAR_ADDED + (param >> 8);
	out_key[0] = MIN_CHAR_ADDED + (param & 0xff);
}
PRIVATE void ocl_append_2char_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	// Append
	out_key[strlen(out_key)+2] = 0;
	out_key[strlen(out_key)+1] = MIN_CHAR_ADDED + (param >> 8);
	out_key[strlen(out_key)+0] = MIN_CHAR_ADDED + (param & 0xff);
}
#define OCL_2_CHARS	"((param<<8)+i)"
#endif

// 3 char
PRIVATE void rule_append_3char(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	unsigned int char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];
	unsigned int char_added2 = rules_data_buffer[CHAR_ADDED2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added1)+LENGHT_CHAR_ADDED*LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added2),
			__min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 25)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			char_added2 = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for(i = 0; i < lenght/2*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = rules_nt_buffer[i+rules_nt_buffer_index];

		if(lenght & 1)
		{
			for(j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = (rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF) | (char_added0 << 16);
				nt_buffer[j+NUM_KEYS] = char_added1 | (char_added2 << 16);
				nt_buffer[j+2*NUM_KEYS] = 0x80;
				if(char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED-1;
					char_added1++;
					if(char_added1 > MAX_CHAR_ADDED)
					{
						char_added1 = MIN_CHAR_ADDED;
						char_added2++;
					}
				}
			}

			i   += 3*NUM_KEYS;
			MAX += 3*NUM_KEYS;
		}
		else
		{
			for(j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = char_added0 | (char_added1 << 16);
				nt_buffer[j+NUM_KEYS] = char_added2 | 0x800000;
				if(char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED-1;
					char_added1++;
					if(char_added1 > MAX_CHAR_ADDED)
					{
						char_added1 = MIN_CHAR_ADDED;
						char_added2++;
					}
				}
			}

			i   += 2*NUM_KEYS;
			MAX += 2*NUM_KEYS;
		}

		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght+3) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if(char_added2 > MAX_CHAR_ADDED)
		{
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			char_added2 = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}
	
	rules_data_buffer[CHAR_ADDED0_INDEX] = char_added0;
	rules_data_buffer[CHAR_ADDED1_INDEX] = char_added1;
	rules_data_buffer[CHAR_ADDED2_INDEX] = char_added2;
}
PRIVATE void rule_prefix_3char(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	unsigned int char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	unsigned int char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];
	unsigned int char_added2 = rules_data_buffer[CHAR_ADDED2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		unsigned int i,j;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added1)+LENGHT_CHAR_ADDED*LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added2),
			__min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		unsigned int MAX = nt_buffer_index + num_to_copy;
		unsigned int MAX_LOWER = (lenght+2)/2*NUM_KEYS;
		unsigned int last_tmp;

		if(lenght >= 25)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			char_added2 = MIN_CHAR_ADDED;
			continue;
		}

		// First and second
		last_tmp = rules_nt_buffer[rules_nt_buffer_index];
		for(j = nt_buffer_index; j < MAX; j++, char_added0++)
		{
			nt_buffer[j] = char_added0 | (char_added1 << 16);
			nt_buffer[j+NUM_KEYS] = char_added2 | (last_tmp << 16);

			if(char_added2 == '~'&&char_added1=='~' && char_added0=='a')
				i=2;

			if(char_added0 >= MAX_CHAR_ADDED)
			{
				char_added0 = MIN_CHAR_ADDED-1;
				char_added1++;
				if(char_added1 > MAX_CHAR_ADDED)
				{
					char_added1 = MIN_CHAR_ADDED;
					char_added2++;
				}
			}
		}
		MAX += 2*NUM_KEYS;

		// Copy
		for(i = NUM_KEYS; i <= MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			last_tmp = (_tmp << 16) | (last_tmp >> 16);
			for(j = i+nt_buffer_index+NUM_KEYS; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}
		i += NUM_KEYS;

		// Fill with 0
		for(; i < 14*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 3) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if(char_added2 > MAX_CHAR_ADDED)
		{
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			char_added2 = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}
	
	rules_data_buffer[CHAR_ADDED0_INDEX] = char_added0;
	rules_data_buffer[CHAR_ADDED1_INDEX] = char_added1;
	rules_data_buffer[CHAR_ADDED2_INDEX] = char_added2;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_rule_append_3char(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 25)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 3) << 4);

	// New var to hold 2 characters
	sprintf(nt_buffer[(lenght + 1) / 2], "+nt_buffer%u", (lenght + 1) / 2);
	sprintf(source + strlen(source), "uint nt_buffer%u;", (lenght + 1) / 2);
	// Append character
	if (lenght & 1)
	{
		strcpy(nt_buffer[lenght / 2 + 2], "+0x80");
		sprintf(source + strlen(source), "nt_buffer%u = %uu+param/%uu;", lenght / 2 + 1, (MIN_CHAR_ADDED<<16) + MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);
		sprintf(source + strlen(source), "nt_buffer%u = (nt_buffer%u & 0xffff) | ((%uu+param%%%uu) << 16);", lenght / 2, lenght / 2, MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);
	}
	else
	{
		sprintf(nt_buffer[lenght / 2 + 1], "+nt_buffer%u", lenght / 2 + 1);
		sprintf(source + strlen(source), "uint nt_buffer%u = %uu;", lenght / 2 + 1, 0x800000 | MIN_CHAR_ADDED);
		sprintf(source + strlen(source), "nt_buffer%u = %uu + ((param/%uu)<<16) + param%%%uu;", lenght / 2, (MIN_CHAR_ADDED<<16)+MIN_CHAR_ADDED, LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
	}
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, nt_buffer%u+=%uu){", LENGHT_CHAR_ADDED, lenght / 2 + 1, 1 << (16 * (lenght & 1)));
}
PRIVATE void ocl_rule_prefix_3char(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	unsigned int i;
	ocl_rule_copy(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	// Check lenght
	if (lenght >= 25)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}
	// Put buffer
	strcpy(nt_buffer[0], "+chars");
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i + 1], "+nt_buffer%u", i);

	// Append character
	if (lenght & 1)
	{
		strcpy(nt_buffer[i + 2], "+0x80");
		sprintf(nt_buffer[i + 1], "+nt_buffer%u", i);
	}
	else
	{
		sprintf(nt_buffer[lenght / 2 + 1], "+nt_buffer%u", lenght / 2);
		sprintf(source + strlen(source), "uint nt_buffer%u = 0x80;", lenght / 2);
	}
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 3) << 4);
	
	// First character
	sprintf(source + strlen(source),
		"uint tmp = nt_buffer0 >> 16;"
		"nt_buffer0 <<= 16;"
		"nt_buffer0 |= %uu;", MIN_CHAR_ADDED);
	// Copy
	for (i = 1; i < lenght / 2 + 1; i++)
		sprintf(source + strlen(source), "a = tmp | (nt_buffer%u << 16);"
		"tmp = nt_buffer%u >> 16;"
		"nt_buffer%u = a;"
		, i, i, i);

	// First 2 chars
	sprintf(source + strlen(source), "uint chars = %uu + param%%%uu + ((param/%uu) << 16);", (MIN_CHAR_ADDED<<16)+MIN_CHAR_ADDED, LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i = 0; i < %uu; i++, nt_buffer0++){", LENGHT_CHAR_ADDED);
}
// Get
PRIVATE void ocl_prefix_3char_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key+3, plain);
	// Prefix
	out_key[2] = MIN_CHAR_ADDED + (param & 0xff);
	out_key[1] = MIN_CHAR_ADDED + (param >> 8) / LENGHT_CHAR_ADDED;
	out_key[0] = MIN_CHAR_ADDED + (param >> 8) % LENGHT_CHAR_ADDED;
}
PRIVATE void ocl_append_3char_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	strcpy(out_key, plain);
	// Append
	out_key[strlen(out_key)+3] = 0;
	out_key[strlen(out_key)+2] = MIN_CHAR_ADDED + (param & 0xff);
	out_key[strlen(out_key)+1] = MIN_CHAR_ADDED + (param >> 8) / LENGHT_CHAR_ADDED;
	out_key[strlen(out_key)+0] = MIN_CHAR_ADDED + (param >> 8) % LENGHT_CHAR_ADDED;
}
#define OCL_3_CHARS	"((param<<8)+i)"
#endif

// Leet Stuff
PRIVATE unsigned char leet_orig[]   = "aaeollssiibccgqttx";
PRIVATE unsigned char leet_change[] = "4@301!$51!6<{997+%";
PRIVATE void rule_lower_leet(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	int leet_index = rules_data_buffer[LEET_INDEX0];

	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; leet_index++)
	{
		unsigned int i;
		int letter_exist = FALSE;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
				_tmp += 32;
			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;
			// Leet change
			if((_tmp & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF0000) | ((unsigned int)(leet_change[leet_index]));
				letter_exist = TRUE;
			}
			if(((_tmp >> 16) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF) | (((unsigned int)(leet_change[leet_index])) << 16);
				letter_exist = TRUE;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(letter_exist)
		{
			for(; i < 14*NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}

		if(leet_index >= LENGHT(leet_orig) - 2)// -2 and not -1 because LENGHT take into account the null terminator
		{
			leet_index = -1;
			rules_nt_buffer_index++;
		}
	}

	if(rules_nt_buffer_index >= NUM_KEYS)
		leet_index = 0;

	rules_data_buffer[LEET_INDEX0] = leet_index;
}
PRIVATE void rule_capitalize_leet(unsigned int* nt_buffer, unsigned int NUM_KEYS, unsigned int* rules_data_buffer)
{
	int leet_index = rules_data_buffer[LEET_INDEX0];

	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; leet_index++)
	{
		unsigned int i;
		int letter_exist = FALSE;
		unsigned int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		unsigned int MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			unsigned int _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i)
			{
				if((_tmp & 0xFF) >= 'A' && (_tmp & 0xFF) <= 'Z')
					_tmp += 32;
			}
			else
			{
				// First position -> to-upper
				if((_tmp & 0xFF) >= 'a' && (_tmp & 0xFF) <= 'z')
					_tmp -= 32;
				else if((_tmp & 0xFF) < 'A' || (_tmp & 0xFF) > 'Z')
					break;//letter_exist = FALSE
			}
			if(_tmp >= 4259840 && _tmp <= 5963775)
				_tmp += 32 << 16;
			// Leet change
			if((_tmp & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF0000) | ((unsigned int)(leet_change[leet_index]));
				letter_exist = TRUE;
			}
			if(((_tmp >> 16) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF) | (((unsigned int)(leet_change[leet_index])) << 16);
				letter_exist = TRUE;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(letter_exist)
		{
			for(; i < 14*NUM_KEYS; i+=NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}

		if(leet_index >= LENGHT(leet_orig) - 2)// -2 and not -1 because LENGHT take into account the null terminator
		{
			leet_index = -1;
			rules_nt_buffer_index++;
		}
	}

	if(rules_nt_buffer_index >= NUM_KEYS)
		leet_index = 0;

	rules_data_buffer[LEET_INDEX0] = leet_index;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_write_leet_constants(char* source)
{
	unsigned int i;

	// Fill leet_orig
	sprintf(source+strlen(source),	"__constant uchar leet_orig[]={");
	for(i = 0; i < strlen(leet_orig); i++)
		sprintf(source+strlen(source), "%s%uU", i?",":"", (unsigned int)leet_orig[i]);
	strcat(source, "};\n");
	// Fill leet_change
	sprintf(source+strlen(source),	"__constant uchar leet_change[]={");
	for(i = 0; i < strlen(leet_change); i++)
		sprintf(source+strlen(source), "%s%uU", i?",":"", (unsigned int)leet_change[i]);
	strcat(source, "};\n");
}
PRIVATE void ocl_rule_lower_leet(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_lower(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Save to cache
	sprintf(source + strlen(source), "uint nt_buffer_cache[%u];", (lenght + 1) / 2);
	for (unsigned int i = 0; i < (lenght + 1) / 2; i++)
		sprintf(source + strlen(source), "nt_buffer_cache[%u] = nt_buffer%u;", i ,i);
		
	sprintf(source + strlen(source), "for(uint i = 0; i < %iu; i++){", (int)strlen(leet_orig));

	// Load from cache
	for (unsigned int i = 0; i < (lenght + 1) / 2; i++)
		sprintf(source + strlen(source), "nt_buffer%u = nt_buffer_cache[%u];", i ,i);

	// Perform leet
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source),"if((nt_buffer%u >> 16) == leet_orig[i])"
												"nt_buffer%u = (nt_buffer%u & 0xffff) | (leet_change[i] << 16);"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source),"if((nt_buffer%u & 0xffff) == leet_orig[i])"
												"nt_buffer%u = (nt_buffer%u & 0xffff0000) | leet_change[i];"
												, i / 2, i / 2, i / 2);
}
PRIVATE void ocl_rule_capitalize_leet(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL)
{
	ocl_rule_capitalize(source, nt_buffer, lenght, NUM_KEYS_OPENCL);

	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return;
	}

	// Save to cache
	sprintf(source + strlen(source), "uint nt_buffer_cache[%u];", (lenght + 1) / 2);
	for (unsigned int i = 0; i < (lenght + 1) / 2; i++)
		sprintf(source + strlen(source), "nt_buffer_cache[%u] = nt_buffer%u;", i ,i);
		
	sprintf(source + strlen(source), "for(uint i = 0; i < %iu; i++){", (int)strlen(leet_orig));

	// Load from cache
	for (unsigned int i = 0; i < (lenght + 1) / 2; i++)
		sprintf(source + strlen(source), "nt_buffer%u = nt_buffer_cache[%u];", i ,i);

	// Perform leet
	for (unsigned int i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u >> 16) == leet_orig[i])"
												"nt_buffer%u = (nt_buffer%u & 0xffff) | (leet_change[i] << 16);"
												, i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if((nt_buffer%u & 0xFF) == leet_orig[i])"
												"nt_buffer%u = (nt_buffer%u & 0xffff0000) | leet_change[i];"
												, i / 2, i / 2, i / 2);
}
// Get
PRIVATE void ocl_lower_leet_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	unsigned int i;

	strcpy(out_key, plain);
	_strlwr(out_key);

	if(param >= strlen(leet_orig))
		return;

	// Leet
	for (i = 0; i < strlen(out_key); i++)
		if(out_key[i] == leet_orig[param])
			out_key[i] = leet_change[param];
}
PRIVATE void ocl_capitalize_leet_get_key(unsigned char* out_key, unsigned char* plain, unsigned int param)
{
	unsigned int i;

	strcpy(out_key, plain);
	_strlwr(out_key);
	// Capitalize
	if(islower(out_key[0]))
		out_key[0] -= 32;

	if(param >= strlen(leet_orig))
		return;
	// Leet
	for (i = 0; i < strlen(out_key); i++)
		if(out_key[i] == leet_orig[param])
			out_key[i] = leet_change[param];
}
#endif

#define RULE_DESC_0		"Try words as they are. (word -> word)"
#define RULE_DESC_1		"Lowercase every word. (woRd -> word)"
#define RULE_DESC_2		"Uppercase every word. (word -> WORD)"

#define RULE_DESC_3		"Capitalize every word. (word -> Word)"
#define RULE_DESC_4		"Duplicate words. (word -> wordword)"
#define RULE_DESC_5		"Lowercase word and made leet substitutions. The substitutions are: a->4@, e->3, o->0, l->1!, s->$5, i->1!, b->6, c-><{, g->9, q->9, t->7+, x->%."

#define RULE_DESC_6		"Capitalize word and made leet substitutions. The substitutions are: a->4@, e->3, o->0, l->1!, s->$5, i->1!, b->6, c-><{, g->9, q->9, t->7+, x->%."
#define RULE_DESC_7		"Lowercase word and uppercase the last letter. (word -> worD)"
#define RULE_DESC_8		"Capitalize word and append all printable characters. (word -> Word#)"

#define RULE_DESC_9		"Lowercase word and append all printable characters. (word -> word#)"
#define RULE_DESC_10	"Prefix word with all printable characters. (word -> #word)"
#define RULE_DESC_11	"Lowercase word and append a year. Years range from 1900 to 2019. (word -> word1985)"

#define RULE_DESC_12	"Capitalize word and append a year. Years range from 1900 to 2019. (word -> Word1985)"
#define RULE_DESC_13	"Lowercase word and append two digits. (word -> word37)"
#define RULE_DESC_14	"Capitalize word and append two digits. (word -> Word37)"

#define RULE_DESC_15	"Insert inside each word all printable characters. (word -> w;ord)"
#define RULE_DESC_16	"Remove each characters of the word. (word -> wod)"
#define RULE_DESC_17	"Overstrike each characters of the word with all printable characters. (word -> wo#d)"

#define RULE_DESC_18	"Prefix word with a year. Years range from 1900 to 2019. (word -> 1992word)"
#define RULE_DESC_19	"Prefix word with two characters (all printable characters). (word -> ;!word)"
#define RULE_DESC_20	"Append two characters to the word (all printable characters). (word -> word;!)"

#define RULE_DESC_21	"Append three characters to the word (all printable characters) (very slow). (word -> word;!#)"
#define RULE_DESC_22	"Prefix word with three characters (all printable characters) (very slow). (word -> ;!#word)"
#define RULE_DESC_23	""	


#ifndef HS_OPENCL_SUPPORT
	#define OCL_INSERT_PARAM						NULL
	#define OCL_REMOVE_PARAM						NULL
	#define OCL_OVERSTRIKE_PARAM					NULL
	#define OCL_2_CHARS								0
	#define OCL_3_CHARS								0
	#define ocl_rule_append_2char					NULL
	#define ocl_append_2char_get_key				NULL
	#define ocl_rule_copy 							NULL
	#define ocl_rule_lower							NULL
	#define ocl_rule_upper							NULL
	#define ocl_copy_get_key 						NULL
	#define ocl_lower_get_key						NULL
	#define ocl_upper_get_key						NULL
	#define ocl_rule_capitalize						NULL
	#define ocl_rule_duplicate 						NULL
	#define ocl_rule_lower_leet						NULL
	#define ocl_capitalize_get_key					NULL
	#define ocl_duplicate_get_key 					NULL
	#define write_finish_brace						NULL
	#define ocl_lower_leet_get_key					NULL
	#define ocl_write_leet_constants				NULL
	#define ocl_rule_capitalize_leet  				NULL
	#define ocl_rule_lower_upper_last 				NULL
	#define ocl_rule_capitalize_append				NULL
	#define ocl_capitalize_leet_get_key				NULL
	#define ocl_rule_append_3char					NULL
	#define ocl_rule_prefix_3char					NULL
	#define ocl_append_3char_get_key				NULL
	#define ocl_prefix_3char_get_key				NULL
	#define ocl_capitalize_append_2digits_get_key	NULL
	#define ocl_capitalize_append_get_key			NULL
	#define ocl_rule_insert    						NULL
	#define ocl_rule_remove    						NULL
	#define ocl_rule_overstrike						NULL
	#define ocl_insert_get_key    					NULL
	#define ocl_remove_get_key    					NULL
	#define ocl_overstrike_get_key					NULL
	#define OCL_INSERT_PARAM    					NULL
	#define OCL_REMOVE_PARAM    					NULL
	#define OCL_OVERSTRIKE_PARAM					NULL
	#define ocl_capitalize_append_year_get_key		NULL
	#define ocl_lower_append_2digits_get_key		NULL
	#define ocl_lower_append_get_key				NULL
	#define ocl_lower_append_year_get_key			NULL
	#define ocl_lower_upper_last_get_key			NULL
	#define ocl_prefix_2char_get_key				NULL
	#define ocl_prefix_get_key						NULL
	#define ocl_prefix_year_get_key					NULL
	#define ocl_rule_capitalize_append_2digits		NULL
	#define ocl_rule_capitalize_append_year			NULL
	#define ocl_rule_lower_append					NULL
	#define ocl_rule_lower_append_2digits			NULL
	#define ocl_rule_lower_append_year				NULL
	#define ocl_rule_prefix							NULL
	#define ocl_rule_prefix_2char					NULL
	#define ocl_rule_prefix_year					NULL
	#define ocl_rule_remove							NULL
	#define ocl_rule_remove_end						NULL
#endif

PUBLIC Rule rules[] = {
	{"Copy",  RULE_DESC_0, rule_copy , TRUE, 1, FALSE, 0, { ocl_rule_copy , NULL, ocl_copy_get_key , "0", 0, NULL } },
	{"Lower", RULE_DESC_1, rule_lower, TRUE, 1, FALSE, 0, { ocl_rule_lower, NULL, ocl_lower_get_key, "0", 0, NULL } },
	{"Upper", RULE_DESC_2, rule_upper, TRUE, 1, FALSE, 0, { ocl_rule_upper, NULL, ocl_upper_get_key, "0", 0, NULL } },

	{"Capitalize", RULE_DESC_3, rule_capitalize, TRUE,		1			 , FALSE, 0, { ocl_rule_capitalize, NULL, ocl_capitalize_get_key, "0", 0, NULL } },
	{"Duplicate" , RULE_DESC_4, rule_duplicate , TRUE,		1			 , FALSE, 0, { ocl_rule_duplicate , NULL, ocl_duplicate_get_key , "0", 0, NULL } },
	{"Lower+Leet", RULE_DESC_5, rule_lower_leet, TRUE,LENGHT(leet_orig)-1, FALSE, 0, { ocl_rule_lower_leet, write_finish_brace, ocl_lower_leet_get_key, "i", 0, ocl_write_leet_constants} },

	{"Capitalize+Leet" , RULE_DESC_6, rule_capitalize_leet	, TRUE, LENGHT(leet_orig)-1, FALSE, 0, {ocl_rule_capitalize_leet  , write_finish_brace, ocl_capitalize_leet_get_key  , "i", 0, ocl_write_leet_constants}},
	{"Lower+Upper Last", RULE_DESC_7, rule_lower_upper_last	, TRUE,		1			   , FALSE, 0, {ocl_rule_lower_upper_last , NULL			  , ocl_lower_upper_last_get_key , "0", 0, NULL}},
	{"Capitalize+char" , RULE_DESC_8, rule_capitalize_append, TRUE, LENGHT_CHAR_ADDED  , FALSE, 0, {ocl_rule_capitalize_append, write_finish_brace, ocl_capitalize_append_get_key, "i", 0, NULL}},

	{"Lower+char", RULE_DESC_9 , rule_lower_append	   , TRUE, LENGHT_CHAR_ADDED, FALSE, 0, {ocl_rule_lower_append	   , write_finish_brace, ocl_lower_append_get_key	  , "i", 0, NULL}},
	{"char+Word" , RULE_DESC_10, rule_prefix		   , TRUE, LENGHT_CHAR_ADDED, FALSE, 0, {ocl_rule_prefix		   , write_finish_brace, ocl_prefix_get_key			  , "i", 0, NULL}},
	{"Lower+Year", RULE_DESC_11, rule_lower_append_year, TRUE,		120			, FALSE, 0, {ocl_rule_lower_append_year, write_finish_brace, ocl_lower_append_year_get_key, "i", 0, NULL}},

	{"Capitalize+Year",		RULE_DESC_12, rule_capitalize_append_year	, TRUE, 120, FALSE, 0, {ocl_rule_capitalize_append_year	  , write_finish_brace, ocl_capitalize_append_year_get_key	 , "i", 0, NULL}},
	{"Lower+2 Digits",		RULE_DESC_13, rule_lower_append_2digits		, TRUE, 100, FALSE, 0, {ocl_rule_lower_append_2digits	  , write_finish_brace, ocl_lower_append_2digits_get_key	 , "i", 0, NULL}},
	{"Capitalize+2 Digits",	RULE_DESC_14, rule_capitalize_append_2digits, TRUE, 100, FALSE, 0, {ocl_rule_capitalize_append_2digits, write_finish_brace, ocl_capitalize_append_2digits_get_key, "i", 0, NULL}},
	
	{"Insert"	 , RULE_DESC_15, rule_insert	, FALSE, LENGHT_CHAR_ADDED*RULE_LENGHT_COMMON, TRUE, -1, {ocl_rule_insert    , write_finish_brace , ocl_insert_get_key    , OCL_INSERT_PARAM    , RULE_LENGHT_COMMON, NULL}},
	{"Remove"	 , RULE_DESC_16, rule_remove	, FALSE,		RULE_LENGHT_COMMON			 , TRUE,  0, {ocl_rule_remove    , ocl_rule_remove_end, ocl_remove_get_key    , OCL_REMOVE_PARAM    , 0, NULL}},
	{"Overstrike", RULE_DESC_17, rule_overstrike, FALSE, LENGHT_CHAR_ADDED*RULE_LENGHT_COMMON, TRUE,  0, {ocl_rule_overstrike, write_finish_brace , ocl_overstrike_get_key, OCL_OVERSTRIKE_PARAM, RULE_LENGHT_COMMON, NULL}},

	{"Year+Word"   , RULE_DESC_18, rule_prefix_year , FALSE,			120			, FALSE, 0, {ocl_rule_prefix_year , write_finish_brace, ocl_prefix_year_get_key ,		"i"	   , 0, NULL}},
	{"2 chars+Word", RULE_DESC_19, rule_prefix_2char, FALSE, POW2(LENGHT_CHAR_ADDED), FALSE, 0, {ocl_rule_prefix_2char, write_finish_brace, ocl_prefix_2char_get_key, OCL_2_CHARS, LENGHT_CHAR_ADDED, NULL}},
	{"Word+2 chars", RULE_DESC_20, rule_append_2char, FALSE, POW2(LENGHT_CHAR_ADDED), FALSE, 0, {ocl_rule_append_2char, write_finish_brace, ocl_append_2char_get_key, OCL_2_CHARS, LENGHT_CHAR_ADDED, NULL}},

	{"Word+3 chars", RULE_DESC_21, rule_append_3char, FALSE, POW3(LENGHT_CHAR_ADDED), FALSE, 0, {ocl_rule_append_3char, write_finish_brace, ocl_append_3char_get_key, OCL_3_CHARS, POW2(LENGHT_CHAR_ADDED), NULL}},
	{"3 chars+Word", RULE_DESC_22, rule_prefix_3char, FALSE, POW3(LENGHT_CHAR_ADDED), FALSE, 0, {ocl_rule_prefix_3char, write_finish_brace, ocl_prefix_3char_get_key, OCL_3_CHARS, POW2(LENGHT_CHAR_ADDED), NULL}}
};
// TODO: If greater than 31, rules need to change code in opencl implementation
PUBLIC int num_rules = LENGHT(rules);

////////////////////////////////////////////////////////////////////////////////////
// Common
////////////////////////////////////////////////////////////////////////////////////
PUBLIC int provider_index;
PUBLIC apply_rule_funtion** current_rules = NULL;
PUBLIC int current_rules_count;
PRIVATE generate_key_funtion* gen_keys_principal = NULL;
// Mutex for thread-safe access
PRIVATE HS_MUTEX rules_mutex;

PRIVATE int64_t last_key_space;
PRIVATE int64_t last_num_keys_served_from_start;
#ifdef HS_OPENCL_SUPPORT
	PRIVATE int64_t num_keys_in_memory[MAX_NUMBER_GPUS_SUPPORTED];
#endif
extern int64_t num_key_space;

// TODO: This only work for less than 128 rules and less than 128 key_providers
//#define RULE_SAVE_KEY_PROV_INDEX(param, key_provider_index) (param[0] = key_provider_index+1)
//#define RULE_GET_KEY_PROV_INDEX(param)						(param[0] - 1)
#define RULE_COUNT_RULES_POS								1
#define RULE_SAVE(param, pos, rule)							(param[pos+2] = rule+1)
#define RULE_GET(param, pos)								(param[pos+2] - 1)
PUBLIC int add_rules_to_param(char* param, int key_provider_index)
{
	int i;
	char* buffer = (char*)malloc(1024);
	current_rules_count = 0;

	for(i = 0; i < num_rules; i++)
		if(rules[i].checked)
		{
			RULE_SAVE(buffer, current_rules_count, i);
			current_rules_count++;
		}

	RULE_SAVE_KEY_PROV_INDEX(buffer, key_provider_index);
	buffer[RULE_COUNT_RULES_POS] = current_rules_count;

	strcpy(buffer+current_rules_count+2, param);
	strcpy(param, buffer);

	free(buffer);

	return current_rules_count;
}

#define RULES_THREAD_DATA_SIZE	(16*256+14)
PUBLIC void rules_resume(int pmin_lenght, int pmax_lenght, char* param, const char* resume_arg, int format_index)
{
	int i, multipler = 0;

	// Mutex for thread-safe access
	HS_CREATE_MUTEX(&rules_mutex);

	// If exist rules -> clean it
	if(current_rules)
		free(current_rules);

	current_rules_count = param[RULE_COUNT_RULES_POS];
	current_rules = (apply_rule_funtion**)malloc(sizeof(apply_rule_funtion*) * current_rules_count);

	for (i = 0; i < current_rules_count; i++)
	{
		current_rules[i] = rules[RULE_GET(param, i)].function;
		multipler += rules[RULE_GET(param, i)].multipler;
	}

	provider_index = RULE_GET_KEY_PROV_INDEX(param);

	for(i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		if(key_providers[provider_index].impls[i].protocol == PROTOCOL_NTLM)
		{
			gen_keys_principal = key_providers[provider_index].impls[i].generate;
			break;
		}

	key_providers[provider_index].resume(pmin_lenght, pmax_lenght, param+current_rules_count+2, resume_arg, format_index);

	last_key_space = num_key_space;
	last_num_keys_served_from_start = 0;
	num_key_space *= multipler;
#ifdef HS_OPENCL_SUPPORT
	memset(num_keys_in_memory, 0, sizeof(num_keys_in_memory));
#endif

	// Put space needed to rules
	key_providers[RULES_INDEX].per_thread_data_size = key_providers[provider_index].per_thread_data_size + sizeof(unsigned int)*RULES_THREAD_DATA_SIZE;
	key_providers[RULES_INDEX].save_resume_arg = key_providers[provider_index].save_resume_arg;
}
// Calculate adequately the key_space
extern double wordlist_completition;
PUBLIC void rules_calculate_key_space(int64_t num_keys_generate, unsigned int num_keys_original, int64_t pnum_keys_in_memory, int gpu_device_index)
{
	HS_ENTER_MUTEX(&rules_mutex);
	// Calculate adequately the key_space
	num_keys_served_from_save += num_keys_generate;
	last_num_keys_served_from_start += num_keys_original;
	// TODO: Eliminate this patch: Possibly put a flag in key_provider to use
	if(num_key_space != KEY_SPACE_UNKNOW)
	{
		if(last_num_keys_served_from_start > last_key_space)
			last_key_space = last_num_keys_served_from_start;

		if (provider_index == WORDLIST_INDEX)
		{
			int64_t total_keys_in_memory = 0;

#ifdef HS_OPENCL_SUPPORT
			if (gpu_device_index >= 0 && gpu_device_index < LENGHT(num_keys_in_memory))
				num_keys_in_memory[gpu_device_index] = pnum_keys_in_memory;

			for (int i = 0; i < LENGHT(num_keys_in_memory); i++)
				total_keys_in_memory += num_keys_in_memory[i];
#endif

			num_key_space = (int64_t)((get_num_keys_served() + total_keys_in_memory) * wordlist_completition);
		}
		else
			num_key_space = (int64_t)(((double)get_num_keys_served())*((double)last_key_space / (double)last_num_keys_served_from_start));// We use double and parenthesis to prevent buffer overflows
	}

	HS_LEAVE_MUTEX(&rules_mutex);
}

extern char* thread_params;
extern unsigned int num_thread_params;
PUBLIC int rules_generate_ntlm(unsigned int* nt_buffer, unsigned int NUM_KEYS, int thread_id)
{
	int current_rule_index;
	unsigned int* rules_data_buffer = ((unsigned int*)(thread_params + num_thread_params*key_providers[provider_index].per_thread_data_size))+RULES_THREAD_DATA_SIZE*thread_id;
	nt_buffer_index = 0;

	// Initialize data
	if (!rules_data_buffer[RULES_IS_INIT_DATA_INDEX])
	{
		rules_data_buffer[RULES_IS_INIT_DATA_INDEX] = TRUE;
		rules_data_buffer[CURRENT_RULE_INDEX] = INT_MAX;
		rules_data_buffer[CHAR_ADDED_INDEX] = MIN_CHAR_ADDED;
		rules_data_buffer[INSERT_POS_INDEX] = 1;
		rules_data_buffer[DIGIT1_INDEX] = 48;
		rules_data_buffer[DIGIT2_INDEX] = 48;
		rules_data_buffer[IS_1900_INDEX] = TRUE;
		rules_data_buffer[CHAR_ADDED0_INDEX] = MIN_CHAR_ADDED;
		rules_data_buffer[CHAR_ADDED1_INDEX] = MIN_CHAR_ADDED;
		rules_data_buffer[CHAR_ADDED2_INDEX] = MIN_CHAR_ADDED;
	}
	current_rule_index = rules_data_buffer[CURRENT_RULE_INDEX];

	do{
		// If finish applying rules to current chunk->get a new one
		if(current_rule_index >= current_rules_count)
		{
			HS_ENTER_MUTEX(&rules_mutex);

			if(!gen_keys_principal(rules_nt_buffer, NUM_KEYS, thread_id))
			{
				HS_LEAVE_MUTEX(&rules_mutex);
				goto end;
			}

			num_keys_served_from_save -= NUM_KEYS;
			last_num_keys_served_from_start += NUM_KEYS;

			HS_LEAVE_MUTEX(&rules_mutex);

			current_rule_index = 0;
			rules_nt_buffer_index = 0;
		}

		current_rules[current_rule_index](nt_buffer, NUM_KEYS, rules_data_buffer);

		if(rules_nt_buffer_index >= NUM_KEYS)
		{
			current_rule_index++;
			rules_nt_buffer_index = 0;
		}
	}
	while(nt_buffer_index < NUM_KEYS);

end:
	rules_data_buffer[CURRENT_RULE_INDEX] = current_rule_index;
	rules_calculate_key_space(nt_buffer_index, 0, 0, -1);

	return nt_buffer_index;
}
PUBLIC void rules_finish()
{
	HS_DELETE_MUTEX(&rules_mutex);
	key_providers[provider_index].finish();
}
PUBLIC void rules_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght)
{
	int provider_index = RULE_GET_KEY_PROV_INDEX(provider_param);
	int current_rules_count = provider_param[RULE_COUNT_RULES_POS];
	
	if(current_rules_count == 1)
		sprintf(description, "[%s] on %s", rules[RULE_GET(provider_param, 0)].name, key_providers[provider_index].name);
	else if(current_rules_count == num_rules)
		sprintf(description, "[All] on %s", key_providers[provider_index].name);
	else
		sprintf(description, "[%i] on %s", current_rules_count, key_providers[provider_index].name);
	key_providers[provider_index].get_param_description(provider_param+current_rules_count+2, description+strlen(description), min_lenght, max_lenght);
}
