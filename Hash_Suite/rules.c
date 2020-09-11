// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014,2016,2020 by Alain Espinosa. See LICENSE.

#include "common.h"
#include <ctype.h>

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
#define YEAR_INDEX					(16*NUM_KEYS+9 )
#define CHAR_ADDED0_INDEX			(16*NUM_KEYS+10)
#define CHAR_ADDED1_INDEX			(16*NUM_KEYS+11)
#define CHAR_ADDED2_INDEX			(16*NUM_KEYS+12)
#define LEET_INDEX0					(16*NUM_KEYS+13)

////////////////////////////////////////////////////////////////////////////////////
// Specific rules
////////////////////////////////////////////////////////////////////////////////////
PRIVATE void rule_copy(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer, uint32_t max)
{
	uint32_t MAX_COPY = max*NUM_KEYS;
	uint32_t num_to_copy = __min(NUM_KEYS - rules_nt_buffer_index, NUM_KEYS - nt_buffer_index);
	uint32_t* rules_nt_buffer_ptr = rules_nt_buffer + rules_nt_buffer_index;
	nt_buffer += nt_buffer_index;

	for (uint32_t i = 0; i < MAX_COPY; i += NUM_KEYS)
		memcpy(nt_buffer + i, rules_nt_buffer_ptr + i, sizeof(uint32_t)*num_to_copy);

	rules_nt_buffer_index += num_to_copy;
	nt_buffer_index += num_to_copy;
}
PRIVATE void rule_copy_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	rule_copy(nt_buffer, NUM_KEYS, rules_data_buffer, 15);
}
PRIVATE void rule_copy_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	rule_copy(nt_buffer, NUM_KEYS, rules_data_buffer, 8);
}
PRIVATE void rule_lower_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		uint32_t MAX = (lenght / 2 + 1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((_tmp - 4259840u) <= 1703935u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(need_change)
		{
			uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
			for (; i < old_len; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
		else
			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = __max(nt_buffer[14 * NUM_KEYS + nt_buffer_index], lenght << 4);
	}
}
PRIVATE void rule_lower_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		int lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t MAX = (lenght / 4 + 1)*NUM_KEYS;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 8;
			}
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}
			if (((_tmp >> 24) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 24;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		if (need_change)
		{
			for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 3;
			nt_buffer_index++;
		}
	}
}
PRIVATE void rule_upper_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		uint32_t MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(((_tmp & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32;
			}
			if ((_tmp - 6356992u) <= 1703935u)
			{
				need_change = TRUE;
				_tmp -= 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(need_change)
		{
			uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
			for (; i < old_len; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
		else
			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = __max(nt_buffer[14 * NUM_KEYS + nt_buffer_index], lenght << 4);
	}
}
PRIVATE void rule_upper_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t MAX = (lenght / 4 + 1)*NUM_KEYS;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32;
			}
			if ((((_tmp >> 8) & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32 << 8;
			}
			if ((((_tmp >> 16) & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32 << 16;
			}
			if (((_tmp >> 24) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32 << 24;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		if (need_change)
		{
			for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 3;
			nt_buffer_index++;
		}
	}
}
PRIVATE void rule_capitalize_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		uint32_t lenght = rules_nt_buffer[14 * NUM_KEYS + rules_nt_buffer_index] >> 4;
		uint32_t MAX = (lenght / 2 + 1)*NUM_KEYS;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
				{
					need_change = TRUE;
					_tmp += 32;
				}
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
				{
					need_change = TRUE;
					_tmp -= 32;
				}
			}
			if ((_tmp - 4259840u) <= 1703935u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		if (need_change)
		{
			uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
			for (; i < old_len; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
		else
			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = __max(nt_buffer[14 * NUM_KEYS + nt_buffer_index], lenght << 4);
	}
}
PRIVATE void rule_capitalize_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		int lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t MAX = (lenght / 4 + 1)*NUM_KEYS;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
				{
					need_change = TRUE;
					_tmp += 32;
				}
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
				{
					need_change = TRUE;
					_tmp -= 32;
				}
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 8;
			}
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}
			if (((_tmp >> 24) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 24;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		if (need_change)
		{
			for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 3;
			nt_buffer_index++;
		}
	}
}
PRIVATE void rule_duplicate_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		int i;
		int lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int lenght_2num_keys = lenght/2*NUM_KEYS;

		if(lenght > 13) continue;

		if(lenght & 1)
		{ 
			uint32_t last_tmp = rules_nt_buffer[lenght_2num_keys+rules_nt_buffer_index] & 0xFF;

			for(i = 0; i < lenght_2num_keys; i+=NUM_KEYS)
			{
				uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
				nt_buffer[i+nt_buffer_index] = _tmp;
				nt_buffer[i+lenght_2num_keys+nt_buffer_index] = (_tmp << 16) | last_tmp;

				last_tmp = _tmp >> 16;
			}

			nt_buffer[i+lenght_2num_keys+nt_buffer_index] = last_tmp | (rules_nt_buffer[i+rules_nt_buffer_index] << 16);
		}
		else
			for(i = 0; i < lenght_2num_keys; i+=NUM_KEYS)
			{
				uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
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
PRIVATE void rule_duplicate_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;

		if (lenght > 13) continue;

		for (uint32_t i = 0; i < lenght / 4; i++)
			nt_buffer[i * NUM_KEYS + nt_buffer_index] = rules_nt_buffer[i* NUM_KEYS + rules_nt_buffer_index];

		switch (lenght&3)
		{
			uint32_t _tmp;
		case 0:
			for (uint32_t i = 0; i < lenght / 4; i++)
				nt_buffer[(lenght / 4+i) * NUM_KEYS + nt_buffer_index] = rules_nt_buffer[i* NUM_KEYS + rules_nt_buffer_index];

			nt_buffer[2 * (lenght / 4) * NUM_KEYS + nt_buffer_index] = 0x80;

			for (uint32_t i = 2 * (lenght / 4)+1; i < 7; i++)
				nt_buffer[i * NUM_KEYS + nt_buffer_index] = 0;
			break;
		case 1:
			_tmp = rules_nt_buffer[lenght / 4 * NUM_KEYS + rules_nt_buffer_index] & 0xff;
			for (uint32_t i = 0; i < lenght / 4; i++)
			{
				uint32_t in_tmp = rules_nt_buffer[i* NUM_KEYS + rules_nt_buffer_index];
				nt_buffer[(lenght / 4 + i) * NUM_KEYS + nt_buffer_index] = _tmp + (in_tmp<<8);
				_tmp = in_tmp >> 24;
			}

			nt_buffer[2 * (lenght / 4) * NUM_KEYS + nt_buffer_index] = _tmp + (rules_nt_buffer[lenght / 4 * NUM_KEYS + rules_nt_buffer_index] << 8);

			for (uint32_t i = 2 * (lenght / 4) + 1; i < 7; i++)
				nt_buffer[i * NUM_KEYS + nt_buffer_index] = 0;
			break;
		case 2:
			_tmp = rules_nt_buffer[lenght / 4 * NUM_KEYS + rules_nt_buffer_index] & 0xffff;
			for (uint32_t i = 0; i < lenght / 4; i++)
			{
				uint32_t in_tmp = rules_nt_buffer[i* NUM_KEYS + rules_nt_buffer_index];
				nt_buffer[(lenght / 4 + i) * NUM_KEYS + nt_buffer_index] = _tmp + (in_tmp << 16);
				_tmp = in_tmp >> 16;
			}

			nt_buffer[2 * (lenght / 4) * NUM_KEYS + nt_buffer_index] = _tmp + (rules_nt_buffer[lenght / 4 * NUM_KEYS + rules_nt_buffer_index] << 16);
			nt_buffer[(2 * (lenght / 4)+1) * NUM_KEYS + nt_buffer_index] = 0x80;

			for (uint32_t i = 2 * (lenght / 4) + 2; i < 7; i++)
				nt_buffer[i * NUM_KEYS + nt_buffer_index] = 0;
			break;
		case 3:
			_tmp = rules_nt_buffer[lenght / 4 * NUM_KEYS + rules_nt_buffer_index] & 0xffffff;
			for (uint32_t i = 0; i < lenght / 4; i++)
			{
				uint32_t in_tmp = rules_nt_buffer[i* NUM_KEYS + rules_nt_buffer_index];
				nt_buffer[(lenght / 4 + i) * NUM_KEYS + nt_buffer_index] = _tmp + (in_tmp << 24);
				_tmp = in_tmp >> 8;
			}

			uint32_t in_tmp = rules_nt_buffer[lenght / 4 * NUM_KEYS + rules_nt_buffer_index];
			nt_buffer[2 * (lenght / 4) * NUM_KEYS + nt_buffer_index] = _tmp + (in_tmp << 24);
			nt_buffer[(2 * (lenght / 4) + 1) * NUM_KEYS + nt_buffer_index] = in_tmp >> 8;

			for (uint32_t i = 2 * (lenght / 4) + 2; i < 7; i++)
				nt_buffer[i * NUM_KEYS + nt_buffer_index] = 0;
			break;
		}

		nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 4;
		nt_buffer_index++;
	}
}
PRIVATE void ru_lower_upperlast_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		uint32_t MAX = (lenght & 1) ? lenght/2*NUM_KEYS : (lenght/2-1)*NUM_KEYS;
		if(!lenght) continue;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((_tmp - 4259840u) <= 1703935u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		// Last letter --> uppercase
		if(lenght & 1)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}
		else
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if(_tmp >= 6356992 && _tmp <= 8060927)
			{
				need_change = TRUE;
				_tmp -= 32 << 16;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
			i += NUM_KEYS;
			nt_buffer[i + nt_buffer_index] = 0x80;
		}

		if(need_change)
		{
			i += NUM_KEYS;

			uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
			for(; i < old_len; i+=NUM_KEYS)
				nt_buffer[i+nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
		else
			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = __max(nt_buffer[14 * NUM_KEYS + nt_buffer_index], lenght << 4);
	}
}
PRIVATE void ru_low_upperlas_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; rules_nt_buffer_index++)
	{
		uint32_t i;
		int need_change = FALSE;
		int lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t MAX = ((lenght-1) / 4)*NUM_KEYS;
		if (!lenght) continue;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 8;
			}
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}
			if (((_tmp >> 24) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 24;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];
		switch (lenght&3)
		{
		case 0:
			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 8;
			}
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 16;
			}
			if (((_tmp >> 24) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32 << 24;
			}
			nt_buffer[i + nt_buffer_index] = _tmp;
			i += NUM_KEYS;
			nt_buffer[i + nt_buffer_index] = 0x80;
			i += NUM_KEYS;
			break;
		case 1:
			if (((_tmp & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
			i += NUM_KEYS;
			break;
		case 2:
			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32 << 8;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
			i += NUM_KEYS;
			break;
		case 3:
			if (((_tmp & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
			{
				need_change = TRUE;
				_tmp += 32 << 8;
			}
			if ((((_tmp >> 16) & 0xFF) - 97u) <= 25u)
			{
				need_change = TRUE;
				_tmp -= 32 << 16;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
			i += NUM_KEYS;
			break;
		}

		if (need_change)
		{
			for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 3;
			nt_buffer_index++;
		}
	}
}
// OpenCL rules
#ifdef HS_OPENCL_SUPPORT
PRIVATE void end_brace(char* source)
{
	strcat(source, "}");
}
PRIVATE void ocl_fill_buffer(char nt_buffer[16][16], cl_uint lenght)
{
	uint32_t i;
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
PRIVATE void ocl_fill_buffer_array(char nt_buffer[16][16], cl_uint lenght)
{
	uint32_t i;
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
PRIVATE cl_uint oclru_copy_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	cl_uint i, gpu_key_buffer_lenght;

	ocl_fill_buffer(nt_buffer, lenght);
	if (!lenght) return 1;

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i < lenght; i++)
		gpu_key_buffer_lenght += (i + 3) / 4;

	// Total number of keys
	sprintf(source + strlen(source), "indx+=%uu;uint copy_tmp;", MAX_KEY_LENGHT_SMALL + gpu_key_buffer_lenght*NUM_KEYS_OPENCL);
	// Convert the key into a nt_buffer
	for (i = 0; i < ((lenght + 3) / 4 - 1); i++)
		sprintf(source + strlen(source),
				"copy_tmp=keys[indx+%uu];"
				"uint nt_buffer%u=GET_1(copy_tmp);"
				"uint nt_buffer%u=GET_2(copy_tmp);"
				, i*NUM_KEYS_OPENCL, 2 * i, 2 * i + 1);

	// Last
	sprintf(source + strlen(source),
		"copy_tmp=keys[indx+%uu];"
		"uint nt_buffer%u=GET_1(copy_tmp);"
		, i*NUM_KEYS_OPENCL, 2 * i);
	if (lenght % 4 == 3 || lenght % 4 == 0)
		sprintf(source + strlen(source), "uint nt_buffer%u=GET_2(copy_tmp);", 2 * i + 1);

	return 1;
}
PRIVATE void oclru_copy_array(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint more_buffer)
{
	uint32_t i, gpu_key_buffer_lenght;

	ocl_fill_buffer_array(nt_buffer, lenght);
	if (!lenght) return;

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i < lenght; i++)
		gpu_key_buffer_lenght += (i + 3) / 4;

	// Total number of keys
	sprintf(source + strlen(source),"indx+=%uu;"
									"uint nt_buffer[%u];uint copy_tmp;", MAX_KEY_LENGHT_SMALL+gpu_key_buffer_lenght*NUM_KEYS_OPENCL, (lenght + 1 + more_buffer) / 2);
	// Convert the key into a nt_buffer
	for (i = 0; i < ((lenght + 3) / 4 - 1); i++)
		sprintf(source + strlen(source),"copy_tmp=keys[indx+%uu];"
										"nt_buffer[%u]=GET_1(copy_tmp);"
										"nt_buffer[%u]=GET_2(copy_tmp);"
										, i*NUM_KEYS_OPENCL, 2 * i, 2 * i + 1);
	// Last
	sprintf(source + strlen(source),"copy_tmp=keys[indx+%uu];"
									"nt_buffer[%u]=GET_1(copy_tmp);"
									, i*NUM_KEYS_OPENCL, 2 * i);
	if (lenght % 4 == 3 || lenght % 4 == 0)
		sprintf(source + strlen(source), "nt_buffer[%u]=GET_2(copy_tmp);", 2 * i + 1);
}
PRIVATE cl_uint oclru_lower_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Lowercase
	for (cl_uint i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u-4259840u)<=1703935u)"
												"nt_buffer%u+=32<<16;"
												, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u&0xFF)-65u)<=25u)"
												"nt_buffer%u+=32u;"
												, i / 2, i / 2);

	return 1;
}
PRIVATE cl_uint oclru_upper_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Uppercase
	for (uint32_t i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u-6356992u)<=1703935u)"
												"nt_buffer%u-=32u<<16u;"
												, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u&0xFF)-97u)<=25u)"
												"nt_buffer%u-=32u;"
												, i / 2, i / 2);

	return 1;
}
PRIVATE cl_uint oclru_capitalize_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	//Capitalize
	if (lenght)
		sprintf(source + strlen(source),"if(((nt_buffer0&0xFF)-97u)<=25u)"
											"nt_buffer0-=32u;");
	// Lowercase
	for (cl_uint i = 1; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u-4259840u)<=1703935u)"
												"nt_buffer%u+=32<<16;"
												, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u&0xFF)-65u)<=25u)"
												"nt_buffer%u+=32u;"
												, i / 2, i / 2);

	return 1;
}
PRIVATE cl_uint oclru_duplicate_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	if (lenght > 13)
	{
		strcat(source, "return;");
		return 1;
	}
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", lenght << 5);
	if (lenght & 1)
	{
		sprintf(source + strlen(source), "nt_buffer%u=(nt_buffer%u&0xff)|(nt_buffer0<<16u);", lenght / 2, lenght / 2);
		for (uint32_t i = 0; i < lenght / 2; i++)
		{
			sprintf(nt_buffer[lenght / 2 + i + 1], "+nt_buffer%u", lenght / 2 + i + 1);
			sprintf(source + strlen(source), "uint nt_buffer%u=(nt_buffer%u<<16u)|(nt_buffer%u>>16u);", lenght / 2 + i + 1, i+1, i);
		}
	}
	else
		for (uint32_t i = 0; i < lenght/2; i++)
			strcpy(nt_buffer[lenght / 2 + i], nt_buffer[i]);

	strcpy(nt_buffer[lenght], "+0x80");
	return 1;
}
PRIVATE cl_uint oclru_lower_upper_last_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	uint32_t i;
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Requires length greater than 0
	if (!lenght)
	{
		strcat(source, "return;");
		return 1;
	}

	// Lowercase
	for (i = 0; i < lenght-1; i++)
		if (i & 1)
			sprintf(source + strlen(source), "if((nt_buffer%u-4259840u)<=1703935u)"
												"nt_buffer%u+=32<<16;"
												, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "if(((nt_buffer%u&0xFF)-65u)<=25u)"
												"nt_buffer%u += 32;"
												, i / 2, i / 2);

	// Upper last
	if (i & 1)
		sprintf(source + strlen(source), "if((nt_buffer%u-6356992u)<=1703935u)"
											"nt_buffer%u-=32<<16;"
											, i / 2, i / 2);
	else
		sprintf(source + strlen(source), "if(((nt_buffer%u&0xFF)-97u)<=25u)"
												"nt_buffer%u-=32;"
												, i / 2, i / 2);

	return 1;
}
// UTF8
PRIVATE void ocl_fill_buffer_utf8(char nt_buffer[16][16], cl_uint lenght)
{
	cl_uint i;
	for (i = 0; i < lenght / 4; i++)
		sprintf(nt_buffer[i], "+buffer%u", i);

	if (lenght & 3)
		sprintf(nt_buffer[i], "+buffer%u", i);
	else
		strcpy(nt_buffer[i], "+0x80");

	i++;
	for (; i < 7; i++)
		strcpy(nt_buffer[i], "");

	sprintf(nt_buffer[7], "+%uu", lenght << 3);
}
PRIVATE void ocl_fill_buffer_array_utf8(char nt_buffer[16][16], cl_uint lenght)
{
	cl_uint i;
	for (i = 0; i < lenght / 4; i++)
		sprintf(nt_buffer[i], "+nt_buffer[%u]", i);

	if (lenght & 3)
		sprintf(nt_buffer[i], "+nt_buffer[%u]", i);
	else
		strcpy(nt_buffer[i], "+0x80");

	i++;
	for (; i < 7; i++)
		strcpy(nt_buffer[i], "");

	sprintf(nt_buffer[7], "+%uu", lenght << 3);
}
PRIVATE void oclru_copy_array_utf8(char* source, char nt_buffer[16][16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint more_buffer)
{
	cl_uint i, gpu_key_buffer_lenght;

	ocl_fill_buffer_array_utf8(nt_buffer, lenght);
	if (!lenght) return;

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i < lenght; i++)
		gpu_key_buffer_lenght += (i + 3) / 4;

	// Total number of keys
	sprintf(source + strlen(source),"indx+=%uu;"
									"uint nt_buffer[%u];", MAX_KEY_LENGHT_SMALL+gpu_key_buffer_lenght*NUM_KEYS_OPENCL, (lenght + 3 + more_buffer) / 4);
	// Convert the key into a nt_buffer
	for (i = 0; i < (lenght + 3) / 4; i++)
		sprintf(source + strlen(source),"nt_buffer[%u]=keys[indx+%uu];",i , i*NUM_KEYS_OPENCL);
}
PRIVATE cl_uint oclru_copy_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	cl_uint i, gpu_key_buffer_lenght;

	ocl_fill_buffer_utf8(nt_buffer, lenght);
	if (!lenght) return 1;

	// Size in bytes
	for (i = 1, gpu_key_buffer_lenght = 0; i < lenght; i++)
		gpu_key_buffer_lenght += (i + 3) / 4;

	// Total number of keys
	sprintf(source + strlen(source), "indx+=%uu;", MAX_KEY_LENGHT_SMALL + gpu_key_buffer_lenght*NUM_KEYS_OPENCL);
	// Convert the key into a nt_buffer
	for (i = 0; i < ((lenght+3)/4); i++)
		sprintf(source + strlen(source), "uint buffer%u=keys[indx+%uu];", i, i*NUM_KEYS_OPENCL);

	return 1;
}
PRIVATE cl_uint oclru_lower_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Lowercase
	for (uint32_t i = 0; i < lenght; i++)
		switch (i & 3)
		{
		case 1: case 2:
			sprintf(source + strlen(source), "if((((buffer%u>>%uu)&0xFF)-65u)<=25u)"
				"buffer%u+=%uu;"
				, i / 4, 8 * (i & 3), i / 4, 32 << (8 * (i & 3)));
			break;
		case 3:
			sprintf(source + strlen(source), "if(((buffer%u>>24u)-65u)<=25u)"
				"buffer%u+=%uu;"
				, i / 4, i / 4, 32 << 24);
			break;
		case 0:
			sprintf(source + strlen(source), "if(((buffer%u&0xFF)-65u)<=25u)"
			"buffer%u+=32u;"
			, i / 4, i / 4);
			break;
		}

	return 1;
}
PRIVATE cl_uint oclru_upper_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Uppercase
	for (uint32_t i = 0; i < lenght; i++)
		switch (i & 3)
		{
			case 1: case 2:
				sprintf(source + strlen(source), "if((((buffer%u>>%uu)&0xFF)-97u)<=25u)"
					"buffer%u-=%uu;"
					, i / 4, 8 * (i & 3), i / 4, 32 << (8 * (i & 3)));
				break;
			case 3:
				sprintf(source + strlen(source), "if(((buffer%u>>24u)-97u)<=25u)"
					"buffer%u-=%uu;"
					, i / 4, i / 4, 32 << 24);
				break;
			case 0:
				sprintf(source + strlen(source), "if(((buffer%u&0xFF)-97u)<=25u)"
					"buffer%u-=32u;"
					, i / 4, i / 4);
				break;
		}

	return 1;
}
PRIVATE cl_uint oclru_capitalize_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Lowercase
	for (uint32_t i = 0; i < lenght; i++)
		switch (i & 3)
		{
			case 1: case 2:
				sprintf(source + strlen(source), "if((((buffer%u>>%uu)&0xFF)-65u)<=25u)"
					"buffer%u+=%uu;"
					, i / 4, 8 * (i & 3), i / 4, 32 << (8 * (i & 3)));
				break;
			case 3:
				sprintf(source + strlen(source), "if(((buffer%u>>24u)-65u)<=25u)"
					"buffer%u+=%uu;"
					, i / 4, i / 4, 32 << 24);
				break;
			case 0:
				if (i)
					sprintf(source + strlen(source), "if(((buffer%u&0xFF)-65u)<=25u)"
						"buffer%u+=32u;"
						, i / 4, i / 4);
				else
					strcat(source, "if(((buffer0&0xFF)-97u)<=25u)"
										"buffer0-=32u;");
				break;
		}

	return 1;
}
PRIVATE cl_uint oclru_duplicate_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	if (lenght > 13)
	{
		strcat(source, "return;");
		return 1;
	}
	// Put lenght
	sprintf(nt_buffer[7], "+%uu", lenght << 4);
	if (lenght & 3)
	{
		if ((lenght & 3) == 3)
		{
			sprintf(nt_buffer[lenght / 2], "+buffer%u", lenght / 2);
			sprintf(source + strlen(source), "uint buffer%u=buffer%u>>8u;", lenght / 2, lenght / 4);
		}
		if ((lenght & 3) == 2)
			strcpy(nt_buffer[lenght / 2], "+0x80");

		for (uint32_t i = 0; i < lenght / 4; i++)
		{
			sprintf(nt_buffer[lenght / 4 + i + 1], "+buffer%u", lenght / 4 + i + 1);
			sprintf(source + strlen(source), "uint buffer%u=(buffer%u<<%uu)|(buffer%u>>%uu);", lenght / 4 + i + 1, i + 1, 8 * (lenght & 3), i, 32-8 * (lenght & 3));
		}
		sprintf(source + strlen(source), "buffer%u=(buffer%u&%uu)|(buffer0<<%uu);", lenght / 4, lenght / 4, 0xffffffff >> (32 - 8 * (lenght & 3)), 8 * (lenght & 3));
	}
	else
	{
		for (uint32_t i = 0; i < lenght / 4; i++)
			strcpy(nt_buffer[lenght / 4 + i], nt_buffer[i]);

		strcpy(nt_buffer[lenght/2], "+0x80");
	}

	return 1;
}
PRIVATE cl_uint oclru_lower_upper_last_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	cl_uint i;
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	if (!lenght)
	{
		strcat(source, "return;");
		return 1;
	}

	// Lowercase
	for (i = 0; i < lenght-1; i++)
		switch (i & 3)
		{
			case 1: case 2:
				sprintf(source + strlen(source), "if((((buffer%u>>%uu)&0xFF)-65u)<=25u)"
					"buffer%u+=%uu;"
					, i / 4, 8 * (i & 3), i / 4, 32 << (8 * (i & 3)));
				break;
			case 3:
				sprintf(source + strlen(source), "if(((buffer%u>>24u)-65u)<=25u)"
					"buffer%u+=%uu;"
					, i / 4, i / 4, 32 << 24);
				break;
			case 0:
				sprintf(source + strlen(source), "if(((buffer%u&0xFF)-65u)<=25u)"
					"buffer%u+=32u;"
					, i / 4, i / 4);
				break;
		}
	// Upper
	switch (i & 3)
	{
	case 1: case 2:
		sprintf(source + strlen(source), "if((((buffer%u>>%uu)&0xFF)-97u)<=25u)"
			"buffer%u-=%uu;"
			, i / 4, 8 * (i & 3), i / 4, 32 << (8 * (i & 3)));
		break;
	case 3:
		sprintf(source + strlen(source), "if(((buffer%u>>24u)-97u)<=25u)"
			"buffer%u-=%uu;"
			, i / 4, i / 4, 32 << 24);
		break;
	case 0:
		sprintf(source + strlen(source), "if(((buffer%u&0xFF)-97u)<=25u)"
			"buffer%u-=32u;"
			, i / 4, i / 4);
		break;
	}

	return 1;
}
// Get plaintext
PRIVATE void ocl_copy_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
}
PRIVATE void ocl_lower_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
}
PRIVATE void ocl_upper_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strupr(out_key);
}
PRIVATE void ocl_capitalize_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	if(islower(out_key[0]))
		out_key[0] -= 32;
}
PRIVATE void ocl_duplicate_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	strcpy(out_key+strlen(out_key), plain);
}
PRIVATE void ocl_lower_upper_last_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	if( islower(out_key[strlen(out_key)-1]) )
		out_key[strlen(out_key)-1] -= 32;
}
// Common
PRIVATE void oclru_common_kernel_definition(char* source, char* rule_name, int need_param)
{
	sprintf(source + strlen(source), 
		"\n__kernel void %s(const __global uint* in_key,__global uint* out_key,__global uint* begin_out_index, uint max_idx%s)"
		"{"
			"uint idx=get_global_id(0);"
			"if(idx>=max_idx)return;", rule_name, need_param ? ",uint param" : "");
}
PRIVATE void oclru_copy_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, FALSE);

	sprintf(source + strlen(source),
		"atomic_inc(begin_out_index);"
		"uint len=in_key[7u*%uu+idx];"
		"out_key[7u*%uu+idx]=len;"
		"uint max_iter=(len>>6u)+1u;"

		"for(uint i=0;i<max_iter;i++)"
			"out_key[i*%uu+idx]=in_key[i*%uu+idx];", in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_lower_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, FALSE);

	sprintf(source + strlen(source),
		"uint tmp[7];"
		"bool have_change=false;"
		"uint len=in_key[7u*%uu+idx];"
		"uint max_iter=(len>>6u)+1u;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(((part_key & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u;"
				"have_change=true;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<8u;"
				"have_change=true;"
			"}"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<16u;"
				"have_change=true;"
			"}"
			"if(((part_key>>24u) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<24u;"
				"have_change=true;"
			"}"

			"tmp[i]=part_key;"
		"}"

		"if(have_change)"
		"{"
			"uint out_index=atomic_inc(begin_out_index);"
			"out_key[7u*%uu+out_index]=len;"
			"for(uint i=0;i<max_iter;i++)"
				"out_key[i*%uu+out_index]=tmp[i];"
		"}", in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_upper_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, FALSE);

	sprintf(source + strlen(source),
		"uint tmp[7];"
		"bool have_change=false;"
		"uint len=in_key[7u*%uu+idx];"
		"uint max_iter=(len>>6u)+1u;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(((part_key & 0xFF) - 97u) <= 25u)"
			"{"
				"part_key -= 32u;"
				"have_change=true;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 97u) <= 25u)"
			"{"
				"part_key -= 32u<<8u;"
				"have_change=true;"
			"}"
			"if((((part_key>>16u) & 0xFF) - 97u) <= 25u)"
			"{"
				"part_key -= 32u<<16u;"
				"have_change=true;"
			"}"
			"if(((part_key>>24u) - 97u) <= 25u)"
			"{"
				"part_key -= 32u<<24u;"
				"have_change=true;"
			"}"

			"tmp[i]=part_key;"
		"}"

		"if(have_change)"
		"{"
			"uint out_index=atomic_inc(begin_out_index);"
			"out_key[7u*%uu+out_index]=len;"
			"for(uint i=0;i<max_iter;i++)"
				"out_key[i*%uu+out_index]=tmp[i];"
		"}", in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_capitalize_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, FALSE);

	sprintf(source + strlen(source),
		"uint tmp[7];"
		"bool have_change=false;"
		"uint len=in_key[7u*%uu+idx];"
		"uint max_iter=(len>>6u)+1u;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(i==0){"
				"if(((part_key & 0xFF) - 97u) <= 25u)"
				"{"
					"part_key -= 32u;"
					"have_change=true;"
				"}"
			"}else{"
				"if(((part_key & 0xFF) - 65u) <= 25u)"
				"{"
					"part_key += 32u;"
					"have_change=true;"
				"}"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<8u;"
				"have_change=true;"
			"}"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<16u;"
				"have_change=true;"
			"}"
			"if(((part_key>>24u) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<24u;"
				"have_change=true;"
			"}"

			"tmp[i]=part_key;"
		"}"

		"if(have_change)"
		"{"
			"uint out_index=atomic_inc(begin_out_index);"
			"out_key[7u*%uu+out_index]=len;"
			"for(uint i=0;i<max_iter;i++)"
				"out_key[i*%uu+out_index]=tmp[i];"
		"}", in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_duplicate_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, FALSE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"

		"if(len > (13u<<4u))return;"

		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len<<1u;"
		"uint max_iter=len>>6u;"
		"len=(len>>1u) & (3u<<3u);"

		"if(len)"
		"{"
			"for(uint i=0;i<max_iter;i++)"
				"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"
			
			"uint part_key=in_key[max_iter*%uu+idx] & (0xffffffff >> (32u-len));"

			"for(uint i=0;i<(max_iter+1);i++)"
			"{"
				"uint in_part=in_key[i*%uu+idx];"
				"out_key[(max_iter+i)*%uu+out_index]=part_key + (in_part<<len);"
				"part_key = in_part >> (32u-len);"
			"}"
			"if(len>=(2u<<3u))"
				"out_key[(2*max_iter+1)*%uu+out_index]=part_key;"
		"}else{"
			"for(uint i=0;i<max_iter;i++)"
			"{"
				"uint in_part=in_key[i*%uu+idx];"
				"out_key[i*%uu+out_index]=in_part;"
				"out_key[(max_iter+i)*%uu+out_index]=in_part;"
			"}"
			"out_key[2*max_iter*%uu+out_index]=0x80;"
		"}"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_lower_upper_last_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, FALSE);

	sprintf(source + strlen(source),
		"uint tmp[7];"
		"bool have_change=false;"
		"uint len=in_key[7u*%uu+idx];"
		"if(len==0)return;"
		"uint max_iter=(len>>6u)+1u;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(((part_key & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u;"
				"have_change=true;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<8u;"
				"have_change=true;"
			"}"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<16u;"
				"have_change=true;"
			"}"
			"if(((part_key>>24u) - 65u) <= 25u)"
			"{"
				"part_key += 32u<<24u;"
				"have_change=true;"
			"}"

			"tmp[i]=part_key;"
		"}"

		"uint len3 = (len>>4u)&3u;"
		"uint index_last = max_iter- (len3 ? 1 : 2);"
		"uint last_part=tmp[index_last];"
		"len3=(len3-1u)&3u;"
		"if((((last_part>>(8u*len3)) & 0xFF) - 97u) <= 25u)"
		"{"
			"last_part -= 32u<<(8u*len3);"
			"have_change=true;"
		"}"
		"tmp[index_last]=last_part;"

		"if(have_change)"
		"{"
			"uint out_index=atomic_inc(begin_out_index);"
			"out_key[7u*%uu+out_index]=len;"
			"for(uint i=0;i<max_iter;i++)"
				"out_key[i*%uu+out_index]=tmp[i];"
		"}", in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// Append and prefix stuff
#define MAX_CHAR_ADDED 126/*'~'*/
#define MIN_CHAR_ADDED  32/*' '*/
#define LENGHT_CHAR_ADDED (MAX_CHAR_ADDED-MIN_CHAR_ADDED+1)

PRIVATE void rule_lower_plus_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	nt_buffer += nt_buffer_index;

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added + 1, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = num_to_copy;

		if (lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			for (j = i; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}
		// Last
		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			_tmp = char_added + 0x8000;
			for (j = i; j < MAX; j++, _tmp++)
				nt_buffer[j] = _tmp;
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if ((_tmp - 65u) <= 25u)
				_tmp += 32;

			_tmp += (char_added << 8) + 0x800000;
			for (j = i; j < MAX; j++, _tmp += (1 << 8))
				nt_buffer[j] = _tmp;
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			if (((_tmp & 0xff) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp>>8) & 0xff) - 65u) <= 25u)
				_tmp += 32<<8;

			_tmp += (char_added << 16) + 0x80000000;
			for (j = i; j < MAX; j++, _tmp += (1 << 16))
				nt_buffer[j] = _tmp;
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			if (((_tmp & 0xff) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8) & 0xff) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xff) - 65u) <= 25u)
				_tmp += 32 << 16;

			_tmp += char_added << 24;
			for (j = i; j < MAX; j++, _tmp += (1 << 24))
				nt_buffer[j] = _tmp;

			// End
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			for (j = i; j < MAX; j++)
				nt_buffer[j] = 0x80;
			break;
		}
		char_added += num_to_copy;

		i += NUM_KEYS;
		MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 1) << 3;
		for (j = 7 * NUM_KEYS; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
		nt_buffer += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_cap_append_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	nt_buffer += nt_buffer_index;

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added + 1, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = num_to_copy;

		if (lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			for (j = i; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}
		// Last
		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			_tmp = char_added + 0x8000;
			for (j = i; j < MAX; j++, _tmp++)
				nt_buffer[j] = _tmp;
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if (i)
			{
				if ((_tmp - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if ((_tmp - 97u) <= 25u)
					_tmp -= 32;
			}

			_tmp += (char_added << 8) + 0x800000;
			for (j = i; j < MAX; j++, _tmp += (1 << 8))
				nt_buffer[j] = _tmp;
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8) & 0xff) - 65u) <= 25u)
				_tmp += 32 << 8;

			_tmp += (char_added << 16) + 0x80000000;
			for (j = i; j < MAX; j++, _tmp += (1 << 16))
				nt_buffer[j] = _tmp;
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8) & 0xff) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xff) - 65u) <= 25u)
				_tmp += 32 << 16;

			_tmp += char_added << 24;
			for (j = i; j < MAX; j++, _tmp += (1 << 24))
				nt_buffer[j] = _tmp;

			// End
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			for (j = i; j < MAX; j++)
				nt_buffer[j] = 0x80;
			break;
		}
		char_added += num_to_copy;

		i += NUM_KEYS;
		MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 1) << 3;
		for (j = 7 * NUM_KEYS; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
		nt_buffer += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_lower_append_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	nt_buffer += nt_buffer_index;

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = num_to_copy;

		if(lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			for(j = i; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if ((_tmp - 65u) <= 25u)
				_tmp += 32;

			_tmp += char_added << 16;

			for (j = i; j < MAX; j++, _tmp += (1 << 16))
				nt_buffer[j] = _tmp;

			i += NUM_KEYS;
			MAX += NUM_KEYS;
			for(j = i; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}
		else
		{
			uint32_t _tmp = char_added + 0x800000;
			for (j = i; j < MAX; j++, _tmp++)
				nt_buffer[j] = _tmp;
		}
		char_added += num_to_copy;

		i += NUM_KEYS;
		// Fill with 0
		for (int j = 0; j < num_to_copy; j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy;

		lenght = (lenght+1) << 4;
		for(j = 14*NUM_KEYS; j < MAX; j++)
			nt_buffer[j] = lenght;

		if(char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
		nt_buffer += num_to_copy;
	}

	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_cap_append_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added + 1, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i)
			{
				if(((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			}else{// First position -> to-upper
				
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if(i)
			{
				if((_tmp - 65u) <= 25u)
				_tmp += 32;
			}else{// First position -> to-upper
				
				if ((_tmp - 97u) <= 25u)
					_tmp -= 32;
			}

			for(j = i + nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = _tmp | (char_added << 16);

			i += NUM_KEYS;
			MAX += NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}
		else
			for(j = i + nt_buffer_index; j < MAX; j++, char_added++)
				nt_buffer[j] = char_added + 0x800000;

		i += NUM_KEYS;
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

		lenght = (lenght+1) << 4;
		for (j = 14 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
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
PRIVATE void rule_prefix_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = (lenght+3)/2*NUM_KEYS;

		if(lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for(i = 0; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];
			uint32_t last_tmp;

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
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void rule_prefix_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added + 1, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = ((lenght+1) / 4 + 1) * NUM_KEYS;

		if (lenght >= 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for (i = 0; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];
			uint32_t last_tmp;

			if (i)
			{
				last_tmp = (_tmp << 8) | last_tmp;
				for (j = i + nt_buffer_index; j < MAX; j++)
					nt_buffer[j] = last_tmp;
			}
			else
			{
				last_tmp = char_added + (_tmp << 8);
				for (j = nt_buffer_index; j < MAX; j++, last_tmp++)
					nt_buffer[j] = last_tmp;
				char_added += num_to_copy;
			}

			last_tmp = _tmp >> 24;
		}

		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 1) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added > MAX_CHAR_ADDED)
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
PRIVATE cl_uint oclru_append_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Append character
	if (lenght & 1)
	{
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
		sprintf(source + strlen(source), "uint%s char_add=(nt_buffer%u&0xff)+%uu;", prefered_vector_size==1?"":"2", lenght / 2, MIN_CHAR_ADDED << 16);
	}
	else
	{
		sprintf(source + strlen(source), "uint%s char_add=%uu;", prefered_vector_size==1?"":"2", 0x800000 | MIN_CHAR_ADDED);
	}

	sprintf(nt_buffer[lenght / 2], "+char_add");
	nt_buffer_vector_size[lenght / 2] = prefered_vector_size;
	if (prefered_vector_size>1)
		sprintf(source + strlen(source), "char_add.s1+=%uu;", 1 << (16 * (lenght & 1)));

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,char_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size << (16 * (lenght & 1)));

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght+1) << 4);

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_lower_append_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_append_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
}
PRIVATE cl_uint oclru_capitalize_plus_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_append_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
}
PRIVATE cl_uint oclru_prefix_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Prefix character
	if (lenght & 1)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
		sprintf(source + strlen(source), "uint nt_buffer%u=0x80;", lenght / 2);
	}
	// First character
	sprintf(source + strlen(source),
		"uint tmp_char=nt_buffer0>>16;"
		"uint%s char_add=(nt_buffer0<<16)+%uu;"
		"uint swap_tmp;", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED);
	// Copy
	for (cl_uint i = 1; i < lenght/2 + 1; i++)
		sprintf(source + strlen(source),
			"swap_tmp=tmp_char+(nt_buffer%u<<16);"
			"tmp_char=nt_buffer%u>>16;"
			"nt_buffer%u=swap_tmp;"
			, i, i, i);

	strcpy(nt_buffer[0], "+char_add");
	nt_buffer_vector_size[0] = prefered_vector_size;
	if (prefered_vector_size>1)
		sprintf(source + strlen(source), "char_add.s1++;");
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,char_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size);
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 1) << 4);

	return prefered_vector_size;
}
// UTF8
PRIVATE cl_uint oclru_plus_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint prefered_vector_size)
{
	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Append character
	switch (lenght & 3)
	{
	case 3:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
		sprintf(source + strlen(source), "uint%s char_add=buffer%u+%uu;", prefered_vector_size==1?"":"2", lenght / 4, (MIN_CHAR_ADDED << 24) - 0x80000000);
		break;
	case 1: case 2:
		sprintf(source + strlen(source), "uint%s char_add=buffer%u+0x%x;", prefered_vector_size==1?"":"2", lenght / 4, (0x8000 + MIN_CHAR_ADDED - 0x80) << (8 * (lenght & 3)));
		break;
	case 0:
		sprintf(source + strlen(source), "uint%s char_add=0x%x;", prefered_vector_size==1?"":"2", 0x8000 + MIN_CHAR_ADDED);
		break;
	}
	sprintf(nt_buffer[lenght / 4], "+char_add");
	nt_buffer_vector_size[lenght / 4] = prefered_vector_size;
	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "char_add.s1+=%uu;", 1 << (8 * (lenght & 3)));

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0u;i<%uu;i+=%uu,char_add+=0x%x){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size << (8 * (lenght & 3)));

	// Put lenght
	sprintf(nt_buffer[7], "+%uu", (lenght + 1) << 3);

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_lower_plus_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, prefered_vector_size);
}
PRIVATE cl_uint oclru_capitalize_plus_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, prefered_vector_size);
}
PRIVATE cl_uint oclru_prefix_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 27)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Prefix character
	switch (lenght & 3)
	{
	case 3:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
	case 1: case 2:
		if (lenght > 3)
			sprintf(source + strlen(source), "buffer%u=(buffer%u<<8u)+(buffer%u>>24u);", lenght / 4, lenght / 4, lenght / 4 - 1);
		break;
	case 0:
		sprintf(nt_buffer[lenght / 4], "+buffer%u", lenght / 4);
		if (lenght)
			sprintf(source + strlen(source), "uint buffer%u=(buffer%u>>24u)+0x8000;", lenght / 4, lenght / 4 - 1);
		else
			sprintf(source + strlen(source), "uint%s char_add=%uu;", prefered_vector_size == 1 ? "" : "2", 0x8000 + MIN_CHAR_ADDED);
		break;
	}

	// Reverse
	for (int i = lenght / 4 - 1; i > 0; i--)
		sprintf(source + strlen(source), "buffer%i=(buffer%i<<8u)+(buffer%i>>24u);", i, i, i - 1);

	if (lenght)
		sprintf(source + strlen(source), "uint%s char_add=(buffer0<<8u)+%uu;", prefered_vector_size == 1 ? "" : "2", MIN_CHAR_ADDED);

	sprintf(nt_buffer[0], "+char_add");
	nt_buffer_vector_size[0] = prefered_vector_size;

	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "char_add.s1++;");

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0u;i<%uu;i+=%uu,char_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size);

	// Put lenght
	sprintf(nt_buffer[7], "+%uu", (lenght + 1) << 3);

	return prefered_vector_size;
}
// Get plaintext
PRIVATE void ocl_lower_append_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	out_key[strlen(out_key)+1] = 0;
	out_key[strlen(out_key)] = (unsigned char)(MIN_CHAR_ADDED + param);
}
PRIVATE void ocl_capitalize_append_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
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
PRIVATE void ocl_prefix_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key+1, plain);
	out_key[0] = (unsigned char)(MIN_CHAR_ADDED + param);
}
// Common
PRIVATE void oclru_lower_plus_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(26u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(1u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(((part_key & 0xFF) - 65u) <= 25u)"
				"part_key += 32u;"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"out_key[i*%uu+out_index]=part_key;"
		"}"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"if(((part_key & 0xFF) - 65u) <= 25u)"
			"part_key += 32u;"
		"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<8u;"
		"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<16u;"

		"uint char_added = (%uu+param)<<len;"
		"out_key[max_iter*%uu+out_index]=bs(part_key, char_added, 0xffffu<<len);"

		"if(len==(3u<<3u))"
			"out_key[(max_iter+1)*%uu+out_index]=0x80;"
			, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, MIN_CHAR_ADDED + 0x8000, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_capitalize_plus_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(26u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(1u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(i==0){"
				"if(((part_key & 0xFF) - 97u) <= 25u)"
					"part_key -= 32u;"
			"}else{"
				"if(((part_key & 0xFF) - 65u) <= 25u)"
					"part_key += 32u;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"out_key[i*%uu+out_index]=part_key;"
		"}"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"if(max_iter==0){"
			"if(((part_key & 0xFF) - 97u) <= 25u)"
				"part_key -= 32u;"
		"}else{"
			"if(((part_key & 0xFF) - 65u) <= 25u)"
				"part_key += 32u;"
		"}"
		"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<8u;"
		"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<16u;"

		"uint char_added = (%uu+param)<<len;"
		"out_key[max_iter*%uu+out_index]=bs(part_key, char_added, 0xffffu<<len);"

		"if(len==(3u<<3u))"
			"out_key[(max_iter+1)*%uu+out_index]=0x80;"
			, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, MIN_CHAR_ADDED + 0x8000, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_prefix_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(26u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(1u<<4u);"
		"uint max_iter=(len>>6u)+1u;"

		"uint char_added = (%uu+param);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"
			"out_key[i*%uu+out_index]=char_added + (part_key << 8u);"
			"char_added = part_key>>24u;"
		"}"

		"if(((len>>4u)&3u)==3u)"
			"out_key[max_iter*%uu+out_index]=0x80;"
			, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, MIN_CHAR_ADDED, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// Less common
PRIVATE void rule_overstrike_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	uint32_t change_pos = rules_data_buffer[CHANGE_POS_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = (lenght + 2) / 2 * NUM_KEYS;

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
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

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

				_tmp += (char_added << shift);

				for (j = i + nt_buffer_index; j < MAX; j++, _tmp += (1 << shift))
					nt_buffer[j] = _tmp;
				char_added += num_to_copy;
			}
			else// Copy
			{
				for(j = i+nt_buffer_index; j < MAX; j++)
					nt_buffer[j] = _tmp;
			}
		}

		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void rule_overstrike_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	uint32_t change_pos = rules_data_buffer[CHANGE_POS_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added + 1, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = (lenght / 4 + 1) * NUM_KEYS;

		if (lenght > 27)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			change_pos = 0;
			continue;
		}

		// Copy and over-strike
		for (i = 0; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i == change_pos / 4 * NUM_KEYS)// over-strike
			{
				uint32_t shift = 8 * (change_pos & 3);
				_tmp = (_tmp & ~(0xff << shift)) + (char_added << shift);

				for (j = i + nt_buffer_index; j < MAX; j++, _tmp += (1u << shift))
					nt_buffer[j] = _tmp;
				char_added += num_to_copy;
			}
			else// Copy
			{
				for (j = i + nt_buffer_index; j < MAX; j++)
					nt_buffer[j] = _tmp;
			}
		}

		// Fill with 0
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		// Change
		if (char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			change_pos++;

			if (change_pos >= lenght)
			{
				change_pos = 0;
				rules_nt_buffer_index++;
			}
		}

		// Copy length
		lenght <<= 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[CHANGE_POS_INDEX] = change_pos;
	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
PRIVATE void rule_remove_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t change_pos = rules_data_buffer[CHANGE_POS_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		uint32_t last_tmp;

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
		for(; i < (lenght+2)/2*NUM_KEYS; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			nt_buffer[i-NUM_KEYS+nt_buffer_index] = (_tmp << 16) | (last_tmp >> 16);

			last_tmp = _tmp;
		}

		if (lenght & 1)
			nt_buffer[i - NUM_KEYS + nt_buffer_index] = 0x80;
		else
			i -= NUM_KEYS;
		// Fill with 0
		uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
		for(; i < old_len; i += NUM_KEYS)
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
PRIVATE void rule_remove_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t change_pos = rules_data_buffer[CHANGE_POS_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t last_tmp;

		if (lenght == 0)
		{
			change_pos = 0;
			rules_nt_buffer_index++;
			continue;
		}

		// Copy
		for (i = 0; i < change_pos / 4 * NUM_KEYS; i += NUM_KEYS)
			nt_buffer[i + nt_buffer_index] = rules_nt_buffer[i + rules_nt_buffer_index];

		// Copy
		last_tmp = rules_nt_buffer[i + rules_nt_buffer_index];
		switch (change_pos & 3)
		{
		case 0:
			last_tmp >>= 8;
			break;
		case 1:
			last_tmp = (last_tmp & 0xff) + ((last_tmp >> 8) & 0xffff00);
			break;
		case 2:
			last_tmp = (last_tmp & 0xffff) + ((last_tmp >> 8) & 0xff0000);
			break;
		case 3:
			last_tmp &= 0xffffff;
			break;
		}
		i += NUM_KEYS;
		// Remove
		for (; i < (lenght / 4+1) * NUM_KEYS; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			nt_buffer[i - NUM_KEYS + nt_buffer_index] = (_tmp << 24) + last_tmp;

			last_tmp = _tmp >> 8;
		}
		i -= NUM_KEYS;
		if (lenght & 3)
		{
			nt_buffer[i + nt_buffer_index] = last_tmp;
			i += NUM_KEYS;
		}
		
		// Fill with 0
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
			nt_buffer[i + nt_buffer_index] = 0;

		// Copy length
		nt_buffer[7 * NUM_KEYS + nt_buffer_index] = (lenght - 1) << 3;

		change_pos++;
		// Change
		if (change_pos >= lenght)
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
PRIVATE cl_uint oclru_overstrike_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_array(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, 0);
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i = 0;return;{");
		return 1;
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

		"for(uint i=0;i<%uu;i++,nt_buffer[param/2]+=to_sum){", MIN_CHAR_ADDED << 16, MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);

	return 1;
}
PRIVATE cl_uint oclru_remove_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_array(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, 0);
	// Check lenght
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint change_index=0;return;{");
		return 1;
	}

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght - 1) << 4);

	// Convert the key into a nt_buffer
	sprintf(source + strlen(source), "uint char_removed = nt_buffer[0] & 0x0000ffff;");

	// Remove first character
	for (cl_uint i = 0; i < (lenght - 1) / 2; i++)
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
	sprintf(source + strlen(source), "for(uint change_index=0;change_index<%uu;change_index++){", lenght);

	// End cycle
	sprintf(source + strlen(source), "if(change_index){"
										"uint index=change_index-1u;"
										"uint last_tmp=nt_buffer[index/2];"

										"if(index&1){"
											"nt_buffer[index/2]=(last_tmp&0x0000ffff)|char_removed;"
											"char_removed=last_tmp>>16;"
										"}else{"
											"nt_buffer[index/2]=(last_tmp&0xffff0000)|char_removed;"
											"char_removed=last_tmp<<16;"
										"}"
									"}");

	return 1;
}
// UTF8
PRIVATE cl_uint oclru_remove_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_array_utf8(source, nt_buffer, lenght, NUM_KEYS_OPENCL, 0);
	// Check lenght
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint change_index=0;return;{");
		return 1;
	}

	// Put lenght
	sprintf(nt_buffer[7], "+%uu", (lenght - 1) << 3);

	// Convert the key into a nt_buffer
	sprintf(source + strlen(source), "uint char_removed=nt_buffer[0]&0xff;");

	// Remove first character
	for (cl_uint i = 0; i < ((lenght + 3) / 4 - 1); i++)
		sprintf(source + strlen(source), "nt_buffer[%u]=(nt_buffer[%u]>>8u)+(nt_buffer[%u]<<24u);", i, i, i + 1);

	// Remove character
	switch (lenght & 3)
	{
	case 0:
		strcpy(nt_buffer[lenght / 4], "");
		sprintf(source + strlen(source), "nt_buffer[%u]=0x80000000+(nt_buffer[%u]>>8u);", lenght / 4 - 1, lenght / 4 - 1);
		break;
	case 1:
		strcpy(nt_buffer[lenght / 4], "+0x80");
		break;
	case 2: case 3:
		sprintf(source + strlen(source), "nt_buffer[%u]>>=8u;", lenght / 4);
		break;
	}
	
	// Lenght and begin cycle
	sprintf(source + strlen(source), "for(uint change_index=0;change_index<%uu;change_index++){", lenght);

	// End cycle
	sprintf(source + strlen(source), "if(change_index){"
										"uint remove_index=(change_index-1)/4;"
										"uint last_tmp=nt_buffer[remove_index];"
										"uint mask=0xff<<(8u*((change_index-1)&3u));"

										"nt_buffer[remove_index]=(last_tmp&(~mask))+char_removed;"
										"char_removed=last_tmp&mask;"
										"char_removed=(change_index&3u)?(char_removed<<8u):(char_removed>>24u);"
								"}");

	return 1;
}
PRIVATE cl_uint oclru_overstrike_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_array_utf8(source, nt_buffer, lenght, NUM_KEYS_OPENCL, 0);
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"uint pos3=8u*(param&3u);"
		"uint to_sum=1u<<pos3;"

		"nt_buffer[param/4]=(%uu<<pos3)+(nt_buffer[param/4] & ~(0xff<<pos3));"

		"for(uint i=0;i<%uu;i++,nt_buffer[param/4]+=to_sum){", MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);

	return 1;
}
// Get
PRIVATE void ocl_overstrike_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	out_key[param >> 8] = (unsigned char)(MIN_CHAR_ADDED + (param & 0xff));
}
PRIVATE void ocl_remove_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
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
#define OCL_OVERSTRIKE_PARAM	"((param<<8)+i)"
// Common
PRIVATE void oclru_overstrike_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	DivisionParams div_param = get_div_params(LENGHT_CHAR_ADDED);
	oclru_common_kernel_definition(source, rule_name, TRUE);

	// Perform division
	if (div_param.magic)sprintf(source + strlen(source), "uint pos=mul_hi(param+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint pos=param>>%iU;", (int)div_param.shift);// Power of two division

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx]>>4;"
		"if(pos >= len)return;"

		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len<<4u;"
		"uint max_iter=(len>>2u)+1u;"

		"for(uint i=0;i<(pos/4);i++)"
			"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"

		"uint part_key=in_key[(pos/4)*%uu+idx];"
		"uint char_change=(%uu+param-pos*%uu)<<(8u*(pos&3u));"
		
		"out_key[(pos/4)*%uu+out_index]=bs(part_key, char_change, 0xffu<<(8u*(pos&3u)));"

		"for(uint i=pos/4+1;i<max_iter;i++)"
			"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"

			, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, MIN_CHAR_ADDED, LENGHT_CHAR_ADDED, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_remove_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx]>>4u;"
		"if(param >= len)return;"

		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=(len-1u)<<4u;"
		"uint max_iter=(len>>2u)+1u;"

		"for(uint i=0;i<(param/4);i++)"
			"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"

		"uint part_key=in_key[(param/4)*%uu+idx];"
		"if(param&3u){"
			"uint pos3 = 8u*(param&3u);"
			"part_key = (part_key & (0xffffffff>>(32u-pos3))) + ((part_key>>8u) & (0xffffffff<<pos3));"
		"}else{"
			"part_key >>= 8u;"
		"}"

		"for(uint i=param/4+1;i<max_iter;i++)"
		"{"
			"uint in_part=in_key[i*%uu+idx];"
			"out_key[(i-1)*%uu+out_index]=part_key+(in_part<<24u);"
			"part_key=in_part>>8u;"
		"}"
		"if((len&3u)>=1u)"
			"out_key[(max_iter-1)*%uu+out_index]=part_key;"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

PRIVATE void rule_insert_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	uint32_t insert_pos = rules_data_buffer[INSERT_POS_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added+1, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = (lenght+3)/2*NUM_KEYS;
		uint32_t last_tmp;

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

		if (insert_pos & 1)
		{
			uint32_t _tmp = (last_tmp & 0x0000FFFF) | (char_added << 16);
			for (j = i + nt_buffer_index; j < MAX; j++, _tmp += (1 << 16))
				nt_buffer[j] = _tmp;
		}
		else
		{
			uint32_t _tmp = (last_tmp << 16) | char_added;
			for (j = i + nt_buffer_index; j < MAX; j++, _tmp++)
				nt_buffer[j] = _tmp;
		}
		char_added += num_to_copy;

		i += NUM_KEYS;
		MAX += NUM_KEYS;

		// Copy
		for(; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			last_tmp = (_tmp << 16) | (last_tmp >> 16);
			for(j = i+nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}

		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void rule_insert_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added = rules_data_buffer[CHAR_ADDED_INDEX];
	uint32_t insert_pos = rules_data_buffer[INSERT_POS_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added + 1, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = ((lenght + 1) / 4 + 1) * NUM_KEYS;
		uint32_t last_tmp;

		if (lenght >= 27 || lenght < 2)
		{
			rules_nt_buffer_index++;
			char_added = MIN_CHAR_ADDED;
			insert_pos = 1;
			continue;
		}

		// Copy
		for (i = 0; i < insert_pos / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = rules_nt_buffer[i + rules_nt_buffer_index];

		// Insert
		last_tmp = rules_nt_buffer[i + rules_nt_buffer_index];
		uint32_t _tmp;
		switch (insert_pos&3)
		{
		case 0:
			_tmp = (last_tmp << 8) + char_added;
			break;
		case 1:
			_tmp = (last_tmp & 0xFF) + ((last_tmp << 8) & 0xffff0000) + (char_added << 8);
			break;
		case 2:
			_tmp = (last_tmp & 0xFFFF) + ((last_tmp << 8) & 0xff000000) + (char_added << 16);
			break;
		case 3:
			_tmp = (last_tmp & 0xFFFFFF) + (char_added << 24);
			break;
		}
		for (j = i + nt_buffer_index; j < MAX; j++, _tmp += (1 << (8 * insert_pos)))
			nt_buffer[j] = _tmp;
		char_added += num_to_copy;

		i += NUM_KEYS;
		MAX += NUM_KEYS;

		// Copy
		for (; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			last_tmp = (_tmp << 8) + (last_tmp >> 24);
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}

		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		if (char_added > MAX_CHAR_ADDED)
		{
			char_added = MIN_CHAR_ADDED;
			insert_pos++;
			if (insert_pos >= lenght)
			{
				insert_pos = 1;
				rules_nt_buffer_index++;
			}
		}

		lenght = (lenght + 1) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[INSERT_POS_INDEX] = insert_pos;
	rules_data_buffer[CHAR_ADDED_INDEX] = char_added;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE cl_uint oclru_insert_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_array(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, 1);

	// Check lenght
	if (lenght >= 27 || lenght < 2)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 1) << 4);
	// Insert character
	if (lenght & 1)
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer[%u]", lenght / 2);
		sprintf(source + strlen(source), "nt_buffer[%u]=0x800000+(nt_buffer[%u]>>16);", lenght / 2, lenght / 2 - 1);
	}

	// Begin cycle of insert
	sprintf(source + strlen(source),
		"uint insert_index=(param+1)/2;"
		"uint tmp=nt_buffer[insert_index];"
		"uint to_sum;"

		"if(param&1){"
			"nt_buffer[insert_index]=%uu+(tmp<<16);"
			"to_sum=1;"
		"}else{"
			"nt_buffer[insert_index]=%uu+(tmp&0xffff);"
			"to_sum=1<<16;"
		"}"
		// Copy the remaining
		"tmp=tmp>>16;"
		"for(uint i=insert_index+1;i<%uu;i++)"
		"{"
			"uint swap_tmp=tmp+(nt_buffer[i]<<16);"
			"tmp=nt_buffer[i]>>16u;"
			"nt_buffer[i]=swap_tmp;"
		"}"

		"for(uint i=0;i<%uu;i++,nt_buffer[insert_index]+=to_sum){", MIN_CHAR_ADDED, MIN_CHAR_ADDED << 16, (lenght+1) / 2, LENGHT_CHAR_ADDED);

	return 1;
}
// UTF8	cl_uint
PRIVATE cl_uint oclru_insert_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_array_utf8(source, nt_buffer, lenght, NUM_KEYS_OPENCL, 1);

	// Check lenght
	if (lenght >= 27 || lenght < 2)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	// Put lenght
	sprintf(nt_buffer[7], "+%uu", (lenght + 1) << 3);

	// Begin cycle of insert
	sprintf(source + strlen(source),
		"uint pos3=param+1;"
		"uint insert_index=pos3/4;"
		"uint tmp=nt_buffer[insert_index];"
		"pos3=8u*(pos3&3u);"

		"uint to_sum=1u<<pos3;"
		"uint char_change=%uu<<pos3;"
		
		"if(pos3){"
			"char_change+=(tmp&(0xffffffff>>(32u-pos3)))+((tmp<<8u)&(0xffffff00<<pos3));"
		"}else{"
			"char_change+=tmp<<8u;"
		"}"

		"nt_buffer[insert_index]=char_change;"
		"char_change=tmp>>24u;"

		"for(uint i=insert_index+1;i<%uu;i++)"
		"{"
			"tmp=nt_buffer[i];"
			"nt_buffer[i]=char_change+(tmp<<8u);"
			"char_change=tmp>>24u;"
		"}"
		, MIN_CHAR_ADDED, (lenght + 3) / 4);

	if (!(lenght & 3))
	{
		strcat(source, "char_change+=0x8000;");
		strcpy(nt_buffer[lenght / 4], "+char_change");
	}

	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i++,nt_buffer[insert_index]+=to_sum){", LENGHT_CHAR_ADDED);

	if ((lenght&3) == 3)
		strcpy(nt_buffer[lenght/4+1], "+0x80");

	return 1;
}
PRIVATE void ocl_insert_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	uint32_t insert_index = param >> 8;
	strcpy(out_key, plain);
	memmove(out_key + insert_index + 1, out_key + insert_index, strlen(out_key) - insert_index + 1);
	out_key[insert_index] = (unsigned char)(MIN_CHAR_ADDED + (param & 0xff));
}
#define OCL_INSERT_PARAM	"(((param+1)<<8)+i)"
// Common
PRIVATE void oclru_insert_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	DivisionParams div_param = get_div_params(LENGHT_CHAR_ADDED);
	oclru_common_kernel_definition(source, rule_name, TRUE);

	// Perform division
	if (div_param.magic)sprintf(source + strlen(source), "uint pos=mul_hi(param+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint pos=param>>%iU;", (int)div_param.shift);// Power of two division

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx]>>4;"
		"pos++;"
		"if(len<2||pos>=len)return;"

		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=(len+1u)<<4u;"
		"uint max_iter=(len>>2u)+1u;"

		"for(uint i=0;i<(pos/4);i++)"
			"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"

		"uint pos3 = 8u*(pos&3u);"
		"uint part_key=in_key[(pos/4)*%uu+idx];"
		"uint char_change=(%uu+param-(pos-1)*%uu)<<pos3;"
		
		"if(pos3){"
			"char_change+= (part_key & (0xffffffff>>(32u-pos3))) + ((part_key<<8u) & (0xffffff00<<pos3));"
		"}else{"
			"char_change+=part_key<<8u;"
		"}"

		"out_key[(pos/4)*%uu+out_index]=char_change;"
		"char_change = part_key>>24u;"

		"for(uint i=pos/4+1;i<max_iter;i++)"
		"{"
			"part_key = in_key[i*%uu + idx]; "
			"out_key[i*%uu+out_index]=char_change + (part_key<<8u);"
			"char_change = part_key>>24u;"
		"}"
		"if((len&3u)==3u)"
			"out_key[max_iter*%uu+out_index]=0x80;"
			, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, MIN_CHAR_ADDED, LENGHT_CHAR_ADDED, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// Append 2 digits
PRIVATE void ru_lower_plus_2dig_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[14 * NUM_KEYS + rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((uint32_t)(('9' - digit1) * 10 + '9' - digit2 + 1), __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 26)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 2 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if (lenght & 1)
		{
			// Lowercase
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if ((_tmp - 65u) <= 25u)
				_tmp += 32;

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp | (digit1 << 16);
				nt_buffer[j + NUM_KEYS] = digit2 | 0x800000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}

			i += NUM_KEYS;
			MAX += NUM_KEYS;
		}
		else
		{
			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = digit1 | (digit2 << 16);
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}

			i += NUM_KEYS;
			MAX += NUM_KEYS;
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i += NUM_KEYS;
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

		lenght = (lenght + 2) << 4;
		for (j = 14 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (digit1 > '9')
		{
			digit1 = '0';
			digit2 = '0';
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
PRIVATE void ru_lo_plus_2dig_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min((uint32_t)(('9' - digit1) * 10 + '9' - digit2 + 1), __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 26)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = digit1 + (digit2 << 8) + 0x800000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if ((_tmp - 65u) <= 25u)
				_tmp += 32;

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp + (digit1 << 8) + (digit2 << 16) + 0x80000000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if (((_tmp >> 8u) - 65u) <= 25u)
				_tmp += 32 << 8;

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp + (digit1 << 16) + (digit2 << 24);
				nt_buffer[j + NUM_KEYS] = 0x80;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if (((_tmp >> 16) - 65u) <= 25u)
				_tmp += 32 << 16;

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp + (digit1 << 24);
				nt_buffer[j + NUM_KEYS] = digit2 + 0x8000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		}

		i += NUM_KEYS;
		MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 2) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (digit1 > '9')
		{
			digit1 = '0';
			digit2 = '0';
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
PRIVATE void rule_cap_plus_2dig_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min((uint32_t)(('9'-digit1)*10+'9'-digit2+1), __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

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
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if(i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}else{// First position -> to-upper
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}

			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else{// First position -> to-upper
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}

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
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void r_cap_plus_2dig_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	unsigned char digit1 = rules_data_buffer[DIGIT1_INDEX];
	unsigned char digit2 = rules_data_buffer[DIGIT2_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min((uint32_t)(('9' - digit1) * 10 + '9' - digit2 + 1), __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 26)
		{
			rules_nt_buffer_index++;
			digit1 = '0';
			digit2 = '0';
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}else{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = digit1 + (digit2 << 8) + 0x800000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if (i)
			{
				if ((_tmp - 65u) <= 25u)
					_tmp += 32;
			}else{
				if ((_tmp - 97u) <= 25u)
					_tmp -= 32;
			}

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp + (digit1 << 8) + (digit2 << 16) + 0x80000000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}else{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if (((_tmp >> 8u) - 65u) <= 25u)
				_tmp += 32 << 8;

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp + (digit1 << 16) + (digit2 << 24);
				nt_buffer[j + NUM_KEYS] = 0x80;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}else{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if (((_tmp >> 16) - 65u) <= 25u)
				_tmp += 32 << 16;

			for (j = i + nt_buffer_index; j < MAX; j++, digit2++)
			{
				nt_buffer[j] = _tmp + (digit1 << 24);
				nt_buffer[j + NUM_KEYS] = digit2 + 0x8000;
				if (digit2 >= '9')
				{
					digit2 = '0' - 1;
					digit1++;
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		}

		i += NUM_KEYS;
		MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 2) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (digit1 > '9')
		{
			digit1 = '0';
			digit2 = '0';
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[DIGIT1_INDEX] = digit1;
	rules_data_buffer[DIGIT2_INDEX] = digit2;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE cl_uint oclru_plus_2dig_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	nt_buffer_vector_size[(lenght + 1) / 2] = prefered_vector_size;
	sprintf(nt_buffer[(lenght + 1) / 2], "+digits");
	sprintf(source + strlen(source), "uint%s digits;", prefered_vector_size == 1 ? "" : "2");

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Begin cycle
	sprintf(source + strlen(source),
		"for(uint i=0;i<100u;i+=%uu)"
		"{"
			// Divide by 10
			"uint dec=mul_hi(i,429496730u);", prefered_vector_size);

	// Last characters
	if (lenght & 1)
		sprintf(source + strlen(source),
			"nt_buffer%u=(nt_buffer%u&0x0000ffff)+0x300000+(dec<<16u);"
			"digits=0x800030+i-dec*10u;", lenght / 2, lenght / 2);
	else
	{
		sprintf(source + strlen(source), "digits=0x300030+(i<<16)-dec*0x9ffff;");
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	}
	if (prefered_vector_size > 1)
		sprintf(source + strlen(source), "digits.s1+=%uu;", 1 << (16 * ((lenght + 1) & 1)));

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_lower_plus_2dig_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_2dig_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
}
PRIVATE cl_uint oclru_cap_plus_2digits_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_2dig_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
}
// UTF8
PRIVATE cl_uint oclru_plus_2dig_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint prefered_vector_size)
{
	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	// Put lenght
	sprintf(nt_buffer[7], "+%uu", (lenght + 2) << 3);

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Begin cycle
	sprintf(source + strlen(source),
		"for(uint i=0;i<100u;i+=%uu)"
		"{"
			// Divide by 10
			"uint dec=mul_hi(i,429496730u);", prefered_vector_size);

	switch (lenght & 3)
	{
		case 3:
		sprintf(source + strlen(source), "buffer%u=(buffer%u&0xffffff)+(dec<<24)+0x30000000;", lenght / 4, lenght / 4);
		sprintf(source + strlen(source), "uint%s digits=i-dec*10u+0x8030;", prefered_vector_size == 1 ? "" : "2");
		break;
		case 2:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
		sprintf(source + strlen(source), "uint%s digits=(buffer%u&0xffff)+(i<<24)-dec*0x9FF0000+0x30300000;", prefered_vector_size == 1 ? "" : "2", lenght / 4);
		break;
	case 1: 
		sprintf(source + strlen(source), "uint%s digits=(buffer%u&0xff)+(i<<16)-dec*0x9FF00+0x80303000;", prefered_vector_size == 1 ? "" : "2", lenght / 4);
		break;
	case 0:
		sprintf(source + strlen(source), "uint%s digits=(i<<8)-dec*0x9FF+0x803030;", prefered_vector_size == 1 ? "" : "2");
		break;
	}

	strcpy(nt_buffer[(lenght + 1) / 4], "+digits");
	nt_buffer_vector_size[(lenght + 1) / 4] = prefered_vector_size;
	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "digits.s1+=%uu;", 1 << (8 * ((lenght+1) & 3)));

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_lower_plus_2dig_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_2dig_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, prefered_vector_size);
}
PRIVATE cl_uint oclru_cap_plus_2dig_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_2dig_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, prefered_vector_size);
}
// Get plaintext
PRIVATE void ocl_lower_plus_2dig_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	out_key[strlen(out_key)+2] = 0;
	out_key[strlen(out_key)+1] = (unsigned char)('0' + param%10);
	out_key[strlen(out_key)] = (unsigned char)('0' + (param/10)%10);
}
PRIVATE void ocl_cap_plus_2digits_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
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
// Common
PRIVATE void oclru_lower_plus_2dig_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(25u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(2u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(((part_key & 0xFF) - 65u) <= 25u)"
				"part_key += 32u;"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"out_key[i*%uu+out_index]=part_key;"
		"}"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"if(((part_key & 0xFF) - 65u) <= 25u)"
			"part_key += 32u;"
		"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<8u;"
		"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<16u;"

		// Divide by 10
		"uint dec=mul_hi(param,429496730u);"
		"uint un=mul_hi(dec,429496730u);"

		"uint digits_added = (param<<8u)-dec*0x9FF-un*0xA+0x803030;"

		"out_key[max_iter*%uu+out_index]=bs(part_key, digits_added<<len, 0xffffffffu<<len);"

		"if(len >= (2u<<3u))"
			"out_key[(max_iter+1)*%uu+out_index]=digits_added>>(32u-len);"

		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_cap_plus_2dig_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(25u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(2u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(i==0){"
				"if(((part_key & 0xFF) - 97u) <= 25u)"
					"part_key -= 32u;"
			"}else{"
				"if(((part_key & 0xFF) - 65u) <= 25u)"
					"part_key += 32u;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"out_key[i*%uu+out_index]=part_key;"
		"}"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"if(max_iter==0){"
			"if(((part_key & 0xFF) - 97u) <= 25u)"
				"part_key -= 32u;"
		"}else{"
			"if(((part_key & 0xFF) - 65u) <= 25u)"
				"part_key += 32u;"
		"}"
		"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<8u;"
		"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<16u;"

		// Divide by 10
		"uint dec=mul_hi(param,429496730u);"
		"uint un=mul_hi(dec,429496730u);"

		"uint digits_added = (param<<8u)-dec*0x9FF-un*0xA+0x803030;"

		"out_key[max_iter*%uu+out_index]=bs(part_key, digits_added<<len, 0xffffffffu<<len);"

		"if(len >= (2u<<3u))"
			"out_key[(max_iter+1)*%uu+out_index]=digits_added>>(32u-len);"

		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// Append a year between 1900-2029
PRIVATE void ru_lower_plus_year_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t year = rules_data_buffer[YEAR_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(130-year, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 24)
		{
			rules_nt_buffer_index++;
			year = 0;
			continue;
		}

		// Lowercase
		for(i = 0; i < lenght/2*NUM_KEYS; i+=NUM_KEYS,MAX+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if(lenght & 1)
		{
			// Lowercase
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index] & 0xFF;
			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp | ((year < 100) ? ('1' << 16) : ('2' << 16));
				nt_buffer[j + NUM_KEYS] = ((year < 100) ? '9' : '0') | ((year / 10 % 10 + '0') << 16);
				nt_buffer[j + 2 * NUM_KEYS] = (year % 10 + '0') | 0x800000;
			}

			i+=2*NUM_KEYS;
			MAX+=2*NUM_KEYS;
		}
		else
		{
			for(j = i + nt_buffer_index; j < MAX; j++,year++)
			{
				nt_buffer[j] = ((year < 100) ? 0x390031 : 0x300032);
				nt_buffer[j + NUM_KEYS] = (year / 10 % 10 + '0') | ((year % 10 + '0') << 16);
			}

			i+=2*NUM_KEYS;
			MAX+=2*NUM_KEYS;
			for(j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i+=NUM_KEYS;
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

		lenght = (lenght+4) << 4;
		for(j = 14*NUM_KEYS+nt_buffer_index; j < MAX; j++)
			nt_buffer[j] =  lenght;

		if (year>=130)
		{
			year = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index+=num_to_copy;
	}

	rules_data_buffer[YEAR_INDEX] = year;
}
PRIVATE void r_low_plus_year_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t year = rules_data_buffer[YEAR_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(130-year, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 24)
		{
			rules_nt_buffer_index++;
			year = 0;
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		// Last
		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = ((year < 100) ? 0x3931 : 0x3032) + ((year / 10 % 10 + '0') << 16) + (((year % 10) + '0') << 24);
				nt_buffer[j + NUM_KEYS] =  0x80;
			}
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if ((_tmp - 65u) <= 25u)
				_tmp += 32;

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp + ((year < 100) ? 0x393100 : 0x303200) + ((year / 10 % 10 + '0') << 24);
				nt_buffer[j + NUM_KEYS] = (year % 10) + '0' + 0x8000;
			}
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if (((_tmp >> 8u) - 65u) <= 25u)
				_tmp += 32 << 8;

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp + ((year < 100) ? 0x39310000 : 0x30320000);
				nt_buffer[j + NUM_KEYS] = (year / 10 % 10 + '0') + (((year % 10) + '0') << 8) + 0x800000;
			}
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if (((_tmp >> 16) - 65u) <= 25u)
				_tmp += 32 << 16;

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp + (((year < 100) ? '1' : '2') << 24);
				nt_buffer[j + NUM_KEYS] = ((year < 100) ? '9' : '0') + ((year / 10 % 10 + '0') << 8) + (((year % 10) + '0') << 16) + 0x80000000;
			}
			break;
		}

		i += 2*NUM_KEYS;
		MAX += 2 * NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 4) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (year >= 130)
		{
			year = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[YEAR_INDEX] = year;
}
PRIVATE void rule_cap_plus_year_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t year = rules_data_buffer[YEAR_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[14 * NUM_KEYS + rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(130 - year, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 24)
		{
			rules_nt_buffer_index++;
			year = 0;
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 2 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		if (lenght & 1)
		{
			// Lowercase
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if (i)
			{
				if ((_tmp - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if ((_tmp- 97u) <= 25u)
					_tmp -= 32;
			}

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp | ((year < 100) ? ('1' << 16) : ('2' << 16));
				nt_buffer[j + NUM_KEYS] = ((year < 100) ? '9' : '0') | ((year / 10 % 10 + '0') << 16);
				nt_buffer[j + 2 * NUM_KEYS] = (year % 10 + '0') | 0x800000;
			}

			i += 2 * NUM_KEYS;
			MAX += 2 * NUM_KEYS;
		}
		else
		{
			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = ((year < 100) ? 0x390031 : 0x300032);
				nt_buffer[j + NUM_KEYS] = (year / 10 % 10 + '0') | ((year % 10 + '0') << 16);
			}

			i += 2 * NUM_KEYS;
			MAX += 2 * NUM_KEYS;
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0x80;
		}

		i += NUM_KEYS;
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

		lenght = (lenght + 4) << 4;
		for (j = 14 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (year >= 130)
		{
			year = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[YEAR_INDEX] = year;
}
PRIVATE void r_cap_plus_year_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t year = rules_data_buffer[YEAR_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(130 - year, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 24)
		{
			rules_nt_buffer_index++;
			year = 0;
			continue;
		}

		// Lowercase
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		// Last
		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = ((year < 100) ? 0x3931 : 0x3032) + ((year / 10 % 10 + '0') << 16) + (((year % 10) + '0') << 24);
				nt_buffer[j + NUM_KEYS] = 0x80;
			}
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			if (i)
			{
				if ((_tmp - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if ((_tmp - 97u) <= 25u)
					_tmp -= 32;
			}

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp + ((year < 100) ? 0x393100 : 0x303200) + ((year / 10 % 10 + '0') << 24);
				nt_buffer[j + NUM_KEYS] = (year % 10) + '0' + 0x8000;
			}
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if (((_tmp >> 8u)  - 65u) <= 25u)
				_tmp += 32 << 8;

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp + ((year < 100) ? 0x39310000 : 0x30320000);
				nt_buffer[j + NUM_KEYS] = (year / 10 % 10 + '0') + (((year % 10) + '0') << 8) + 0x800000;
			}
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if (((_tmp >> 16) - 65u) <= 25u)
				_tmp += 32 << 16;

			for (j = i + nt_buffer_index; j < MAX; j++, year++)
			{
				nt_buffer[j] = _tmp + (((year < 100) ? '1' : '2') << 24);
				nt_buffer[j + NUM_KEYS] = ((year < 100) ? '9' : '0') + ((year / 10 % 10 + '0') << 8) + (((year % 10) + '0') << 16) + 0x80000000;
			}
			break;
		}

		i += 2 * NUM_KEYS;
		MAX += 2 * NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 4) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (year >= 130)
		{
			year = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[YEAR_INDEX] = year;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE cl_uint oclru_plus_year_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 4) << 4);
	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"for(uint i=0;i<130u;i+=%uu)"
		"{"
			// Divide by 10
			"uint dec=mul_hi(i,429496730u);"
			"uint un=mul_hi(dec,429496730u);", prefered_vector_size);

	// Last characters
	sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);
	sprintf(nt_buffer[lenght / 2 + 1], "+nt_buffer%u", lenght / 2 + 1);
	if (lenght & 1)
		sprintf(source + strlen(source),
			"nt_buffer%u=(nt_buffer%u&0xffff)|((i>=100u)?3276800u:3211264u);"
			"uint nt_buffer%u=(dec<<16)-un*0xA0000+((i>=100u)?0x300030:0x300039);"
			"uint%s year=0x800030+i-dec*10u;", lenght / 2, lenght / 2, lenght / 2 + 1, prefered_vector_size==1?"":"2");
	else{
		sprintf(source + strlen(source),
			"uint nt_buffer%u=(i>=100u)?3145778u:3735601u;"
			"uint%s year=0x300030+(i<<16)-dec*0x9FFFF-un*10u;", lenght / 2, prefered_vector_size==1?"":"2");
		sprintf(nt_buffer[lenght / 2 + 2], "+0x80");
	}

	strcpy(nt_buffer[(lenght + 1) / 2 + 1], "+year");
	nt_buffer_vector_size[(lenght + 1) / 2 + 1] = prefered_vector_size;
	if (prefered_vector_size > 1)
		sprintf(source + strlen(source), "year.s1+=%uu;", 1 << (16 * ((lenght+1) & 1)));

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_lower_plus_year_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_year_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
}
PRIVATE cl_uint oclru_cap_plus_year_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_year_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
}
// UTF8
PRIVATE cl_uint oclru_plus_year_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint prefered_vector_size)
{
	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Put lenght
	sprintf(nt_buffer[7], "+%uu", (lenght + 4) << 3);
	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"for(uint i=0;i<130u;i+=%uu)"
		"{"
			// Divide by 10
			"uint dec=mul_hi(i,429496730u);"
			"uint un=mul_hi(dec,429496730u);", prefered_vector_size);

	// Last characters
	sprintf(nt_buffer[(lenght + 3) / 4], "+year");
	nt_buffer_vector_size[(lenght + 3) / 4] = prefered_vector_size;
	switch (lenght & 3)
	{
		case 0:
			sprintf(source + strlen(source),
				"uint%s year=(i<100u)?0x30303931:0x30303032;"
				"year+=(i<<24u)-dec*0x9FF0000-un*0xA0000;", prefered_vector_size == 1 ? "" : "2");
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
		break;

		case 1:
		sprintf(source + strlen(source), "buffer%u=(buffer%u&0xff)+((i<100u)?%uu:%uu);"
										 "buffer%u+=((dec-un*10u)<<24u);", lenght / 4, lenght / 4, 0x30393100u/*-0x8000u*/, 0x30303200u/*-0x8000u*/, lenght / 4);
		sprintf(source + strlen(source), "uint%s year=i-dec*10u+0x8030;", prefered_vector_size == 1 ? "" : "2");
		break;

		case 2:
		sprintf(source + strlen(source), "buffer%u=(buffer%u&0xffff)+((i<100u)?%uu:%uu);", lenght / 4, lenght / 4, 0x39310000u/*-0x800000u*/, 0x30320000u/*-0x800000u*/);
		sprintf(source + strlen(source), "uint%s year=(i<<8)-dec*0x9FF-un*10u+0x803030;", prefered_vector_size == 1 ? "" : "2");
		break;

		case 3:
		sprintf(source + strlen(source), "buffer%u=(buffer%u&0xffffff)+((i<100u)?%uu:%uu);", lenght / 4, lenght / 4, 0x31000000u/*-0x80000000u*/, 0x32000000u/*-0x80000000u*/);
		sprintf(source + strlen(source), "uint%s year=(i<<16)-dec*0x9FF00-un*0xA00+((i<100u)?0x80303039:0x80303030);", prefered_vector_size == 1 ? "" : "2");
		break;
	}

	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "year.s1+=%uu;", 1 << (8 * ((lenght + 3) & 3)));

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_lower_plus_year_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_year_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, prefered_vector_size);
}
PRIVATE cl_uint oclru_cap_plus_year_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_plus_year_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, prefered_vector_size);
}
// Get
PRIVATE void ocl_lower_plus_year_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
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
PRIVATE void ocl_cap_plus_year_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
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
// Common
PRIVATE void oclru_lower_plus_year_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(23u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(4u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(((part_key & 0xFF) - 65u) <= 25u)"
				"part_key += 32u;"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"out_key[i*%uu+out_index]=part_key;"
		"}"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"if(((part_key & 0xFF) - 65u) <= 25u)"
			"part_key += 32u;"
		"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<8u;"
		"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<16u;"

		// Divide by 10
		"uint dec=mul_hi(param,429496730u);"
		"uint un=mul_hi(dec,429496730u);"

		"uint year_added = (param < 100) ? 0x30303931 : 0x30303032;"
		"year_added+= (param<<24u) - dec*0x9FF0000-un*0xA0000;"

		"if(len)"
		"{"
			"out_key[max_iter*%uu+out_index]=bs(part_key, year_added<<len, 0xffffffffu<<len);"
			"out_key[(max_iter+1)*%uu+out_index]=(year_added>>(32u-len)) + (0x80<<len);"
		"}else{"
			"out_key[max_iter*%uu+out_index]=year_added;"
			"out_key[(max_iter+1)*%uu+out_index]=0x80;"
		"}"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_cap_plus_year_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(23u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(4u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"if(i==0){"
				"if(((part_key & 0xFF) - 97u) <= 25u)"
					"part_key -= 32u;"
			"}else{"
				"if(((part_key & 0xFF) - 65u) <= 25u)"
					"part_key += 32u;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"out_key[i*%uu+out_index]=part_key;"
		"}"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"if(max_iter==0){"
			"if(((part_key & 0xFF) - 97u) <= 25u)"
				"part_key -= 32u;"
		"}else{"
			"if(((part_key & 0xFF) - 65u) <= 25u)"
				"part_key += 32u;"
		"}"
		"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<8u;"
		"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
			"part_key += 32u<<16u;"

		// Divide by 10
		"uint dec=mul_hi(param,429496730u);"
		"uint un=mul_hi(dec,429496730u);"

		"uint year_added = (param < 100) ? 0x30303931 : 0x30303032;"
		"year_added+= (param<<24u) - dec*0x9FF0000-un*0xA0000;"

		"if(len)"
		"{"
			"out_key[max_iter*%uu+out_index]=bs(part_key, year_added<<len, 0xffffffffu<<len);"
			"out_key[(max_iter+1)*%uu+out_index]=(year_added>>(32u-len)) + (0x80<<len);"
		"}else{"
			"out_key[max_iter*%uu+out_index]=year_added;"
			"out_key[(max_iter+1)*%uu+out_index]=0x80;"
		"}"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// Prefix a year between 1900-2029
PRIVATE void rule_prefix_year_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t year = rules_data_buffer[YEAR_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(130-year, __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if(lenght >= 24)
		{
			rules_nt_buffer_index++;
			year = 0;
			continue;
		}

		// Prefix the year
		for(j = nt_buffer_index; j < MAX; j++, year++)
		{
			nt_buffer[j] = ((year < 100) ? 0x390031 : 0x300032);
			nt_buffer[j + NUM_KEYS] = (year / 10 % 10 + '0') | ((year % 10 + '0') << 16);
		}

		// Copy
		for (i = 0; i < (lenght / 2 + 1)*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j + 2 * NUM_KEYS] = rules_nt_buffer[i + rules_nt_buffer_index];

		i += 2 * NUM_KEYS;
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

		lenght = (lenght+4) << 4;
		for (j = 14 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if(year >= 130)
		{
			year = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[YEAR_INDEX] = year;
}
PRIVATE void rul_prefix_year_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t year = rules_data_buffer[YEAR_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(130 - year, __min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 24)
		{
			rules_nt_buffer_index++;
			year = 0;
			continue;
		}

		// Prefix the year
		for (j = nt_buffer_index; j < MAX; j++, year++)
			nt_buffer[j] = ((year < 100) ? 0x3931 : 0x3032) + ((year / 10 % 10 + '0') << 16) + ((year % 10 + '0') << 24);

		// Copy
		MAX += NUM_KEYS;
		for (i = 0; i < (lenght / 4 + 1)*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];
			for (j = i + nt_buffer_index + NUM_KEYS; j < MAX; j++)
				nt_buffer[j] = _tmp;
		}

		i += NUM_KEYS;
		//MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 4) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (year >= 130)
		{
			year = 0;
			rules_nt_buffer_index++;
		}

		nt_buffer_index += num_to_copy;
	}

	rules_data_buffer[YEAR_INDEX] = year;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE cl_uint oclru_prefix_year_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	uint32_t i;
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Put buffer
	strcpy(nt_buffer[0], "+century");
	strcpy(nt_buffer[1], "+digits");
	nt_buffer_vector_size[1] = prefered_vector_size;
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i+2], "+nt_buffer%u", i);

	if (lenght & 1)
		sprintf(nt_buffer[i + 2], "+nt_buffer%u", i);
	else
		strcpy(nt_buffer[i + 2], "+0x80");

	sprintf(nt_buffer[14], "+%uu", (lenght+4)<<4);

	// Lenght and begin cycle
	sprintf(source + strlen(source),
		"for(uint i=0;i<130u;i+=%uu)"
		"{"
			// "20" and "19" transformed to Unicode
			"uint century=(i>=100u)?3145778u:3735601u;"
			// Divide by 10
			"uint dec=mul_hi(i,429496730u);"
			"uint un=mul_hi(dec,429496730u);"
			"uint%s digits=0x300030+(i<<16)-dec*0x9FFFF-un*10u;", prefered_vector_size, prefered_vector_size == 1 ? "" : "2");

	if (prefered_vector_size > 1)
		sprintf(source + strlen(source), "digits.s1+=1u<<16u;");

	return prefered_vector_size;
}
// UTF8
PRIVATE cl_uint oclru_prefix_year_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 24)
	{
		sprintf(source + strlen(source), "uint i=0,year=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Put buffer
	for (int i = 6; i > 0; i--)
		strcpy(nt_buffer[i], nt_buffer[i-1]);
	strcpy(nt_buffer[0], "+year");
	nt_buffer_vector_size[0] = prefered_vector_size;
	sprintf(nt_buffer[7], "+%uu", (lenght+4)<<3);

	// Begin cycle
	sprintf(source + strlen(source),
		"for(uint i=0;i<130u;i+=%uu)"
		"{"
			// Divide by 10
			"uint dec=mul_hi(i,429496730u);"
			"uint un=mul_hi(dec,429496730u);"

			"uint%s year=(i<100u)?0x30303931:0x30303032;"
			"year+=(i<<24u)-dec*0x9FF0000-un*0xA0000;", prefered_vector_size, prefered_vector_size == 1 ? "" : "2");

	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "year.s1+=%uu;", 1<<24);

	return prefered_vector_size;
}
// Get
PRIVATE void ocl_prefix_year_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key+4, plain);
	// Prefix
	out_key[3] = '0' + param%10;
	out_key[2] = '0' + (param/10)%10;
	out_key[1] = param >= 100 ? '0' : '9';
	out_key[0] = param >= 100 ? '2' : '1';
}
// Common
PRIVATE void oclru_prefix_year_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(23u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(4u<<4u);"
		"uint max_iter=(len>>6u)+1u;"

		// Divide by 10
		"uint dec=mul_hi(param,429496730u);"
		"uint un=mul_hi(dec,429496730u);"

		"uint year_added = (param < 100) ? 0x30303931 : 0x30303032;"
		"year_added+= (param<<24u) - dec*0x9FF0000-un*0xA0000;"
		"out_key[out_index] = year_added;"

		"for(uint i=0;i<max_iter;i++)"
			"out_key[(i+1)*%uu+out_index]=in_key[i*%uu+idx];"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// Prefix two characters
PRIVATE void rule_prefix_2char_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+(MAX_CHAR_ADDED-MIN_CHAR_ADDED+1)*(MAX_CHAR_ADDED-char_added1), 
							  __min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

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
			nt_buffer[j] = char_added0 + (char_added1 << 16);
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
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void ru_prefix_2char_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added0 + 1 + (MAX_CHAR_ADDED - MIN_CHAR_ADDED + 1)*(MAX_CHAR_ADDED - char_added1),
			__min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 26)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			continue;
		}

		uint32_t last_tmp = rules_nt_buffer[rules_nt_buffer_index];
		// Prefix 2 char
		for (j = nt_buffer_index; j < MAX; j++, char_added0++)
		{
			nt_buffer[j] = char_added0 + (char_added1 << 8) + (last_tmp << 16);
			if (char_added0 >= MAX_CHAR_ADDED)
			{
				char_added0 = MIN_CHAR_ADDED - 1;
				char_added1++;
			}
		}

		// Copy
		MAX += NUM_KEYS;
		for (i = NUM_KEYS; i < (lenght / 4 + 1)*NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];
			last_tmp = (last_tmp >> 16) + (_tmp << 16);

			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}
		if ((lenght & 3) >= 2)
		{
			last_tmp >>= 16;
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp;
			i += NUM_KEYS;
			MAX += NUM_KEYS;
		}

		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 2) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added1 > MAX_CHAR_ADDED)
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
PRIVATE void rule_append_2char_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+(MAX_CHAR_ADDED-MIN_CHAR_ADDED+1)*(MAX_CHAR_ADDED-char_added1),
			__min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

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
		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void rule_plus_2char_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added0 + 1 + (MAX_CHAR_ADDED - MIN_CHAR_ADDED + 1)*(MAX_CHAR_ADDED - char_added1),
			__min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 26)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = rules_nt_buffer[i + rules_nt_buffer_index];

		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = char_added0 + (char_added1 << 8) + 0x800000;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
				}
			}
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = _tmp + (char_added0 << 8) + (char_added1 << 16) + 0x80000000;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
				}
			}
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = _tmp + (char_added0 << 16) + (char_added1 << 24);
				nt_buffer[j + NUM_KEYS] = 0x80;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = _tmp + (char_added0 << 24);
				nt_buffer[j + NUM_KEYS] = char_added1 + 0x8000;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		}

		i += NUM_KEYS;
		MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 2) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added1 > MAX_CHAR_ADDED)
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
PRIVATE cl_uint oclru_prefix_2char_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	uint32_t i;
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Put buffer
	strcpy(nt_buffer[0], "+chars");
	nt_buffer_vector_size[0] = prefered_vector_size;
	for (i = 0; i < lenght / 2; i++)
		sprintf(nt_buffer[i + 1], "+nt_buffer%u", i);

	if (lenght & 1)
		sprintf(nt_buffer[i + 1], "+nt_buffer%u", i);
	else
		strcpy(nt_buffer[i + 1], "+0x80");

	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Convert the key into a nt_buffer
	sprintf(source + strlen(source), "uint%s chars=%uu+(param<<16u);", prefered_vector_size == 1 ? "" : "2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 16));

	if (prefered_vector_size > 1)
		sprintf(source + strlen(source), "chars.s1++;");
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,chars+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size);

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_append_2char_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	sprintf(nt_buffer[lenght / 2], "+chars");
	sprintf(source + strlen(source), "uint%s chars;", prefered_vector_size == 1 ? "" : "2");
	nt_buffer_vector_size[lenght / 2] = prefered_vector_size;

	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 2) << 4);

	// Last characters
	if (lenght & 1)
	{
		sprintf(source + strlen(source),
			"chars=(nt_buffer%u&0x0000ffff)+%uu;"
			"nt_buffer%u=%uu+param;", lenght / 2, MIN_CHAR_ADDED << 16, lenght / 2, 0x800000 + MIN_CHAR_ADDED);
		sprintf(nt_buffer[lenght / 2 + 1], "+nt_buffer%u", lenght / 2);
	}
	else
	{
		sprintf(source + strlen(source), "chars=(param<<16)+%uu;", (MIN_CHAR_ADDED << 16) + MIN_CHAR_ADDED);
		strcpy(nt_buffer[lenght / 2 + 1], "+0x80");
	}
	if (prefered_vector_size > 1)
		sprintf(source + strlen(source), "chars.s1+=%uu;", 1 << (16 * (lenght & 1)));

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,chars+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size << (16*(lenght&1)));

	return prefered_vector_size;
}
// UTF8
PRIVATE cl_uint oclru_prefix_2char_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Prefix 2 character
	switch (lenght & 3)
	{
	case 3:
		sprintf(nt_buffer[lenght / 4 + 1], "+buffer%u", lenght / 4 + 1);
		sprintf(source + strlen(source), "uint buffer%u=buffer%u>>16u;", lenght / 4 + 1, lenght / 4);
		if (lenght / 4)
			sprintf(source + strlen(source), "buffer%u=(buffer%u<<16u)+(buffer%u>>16u);", lenght / 4, lenght / 4, lenght / 4 - 1);
		break;
	case 2:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
	case 1: 
		if (lenght / 4)
			sprintf(source + strlen(source), "buffer%u=(buffer%u<<16u)+(buffer%u>>16u);", lenght / 4, lenght / 4, lenght / 4 - 1);
		break;
	case 0:
		sprintf(nt_buffer[lenght / 4], "+buffer%u", lenght / 4);
		if (lenght)
			sprintf(source + strlen(source), "uint buffer%u=(buffer%u>>16u)+0x800000;", lenght / 4, lenght / 4 - 1);
		else
			sprintf(source + strlen(source), "uint%s chars_add=%uu+(param<<8u);", prefered_vector_size == 1 ? "" : "2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + 0x800000);
		break;
	}

	strcpy(nt_buffer[0], "+chars_add");
	nt_buffer_vector_size[0] = prefered_vector_size;

	// Reverse
	for (int i = lenght / 4 - 1; i > 0; i--)
		sprintf(source + strlen(source), "buffer%i=(buffer%i<<16u)+(buffer%i>>16u);", i, i, i - 1);

	if (lenght)
		sprintf(source + strlen(source), "uint%s chars_add=(buffer0<<16u)+%uu+(param<<8u);", prefered_vector_size == 1 ? "" : "2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED<<8));

	sprintf(nt_buffer[7], "+%uu", (lenght + 2) << 3);

	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "chars_add.s1++;");

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,chars_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size);

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_append_2char_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 26)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Append 2 character
	switch (lenght & 3)
	{
	case 3:
		sprintf(source + strlen(source), "uint%s chars_add=(buffer%u&0xffffff)+%uu;", prefered_vector_size == 1 ? "" : "2", lenght / 4, MIN_CHAR_ADDED << 24u);
		sprintf(source + strlen(source), "buffer%u=param+%uu;", lenght / 4, MIN_CHAR_ADDED+0x8000);
		sprintf(nt_buffer[lenght / 4 + 1], "+buffer%u", lenght / 4);
		break;
	case 2:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
		sprintf(source + strlen(source), "uint%s chars_add=(buffer%u&0xffff)+%uu+(param<<24u);", prefered_vector_size == 1 ? "" : "2", lenght / 4, (MIN_CHAR_ADDED<<16) + (MIN_CHAR_ADDED << 24));
		break;
	case 1:
		sprintf(source + strlen(source), "uint%s chars_add=(buffer%u&0xff)+%uu+(param<<16u);", prefered_vector_size == 1 ? "" : "2", lenght / 4, (MIN_CHAR_ADDED<<8) + (MIN_CHAR_ADDED << 16) + 0x80000000);
		break;
	case 0:
		sprintf(source + strlen(source), "uint%s chars_add=%uu+(param<<8);", prefered_vector_size == 1 ? "" : "2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + 0x800000);
		break;
	}

	sprintf(nt_buffer[7], "+%uu", (lenght + 2) << 3);

	strcpy(nt_buffer[lenght / 4], "+chars_add");
	nt_buffer_vector_size[lenght / 4] = prefered_vector_size;

	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "chars_add.s1+=%uu;", 1 << (8 * (lenght & 3)));

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,chars_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size << (8 * (lenght & 3)));

	return prefered_vector_size;
}
// Get
PRIVATE void ocl_prefix_2char_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key+2, plain);
	// Prefix
	out_key[1] = MIN_CHAR_ADDED + (param >> 8);
	out_key[0] = MIN_CHAR_ADDED + (param & 0xff);
}
PRIVATE void ocl_append_2char_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	// Append
	out_key[strlen(out_key)+2] = 0;
	out_key[strlen(out_key)+1] = MIN_CHAR_ADDED + (param >> 8);
	out_key[strlen(out_key)+0] = MIN_CHAR_ADDED + (param & 0xff);
}
#define OCL_2_CHARS	"((param<<8)+i)"
// Common
PRIVATE void oclru_prefix_2char_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	DivisionParams div_param = get_div_params(LENGHT_CHAR_ADDED);

	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(25u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(2u<<4u);"
		"uint max_iter=(len>>6u)+1u;"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	// Perform division
	if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(param+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint div=param>>%iU;", (int)div_param.shift);// Power of two division

	sprintf(source + strlen(source),
		"uint char_added = %uu+param+div*%uu;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"
			"out_key[i*%uu+out_index]=char_added + (part_key << 16u);"
			"char_added = part_key>>16u;"
		"}"

		"if(((len>>4u)&3u)>=2u)"
			"out_key[max_iter*%uu+out_index]=char_added;"
			, MIN_CHAR_ADDED + (MIN_CHAR_ADDED<<8), 256-LENGHT_CHAR_ADDED, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_plus_2char_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	DivisionParams div_param = get_div_params(LENGHT_CHAR_ADDED);

	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(25u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(2u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	// Perform division
	if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(param+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint div=param>>%iU;", (int)div_param.shift);// Power of two division

	sprintf(source + strlen(source),
		"uint char_added = %uu+param+div*%uu;"

		"for(uint i=0;i<max_iter;i++)"
			"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"out_key[max_iter*%uu+out_index]=bs(part_key,char_added<<len,0xffffffffu<<len);"

		"if(len>=(2u<<3u))"
			"out_key[(max_iter+1)*%uu+out_index]=char_added>>(32u-len);"
			, MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + 0x800000, 256 - LENGHT_CHAR_ADDED, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
#endif

// 3 char
PRIVATE void rule_append_3char_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];
	uint32_t char_added2 = rules_data_buffer[CHAR_ADDED2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added1)+LENGHT_CHAR_ADDED*LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added2),
			__min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

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

		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void rule_plus_3char_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];
	uint32_t char_added2 = rules_data_buffer[CHAR_ADDED2_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added0 + 1 + LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED - char_added1) + LENGHT_CHAR_ADDED*LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED - char_added2),
			__min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;

		if (lenght >= 25)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			char_added2 = MIN_CHAR_ADDED;
			continue;
		}

		// Copy
		for (i = 0; i < lenght / 4 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = rules_nt_buffer[i + rules_nt_buffer_index];

		switch (lenght & 3)
		{
			uint32_t _tmp;
		case 0:
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = char_added0 + (char_added1 << 8) + (char_added2 << 16) + 0x80000000;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
					if (char_added1 > MAX_CHAR_ADDED)
					{
						char_added1 = MIN_CHAR_ADDED;
						char_added2++;
					}
				}
			}
			break;
		case 1:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFF;
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = _tmp + (char_added0 << 8) + (char_added1 << 16) + (char_added2 << 24);
				nt_buffer[j + NUM_KEYS] = 0x80;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
					if (char_added1 > MAX_CHAR_ADDED)
					{
						char_added1 = MIN_CHAR_ADDED;
						char_added2++;
					}
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		case 2:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFF;
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = _tmp + (char_added0 << 16) + (char_added1 << 24);
				nt_buffer[j + NUM_KEYS] = (char_added2) + 0x8000;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
					if (char_added1 > MAX_CHAR_ADDED)
					{
						char_added1 = MIN_CHAR_ADDED;
						char_added2++;
					}
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		case 3:
			_tmp = rules_nt_buffer[i + rules_nt_buffer_index] & 0xFFFFFF;
			for (j = i + nt_buffer_index; j < MAX; j++, char_added0++)
			{
				nt_buffer[j] = _tmp + (char_added0 << 24);
				nt_buffer[j + NUM_KEYS] = char_added1 + (char_added2 << 8) + 0x800000;
				if (char_added0 >= MAX_CHAR_ADDED)
				{
					char_added0 = MIN_CHAR_ADDED - 1;
					char_added1++;
					if (char_added1 > MAX_CHAR_ADDED)
					{
						char_added1 = MIN_CHAR_ADDED;
						char_added2++;
					}
				}
			}
			i += NUM_KEYS;
			MAX += NUM_KEYS;
			break;
		}

		i += NUM_KEYS;
		MAX += NUM_KEYS;
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 3) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added2 > MAX_CHAR_ADDED)
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
PRIVATE void rule_prefix_3char_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];
	uint32_t char_added2 = rules_data_buffer[CHAR_ADDED2_INDEX];

	while(rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i,j;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		int num_to_copy = __min(MAX_CHAR_ADDED-char_added0+1+LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added1)+LENGHT_CHAR_ADDED*LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED-char_added2),
			__min(NUM_KEYS-nt_buffer_index, NUM_KEYS-rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = (lenght+2)/2*NUM_KEYS;
		uint32_t last_tmp;

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
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			last_tmp = (_tmp << 16) | (last_tmp >> 16);
			for(j = i+nt_buffer_index+NUM_KEYS; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}
		i += NUM_KEYS;

		// Fill with 0
		for (j = nt_buffer_index; j < (num_to_copy+nt_buffer_index); j++)
		{
			uint32_t old_len = ((nt_buffer[j + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS + j;
			for (uint32_t z_index = j + i; z_index < old_len; z_index += NUM_KEYS)
				nt_buffer[z_index] = 0;
		}
		MAX = 14 * NUM_KEYS + num_to_copy + nt_buffer_index;

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
PRIVATE void ru_prefix_3char_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	uint32_t char_added0 = rules_data_buffer[CHAR_ADDED0_INDEX];
	uint32_t char_added1 = rules_data_buffer[CHAR_ADDED1_INDEX];
	uint32_t char_added2 = rules_data_buffer[CHAR_ADDED2_INDEX];

	while (rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS)
	{
		uint32_t i, j;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		int num_to_copy = __min(MAX_CHAR_ADDED - char_added0 + 1 + LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED - char_added1) + LENGHT_CHAR_ADDED*LENGHT_CHAR_ADDED*(MAX_CHAR_ADDED - char_added2),
			__min(NUM_KEYS - nt_buffer_index, NUM_KEYS - rules_nt_buffer_index));
		uint32_t MAX = nt_buffer_index + num_to_copy;
		uint32_t MAX_LOWER = (lenght / 4 + 1) * NUM_KEYS;
		uint32_t last_tmp;

		if (lenght >= 25)
		{
			rules_nt_buffer_index++;
			char_added0 = MIN_CHAR_ADDED;
			char_added1 = MIN_CHAR_ADDED;
			char_added2 = MIN_CHAR_ADDED;
			continue;
		}

		// First and second
		last_tmp = rules_nt_buffer[rules_nt_buffer_index];
		for (j = nt_buffer_index; j < MAX; j++, char_added0++)
		{
			nt_buffer[j] = char_added0 + (char_added1 << 8) + (char_added2 << 16) + (last_tmp << 24);

			if (char_added0 >= MAX_CHAR_ADDED)
			{
				char_added0 = MIN_CHAR_ADDED - 1;
				char_added1++;
				if (char_added1 > MAX_CHAR_ADDED)
				{
					char_added1 = MIN_CHAR_ADDED;
					char_added2++;
				}
			}
		}
		MAX += NUM_KEYS;
		// Copy
		for (i = NUM_KEYS; i < MAX_LOWER; i += NUM_KEYS, MAX += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			last_tmp = (_tmp << 24) | (last_tmp >> 8);
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp;

			last_tmp = _tmp;
		}
		if ((lenght & 3) >= 1)
		{
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = last_tmp >> 8;
			i += NUM_KEYS;
			MAX += NUM_KEYS;
		}

		// Fill with 0
		for (; i < 7 * NUM_KEYS; i += NUM_KEYS, MAX += NUM_KEYS)
			for (j = i + nt_buffer_index; j < MAX; j++)
				nt_buffer[j] = 0;

		lenght = (lenght + 3) << 3;
		for (j = 7 * NUM_KEYS + nt_buffer_index; j < MAX; j++)
			nt_buffer[j] = lenght;

		if (char_added2 > MAX_CHAR_ADDED)
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
PRIVATE cl_uint oclru_append_3char_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 25)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 3) << 4);

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Append character
	if (lenght & 1)
	{
		strcpy(nt_buffer[lenght / 2 + 2], "+0x80");
		sprintf(source + strlen(source), "uint%s chars=%uu+param/%uu;", prefered_vector_size == 1 ? "" : "2", (MIN_CHAR_ADDED<<16) + MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);
		sprintf(source + strlen(source), "nt_buffer%u=(nt_buffer%u&0xffff)+((%uu+param%%%uu)<<16);", lenght / 2, lenght / 2, MIN_CHAR_ADDED, LENGHT_CHAR_ADDED);
	}
	else
	{
		sprintf(nt_buffer[lenght / 2], "+nt_buffer%u", lenght / 2);

		sprintf(source + strlen(source), "uint%s chars=%uu;", prefered_vector_size == 1 ? "" : "2", 0x800000 | MIN_CHAR_ADDED);
		sprintf(source + strlen(source), "uint nt_buffer%u=%uu+((param/%uu)<<16)+param%%%uu;", lenght / 2, (MIN_CHAR_ADDED << 16) + MIN_CHAR_ADDED, LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
	}

	sprintf(nt_buffer[lenght / 2 + 1], "+chars");
	nt_buffer_vector_size[lenght / 2 + 1] = prefered_vector_size;
	if (prefered_vector_size > 1)
		sprintf(source + strlen(source), "chars.s1+=%uu;", 1 << (16 * (lenght & 1)));

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,chars+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size << (16 * (lenght & 1)));

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_prefix_3char_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	uint32_t i;
	oclru_copy_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 25)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

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
		sprintf(source + strlen(source), "uint nt_buffer%u=0x80;", lenght / 2);
	}
	// Put lenght
	sprintf(nt_buffer[14], "+%uu", (lenght + 3) << 4);
	
	// First character
	sprintf(source + strlen(source),
		"uint tmp=nt_buffer0>>16;"
		"uint%s last_char=(nt_buffer0<<16)+%uu;"
		"uint swap_tmp;", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED);
	// Copy
	for (i = 1; i < lenght / 2 + 1; i++)
		sprintf(source + strlen(source), 
		"swap_tmp=tmp+(nt_buffer%u<<16);"
		"tmp=nt_buffer%u>>16;"
		"nt_buffer%u=swap_tmp;"
		, i, i, i);

	sprintf(nt_buffer[1], "+last_char");
	nt_buffer_vector_size[1] = prefered_vector_size;
	if (prefered_vector_size>1)
		sprintf(source + strlen(source), "last_char.s1++;");

	// First 2 chars
	sprintf(source + strlen(source), "uint chars=%uu+param%%%uu+((param/%uu)<<16);", (MIN_CHAR_ADDED<<16)+MIN_CHAR_ADDED, LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,last_char+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size);

	return prefered_vector_size;
}
// UTF8
PRIVATE cl_uint oclru_append_3char_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 25)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Append 3 character
	switch (lenght & 3)
	{
	case 3:
		sprintf(source + strlen(source), "uint%s chars_add=%uu+(param/%uu);", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + 0x800000, LENGHT_CHAR_ADDED);
		sprintf(source + strlen(source), "buffer%u=(buffer%u&0xffffff)+%uu+((param%%%uu)<<24u);", lenght / 4, lenght / 4, MIN_CHAR_ADDED << 24u, LENGHT_CHAR_ADDED);
		break;
	case 2:
		sprintf(source + strlen(source), "uint%s chars_add=%uu;", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED + 0x8000);
		sprintf(source + strlen(source), "buffer%u=(buffer%u&0xffff)+%uu+((param%%%uu)<<16u)+((param/%uu)<<24u);", lenght / 4, lenght / 4, (MIN_CHAR_ADDED << 16) + (MIN_CHAR_ADDED << 24), LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
		break;
	case 1:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
		sprintf(source + strlen(source), "uint%s chars_add=(buffer%u&0xff)+%uu+((param/%uu)<<16u)+((param%%%uu)<<8u);", prefered_vector_size==1?"":"2", lenght / 4, (MIN_CHAR_ADDED << 8) + (MIN_CHAR_ADDED << 16) + (MIN_CHAR_ADDED << 24), LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
		break;
	case 0:
		sprintf(source + strlen(source), "uint%s chars_add=%uu+((param/%uu)<<8u) + param%%%uu;", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + (MIN_CHAR_ADDED << 16) + 0x80000000, LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
		break;
	}

	sprintf(nt_buffer[7], "+%uu", (lenght + 3) << 3);

	strcpy(nt_buffer[(lenght+2) / 4], "+chars_add");
	nt_buffer_vector_size[(lenght + 2) / 4] = prefered_vector_size;
	if (prefered_vector_size == 2)
		sprintf(source + strlen(source), "chars_add.s1+=%uu;", 1 << (8 * ((lenght + 2) & 3)));

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%u,chars_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size << (8*((lenght+2)&3)));

	return prefered_vector_size;
}
PRIVATE cl_uint oclru_prefix_3char_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_copy_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	// Check lenght
	if (lenght >= 25)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	if (prefered_vector_size > 1)
		prefered_vector_size = 2;

	// Prefix 2 character
	switch (lenght & 3)
	{
	case 3:
	case 2:
		sprintf(nt_buffer[lenght / 4 + 1], "+buffer%u", lenght / 4 + 1);
		sprintf(source + strlen(source), "uint buffer%u=buffer%u>>8u;", lenght / 4 + 1, lenght / 4);
		if (lenght / 4)
			sprintf(source + strlen(source), "buffer%u=(buffer%u<<24u)+(buffer%u>>8u);", lenght / 4, lenght / 4, lenght / 4 - 1);
		break;
	case 1:
		strcpy(nt_buffer[lenght / 4 + 1], "+0x80");
		if (lenght / 4)
			sprintf(source + strlen(source), "buffer%u=(buffer%u<<24u)+(buffer%u>>8u);", lenght / 4, lenght / 4, lenght / 4 - 1);
		break;
	case 0:
		sprintf(nt_buffer[lenght / 4], "+buffer%u", lenght / 4);
		if (lenght)
			sprintf(source + strlen(source), "uint buffer%u=(buffer%u>>8u)+0x80000000;", lenght / 4, lenght / 4 - 1);
		break;
	}

	// Reverse
	for (int i = lenght / 4 - 1; i > 0; i--)
		sprintf(source + strlen(source), "buffer%i=(buffer%i<<24u)+(buffer%i>>8u);", i, i, i - 1);

	if (lenght)
		sprintf(source + strlen(source), "uint%s chars_add=(buffer0<<24u)+%uu+((param/%uu)<<8u)+(param%%%uu);", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + (MIN_CHAR_ADDED << 16), LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);
	else
		sprintf(source + strlen(source), "uint%s chars_add=%uu+((param/%uu)<<8u)+(param%%%uu);", prefered_vector_size==1?"":"2", MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + (MIN_CHAR_ADDED << 16) + 0x80000000, LENGHT_CHAR_ADDED, LENGHT_CHAR_ADDED);

	sprintf(nt_buffer[7], "+%uu", (lenght + 3) << 3);

	strcpy(nt_buffer[0], "+chars_add");
	nt_buffer_vector_size[0] = prefered_vector_size;
	if (prefered_vector_size==2)
		sprintf(source + strlen(source), "chars_add.s1+=%uu;", 1<<16);

	// Begin cycle
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i+=%uu,chars_add+=%uu){", LENGHT_CHAR_ADDED, prefered_vector_size, prefered_vector_size<<16);

	return prefered_vector_size;
}
// Get
PRIVATE void ocl_prefix_3char_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key+3, plain);
	// Prefix
	out_key[2] = MIN_CHAR_ADDED + (param & 0xff);
	out_key[1] = MIN_CHAR_ADDED + (param >> 8) / LENGHT_CHAR_ADDED;
	out_key[0] = MIN_CHAR_ADDED + (param >> 8) % LENGHT_CHAR_ADDED;
}
PRIVATE void ocl_append_3char_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	// Append
	out_key[strlen(out_key)+3] = 0;
	out_key[strlen(out_key)+2] = MIN_CHAR_ADDED + (param & 0xff);
	out_key[strlen(out_key)+1] = MIN_CHAR_ADDED + (param >> 8) / LENGHT_CHAR_ADDED;
	out_key[strlen(out_key)+0] = MIN_CHAR_ADDED + (param >> 8) % LENGHT_CHAR_ADDED;
}
#define OCL_3_CHARS	"((param<<8)+i)"
// Common
PRIVATE void oclru_prefix_3char_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	DivisionParams div_param = get_div_params(LENGHT_CHAR_ADDED);

	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(24u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(3u<<4u);"
		"uint max_iter=(len>>6u)+1u;"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	// Perform division
	if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(param+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint div=param>>%iU;", (int)div_param.shift);// Power of two division

	if (div_param.magic)sprintf(source + strlen(source), "uint div1=mul_hi(div+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint div1=div>>%iU;", (int)div_param.shift);// Power of two division

	sprintf(source + strlen(source),
		"uint char_added = %uu+param+div*%uu+div1*%uu;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"
			"out_key[i*%uu+out_index]=char_added + (part_key << 24u);"
			"char_added = part_key>>8u;"
		"}"

		"if(((len>>4u)&3u)>=1u)"
			"out_key[max_iter*%uu+out_index]=char_added;"
			, MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + (MIN_CHAR_ADDED << 16), 256 - LENGHT_CHAR_ADDED, 0x10000 - LENGHT_CHAR_ADDED * 256, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_plus_3char_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	DivisionParams div_param = get_div_params(LENGHT_CHAR_ADDED);

	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source),
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(24u<<4u))return;"
		"uint out_index=atomic_inc(begin_out_index);"
		"out_key[7u*%uu+out_index]=len+(3u<<4u);"
		"uint max_iter=len>>6u;"
		"len=(len>>1u)&(3u<<3u);"
		, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	// Perform division
	if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(param+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint div=param>>%iU;", (int)div_param.shift);// Power of two division

	if (div_param.magic)sprintf(source + strlen(source), "uint div1=mul_hi(div+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
	else				sprintf(source + strlen(source), "uint div1=div>>%iU;", (int)div_param.shift);// Power of two division

	sprintf(source + strlen(source),
		"uint char_added = %uu+param+div*%uu+div1*%uu;"

		"for(uint i=0;i<max_iter;i++)"
			"out_key[i*%uu+out_index]=in_key[i*%uu+idx];"

		"uint part_key=in_key[max_iter*%uu+idx];"

		"out_key[max_iter*%uu+out_index]=bs(part_key,char_added<<len,0xffffffffu<<len);"

		"if(len>=(1u<<3u))"
			"out_key[(max_iter+1)*%uu+out_index]=char_added>>(32u-len);"
		, MIN_CHAR_ADDED + (MIN_CHAR_ADDED << 8) + (MIN_CHAR_ADDED << 16)+0x80000000, 256 - LENGHT_CHAR_ADDED, 0x10000 - LENGHT_CHAR_ADDED * 256, out_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}

#endif

// Leet Stuff
PRIVATE unsigned char leet_orig[]   = "aaeollssiibccgqttx";
PRIVATE unsigned char leet_change[] = "4@301!$51!6<{997+%";
PRIVATE void rule_lower_leet_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	int leet_index = rules_data_buffer[LEET_INDEX0];

	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; leet_index++)
	{
		uint32_t i;
		int letter_exist = FALSE;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		uint32_t MAX = (lenght / 2 + 1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;

			// Leet change
			if((_tmp & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF0000) | ((uint32_t)(leet_change[leet_index]));
				letter_exist = TRUE;
			}
			if(((_tmp >> 16) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF) | (((uint32_t)(leet_change[leet_index])) << 16);
				letter_exist = TRUE;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(letter_exist)
		{
			uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
			for (; i < old_len; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
		else
			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = __max(nt_buffer[14 * NUM_KEYS + nt_buffer_index], lenght << 4);

		if(leet_index >= LENGTH(leet_orig) - 2)// -2 and not -1 because LENGHT take into account the null terminator
		{
			leet_index = -1;
			rules_nt_buffer_index++;
		}
	}

	if(rules_nt_buffer_index >= NUM_KEYS)
		leet_index = 0;

	rules_data_buffer[LEET_INDEX0] = leet_index;
}
PRIVATE void rule_lower_leet_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	int leet_index = rules_data_buffer[LEET_INDEX0];

	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; leet_index++)
	{
		uint32_t i;
		int letter_exist = FALSE;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t MAX = (lenght / 4 + 1)*NUM_KEYS;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (((_tmp & 0xFF) - 65u) <= 25u)
				_tmp += 32;
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			// Leet change
			if ((_tmp & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFFFF00) | ((uint32_t)(leet_change[leet_index]));
				letter_exist = TRUE;
			}
			if (((_tmp >> 8) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF00FF) | (((uint32_t)(leet_change[leet_index])) << 8);
				letter_exist = TRUE;
			}
			if (((_tmp >> 16) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFF00FFFF) | (((uint32_t)(leet_change[leet_index])) << 16);
				letter_exist = TRUE;
			}
			if (((_tmp >> 24)) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0x00FFFFFF) | (((uint32_t)(leet_change[leet_index])) << 24);
				letter_exist = TRUE;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		if (letter_exist)
		{
			for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 3;
			nt_buffer_index++;
		}

		if (leet_index >= LENGTH(leet_orig) - 2)// -2 and not -1 because LENGHT take into account the null terminator
		{
			leet_index = -1;
			rules_nt_buffer_index++;
		}
	}

	if (rules_nt_buffer_index >= NUM_KEYS)
		leet_index = 0;

	rules_data_buffer[LEET_INDEX0] = leet_index;
}
PRIVATE void rule_cap_leet_ucs(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	int leet_index = rules_data_buffer[LEET_INDEX0];

	for(; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; leet_index++)
	{
		uint32_t i;
		int letter_exist = FALSE;
		uint32_t lenght = rules_nt_buffer[14*NUM_KEYS+rules_nt_buffer_index] >> 4;
		uint32_t MAX = (lenght/2+1)*NUM_KEYS;

		for(i = 0; i < MAX; i+=NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i+rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((_tmp - 4259840u) <= 1703935u)
				_tmp += 32 << 16;
			// Leet change
			if((_tmp & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF0000) | ((uint32_t)(leet_change[leet_index]));
				letter_exist = TRUE;
			}
			if(((_tmp >> 16) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF) | (((uint32_t)(leet_change[leet_index])) << 16);
				letter_exist = TRUE;
			}

			nt_buffer[i+nt_buffer_index] = _tmp;
		}

		if(letter_exist)
		{
			uint32_t old_len = ((nt_buffer[nt_buffer_index + 14 * NUM_KEYS] >> 5) + 1)*NUM_KEYS;
			for (; i < old_len; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[14*NUM_KEYS+nt_buffer_index] = lenght << 4;
			nt_buffer_index++;
		}
		else
			nt_buffer[14 * NUM_KEYS + nt_buffer_index] = __max(nt_buffer[14 * NUM_KEYS + nt_buffer_index], lenght << 4);

		if(leet_index >= LENGTH(leet_orig) - 2)// -2 and not -1 because LENGHT take into account the null terminator
		{
			leet_index = -1;
			rules_nt_buffer_index++;
		}
	}

	if(rules_nt_buffer_index >= NUM_KEYS)
		leet_index = 0;

	rules_data_buffer[LEET_INDEX0] = leet_index;
}
PRIVATE void rule_cap_leet_utf8(uint32_t* nt_buffer, uint32_t NUM_KEYS, uint32_t* rules_data_buffer)
{
	int leet_index = rules_data_buffer[LEET_INDEX0];

	for (; rules_nt_buffer_index < NUM_KEYS && nt_buffer_index < NUM_KEYS; leet_index++)
	{
		uint32_t i;
		int letter_exist = FALSE;
		uint32_t lenght = rules_nt_buffer[7 * NUM_KEYS + rules_nt_buffer_index] >> 3;
		uint32_t MAX = (lenght / 4 + 1)*NUM_KEYS;

		for (i = 0; i < MAX; i += NUM_KEYS)
		{
			uint32_t _tmp = rules_nt_buffer[i + rules_nt_buffer_index];

			if (i)
			{
				if (((_tmp & 0xFF) - 65u) <= 25u)
					_tmp += 32;
			}
			else
			{
				if (((_tmp & 0xFF) - 97u) <= 25u)
					_tmp -= 32;
			}
			if ((((_tmp >> 8u) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 8;
			if ((((_tmp >> 16) & 0xFF) - 65u) <= 25u)
				_tmp += 32 << 16;
			if (((_tmp >> 24) - 65u) <= 25u)
				_tmp += 32 << 24;

			// Leet change
			if ((_tmp & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFFFF00) | ((uint32_t)(leet_change[leet_index]));
				letter_exist = TRUE;
			}
			if (((_tmp >> 8) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFFFF00FF) | (((uint32_t)(leet_change[leet_index])) << 8);
				letter_exist = TRUE;
			}
			if (((_tmp >> 16) & 0xFF) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0xFF00FFFF) | (((uint32_t)(leet_change[leet_index])) << 16);
				letter_exist = TRUE;
			}
			if (((_tmp >> 24)) == leet_orig[leet_index])
			{
				_tmp = (_tmp & 0x00FFFFFF) | (((uint32_t)(leet_change[leet_index])) << 24);
				letter_exist = TRUE;
			}

			nt_buffer[i + nt_buffer_index] = _tmp;
		}

		if (letter_exist)
		{
			for (; i < 7 * NUM_KEYS; i += NUM_KEYS)
				nt_buffer[i + nt_buffer_index] = 0;

			nt_buffer[7 * NUM_KEYS + nt_buffer_index] = lenght << 3;
			nt_buffer_index++;
		}

		if (leet_index >= LENGTH(leet_orig) - 2)// -2 and not -1 because LENGHT take into account the null terminator
		{
			leet_index = -1;
			rules_nt_buffer_index++;
		}
	}

	if (rules_nt_buffer_index >= NUM_KEYS)
		leet_index = 0;

	rules_data_buffer[LEET_INDEX0] = leet_index;
}
// OpenCL
#ifdef HS_OPENCL_SUPPORT
PRIVATE void ocl_write_leet_consts(char* source)
{
	// Fill leet_orig
	sprintf(source+strlen(source),	"__constant uchar leet_array[]={");
	for(cl_uint i = 0; i < strlen(leet_orig); i++)
		sprintf(source+strlen(source), "%s%uu", i?",":"", (cl_uint)leet_orig[i]);
	// Fill leet_change
	for(cl_uint i = 0; i < strlen(leet_change); i++)
		sprintf(source+strlen(source), ",%uu", (cl_uint)leet_change[i]);
	strcat(source, "};\n");
}
PRIVATE cl_uint oclru_leet_ucs(char* source, cl_uint lenght)
{
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	sprintf(source + strlen(source), "local uchar leet_local[%u];", (cl_uint)(2*strlen(leet_orig)));

	// Copy from global to local
	sprintf(source + strlen(source), "for(uint i=get_local_id(0);i<%uu;i+=get_local_size(0))"
										"leet_local[i]=leet_array[i];"
									"barrier(CLK_LOCAL_MEM_FENCE);", (cl_uint)(2*strlen(leet_orig)));

	// Save to cache
	for (cl_uint i = 0; i < (lenght + 1) / 2; i++)
		sprintf(source + strlen(source), "uint nt_buffer_cache%u=nt_buffer%u;", i ,i);
		
	sprintf(source + strlen(source), "for(uint i=0;i<%iu;i++){"
										"uint bs_tmp;"
										"uint leet_orig=leet_local[i];"
										"uint leet_change=leet_local[i+%iu];", (cl_uint)strlen(leet_orig), (cl_uint)strlen(leet_orig));
	// Perform leet
	for (cl_uint i = 0; i < lenght; i++)
		if (i & 1)
			sprintf(source + strlen(source), "bs_tmp=((nt_buffer%u>>16u)==leet_orig)?0xff0000:0;"
											 "nt_buffer%u=bitselect(nt_buffer%u,leet_change<<16u,bs_tmp);"
											 , i / 2, i / 2, i / 2);
		else
			sprintf(source + strlen(source), "bs_tmp=((nt_buffer_cache%u&0xff)==leet_orig)?0xff:0;"
											 "nt_buffer%u=bitselect(nt_buffer_cache%u,leet_change,bs_tmp);"
												, i / 2, i / 2, i / 2);

	return 1;
}
PRIVATE cl_uint oclru_lower_leet_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_leet_ucs(source, lenght);
}
PRIVATE cl_uint oclru_capitalize_leet_ucs(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_ucs(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_leet_ucs(source, lenght);
}
// UTF8
PRIVATE cl_uint oclru_leet_utf8(char* source, cl_uint lenght)
{
	if (!lenght)
	{
		sprintf(source + strlen(source), "uint i=0;return;{");
		return 1;
	}

	sprintf(source + strlen(source), "local uchar leet_local[%u];", (cl_uint)(2*strlen(leet_orig)));
	// Copy from global to local
	sprintf(source + strlen(source), "for(uint i=get_local_id(0);i<%uu;i+=get_local_size(0))"
										"leet_local[i]=leet_array[i];"
									"barrier(CLK_LOCAL_MEM_FENCE);", (cl_uint)(2*strlen(leet_orig)));

	// Save to cache
	for (cl_uint i = 0; i < (lenght + 3) / 4; i++)
		sprintf(source + strlen(source), "uint nt_buffer_cache%u=buffer%u;", i, i);

	sprintf(source + strlen(source), "for(uint i=0;i<%iu;i++){"
										"uint bs_tmp;"
										"uint leet_orig=leet_local[i];"
										"uint leet_change=leet_local[i+%iu];", (cl_uint)strlen(leet_orig), (cl_uint)strlen(leet_orig));
	// Perform leet
	for (cl_uint i = 0; i < lenght; i++)
		switch (i & 3)
		{
			case 1:
				sprintf(source + strlen(source), "bs_tmp=(((buffer%u>>8u)&0xff)==leet_orig)?0xff00:0;"
												 "buffer%u=bitselect(buffer%u,leet_change<<8u,bs_tmp);"
												 , i / 4, i / 4, i / 4);
				break;
			case 2:
				sprintf(source + strlen(source), "bs_tmp=(((buffer%u>>16u)&0xff)==leet_orig)?0xff0000:0;"
												 "buffer%u=bitselect(buffer%u,leet_change<<16u,bs_tmp);"
												 , i / 4, i / 4, i / 4);
				break;
			case 3:
				sprintf(source + strlen(source), "bs_tmp=((buffer%u>>24u)==leet_orig)?0xff000000:0;"
												 "buffer%u=bitselect(buffer%u,leet_change<<24u,bs_tmp);"
													, i / 4, i / 4, i / 4);
				break;
			case 0:
				sprintf(source + strlen(source), "bs_tmp=((nt_buffer_cache%u&0xff)==leet_orig)?0xff:0;"
												 "buffer%u=bitselect(nt_buffer_cache%u,leet_change,bs_tmp);"
													, i / 4, i / 4, i / 4);
				break;
		}

	return 1;
}
PRIVATE cl_uint oclru_lower_leet_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_lower_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_leet_utf8(source, lenght);
}
PRIVATE cl_uint oclru_capitalize_leet_utf8(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	oclru_capitalize_utf8(source, nt_buffer, nt_buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);

	return oclru_leet_utf8(source, lenght);
}
// Get
PRIVATE void ocl_lower_leet_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);

	if(param >= strlen(leet_orig))
		return;

	// Leet
	for (cl_uint i = 0; i < strlen(out_key); i++)
		if(out_key[i] == leet_orig[param])
			out_key[i] = leet_change[param];
}
PRIVATE void ocl_capitalize_leet_get_key(unsigned char* out_key, unsigned char* plain, cl_uint param)
{
	strcpy(out_key, plain);
	_strlwr(out_key);
	// Capitalize
	if(islower(out_key[0]))
		out_key[0] -= 32;

	if(param >= strlen(leet_orig))
		return;
	// Leet
	for (cl_uint i = 0; i < strlen(out_key); i++)
		if(out_key[i] == leet_orig[param])
			out_key[i] = leet_change[param];
}
// Common
PRIVATE void oclru_leet_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL, int is_capitalize)
{
	oclru_common_kernel_definition(source, rule_name, TRUE);

	sprintf(source + strlen(source), "uint leet_orig=leet_array[param];"
									 "uint leet_change=leet_array[param+%iu];", (int)strlen(leet_orig));

	sprintf(source + strlen(source),
		"uint tmp[7];"
		"bool have_change=false;"
		"uint len=in_key[7u*%uu+idx];"
		"if(len>(27u<<4u))return;"
		"uint max_iter=(len>>6u)+1u;"

		"for(uint i=0;i<max_iter;i++)"
		"{"
			"uint part_key=in_key[i*%uu+idx];"

			"%s{"
				"if(((part_key & 0xFF) - 65u) <= 25u)"
					"part_key += 32u;"
			"}"
			"if((((part_key>>8u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<8u;"
			"if((((part_key>>16u) & 0xFF) - 65u) <= 25u)"
				"part_key += 32u<<16u;"
			"if(((part_key>>24u) - 65u) <= 25u)"
				"part_key += 32u<<24u;"

			"if((part_key & 0xFF) == leet_orig)"
			"{"
				"part_key = bs(part_key,leet_change,0xffu);"
				"have_change=true;"
			"}"
			"if(((part_key>>8u) & 0xFF) == leet_orig)"
			"{"
				"part_key = bs(part_key,leet_change<<8u,0xff00u);"
				"have_change=true;"
			"}"
			"if(((part_key>>16u) & 0xFF) == leet_orig)"
			"{"
				"part_key = bs(part_key,leet_change<<16u,0xff0000u);"
				"have_change=true;"
			"}"
			"if((part_key>>24u) == leet_orig)"
			"{"
				"part_key = bs(part_key,leet_change<<24u,0xff000000u);"
				"have_change=true;"
			"}"

			"tmp[i]=part_key;"
		"}"

		"if(have_change)"
		"{"
			"uint out_index=atomic_inc(begin_out_index);"
			"out_key[7u*%uu+out_index]=len;"
			"for(uint i=0;i<max_iter;i++)"
				"out_key[i*%uu+out_index]=tmp[i];"
		"}", in_NUM_KEYS_OPENCL, in_NUM_KEYS_OPENCL, is_capitalize ? "if(i==0){if(((part_key&0xFF)-97u)<=25u)part_key-=32u;}else" : "", out_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL);

	strcat(source, "}");
}
PRIVATE void oclru_lower_leet_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_leet_common(source, rule_name, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, FALSE);
}
PRIVATE void oclru_cap_leet_common(char* source, char* rule_name, cl_uint in_NUM_KEYS_OPENCL, cl_uint out_NUM_KEYS_OPENCL)
{
	oclru_leet_common(source, rule_name, in_NUM_KEYS_OPENCL, out_NUM_KEYS_OPENCL, TRUE);
}
#endif

#define DESC_0		"Try words as they are. (word -> word)"
#define DESC_1		"Lowercase every word. (woRd -> word)"
#define DESC_2		"Uppercase every word. (word -> WORD)"

#define DESC_3		"Capitalize every word. (word -> Word)"
#define DESC_4		"Duplicate words. (word -> wordword)"
#define DESC_5		"Lowercase word and made leet substitutions. The substitutions are: a->4@, e->3, o->0, l->1!, s->$5, i->1!, b->6, c-><{, g->9, q->9, t->7+, x->%."

#define DESC_6		"Capitalize word and made leet substitutions. The substitutions are: a->4@, e->3, o->0, l->1!, s->$5, i->1!, b->6, c-><{, g->9, q->9, t->7+, x->%."
#define DESC_7		"Lowercase word and uppercase the last letter. (word -> worD)"
#define DESC_8		"Capitalize word and append all printable characters. (word -> Word#)"

#define DESC_9		"Lowercase word and append all printable characters. (word -> word#)"
#define DESC_10		"Prefix word with all printable characters. (word -> #word)"
#define DESC_11		"Lowercase word and append a year. Years range from 1900 to 2029. (word -> word1985)"

#define DESC_12		"Capitalize word and append a year. Years range from 1900 to 2029. (word -> Word1985)"
#define DESC_13		"Lowercase word and append two digits. (word -> word37)"
#define DESC_14		"Capitalize word and append two digits. (word -> Word37)"

#define DESC_15		"Insert inside each word all printable characters. (word -> w;ord)"
#define DESC_16		"Remove each characters of the word. (word -> wod)"
#define DESC_17		"Overstrike each characters of the word with all printable characters. (word -> wo#d)"

#define DESC_18		"Prefix word with a year. Years range from 1900 to 2029. (word -> 1992word)"
#define DESC_19		"Prefix word with two characters (all printable characters). (word -> ;!word)"
#define DESC_20		"Append two characters to the word (all printable characters). (word -> word;!)"

#define DESC_21		"Append three characters to the word (all printable characters) (very slow). (word -> word;!#)"
#define DESC_22		"Prefix word with three characters (all printable characters) (very slow). (word -> ;!#word)"
#define DESC_23		""	

#ifndef HS_OPENCL_SUPPORT
	#define OCL_INSERT_PARAM						NULL
	#define OCL_REMOVE_PARAM						NULL
	#define OCL_OVERSTRIKE_PARAM					NULL
	#define OCL_2_CHARS								0
	#define OCL_3_CHARS								0

	#define oclru_copy_common NULL
	#define oclru_copy_ucs NULL
	#define oclru_copy_utf8 NULL
	#define oclru_lower_common NULL
	#define oclru_lower_ucs NULL
	#define oclru_lower_utf8 NULL
	#define oclru_upper_common NULL
	#define oclru_upper_ucs NULL
	#define oclru_upper_utf8 NULL
	#define oclru_capitalize_common NULL
	#define oclru_capitalize_ucs NULL
	#define oclru_capitalize_utf8 NULL
	#define oclru_duplicate_common NULL
	#define oclru_duplicate_ucs NULL
	#define oclru_duplicate_utf8 NULL
	#define oclru_lower_leet_common NULL
	#define oclru_lower_leet_ucs NULL
	#define oclru_lower_leet_utf8 NULL
	#define end_brace NULL
	#define ocl_write_leet_consts NULL
	#define oclru_cap_leet_common NULL
	#define oclru_capitalize_leet_ucs NULL
	#define oclru_capitalize_leet_utf8 NULL
	#define oclru_lower_upper_last_common NULL
	#define oclru_lower_upper_last_ucs NULL
	#define oclru_lower_upper_last_utf8 NULL
	#define oclru_capitalize_plus_common NULL
	#define oclru_capitalize_plus_ucs NULL
	#define oclru_capitalize_plus_utf8 NULL
	#define oclru_lower_plus_common NULL
	#define oclru_lower_append_ucs NULL
	#define oclru_lower_plus_utf8 NULL
	#define oclru_prefix_common NULL
	#define oclru_prefix_ucs NULL
	#define oclru_prefix_utf8 NULL
	#define oclru_lower_plus_year_common NULL
	#define oclru_lower_plus_year_ucs NULL
	#define oclru_lower_plus_year_utf8 NULL
	#define ocl_lower_plus_year_get_key NULL
	#define oclru_cap_plus_year_common NULL
	#define oclru_cap_plus_year_ucs NULL
	#define oclru_cap_plus_year_utf8 NULL
	#define ocl_cap_plus_year_get_key NULL
	#define oclru_lower_plus_2dig_common NULL
	#define oclru_lower_plus_2dig_ucs NULL
	#define oclru_lower_plus_2dig_utf8 NULL
	#define ocl_lower_plus_2dig_get_key NULL
	#define oclru_cap_plus_2dig_common NULL
	#define oclru_cap_plus_2digits_ucs NULL
	#define oclru_cap_plus_2dig_utf8 NULL
	#define ocl_cap_plus_2digits_get_key NULL
	#define oclru_insert_common NULL
	#define oclru_insert_ucs NULL
	#define oclru_insert_utf8 NULL
	#define oclru_remove_common NULL
	#define oclru_remove_ucs NULL
	#define oclru_remove_utf8 NULL
	#define oclru_overstrike_common NULL
	#define oclru_overstrike_ucs NULL
	#define oclru_overstrike_utf8 NULL
	#define oclru_prefix_year_common NULL
	#define oclru_prefix_year_ucs NULL
	#define oclru_prefix_year_utf8 NULL
	#define oclru_prefix_2char_common NULL
	#define oclru_prefix_2char_ucs NULL
	#define oclru_prefix_2char_utf8 NULL
	#define oclru_plus_2char_common NULL
	#define oclru_append_2char_ucs NULL
	#define oclru_append_2char_utf8 NULL
	#define oclru_plus_3char_common NULL
	#define oclru_append_3char_ucs NULL
	#define oclru_append_3char_utf8 NULL
	#define oclru_prefix_3char_common NULL
	#define oclru_prefix_3char_ucs NULL
	#define oclru_prefix_3char_utf8 NULL
	#define ocl_copy_get_key NULL
	#define ocl_lower_get_key NULL
	#define ocl_upper_get_key NULL
	#define ocl_capitalize_get_key NULL
	#define ocl_duplicate_get_key NULL
	#define ocl_lower_leet_get_key NULL
	#define ocl_capitalize_leet_get_key NULL
	#define ocl_lower_upper_last_get_key NULL
	#define ocl_capitalize_append_get_key NULL
	#define ocl_lower_append_get_key NULL
	#define ocl_prefix_get_key NULL
	#define ocl_insert_get_key NULL
	#define ocl_remove_get_key NULL
	#define ocl_overstrike_get_key NULL
	#define ocl_prefix_year_get_key NULL
	#define ocl_prefix_2char_get_key NULL
	#define ocl_append_2char_get_key NULL
	#define ocl_append_3char_get_key NULL
	#define ocl_prefix_3char_get_key NULL
#endif

#define INSERT_MULTIPLIER LENGHT_CHAR_ADDED*RULE_LENGHT_COMMON
PUBLIC Rule rules[] = {
 //																									 depend_key_lenght   key_lenght_sum																													  max_param_value  setup_constants
 // Name				Description Rule_Unicode			Rule_UTF8			 checked		multipler			|	 /  common_implementation			 Begin Unicode				Begin UTF8					   end			get_key				  found_param  |	/
 {"Copy"				, DESC_0 , {rule_copy_ucs		  , rule_copy_utf8		}, TRUE,			1			, FALSE, 0, {oclru_copy_common			  , {oclru_copy_ucs			   , oclru_copy_utf8			}, NULL		, ocl_copy_get_key				, "0", 0, NULL}},
 {"Lower"				, DESC_1 , {rule_lower_ucs		  , rule_lower_utf8		}, TRUE,			1			, FALSE, 0, {oclru_lower_common			  , {oclru_lower_ucs		   , oclru_lower_utf8			}, NULL		, ocl_lower_get_key				, "0", 0, NULL}},
 {"Upper"				, DESC_2 , {rule_upper_ucs		  , rule_upper_utf8		}, TRUE,			1			, FALSE, 0, {oclru_upper_common			  , {oclru_upper_ucs		   , oclru_upper_utf8			}, NULL		, ocl_upper_get_key				, "0", 0, NULL}},
														  	 											     												  
 {"Capitalize"			, DESC_3 , {rule_capitalize_ucs	  , rule_capitalize_utf8}, TRUE,			1			, FALSE, 0, {oclru_capitalize_common	  , {oclru_capitalize_ucs	   , oclru_capitalize_utf8		}, NULL		, ocl_capitalize_get_key		, "0", 0, NULL}},
 {"Duplicate"			, DESC_4 , {rule_duplicate_ucs	  , rule_duplicate_utf8	}, TRUE,			1			, FALSE, 0, {oclru_duplicate_common		  , {oclru_duplicate_ucs	   , oclru_duplicate_utf8		}, NULL		, ocl_duplicate_get_key			, "0", 0, NULL}},
 {"Lower+Leet"			, DESC_5 , {rule_lower_leet_ucs	  , rule_lower_leet_utf8}, TRUE, LENGTH(leet_orig)-1	, FALSE, 0, {oclru_lower_leet_common	  , {oclru_lower_leet_ucs	   , oclru_lower_leet_utf8		}, end_brace, ocl_lower_leet_get_key		, "i", 0, ocl_write_leet_consts}},
															 														    
 {"Capitalize+Leet"		, DESC_6 , {rule_cap_leet_ucs	  , rule_cap_leet_utf8	}, TRUE, LENGTH(leet_orig)-1	, FALSE, 0, {oclru_cap_leet_common		  , {oclru_capitalize_leet_ucs , oclru_capitalize_leet_utf8	}, end_brace, ocl_capitalize_leet_get_key	, "i", 0, ocl_write_leet_consts}},
 {"Lower+Upper Last"	, DESC_7 , {ru_lower_upperlast_ucs, ru_low_upperlas_utf8}, TRUE,			1			, FALSE, 0, {oclru_lower_upper_last_common, {oclru_lower_upper_last_ucs, oclru_lower_upper_last_utf8}, NULL		, ocl_lower_upper_last_get_key	, "0", 0, NULL}},
 {"Capitalize+char"		, DESC_8 , {rule_cap_append_ucs	  , rule_cap_append_utf8}, TRUE, LENGHT_CHAR_ADDED		, FALSE, 0, {oclru_capitalize_plus_common , {oclru_capitalize_plus_ucs , oclru_capitalize_plus_utf8	}, end_brace, ocl_capitalize_append_get_key	, "i", 0, NULL}},
															 									    
 {"Lower+char"			, DESC_9 , {rule_lower_append_ucs , rule_lower_plus_utf8}, TRUE, LENGHT_CHAR_ADDED		, FALSE, 0, {oclru_lower_plus_common	  , {oclru_lower_append_ucs	   , oclru_lower_plus_utf8		}, end_brace, ocl_lower_append_get_key	    , "i", 0, NULL}},
 {"char+Word"			, DESC_10, {rule_prefix_ucs		  , rule_prefix_utf8	}, TRUE, LENGHT_CHAR_ADDED		, FALSE, 0, {oclru_prefix_common		  , {oclru_prefix_ucs		   , oclru_prefix_utf8			}, end_brace, ocl_prefix_get_key			, "i", 0, NULL}},
 {"Lower+Year"			, DESC_11, {ru_lower_plus_year_ucs, r_low_plus_year_utf8}, TRUE,			130			, FALSE, 0, {oclru_lower_plus_year_common , {oclru_lower_plus_year_ucs , oclru_lower_plus_year_utf8	}, end_brace, ocl_lower_plus_year_get_key	, "i", 0, NULL}},
															 									    
 {"Capitalize+Year"		, DESC_12, {rule_cap_plus_year_ucs, r_cap_plus_year_utf8}, TRUE,			130			, FALSE, 0, {oclru_cap_plus_year_common	  , {oclru_cap_plus_year_ucs   , oclru_cap_plus_year_utf8	}, end_brace, ocl_cap_plus_year_get_key		, "i", 0, NULL}},
 {"Lower+2 Digits"		, DESC_13, {ru_lower_plus_2dig_ucs, ru_lo_plus_2dig_utf8}, TRUE,			100			, FALSE, 0, {oclru_lower_plus_2dig_common , {oclru_lower_plus_2dig_ucs , oclru_lower_plus_2dig_utf8	}, end_brace, ocl_lower_plus_2dig_get_key	, "i", 0, NULL}},
 {"Capitalize+2 Digits" , DESC_14, {rule_cap_plus_2dig_ucs, r_cap_plus_2dig_utf8}, TRUE,			100			, FALSE, 0, {oclru_cap_plus_2dig_common   , {oclru_cap_plus_2digits_ucs, oclru_cap_plus_2dig_utf8	}, end_brace, ocl_cap_plus_2digits_get_key	, "i", 0, NULL}},
															 										    
 {"Insert"				, DESC_15, {rule_insert_ucs		  , rule_insert_utf8	}, FALSE, INSERT_MULTIPLIER		, TRUE, -1, {oclru_insert_common		  , {oclru_insert_ucs		   , oclru_insert_utf8			}, end_brace, ocl_insert_get_key			, OCL_INSERT_PARAM    , RULE_LENGHT_COMMON, NULL}},
 {"Remove"				, DESC_16, {rule_remove_ucs		  , rule_remove_utf8	}, FALSE, RULE_LENGHT_COMMON	, TRUE,  0, {oclru_remove_common		  , {oclru_remove_ucs		   , oclru_remove_utf8			}, end_brace, ocl_remove_get_key			, OCL_REMOVE_PARAM    , 0, NULL}},
 {"Overstrike"			, DESC_17, {rule_overstrike_ucs	  , rule_overstrike_utf8}, FALSE, INSERT_MULTIPLIER		, TRUE,  0, {oclru_overstrike_common	  , {oclru_overstrike_ucs	   , oclru_overstrike_utf8		}, end_brace, ocl_overstrike_get_key		, OCL_OVERSTRIKE_PARAM, RULE_LENGHT_COMMON, NULL}},
														  	 							  																							   
 {"Year+Word"			, DESC_18, {rule_prefix_year_ucs  , rul_prefix_year_utf8}, FALSE,			130			, FALSE, 0, {oclru_prefix_year_common	  , {oclru_prefix_year_ucs	   , oclru_prefix_year_utf8		}, end_brace, ocl_prefix_year_get_key		, "i"	     , 0, NULL}},
 {"2 chars+Word"		, DESC_19, {rule_prefix_2char_ucs , ru_prefix_2char_utf8}, FALSE,POW2(LENGHT_CHAR_ADDED), FALSE, 0, {oclru_prefix_2char_common	  , {oclru_prefix_2char_ucs	   , oclru_prefix_2char_utf8	}, end_brace, ocl_prefix_2char_get_key		, OCL_2_CHARS, LENGHT_CHAR_ADDED, NULL}},
 {"Word+2 chars"		, DESC_20, {rule_append_2char_ucs , rule_plus_2char_utf8}, FALSE,POW2(LENGHT_CHAR_ADDED), FALSE, 0, {oclru_plus_2char_common	  , {oclru_append_2char_ucs	   , oclru_append_2char_utf8	}, end_brace, ocl_append_2char_get_key		, OCL_2_CHARS, LENGHT_CHAR_ADDED, NULL}},
														  	 									 																					   
 {"Word+3 chars"		, DESC_21, {rule_append_3char_ucs , rule_plus_3char_utf8}, FALSE,POW3(LENGHT_CHAR_ADDED), FALSE, 0, {oclru_plus_3char_common	  , {oclru_append_3char_ucs	   , oclru_append_3char_utf8	}, end_brace, ocl_append_3char_get_key		, OCL_3_CHARS, POW2(LENGHT_CHAR_ADDED), NULL}},
 {"3 chars+Word"		, DESC_22, {rule_prefix_3char_ucs , ru_prefix_3char_utf8}, FALSE,POW3(LENGHT_CHAR_ADDED), FALSE, 0, {oclru_prefix_3char_common	  , {oclru_prefix_3char_ucs	   , oclru_prefix_3char_utf8	}, end_brace, ocl_prefix_3char_get_key		, OCL_3_CHARS, POW2(LENGHT_CHAR_ADDED), NULL}}
};
// TODO: If greater than 31, rules need to change code in opencl implementation
PUBLIC int num_rules = LENGTH(rules);

////////////////////////////////////////////////////////////////////////////////////
// Common
////////////////////////////////////////////////////////////////////////////////////
PUBLIC int provider_index;
PRIVATE apply_rule_funtion** current_rules = NULL;
PUBLIC int current_rules_count;
PUBLIC int* rules_remapped = NULL;
PRIVATE generate_key_funtion* gen_keys_principal = NULL;
// Mutex for thread-safe access
PRIVATE HS_MUTEX rules_mutex;

PRIVATE int64_t last_key_space;
PRIVATE int64_t last_num_keys_served_from_start;
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
	int multipler = 0;

	// Mutex for thread-safe access
	HS_CREATE_MUTEX(&rules_mutex);

	current_rules_count = param[RULE_COUNT_RULES_POS];
	current_rules = (apply_rule_funtion**)malloc(sizeof(apply_rule_funtion*) * current_rules_count);
	rules_remapped = (int*)malloc(sizeof(int)*current_rules_count);

	int USED_PROTOCOL = PROTOCOL_UTF8_COALESC_LE;
	if (formats[batch[current_attack_index].format_index].impls[0].protocol == PROTOCOL_NTLM)
		USED_PROTOCOL = PROTOCOL_NTLM;

	for (int i = 0; i < current_rules_count; i++)
	{
		int rule_index = RULE_GET(param, i);
		rules_remapped[i] = rule_index;
		current_rules[i] = (USED_PROTOCOL == PROTOCOL_NTLM) ? rules[rule_index].function[RULE_UNICODE_INDEX] : rules[rule_index].function[RULE_UTF8_LE_INDEX];
		multipler += rules[rule_index].multipler;
	}

	provider_index = RULE_GET_KEY_PROV_INDEX(param);

	for(int i = 0; i < LENGTH(key_providers[provider_index].impls); i++)
		if (key_providers[provider_index].impls[i].protocol == USED_PROTOCOL)
		{
			gen_keys_principal = key_providers[provider_index].impls[i].generate;
			break;
		}

	key_providers[provider_index].resume(pmin_lenght, pmax_lenght, param+current_rules_count+2, resume_arg, format_index);

	last_key_space = num_key_space;
	last_num_keys_served_from_start = 0;
	num_key_space *= multipler;

	// Put space needed to rules
	key_providers[RULES_INDEX].per_thread_data_size = key_providers[provider_index].per_thread_data_size + sizeof(uint32_t)*RULES_THREAD_DATA_SIZE;
	key_providers[RULES_INDEX].save_resume_arg = key_providers[provider_index].save_resume_arg;
}
// Calculate adequately the key_space
extern double wordlist_completition;
extern char* thread_params;
extern uint32_t num_thread_params;
PRIVATE int64_t* num_keys_in_memory = NULL;
PUBLIC void rules_calculate_key_space(uint32_t num_keys_original, int64_t pnum_keys_in_memory, uint32_t thread_id)
{
	HS_ENTER_MUTEX(&rules_mutex);

	if (!num_keys_in_memory)
		num_keys_in_memory = (int64_t*)calloc(num_thread_params, sizeof(int64_t));

	// Calculate adequately the key_space
	last_num_keys_served_from_start += num_keys_original;
	// TODO: Eliminate this patch: Possibly put a flag in key_provider to use
	if(num_key_space != KEY_SPACE_UNKNOW)
	{
		if(last_num_keys_served_from_start > last_key_space)
			last_key_space = last_num_keys_served_from_start;

		if (provider_index == WORDLIST_INDEX)
		{
			int64_t total_keys_in_memory = 0;

			if (thread_id < num_thread_params)
				num_keys_in_memory[thread_id] = pnum_keys_in_memory;

			for (uint32_t i = 0; i < num_thread_params; i++)
				total_keys_in_memory += num_keys_in_memory[i];

			num_key_space = (int64_t)((get_num_keys_served() + total_keys_in_memory) * wordlist_completition);
		}
		else
			num_key_space = (int64_t)(((double)get_num_keys_served())*((double)last_key_space / (double)last_num_keys_served_from_start));// We use double and parenthesis to prevent buffer overflows
	}

	HS_LEAVE_MUTEX(&rules_mutex);
}
PUBLIC void rules_report_remain_key_space(int64_t pnum_keys_in_memory, uint32_t thread_id)
{
	HS_ENTER_MUTEX(&rules_mutex);

	if (!num_keys_in_memory)
		num_keys_in_memory = (int64_t*)calloc(num_thread_params, sizeof(int64_t));

	// TODO: Eliminate this patch: Possibly put a flag in key_provider to use
	if (num_key_space != KEY_SPACE_UNKNOW)
	{
		int64_t total_keys_in_memory = 0;

		if (thread_id < num_thread_params)
			num_keys_in_memory[thread_id] = pnum_keys_in_memory;

		for (uint32_t i = 0; i < num_thread_params; i++)
			total_keys_in_memory += num_keys_in_memory[i];

		num_key_space = get_num_keys_served() + total_keys_in_memory;
	}

	HS_LEAVE_MUTEX(&rules_mutex);
}

PUBLIC int rules_gen_common(uint32_t* nt_buffer, uint32_t NUM_KEYS, int thread_id)
{
	assert(NUM_KEYS <= 256);// 512 for ut8

	uint32_t* rules_data_buffer = ((uint32_t*)(thread_params + num_thread_params*key_providers[provider_index].per_thread_data_size)) + RULES_THREAD_DATA_SIZE*thread_id;
	nt_buffer_index = 0;
	uint32_t num_orig_keys_processed = 0;

	// Initialize data
	if (!rules_data_buffer[RULES_IS_INIT_DATA_INDEX])
	{
		rules_data_buffer[RULES_IS_INIT_DATA_INDEX] = TRUE;
		rules_data_buffer[CURRENT_RULE_INDEX] = 0xffff;
		rules_data_buffer[CHAR_ADDED_INDEX] = MIN_CHAR_ADDED;
		rules_data_buffer[INSERT_POS_INDEX] = 1;
		rules_data_buffer[DIGIT1_INDEX] = 48;
		rules_data_buffer[DIGIT2_INDEX] = 48;
		rules_data_buffer[YEAR_INDEX] = 0;
		rules_data_buffer[CHAR_ADDED0_INDEX] = MIN_CHAR_ADDED;
		rules_data_buffer[CHAR_ADDED1_INDEX] = MIN_CHAR_ADDED;
		rules_data_buffer[CHAR_ADDED2_INDEX] = MIN_CHAR_ADDED;
	}
	int current_rule_index = rules_data_buffer[CURRENT_RULE_INDEX];

	do{
		// If finish applying rules to current chunk->get a new one
		if(current_rule_index >= current_rules_count)
		{
			if(!gen_keys_principal(rules_nt_buffer, NUM_KEYS, thread_id))
				goto end;

			current_rule_index = 0;
			rules_nt_buffer_index = 0;
			num_orig_keys_processed = NUM_KEYS;
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

	// Calculate the number of keys in memory
	int64_t num_keys_in_memory = 0;
	if (current_rule_index < current_rules_count)
		num_keys_in_memory += __min(NUM_KEYS, NUM_KEYS - rules_nt_buffer_index)*rules[rules_remapped[current_rule_index]].multipler;
	for (int i = current_rule_index + 1; i < current_rules_count; i++)
		num_keys_in_memory += NUM_KEYS*rules[rules_remapped[i]].multipler;

	rules_calculate_key_space(num_orig_keys_processed, num_keys_in_memory, thread_id);

	return nt_buffer_index;
}

//// TODO: add AVX, AVX2 and Neon code
//typedef void convert_ntlm_2_utf8_coalesc_func(uint32_t* nt_buffer, uint32_t NUM_KEYS);
//#ifndef _M_X64
//PRIVATE void convert_ntlm_2_utf8_coalesc_le_c_code(uint32_t* nt_buffer, uint32_t NUM_KEYS)
//{
//	for (uint32_t i = 0; i < NUM_KEYS; i++, nt_buffer++)
//	{
//		uint32_t val0 = nt_buffer[0 * NUM_KEYS];
//		uint32_t val1 = nt_buffer[1 * NUM_KEYS];
//		nt_buffer[0 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		val0 = nt_buffer[2 * NUM_KEYS];
//		val1 = nt_buffer[3 * NUM_KEYS];
//		nt_buffer[1 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		val0 = nt_buffer[4 * NUM_KEYS];
//		val1 = nt_buffer[5 * NUM_KEYS];
//		nt_buffer[2 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		val0 = nt_buffer[6 * NUM_KEYS];
//		val1 = nt_buffer[7 * NUM_KEYS];
//		nt_buffer[3 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		val0 = nt_buffer[8 * NUM_KEYS];
//		val1 = nt_buffer[9 * NUM_KEYS];
//		nt_buffer[4 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		val0 = nt_buffer[10 * NUM_KEYS];
//		val1 = nt_buffer[11 * NUM_KEYS];
//		nt_buffer[5 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		val0 = nt_buffer[12 * NUM_KEYS];
//		val1 = nt_buffer[13 * NUM_KEYS];
//		nt_buffer[6 * NUM_KEYS] = (val0 & 0xff) + (val0 >> 8) + (val1 << 16) + ((val1 << 8) & 0xff000000);
//
//		nt_buffer[7 * NUM_KEYS] = nt_buffer[14 * NUM_KEYS] >> 1;
//	}
//}
//#endif
//#include "arch_simd.h"
//PRIVATE void convert_ntlm_2_utf8_coalesc_le_v128(V128_WORD* nt_buffer, uint32_t NUM_KEYS)
//{
//	NUM_KEYS /= 4;
//	V128_WORD ff = V128_CONST(0xff);
//	V128_WORD ff000000 = V128_CONST(0xff000000);
//
//	for (uint32_t i = 0; i < NUM_KEYS; i++, nt_buffer++)
//	{
//		V128_WORD val0 = nt_buffer[0 * NUM_KEYS];
//		V128_WORD val1 = nt_buffer[1 * NUM_KEYS];
//		nt_buffer[0 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		val0 = nt_buffer[2 * NUM_KEYS];
//		val1 = nt_buffer[3 * NUM_KEYS];
//		nt_buffer[1 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		val0 = nt_buffer[4 * NUM_KEYS];
//		val1 = nt_buffer[5 * NUM_KEYS];
//		nt_buffer[2 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		val0 = nt_buffer[6 * NUM_KEYS];
//		val1 = nt_buffer[7 * NUM_KEYS];
//		nt_buffer[3 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		val0 = nt_buffer[8 * NUM_KEYS];
//		val1 = nt_buffer[9 * NUM_KEYS];
//		nt_buffer[4 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		val0 = nt_buffer[10 * NUM_KEYS];
//		val1 = nt_buffer[11 * NUM_KEYS];
//		nt_buffer[5 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		val0 = nt_buffer[12 * NUM_KEYS];
//		val1 = nt_buffer[13 * NUM_KEYS];
//		nt_buffer[6 * NUM_KEYS] = SSE2_4ADD(V128_AND(val0, ff), V128_SR(val0, 8), V128_SL(val1, 16), V128_AND(V128_SL(val1, 8), ff000000));
//
//		nt_buffer[7 * NUM_KEYS] = V128_SR(nt_buffer[14 * NUM_KEYS], 1);
//	}
//}

PUBLIC void rules_finish()
{
	HS_DELETE_MUTEX(&rules_mutex);
	key_providers[provider_index].finish();

	free(current_rules);
	free(rules_remapped);
	free(num_keys_in_memory);

	current_rules = NULL;
	rules_remapped = NULL;
	num_keys_in_memory = NULL;
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
