// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include "sqlite3.h"
#include "common.h"
#include "sql.h"
#include "compilation_flags.h"

void register_in_out();
void init_attack_data();
void detect_hardware();
PRIVATE void load_settings_from_db();
PRIVATE void load_cache();
void fill_bits();
#ifdef HS_OPENCL_SUPPORT
void init_opencl();
#endif

PUBLIC sqlite3* db = NULL;

// Formats supported by the program
extern Format ntlm_format;
extern Format mscash_format;
extern Format lm_format;
#ifdef INCLUDE_DCC2
extern Format dcc2_format;
#endif
PUBLIC Format formats[MAX_NUM_FORMATS];
PUBLIC int num_formats = 0;


// Map to convert hexadecimal char into his corresponding value
PUBLIC unsigned char hex_to_num[256];

#ifndef _WIN32
PUBLIC unsigned char* _strupr(unsigned char* string)
{
	unsigned char* ptr = string;
	for (; *ptr; ptr++)
		*ptr = toupper(*ptr);
	return string;
}
PUBLIC unsigned char* _strlwr(unsigned char* string)
{
	unsigned char* ptr = string;
	for (; *ptr; ptr++)
		*ptr = tolower(*ptr);
	return string;
}
#include <sys/stat.h>
PUBLIC long long _filelengthi64(int file)
{
    struct stat st;

    if (fstat(file, &st) == 0)
        return st.st_size;

    return 0;//-1
}

PUBLIC inline __attribute__((always_inline)) unsigned int _rotl(unsigned int v, unsigned int sh)
{
  return ((v<<sh) | (v>>(32-sh)));
}
PUBLIC void _BitScanReverse(unsigned int* index, unsigned int v)
{
	unsigned int r = 0; // r will be lg(v)

	while (v >>= 1) // unroll for more speed...
		r++;
	*index = r;
}
PUBLIC void _BitScanForward(unsigned int* index, unsigned int v)
{
	unsigned int r = 0; // r will be lg(v)

	if (v)
		for (; (v & 1)==0; v>>=1, r++);
	*index = r;
}

#endif

// Conversion from division by a constant to a multiplication by a constant and a shift
PUBLIC DivisionParams get_div_params(unsigned int divisor)
{
	DivisionParams result;
	unsigned int i, r = 32;
	double f = 1;

	// Find significant bits of divisor
	_BitScanReverse(&result.shift, divisor);
	r += result.shift;
	//r = 32;// To not use shift

	 // If divisor is not a power of 2
	if((divisor & (divisor - 1)))
	{
		// f = 2^r/d
		for(i = 0; i < r; i++, f *= 2);
		f /= divisor;

		// Handle two cases
		if(f - ((uint64_t)f) < 0.5)
		{
			result.sum_one = TRUE;
			result.magic = (unsigned int)f;
		}
		else
		{
			result.sum_one = FALSE;
			result.magic = (unsigned int)(f+1);
		}
	}
	else
	{
		result.sum_one = FALSE;
		result.magic = 0;
	}

	return result;
}
// Testing of good division
//{
//	unsigned int64_t i;
//	//DivisionParams div_param = get_div_params(10);
//	//div_param.sum_one++;
//	for (i = 0; i < 120; i++)
//	{
//		unsigned int rem, div = (i*429496730u) >> 32;
//		rem = i - div * 10;
//		if (i%10 != rem || i/10 != div)
//		{
//			i++;
//		}
//	}
//	i++;
//}

// Path of the executable
PRIVATE char full_path[FILENAME_MAX];
PRIVATE int dir_index;

PUBLIC Format* find_format(sqlite3_int64 db_id)
{
	int i = 0;

	for(; i < num_formats; i++)
		if(formats[i].db_id == db_id)
			return formats + i;

	return NULL;
}
PUBLIC KeyProvider* find_key_provider(sqlite3_int64 db_id)
{
	int i = 0;

	for(; i<num_key_providers; i++)
		if(key_providers[i].db_id == db_id)
			return key_providers + i;

	return NULL;
}
PUBLIC int find_format_index(sqlite3_int64 db_id)
{
	int i = 0;

	for(; i < num_formats; i++)
		if(formats[i].db_id == db_id)
			return i;

	return -1;
}
PUBLIC int find_key_provider_index(sqlite3_int64 db_id)
{
	int i = 0;

	for(; i < num_key_providers; i++)
		if(key_providers[i].db_id == db_id)
			return i;

	return -1;
}
PUBLIC unsigned char* ntlm2utf8_key(unsigned int* nt_buffer, unsigned char* key,unsigned int NUM_KEYS, unsigned int index)
{
	int lenght = nt_buffer[14*NUM_KEYS+index] >> 4;
	int j = 0;

	for(; j < lenght; j++)
		key[j] = (j%2) ? (nt_buffer[j/2*NUM_KEYS+index] >> 16) : nt_buffer[j/2*NUM_KEYS+index];

	key[lenght] = 0;

	return key;
}
PUBLIC int valid_hex_string(unsigned char* ciphertext, int lenght)
{
    int pos = 0;

	if(strlen((char*)ciphertext) != lenght)
		return FALSE;

    for (; pos < lenght; pos++)
		if(!isxdigit(ciphertext[pos]))
			return FALSE;

	return TRUE;
}
PUBLIC int src_contained_in(const char* src, const char* container)
{
	int i,j;

	for(i = 0; src[i]; i++)
		for(j = 0; ; j++)
		{
			if(!container[j])
				return FALSE;

			if(src[i] == container[j])
				break;
		}

	return TRUE;
}
// Expand filename to full path including directory of the app
PUBLIC char* get_full_path(char* filename)
{
	strcpy(full_path + dir_index, filename);

	return full_path;
}
PUBLIC int is_charset_consecutive(unsigned char* charset)
{
	unsigned char min_val = 255;
	unsigned int i,j;

	// Find the minimum char value
	for (i = 0; i < strlen(charset); i++)
		if(charset[i] < min_val)
			min_val = charset[i];

	// Search that all consecutive characters exist
	for (i = 0; i < strlen(charset); i++)
	{
		int found_val = FALSE;
		for (j = 0; j < strlen(charset); j++)
			if(min_val+i == charset[j])
			{
				found_val = TRUE;
				break;
			}
		
		if(!found_val)	return FALSE;
	}

	return min_val;
}
PUBLIC unsigned int get_bit_table_mask(unsigned int num_passwords_loaded, uint64_t l1_size, uint64_t l2_size)
{
	int i;
	unsigned int result = 1;
	int num_bytes_bit_table;

	// Generate result with all bits less than
	// first bit in num_elem in 1
	while(result < num_passwords_loaded)
		result = (result << 1) + 1;

	// 4 bits more into account
	for(i = 0; i < 4; i++)
		result = (result << 1) + 1;

	if(l1_size==0 || l2_size==0)
		return result;

	// Calculate size
	num_bytes_bit_table = sizeof(unsigned int) * (result/32+1);

	// Bit_table overflow L2 cache
	if(num_bytes_bit_table > 4*l2_size)
		return (result << 2) + 3;
	// Bit_table is at limit of L2 cache
	//if(num_bytes_bit_table >= l2_size/4)
	//	result >>= 1;
	// Bit_table is at limit of L2 cache
	if(num_bytes_bit_table >= l2_size/2)
		return result >> 1;

	num_bytes_bit_table = (int)log((double)l2_size/num_bytes_bit_table/8);
	if(num_bytes_bit_table >= 8 )
		num_bytes_bit_table--;

	for(i = 0; i < num_bytes_bit_table; i++)
		result = (result << 1) + 1;

	return result;
}
// Create the hexadecimal map
PRIVATE void hex_init()
{
	memset(hex_to_num, NOT_HEX_CHAR, sizeof(hex_to_num));

	hex_to_num['0'] = 0;
	hex_to_num['1'] = 1;
	hex_to_num['2'] = 2;
	hex_to_num['3'] = 3;
	hex_to_num['4'] = 4;
	hex_to_num['5'] = 5;
	hex_to_num['6'] = 6;
	hex_to_num['7'] = 7;
	hex_to_num['8'] = 8;
	hex_to_num['9'] = 9;

	hex_to_num['A'] = hex_to_num['a'] = 10;
	hex_to_num['B'] = hex_to_num['b'] = 11;
	hex_to_num['C'] = hex_to_num['c'] = 12;
	hex_to_num['D'] = hex_to_num['d'] = 13;
	hex_to_num['E'] = hex_to_num['e'] = 14;
	hex_to_num['F'] = hex_to_num['f'] = 15;
}
PRIVATE void formats_init(int db_already_initialize)
{
	int i;

	formats[LM_INDEX] = lm_format;
	formats[NTLM_INDEX] = ntlm_format;
	formats[DCC_INDEX] = mscash_format;
	num_formats = 3;
#ifdef INCLUDE_DCC2
	formats[DCC2_INDEX] = dcc2_format;
	num_formats++;
#endif

	if (!db_already_initialize)
	{
		sqlite3_stmt* insert;
		// Formats in database
		sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO FORMAT (ID, Name, Description) VALUES (?, ?, ?);", -1, &insert, NULL);

		for (i = 0; i < num_formats; i++)
		{
			// Ensures all formats are in the db
			sqlite3_reset(insert);
			sqlite3_bind_int64(insert, 1, formats[i].db_id);
			sqlite3_bind_text(insert, 2, formats[i].name, -1, SQLITE_STATIC);
			sqlite3_bind_text(insert, 3, formats[i].description, -1, SQLITE_STATIC);
			sqlite3_step(insert);
		}

		sqlite3_finalize(insert);
	}
}

// Initialize all data needed by app
PUBLIC void init_all(const char* program_exe_path)
{
	char* db_path = NULL;
	FILE* db_file = NULL;
	int db_already_exits = FALSE;
	detect_hardware();

	// Save path of program
	if (program_exe_path)
	{
		dir_index = (int)(strrchr(program_exe_path, PATH_SEPARATOR) - program_exe_path + 1);
		strncpy(full_path, program_exe_path, dir_index);
	}
	else
	{
		full_path[0] = 0;
		dir_index = 0;
	}

	db_path = get_full_path(DB_FILE);
	
	// Check if the db exits
	db_file = fopen(db_path, "rb");
	if (db_file)
	{
		db_already_exits = TRUE;
		fclose(db_file);
	}

	// Database
	sqlite3_open(db_path, &db);

	BEGIN_TRANSACTION;

	if (!db_already_exits)
		sqlite3_exec(db, CREATE_SCHEMA, NULL, NULL, NULL);

	hex_init();
	register_in_out();
	register_key_providers(db_already_exits);
	formats_init(db_already_exits);
	init_attack_data();

	END_TRANSACTION;

	load_settings_from_db();
	load_cache();
	fill_bits();
#ifdef HS_OPENCL_SUPPORT
	init_opencl();
#endif
}

// Get info formatted
PRIVATE char buffer[1024];
PUBLIC char* get_work_done()
{
	if(get_key_space_batch() == KEY_SPACE_UNKNOW)
		strcpy(buffer, "Unknown");
	else if(get_key_space_batch() == 0)
		strcpy(buffer, "100%");
	else
		sprintf(buffer, "%i%%", (int)(get_num_keys_served() * 100 / get_key_space_batch()));

	return buffer;
}
PRIVATE char* format_time(int64_t seconds)
{
	if(seconds < 0) seconds = 0;

	if(seconds > 3153600000ll)// 100 year (year have 365 days)
	{
		strcpy(buffer, ">100 years");
	}
	else if(seconds > 2*31536000)// 2 year (year have 365 days)
	{
		sprintf(buffer, "%.1f years", seconds / 31536000.);
	}
	else if(seconds >= 25920000)// 10 months (month have 30 days)
	{
		sprintf(buffer, "%.0f months", seconds / 2592000.);
	}
	else if(seconds > 2*2592000)// 2 months (month have 30 days)
	{
		sprintf(buffer, "%.1f months", seconds / 2592000.);
	}
	else if(seconds > 2*86400)// 2 days
	{
		sprintf(buffer, "%.1f days", seconds / 86400.);
	}
	else
	{
		int i = 6;
		for(; i >= 0; i -= 3, seconds /= 60)
			sprintf(buffer + i, "%02i", (int)(seconds%60));

		buffer[8] = 0;
		buffer[2] = ':';
		buffer[5] = ':';
	}

	return buffer;
}
PUBLIC char* get_time_from_begin(int isTotal)
{
	return format_time(SECONDS_SINCE(start_time) + (isTotal ? batch[current_attack_index].secs_before_this_attack : 0));
}
PUBLIC char* finish_time()
{
	if(get_key_space_batch() == KEY_SPACE_UNKNOW)
		strcpy(buffer, "Unknown");
	else
	{
		double time_in_sec = (double)(clock() - save_time) / CLOCKS_PER_SEC;
		int64_t _secs = (int64_t)(num_keys_served_from_save ? 
			((get_key_space_batch() - num_keys_served_from_start - num_keys_served_from_save) * time_in_sec / num_keys_served_from_save) : 
			((get_key_space_batch() - num_keys_served_from_start - num_keys_served_from_save) * time_in_sec));
		format_time(_secs);
	}

	return buffer;
}
PUBLIC char* password_per_sec()
{
	double time_in_sec = (double)(clock() - save_time) / CLOCKS_PER_SEC;
	int64_t num_per_sec = (int64_t)(num_keys_served_from_save / time_in_sec);

	if(num_per_sec >= 100000000000l)
		sprintf(buffer, "%.0fG", num_per_sec/1000000000.);
	else if(num_per_sec >= 10000000000l)
		sprintf(buffer, "%.1fG", num_per_sec/1000000000.);
	else if(num_per_sec >= 1000000000)
		sprintf(buffer, "%.2fG", num_per_sec/1000000000.);
	else if(num_per_sec >= 100000000)
		sprintf(buffer, "%.0fM", num_per_sec/1000000.);
	else if(num_per_sec >= 10000000)
		sprintf(buffer, "%.1fM", num_per_sec/1000000.);
	else if(num_per_sec >= 1000000)
		sprintf(buffer, "%.2fM", num_per_sec/1000000.);
	else if(num_per_sec >= 100000)
		sprintf(buffer, "%.0fK", num_per_sec/1000.);
	else if(num_per_sec >= 10000)
		sprintf(buffer, "%.1fK", num_per_sec/1000.);
	else if(num_per_sec >= 1000)
		sprintf(buffer, "%.2fK", num_per_sec/1000.);
	else
		sprintf(buffer, "%lli", num_per_sec);

	return buffer;
}
PUBLIC void itoaWithDigitGrouping(int64_t number, char* str)
{
	int len, skip, num_comas;

	//_i64toa(number, buffer, 10);
	sprintf(buffer, "%lli", number);

	len = (int)strlen(buffer);
	skip = (len%3) ? (len%3) : 3;

	strncpy(str, buffer, skip);
	str[skip] = 0;

	for(num_comas = (len-1)/3; num_comas > 0; num_comas--, skip += 3)
	{
		strcat(str,",");
		strncat(str, buffer + skip, 3);
	}
}
PUBLIC void filelength2string(int64_t length, char* str)
{
	if(length >= 107374182400ll)
		sprintf(str, "%.0f GB", length/1073741824.);
	else if(length >= 1073741824)
		sprintf(str, "%.1f GB", length/1073741824.);
	else if(length >= 104857600)
		sprintf(str, "%.0f MB", length/1048576.);
	else if(length >= 1048576)
		sprintf(str, "%.1f MB", length/1048576.);
	else if(length >= 102400)
		sprintf(str, "%.0f KB", length/1024.);
	else if(length >= 1024)
		sprintf(str, "%.1f KB", length/1024.);
	else
		sprintf(str, "%lli B", length);
}

// Settings
PRIVATE int* save_setting_ids	 = NULL;
PRIVATE int* save_setting_values = NULL;
PRIVATE int count_settings_saved = 0;
PRIVATE int setting_capacity = 16;

PUBLIC void save_setting(int id, int value)
{
	int i = 0;

	// First call initialize settings
	if(!save_setting_ids)
	{
		save_setting_ids	= (int*)malloc(setting_capacity * sizeof(int));
		save_setting_values = (int*)malloc(setting_capacity * sizeof(int));
	}
	
	for(; i < count_settings_saved; i++)
		if(save_setting_ids[i] == id)
		{
			save_setting_values[i] = value;
			return;
		}

	save_setting_ids[count_settings_saved] = id;
	save_setting_values[count_settings_saved] = value;
	count_settings_saved++;

	// If it is full --> grow
	if(count_settings_saved == setting_capacity)
	{
		setting_capacity *= 2;

		save_setting_ids	= (int*)realloc(save_setting_ids	, setting_capacity * sizeof(int));
		save_setting_values = (int*)realloc(save_setting_values , setting_capacity * sizeof(int));
	}
}
PUBLIC void save_settings_to_db()
{
	if (db)
	{
		int i = 0;
		sqlite3_stmt* _update_settings;

		sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO Settings (ID, Value) VALUES (?, ?);", -1, &_update_settings, NULL);

		BEGIN_TRANSACTION;

		for (; i < count_settings_saved; i++)
		{
			sqlite3_reset(_update_settings);
			sqlite3_bind_int(_update_settings, 1, save_setting_ids[i]);
			sqlite3_bind_int(_update_settings, 2, save_setting_values[i]);
			sqlite3_step(_update_settings);
		}

		END_TRANSACTION;

		sqlite3_finalize(_update_settings);
	}
}
PRIVATE void load_settings_from_db()
{
	sqlite3_stmt* _select_settings;

	sqlite3_prepare_v2(db, "SELECT ID,Value FROM Settings;" , -1, &_select_settings, NULL);
	
	while(sqlite3_step(_select_settings) == SQLITE_ROW)
		save_setting(sqlite3_column_int(_select_settings, 0), sqlite3_column_int(_select_settings, 1));

	sqlite3_finalize(_select_settings);
}
PUBLIC int get_setting(int id, int default_value)
{
	int i = 0;

	for(; i < count_settings_saved; i++)
		if(save_setting_ids[i] == id)
			return save_setting_values[i];

	return default_value;
}

// Cache
// TODO: Unified all this cache in a struct
PUBLIC int* num_hashes_by_formats = NULL;
PUBLIC int* num_hashes_found_by_format = NULL;
PUBLIC int* num_user_by_formats = NULL;

PRIVATE void load_cache()
{
	sqlite3_stmt* _countHashFormat;
	sqlite3_stmt* _countHashFoundFormat;
	sqlite3_stmt* _countUserFormat;
	int i = 0;

	// Cache
	num_hashes_by_formats		= (int*)calloc(num_formats, sizeof(int));
	num_hashes_found_by_format	= (int*)calloc(num_formats, sizeof(int));
	num_user_by_formats			= (int*)calloc(num_formats, sizeof(int));

	// Count hash by formats
	sqlite3_prepare_v2(db, "SELECT count(*) FROM Hash WHERE Type=?;", -1, &_countHashFormat, NULL);
	sqlite3_prepare_v2(db, "SELECT count(*) FROM (FindHash INNER JOIN Hash ON Hash.ID==FindHash.ID) WHERE Hash.Type=?;", -1, &_countHashFoundFormat, NULL);
	sqlite3_prepare_v2(db, "SELECT count(*) FROM (Hash INNER JOIN Account ON Account.Hash==Hash.ID) WHERE Hash.Type=?;", -1, &_countUserFormat, NULL);

	for(; i < num_formats; i++)
	{
		// Count hash
		sqlite3_reset(_countHashFormat);
		sqlite3_bind_int64(_countHashFormat, 1, formats[i].db_id);
		sqlite3_step(_countHashFormat);
		num_hashes_by_formats[i] = sqlite3_column_int(_countHashFormat, 0);

		// Count found hash
		sqlite3_reset(_countHashFoundFormat);
		sqlite3_bind_int64(_countHashFoundFormat, 1, formats[i].db_id);
		sqlite3_step(_countHashFoundFormat);
		num_hashes_found_by_format[i] = sqlite3_column_int(_countHashFoundFormat, 0);

		// Count users
		sqlite3_reset(_countUserFormat);
		sqlite3_bind_int64(_countUserFormat, 1, formats[i].db_id);
		sqlite3_step(_countUserFormat);
		num_user_by_formats[i] = sqlite3_column_int(_countUserFormat, 0);
	}

	sqlite3_finalize(_countHashFormat);
	sqlite3_finalize(_countHashFoundFormat);
	sqlite3_finalize(_countUserFormat);

	// Give to LM a special treatment
	sqlite3_prepare_v2(db, "SELECT count(*) FROM AccountLM;", -1, &_countUserFormat, NULL);
	sqlite3_step(_countUserFormat);
	num_user_by_formats[LM_INDEX] = sqlite3_column_int(_countUserFormat, 0);
	sqlite3_finalize(_countUserFormat);
}
PUBLIC int total_num_hashes_found()
{
	int _result = 0;
	int i = 0;

	for(; i < num_formats; i++)
		_result += num_hashes_found_by_format[i];

	return _result ;
}
PUBLIC int has_hashes(int format_index)
{
	return num_hashes_by_formats[format_index];
}
// All hashes was found for a specific format?
PUBLIC int is_found_all_hashes(int format_index)
{
	return num_hashes_found_by_format[format_index] < num_hashes_by_formats[format_index];
}

PUBLIC void clear_db_accounts()
{
	// Delete all
	sqlite3_exec(db, "DELETE FROM Attack;DELETE FROM Batch;DELETE FROM BatchAttack;DELETE FROM FindHash;DELETE FROM Hash;DELETE FROM TagAccount;DELETE FROM Tag;DELETE FROM AccountLM;DELETE FROM Account;", NULL, NULL, NULL);
	sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);

	// Put cache in 0
	memset(num_hashes_by_formats, 0, num_formats*sizeof(int));
	memset(num_hashes_found_by_format, 0, num_formats*sizeof(int));
	memset(num_user_by_formats, 0, num_formats*sizeof(int));
}
