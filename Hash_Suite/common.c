// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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
extern Format lm_format;
extern Format ntlm_format;
extern Format raw_md5_format;

extern Format raw_sha1_format;
extern Format raw_sha256_format;
extern Format raw_sha512_format;

extern Format dcc_format;
extern Format dcc2_format;
extern Format wpa_format;

extern Format bcrypt_format;
extern Format ssha_format;
extern Format md5crypt_format;

extern Format sha256crypt_format;
extern Format sha512crypt_format;
#ifdef INCLUDE_DEVELOPING_FORMAT
extern Format <name>_format;
#endif

PUBLIC Format formats[MAX_NUM_FORMATS];
PUBLIC int num_formats = 0;

// Bench
#ifdef __ANDROID__
PRIVATE int bench_values_raw[] = { 1, 10, 100, 1000, 10000, 100000 };
#else
PRIVATE int bench_values_raw[]  = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000 };
#endif
PRIVATE int bench_values_salt[] = { 1, 4, 16, 64 };

// Map to convert hexadecimal char into his corresponding value
PUBLIC unsigned char hex_to_num[256];
PUBLIC unsigned char base64_to_num[256];
PUBLIC char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#ifdef _WIN32
#include <Windows.h>
PRIVATE LARGE_INTEGER clock_freq;
PUBLIC int64_t get_milliseconds()
{
	LARGE_INTEGER _now;
	QueryPerformanceCounter(&_now);

	return (_now.QuadPart + clock_freq.QuadPart / 2) / clock_freq.QuadPart;
}
#else
#include <time.h>
#include <sys/times.h>
PUBLIC int64_t get_milliseconds()
{
	struct timespec _now;

	clock_gettime(CLOCK_MONOTONIC, &_now);

	return ((int64_t)_now.tv_sec)*1000 + (_now.tv_nsec+500000)/1000000;
}
// Compares n characters of two strings, ignoring case.
PUBLIC int _strnicmp(char* string0, char* string1, int count)
{
	for (int i = 0; i < count; i++)
	{
		int char0 = tolower(string0[i]);
		int char1 = tolower(string1[i]);

		if(char0 != char1)
			return (char0 < char1) ? -1 : 1;
	}

	return 0;
}
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

PUBLIC inline __attribute__((always_inline)) uint32_t _rotl(uint32_t v, uint32_t sh)
{
  return ((v<<sh) | (v>>(32-sh)));
}

PUBLIC inline __attribute__((always_inline)) uint64_t _rotl64(uint64_t v, uint32_t sh)
{
  return ((v<<sh) | (v>>(64-sh)));
}
PUBLIC void _BitScanReverse(uint32_t* index, uint32_t v)
{
	uint32_t r = 0; // r will be lg(v)

	while (v >>= 1) // unroll for more speed...
		r++;
	*index = r;
}
PUBLIC void _BitScanForward(uint32_t* index, uint32_t v)
{
	uint32_t r = 0; // r will be lg(v)

	if (v)
		for (; (v & 1)==0; v>>=1, r++);
	*index = r;
}

#endif

PUBLIC uint32_t is_power_2(uint32_t x)
{
	return (x && !(x & (x - 1)));
}

// Greatest power of 2 <= x
PUBLIC uint32_t floor_power_2(uint32_t x)
{
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return x - (x >> 1);
}
// Small power of 2 >= x
PUBLIC uint32_t ceil_power_2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	return x + 1;
}

// Conversion from division by a constant to a multiplication by a constant and a shift
PUBLIC DivisionParams get_div_params(uint32_t divisor)
{
	DivisionParams result;
	uint32_t i, r = 32;
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
			result.magic = (uint32_t)f;
		}
		else
		{
			result.sum_one = FALSE;
			result.magic = (uint32_t)(f+1);
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
//	uint32_t64_t i;
//	//DivisionParams div_param = get_div_params(10);
//	//div_param.sum_one++;
//	for (i = 0; i < 120; i++)
//	{
//		uint32_t rem, div = (i*429496730u) >> 32;
//		rem = i - div * 10;
//		if (i%10 != rem || i/10 != div)
//		{
//			i++;
//		}
//	}
//	i++;
//}
PUBLIC void remove_str(char* data, const char* pattern)
{
	char* str_found = strstr(data, pattern);
	if (str_found)
	{
		size_t len = strlen(pattern);
		memmove(str_found, str_found + len, strlen(str_found) - len + 1);
	}
}

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
	for(int i = 0; i < num_formats; i++)
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
PUBLIC void swap_endianness_array(uint32_t* data, int count)
{
	for (int i = 0; i < count; i++)
		data[i] = _byteswap_ulong(data[i]);
}
PUBLIC void swap_endianness_array64(uint64_t* data, int count)
{
	for (int i = 0; i < count; i++)
		data[i] = _byteswap_uint64(data[i]);
}
PUBLIC unsigned char* ntlm2utf8_key(uint32_t* nt_buffer, unsigned char* key,uint32_t NUM_KEYS, uint32_t index)
{
	int lenght = nt_buffer[14*NUM_KEYS+index] >> 4;
	int j = 0;

	for(; j < lenght; j++)
		key[j] = (j%2) ? (nt_buffer[j/2*NUM_KEYS+index] >> 16) : nt_buffer[j/2*NUM_KEYS+index];

	key[lenght] = 0;

	return key;
}
PUBLIC unsigned char* utf8_coalesc2utf8_key(uint32_t* nt_buffer, unsigned char* key, uint32_t NUM_KEYS, uint32_t index)
{
	uint32_t len = nt_buffer[7 * NUM_KEYS + index] >> 3;
	for (uint32_t j = 0; j < (len / 4 + 1); j++)
		((uint32_t*)key)[j] = nt_buffer[j * NUM_KEYS + index];

	key[len] = 0;
	return key;
}
PUBLIC unsigned char* utf8_be_coalesc2utf8_key(uint32_t* nt_buffer, unsigned char* key, uint32_t NUM_KEYS, uint32_t index)
{
	uint32_t len = nt_buffer[7 * NUM_KEYS + index] >> 3;
	for (uint32_t j = 0; j < (len / 4 + 1); j++)
		((uint32_t*)key)[j] = _byteswap_ulong(nt_buffer[j * NUM_KEYS + index]);

	key[len] = 0;
	return key;
}
PUBLIC int valid_hex_string(unsigned char* ciphertext, int lenght)
{
	if (ciphertext == NULL)
		return FALSE;

	if(strlen((char*)ciphertext) != lenght)
		return FALSE;

    for (int pos = 0; pos < lenght; pos++)
		if(!isxdigit(ciphertext[pos]))
			return FALSE;

	return TRUE;
}
PUBLIC int valid_base64_string(unsigned char* ciphertext, int lenght)
{
	if (ciphertext == NULL)
		return FALSE;

	if(strlen((char*)ciphertext) != lenght)
		return FALSE;

    for (int pos = 0; pos < lenght; pos++)
		if(base64_to_num[ciphertext[pos]] == NOT_HEX_CHAR)
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
PUBLIC void binary_to_hex(const uint32_t* binary, unsigned char* ciphertext, uint32_t num_dwords, int is_big_endian)
{
	for (uint32_t i = 0; i < num_dwords; i++)
	{
		uint32_t val = is_big_endian ? _byteswap_ulong(binary[i]) : binary[i];
		sprintf((char*)ciphertext + i * 8, "%08X", val);
	}

	ciphertext[num_dwords * 8] = 0;
}
/*********************************************************************
* Encode functions for mime base-64
*********************************************************************/
PRIVATE const char *itoa64m = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
PRIVATE void enc_base64_1(char *out, uint32_t val, uint32_t cnt)
{
	while (cnt--)
	{
		uint32_t v = (val & 0xFC0000) >> 18;
		val <<= 6;
		*out++ = itoa64m[v];
	}
}
PUBLIC void base64_encode_mime(const unsigned char *in, int len, char *outy)
{
	int mod = len % 3;
	uint32_t u;

	for (int i = 0; i * 3 < len; ++i)
	{
		if ((i + 1) * 3 >= len)
		{
			switch (mod)
			{
			case 0:
				u = ((((uint32_t)in[i * 3]) << 16) | (((uint32_t)in[i * 3 + 1]) << 8) | (((uint32_t)in[i * 3 + 2])));
				enc_base64_1(outy, u, 4);
				outy[4] = 0;
				break;
			case 1:
				u = ((uint32_t)in[i * 3]) << 16;
				enc_base64_1(outy, u, 2);
				outy[2] = 0;
				break;
			case 2:
				u = (((uint32_t)in[i * 3]) << 16) | (((uint32_t)in[i * 3 + 1]) << 8);
				enc_base64_1(outy, u, 3);
				outy[3] = 0;
				break;
			}
		}
		else
		{
			u = ((((uint32_t)in[i * 3]) << 16) | (((uint32_t)in[i * 3 + 1]) << 8) | (((uint32_t)in[i * 3 + 2])));
			enc_base64_1(outy, u, 4);
		}
		outy += 4;
	}
	if (mod && len)
	{
		outy -= 4;
		switch (mod)
		{
		case 1: strcpy(&outy[2], "=="); break;
		case 2: strcpy(&outy[3], "="); break;
		}
	}
	if (len == 0) outy[0] = 0;
}
// Decode
PRIVATE void base64_unmap(unsigned char* in_block)
{
	for (int i = 0; i < 4; i++)
	{
		unsigned char* c = in_block + i;

		if (*c >= 'A' && *c <= 'Z')
		{
			*c -= 'A';
			continue;
		}

		if (*c >= 'a' && *c <= 'z')
		{
			*c -= 'a';
			*c += 26;
			continue;
		}

		if (*c == '+')
		{
			*c = 62;
			continue;
		}

		if (*c == '/')
		{
			*c = 63;
			continue;
		}

		if (*c >= '0' && *c <= '9')
		{
			*c -= '0';
			*c += 52;
			continue;
		}
		/* ignore trailing trash (if there were no '=' values */
		*c = 0;
	}
}
PUBLIC int base64_decode_mime(const char* base64, int inlen, unsigned char* bin)
{
	char temp[4];

	const char* in_block = base64;
	unsigned char* out_block = bin;
	int bin_size = 0;
	
	for (int i = 0; i < inlen; i += 4)
	{
		if (*in_block == '=')
			return bin_size;

		memcpy(temp, in_block, 4);
		base64_unmap(temp);

		out_block[0] = ((temp[0] << 2) & 0xfc) | ((temp[1] >> 4) & 3);
		out_block[1] = ((temp[1] << 4) & 0xf0) | ((temp[2] >> 2) & 0xf);
		out_block[2] = ((temp[2] << 6) & 0xc0) | ((temp[3]) & 0x3f);

		out_block += 3;
		bin_size += 3;
		if (in_block[2] == '=') return bin_size - 2;
		if (in_block[3] == '=') return bin_size - 1;
		in_block += 4;
	}

	return bin_size;
}

// Expand filename to full path including directory of the app
PUBLIC char* get_full_path(char* filename)
{
	strcpy(full_path + dir_index, filename);

	return full_path;
}
PUBLIC uint32_t is_charset_consecutive(unsigned char* charset)
{
	unsigned char min_val = 255;
	uint32_t i,j;

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
PUBLIC uint32_t get_bit_table_mask(uint32_t num_passwords_loaded, uint64_t l1_size, uint64_t l2_size)
{
	int i;
	uint32_t result = 1;
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
	num_bytes_bit_table = sizeof(uint32_t) * (result/32+1);

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

	memset(base64_to_num, NOT_HEX_CHAR, sizeof(base64_to_num));
	for (uint32_t pos = 0; pos < 64; pos++)
		base64_to_num[itoa64[pos]] = pos;
}
PRIVATE void formats_init(int db_already_initialize)
{
	formats[LM_INDEX] = lm_format;
	formats[NTLM_INDEX] = ntlm_format;
	formats[MD5_INDEX] = raw_md5_format;

	formats[SHA1_INDEX] = raw_sha1_format;
	formats[SHA256_INDEX] = raw_sha256_format;
	formats[SHA512_INDEX] = raw_sha512_format;

	formats[DCC_INDEX] = dcc_format;
	formats[DCC2_INDEX] = dcc2_format;
	formats[WPA_INDEX] = wpa_format;

	formats[BCRYPT_INDEX] = bcrypt_format;
	formats[SSHA_INDEX] = ssha_format;
	formats[MD5CRYPT_INDEX] = md5crypt_format;

	formats[SHA256CRYPT_INDEX] = sha256crypt_format;
	formats[SHA512CRYPT_INDEX] = sha512crypt_format;
	num_formats = 14;
#ifdef INCLUDE_DEVELOPING_FORMAT
	formats[<name>_INDEX] = <name>_format;
	num_formats++;
#endif

	// Initialize bench data
	for (int i = 0; i < num_formats; i++)
	{
		if (formats[i].salt_size)
		{
			formats[i].bench_values = bench_values_salt;
			formats[i].lenght_bench_values = LENGTH(bench_values_salt);
		}
		else
		{
			formats[i].bench_values = bench_values_raw;
			formats[i].lenght_bench_values = LENGTH(bench_values_raw);
		}
	}

	if (!db_already_initialize)
	{
		sqlite3_stmt* insert;
		// Formats in database
		sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO FORMAT (ID, Name, Description) VALUES (?, ?, ?);", -1, &insert, NULL);

		for (int i = 0; i < num_formats; i++)
		{
			// Ensures all formats are in the db
			sqlite3_reset(insert);
			sqlite3_bind_int64(insert, 1, formats[i].db_id);
			sqlite3_bind_text (insert, 2, formats[i].name, -1, SQLITE_STATIC);
			sqlite3_bind_text (insert, 3, formats[i].description, -1, SQLITE_STATIC);
			sqlite3_step(insert);
		}

		sqlite3_finalize(insert);
	}
}

PRIVATE void ciphertext(sqlite3_context* context, int nArgs, sqlite3_value** values)
{
	Format* format = find_format(sqlite3_value_int(values[1]));

	const void* binary = sqlite3_value_blob(values[0]);
	unsigned char* result = (unsigned char*)malloc(((size_t)format->binary_size + format->salt_size) * 2 + 1);

	format->convert_to_string(binary, ((const char*)binary) + format->binary_size, result);

	sqlite3_result_text(context, result, -1, free);
}
// Initialize all data needed by app
PUBLIC void init_all(const char* program_exe_path)
{
	char* db_path = NULL;
	FILE* db_file = NULL;
	int db_already_exits = FALSE;
	detect_hardware();

	// Windows high-resolution clock support
#ifdef _WIN32
	QueryPerformanceFrequency(&clock_freq);
	clock_freq.QuadPart = (clock_freq.QuadPart + 500) / 1000;
#endif

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
		sqlite3_exec(db, CREATE_ACCOUNT_HASH CREATE_OTHER_SCHEMA, NULL, NULL, NULL);

	hex_init();
	register_in_out();
	register_key_providers(db_already_exits);
	formats_init(db_already_exits);
	load_settings_from_db();
	load_cache();
	init_attack_data();

	END_TRANSACTION;

	fill_bits();
#ifdef HS_OPENCL_SUPPORT
	init_opencl();
#endif

	sqlite3_create_function(db, "ciphertext", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, ciphertext, NULL, NULL);
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
	return format_time(seconds_since_start(isTotal));
}
PUBLIC char* finish_time()
{
	if(get_key_space_batch() == KEY_SPACE_UNKNOW)
		strcpy(buffer, "Unknown");
	else
	{
		double time_in_sec = (double)(get_milliseconds() - save_time) / 1000.;

		int64_t num_keys_served_from_save, num_keys_served_from_start;
		get_num_keys_served_ptr(&num_keys_served_from_save, &num_keys_served_from_start);

		int64_t _secs = llrint(num_keys_served_from_save ? 
			((get_key_space_batch() - num_keys_served_from_start - num_keys_served_from_save) * time_in_sec / num_keys_served_from_save) : 
			((get_key_space_batch() - num_keys_served_from_start - num_keys_served_from_save) * time_in_sec));
		format_time(_secs);
	}

	return buffer;
}
PUBLIC char* password_per_sec(char* buffer)
{
	double time_in_sec = (double)(get_milliseconds() - save_time) / 1000.;
	int64_t num_per_sec = llrint(get_num_keys_served_from_save() / time_in_sec);

	if (num_per_sec < 0)
		strcpy(buffer, "0");
	else if(num_per_sec >= 100000000000l)
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
		sqlite3_stmt* _update_settings;

		sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO Settings (ID, Value) VALUES (?, ?);", -1, &_update_settings, NULL);

		BEGIN_TRANSACTION;

		for (int i = 0; i < count_settings_saved; i++)
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

	sqlite3_prepare_v2(db, "SELECT ID,Value FROM Settings;", -1, &_select_settings, NULL);
	
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
PUBLIC uint32_t* num_hashes_by_formats1 = NULL;
PUBLIC uint32_t* num_hashes_found_by_format1 = NULL;
PUBLIC uint32_t* num_user_by_formats1 = NULL;
PUBLIC uint32_t total_deleted_hashes = 0;

#define ID_NUM_DELETED_HASHES           69999
#define ID_NUM_HASHES_DATA              70000
PRIVATE void load_cache()
{
	// Cache
	num_hashes_by_formats1		= (uint32_t*)calloc(num_formats, sizeof(uint32_t));
	num_hashes_found_by_format1	= (uint32_t*)calloc(num_formats, sizeof(uint32_t));
	num_user_by_formats1		= (uint32_t*)calloc(num_formats, sizeof(uint32_t));

	for(int i = 0; i < num_formats; i++)
	{
		// Count hash
		num_hashes_by_formats1[i] = get_setting(ID_NUM_HASHES_DATA + 3 * i + 0, 0);
		// Count found hash
		num_hashes_found_by_format1[i] = get_setting(ID_NUM_HASHES_DATA + 3 * i + 1, 0);
		// Count users
		num_user_by_formats1[i] = get_setting(ID_NUM_HASHES_DATA + 3 * i + 2, 0);
	}
	total_deleted_hashes = get_setting(ID_NUM_DELETED_HASHES, 0);
}
PUBLIC void save_num_hashes_cache()
{
	for (int i = 0; i < num_formats; i++)
	{
		// Count hash
		save_setting(ID_NUM_HASHES_DATA + 3 * i + 0, num_hashes_by_formats1[i]);
		// Count found hash
		save_setting(ID_NUM_HASHES_DATA + 3 * i + 1, num_hashes_found_by_format1[i]);
		// Count users
		save_setting(ID_NUM_HASHES_DATA + 3 * i + 2, num_user_by_formats1[i]);
	}
	save_setting(ID_NUM_DELETED_HASHES, total_deleted_hashes);

	save_settings_to_db();
}
PUBLIC uint32_t total_num_users()
{
	uint32_t _result = 0;

	for (int i = 0; i < num_formats; i++)
		_result += num_user_by_formats1[i];

	return _result;
}
PUBLIC uint32_t total_num_hashes_found()
{
	uint32_t _result = 0;

	for(int i = 0; i < num_formats; i++)
		_result += num_hashes_found_by_format1[i];

	return _result ;
}
PUBLIC uint32_t total_num_hashes()
{
	uint32_t _result = 0;

	for (int i = 0; i < num_formats; i++)
		_result += num_hashes_by_formats1[i];

	return _result;
}
PUBLIC uint32_t has_hashes(int format_index)
{
	assert(format_index >= 0 && format_index < num_formats);

	return num_hashes_by_formats1[format_index];
}
// All hashes was found for a specific format?
PUBLIC int is_found_all_hashes(int format_index)
{
	if (format_index < 0 || format_index >= num_formats)
		return TRUE;

	return num_hashes_found_by_format1[format_index] >= num_hashes_by_formats1[format_index];
}

PUBLIC void clear_db_accounts()
{
	// Delete all
	sqlite3_exec(db, "DELETE FROM Attack;DELETE FROM Batch;DELETE FROM BatchAttack;DELETE FROM FindHash;DELETE FROM Hash;DELETE FROM TagAccount;DELETE FROM Tag;DELETE FROM AccountLM;DELETE FROM Account;", NULL, NULL, NULL);
	sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);

	// Put cache in 0
	memset(num_hashes_by_formats1, 0, num_formats*sizeof(uint32_t));
	memset(num_hashes_found_by_format1, 0, num_formats*sizeof(uint32_t));
	memset(num_user_by_formats1, 0, num_formats*sizeof(uint32_t));

	save_num_hashes_cache();
	resize_fam();
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32
#ifdef HS_TESTING
#include <Windows.h>
PUBLIC void hs_log(int priority, const char* tag, char* format_message, ...)
{
	va_list ap;
	char log_buffer[128];

	if (priority == HS_LOG_ERROR)
	{
		//char* captions[] = { "DEBUG", "INFO", "WARNING", "ERROR" };
		int icons[] = { MB_ICONINFORMATION, MB_ICONINFORMATION, MB_ICONWARNING, MB_ICONERROR };

		va_start(ap, format_message);     /* Initialize variable arguments. */
		vsprintf(log_buffer, format_message, ap);

		MessageBox(NULL, log_buffer, tag, MB_OK | icons[priority]);
	}
}
#endif
#endif