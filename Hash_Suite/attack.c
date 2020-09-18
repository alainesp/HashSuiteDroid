// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2020 by Alain Espinosa. See LICENSE.

#include "common.h"
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "attack.h"

#ifdef _WIN32
	#include <windows.h>
	#include <process.h>
#else
	#include <pthread.h>
	#include <fcntl.h>
	#include <unistd.h>
	#include <sys/mman.h>
	#include <sys/stat.h>
#endif

// Mutex for thread-safe access
extern HS_MUTEX key_provider_mutex;

PUBLIC uint32_t MAX_NUM_PASWORDS_LOADED = UINT32_MAX;
PUBLIC int is_benchmark = FALSE;

// Number of threads used
PUBLIC uint32_t num_threads;
PUBLIC uint32_t app_num_threads;
// Used to stop the attack
PUBLIC int continue_attack;
PUBLIC int stop_universe;
PUBLIC int save_needed = FALSE;
PUBLIC callback_funtion* send_message_gui;
// Number of passwords currently loaded
PUBLIC uint32_t num_passwords_loaded;
// The binary values of the hashes
PUBLIC void* binary_values = NULL;
// His DB ids to save when cracked
PRIVATE uint32_t* hash_ids32 = NULL;

////////////////////////////////////////////////////////////////////////////////////
// Table map for fast compare
////////////////////////////////////////////////////////////////////////////////////
PUBLIC uint32_t* table = NULL;
PUBLIC uint32_t* bit_table = NULL;
// If there are more than one password with the same hash point to next
PUBLIC uint32_t* same_hash_next = NULL;
PUBLIC uint32_t size_table;
PUBLIC uint32_t size_bit_table;
PUBLIC HS_ALIGN(16) uint32_t size_table_see2[4];
PUBLIC HS_ALIGN(16) uint32_t size_bit_table_see2[4];
PUBLIC uint32_t first_bit_size_bit_table;
PUBLIC uint32_t first_bit_size_table;

PUBLIC uint16_t* cbg_filter = NULL;
PUBLIC uint32_t* cbg_table = NULL;
PUBLIC uint32_t cbg_mask;
PUBLIC uint32_t cbg_count_unlucky;
PUBLIC uint32_t cbg_count_moved;

////////////////////////////////////////////////////////////////////////////////////
// Salted hash
////////////////////////////////////////////////////////////////////////////////////
PUBLIC void* salts_values = NULL;
PUBLIC uint32_t num_diff_salts;
PUBLIC uint32_t* salt_index = NULL;
PUBLIC uint32_t* same_salt_next = NULL;

////////////////////////////////////////////////////////////////////////////////////
// Found hashes
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_TESTING
PUBLIC
#else
PRIVATE
#endif
uint32_t num_passwords_found = 0;

typedef struct FoundKey
{
	unsigned char cleartext[MAX_KEY_LENGHT_BIG];
	uint32_t elapsed;
	uint32_t hash_id;
}FoundKey;

PRIVATE FoundKey* found_keys = NULL;
PRIVATE int capacity;
PRIVATE int current_num_keys;

////////////////////////////////////////////////////////////////////////////////////
// General utilities
////////////////////////////////////////////////////////////////////////////////////
PRIVATE int64_t start_time;
PUBLIC int64_t save_time;

PUBLIC uint32_t seconds_since_start(int isTotal)
{
	return (uint32_t)((get_milliseconds() - start_time+500) / 1000 + (isTotal ? batch[current_attack_index].secs_before_this_attack : 0));
}

PRIVATE HS_MUTEX found_keys_mutex;
PRIVATE sqlite3_stmt* save_state_update;
PRIVATE sqlite3_stmt* insert_found_hash;

////////////////////////////////////////////////////////////////////////////////////
// Batch
////////////////////////////////////////////////////////////////////////////////////
PRIVATE char batch_name[128];
PRIVATE char batch_description[64];
#ifdef __ANDROID__
PUBLIC sqlite3_int64 batch_db_id;
#else
PRIVATE sqlite3_int64 batch_db_id;
#endif
PUBLIC AttackData* batch = NULL;
PUBLIC int num_attack_in_batch;
PUBLIC int current_attack_index;

PUBLIC uint32_t* is_foundBit = NULL;
PUBLIC int attack_need_restart = FALSE;
////////////////////////////////////////////////////////////////////////////////////////////
// Cache
////////////////////////////////////////////////////////////////////////////////////////////
PUBLIC int cache_had_hashes = FALSE;
PRIVATE int cache_format_index;
PRIVATE uint32_t cache_total_hashes;
PRIVATE uint32_t cache_num_hashes_loaded;
PRIVATE void* backup_binaries = NULL;
PRIVATE void* backup_salts = NULL;
PRIVATE void* backup_ids = NULL;
PRIVATE void set_cache(int format_index)
{
	// TODO: This is because the copy of salts it's currently done wrong
	if (formats[format_index].salt_size && num_diff_salts != num_passwords_found)
	{
		cache_had_hashes = FALSE;
	}
	else
	{
		cache_had_hashes = TRUE;
		cache_format_index = format_index;
		cache_total_hashes = num_hashes_by_formats1[format_index];
		cache_num_hashes_loaded = num_passwords_loaded;
	}
}
PUBLIC void get_cache_info(char* buffer)
{
	uint32_t unknow_hashes = num_hashes_by_formats1[cache_format_index] - num_hashes_found_by_format1[cache_format_index];

	itoaWithDigitGrouping(cache_num_hashes_loaded, buffer);
	strcat(buffer, " hashes are in cache.\n");
	filelength2string((sizeof(uint32_t) + formats[cache_format_index].binary_size + formats[cache_format_index].salt_size)*cache_num_hashes_loaded, buffer + strlen(buffer));
	sprintf(buffer + strlen(buffer), " of memory is used.\n%i%% of wasted cache.", (uint32_t)((cache_num_hashes_loaded - unknow_hashes)*100ll/cache_num_hashes_loaded));
}
PRIVATE void backup_if_cached()
{
	if (cache_had_hashes)
	{
		cache_had_hashes = FALSE;

		backup_binaries = binary_values;
		backup_salts = salts_values;
		backup_ids = hash_ids32;

		binary_values = NULL;
		salts_values = NULL;
		hash_ids32 = NULL;
	}
}
PRIVATE void restore_backup_if_needed()
{
	if (backup_binaries)
	{
		cache_had_hashes = TRUE;

		free(binary_values);
		free(salts_values);
		free(hash_ids32);

		binary_values = backup_binaries;
		salts_values = backup_salts;
		hash_ids32 = backup_ids;

		backup_binaries = NULL;
		backup_salts = NULL;
		backup_ids = NULL;
	}
}

extern void* thread_params;// This is defined in key_provider.c
extern uint32_t num_thread_params;

////////////////////////////////////////////////////////////////////////////////////////////
// Testing support
////////////////////////////////////////////////////////////////////////////////////////////
PUBLIC int is_test = FALSE;
#ifdef __ANDROID__
PUBLIC uint32_t test_sleep_time = 10000;
#else
PUBLIC uint32_t test_sleep_time = 3000;
#endif
PUBLIC int test_rules_on_gpu = FALSE;
PRIVATE int test_errors_detected = FALSE;
PRIVATE char* test_cleartexts = NULL;
PRIVATE uint32_t test_num_hashes = 0;

typedef void apply_format(const char* cleartext, char* hash);
PRIVATE apply_format* hash_format[MAX_NUM_FORMATS] = {
	hash_lm , hash_ntlm , hash_md5     , hash_sha1, hash_sha256, hash_sha512,
	hash_dcc, hash_ssha1, hash_md5crypt, hash_dcc2, hash_wpa   , hash_bcrypt, 
	hash_sha256crypt, hash_sha512crypt
};
PUBLIC uint32_t hash_count_to_test[MAX_NUM_FORMATS] = {
	1024, 1024, 1024, 1024, 1024, 1024,
#ifdef __ANDROID__
	512, 256, 128,  8,   8, 2, 4, 2
#else
	1024, 512, 256, 16, 16, 2,/*8 if only CPU*/4, 2
#endif
};
PRIVATE uint32_t num_keys_asked_by_format[MAX_NUM_FORMATS] = {
#ifdef __ANDROID__
	128*8, 128, 128, 128, 128, 128,
	   64, 128,   1,  64,  64,   1,  1, 1
#else
	128*8, 256, 256, 256, 256, 256,
	   64, 256,   1,  64,  64,   3,  1, 1
#endif
};
PRIVATE void update_num_keys_asked_by_format()
{
#ifdef HS_X86
	if (current_cpu.capabilites[CPU_CAP_SSE2])
	{
		num_keys_asked_by_format[MD5CRYPT_INDEX] = 4;
		num_keys_asked_by_format[SHA256CRYPT_INDEX] = 4;
		num_keys_asked_by_format[SHA512CRYPT_INDEX] = 2;
	}
	if (current_cpu.capabilites[CPU_CAP_AVX])
	{
		num_keys_asked_by_format[DCC_INDEX] = 256;
		num_keys_asked_by_format[MD5CRYPT_INDEX] = 8;
		num_keys_asked_by_format[SHA256CRYPT_INDEX] = 4;
		num_keys_asked_by_format[SHA512CRYPT_INDEX] = 2;
		num_keys_asked_by_format[DCC2_INDEX] = 256;
		num_keys_asked_by_format[WPA_INDEX] = 256;
	}
	if (current_cpu.capabilites[CPU_CAP_AVX2])
	{
		num_keys_asked_by_format[DCC_INDEX] = 256;
		num_keys_asked_by_format[MD5CRYPT_INDEX] = 16;
		num_keys_asked_by_format[SHA256CRYPT_INDEX] = 8;
		num_keys_asked_by_format[SHA512CRYPT_INDEX] = 4;
		num_keys_asked_by_format[DCC2_INDEX] = 256;
		num_keys_asked_by_format[WPA_INDEX] = 256;
	}
#ifdef _M_X64
	if (current_cpu.capabilites[CPU_CAP_BMI])
		num_keys_asked_by_format[BCRYPT_INDEX] = 4;
#endif

#elif defined(HS_ARM)
	if (current_cpu.capabilites[CPU_CAP_NEON])
	{
		num_keys_asked_by_format[MD5CRYPT_INDEX] = 8;
		num_keys_asked_by_format[SHA256CRYPT_INDEX] = 4;
		num_keys_asked_by_format[SHA512CRYPT_INDEX] = 2;
	}
#endif
}

#if MAX_NUM_FORMATS != 14
#error 'hash_format' hasn't enough definitions
#endif

void strings_clear_collection();
int string_exist_in_collection(const char* s);

PRIVATE void generate_keys_for_testing()
{
	// Initialization
	free(test_cleartexts); test_cleartexts = NULL;
	test_errors_detected = FALSE;
	AttackData* attack = batch + current_attack_index;
	int provider_index = attack->provider_index;
	int format_index = attack->format_index;
	if (provider_index == FAST_LM_INDEX)
		provider_index = CHARSET_INDEX;

	// Find good protocol from the key_provider
	generate_key_funtion* generate = NULL;
	for (size_t i = 0; i < LENGTH(key_providers[provider_index].impls); i++)
		if (PROTOCOL_UTF8_COALESC_LE == key_providers[provider_index].impls[i].protocol)
		{
			generate = key_providers[provider_index].impls[i].generate;
			break;
		}

	// Test rule support in the GPUs. Fails: MD5CRYPT (because short key_length support)
	if (!test_rules_on_gpu && provider_index == RULES_INDEX && get_num_gpus_used())
		generate = NULL;

	if (!is_benchmark && test_sleep_time && generate && hash_format[format_index])
	{
		uint32_t num2test = hash_count_to_test[format_index];
		update_num_keys_asked_by_format();
		uint32_t block_size = __min(num2test, provider_index == RULES_INDEX ? num_keys_asked_by_format[format_index] : num2test);

		test_cleartexts = calloc(num2test, MAX_KEY_LENGHT_SMALL);
		uint32_t* generated_keys = calloc(block_size, MAX_KEY_LENGHT_SMALL);

		// Generate keys init
		free(thread_params);
		attack->format_index = MD5_INDEX;// Required by rules

		// Generate keys process
		key_providers[provider_index].resume(attack->min_lenght, attack->max_lenght, attack->params, (attack->provider_index==FAST_LM_INDEX ? NULL : attack->resume_arg), attack->format_index);
		thread_params = calloc(1, key_providers[provider_index].per_thread_data_size);// Because of rules this is below key_provider.resume(...)
		num_thread_params = 1;

		size_t num_cleartext_postprocessed = 0;
		strings_clear_collection();
		for (; num2test; num2test -= test_num_hashes)
		{
			uint32_t count_block = __min(num2test, block_size);// Required by rules
			test_num_hashes = generate(generated_keys, count_block, 0);
			if (test_num_hashes == 0)
				break;

			// Convert to PROTOCOL_UTF8
			for (size_t i = 0; i < test_num_hashes; i++)
			{
				char cleartext[MAX_KEY_LENGHT_SMALL];
				uint32_t len = generated_keys[7 * count_block + i] >> 3;

				for (size_t j = 0; j < (len + 3) / 4; j++)
					((uint32_t*)cleartext)[j] = generated_keys[j * count_block + i];

				cleartext[__min(len, formats[format_index].max_plaintext_lenght)] = 0;
				if (format_index == LM_INDEX)
					_strupr(cleartext);

				// Search for duplicates
				strcpy(test_cleartexts + num_cleartext_postprocessed * MAX_KEY_LENGHT_SMALL, cleartext);
				if (!string_exist_in_collection(test_cleartexts + num_cleartext_postprocessed * MAX_KEY_LENGHT_SMALL))
					num_cleartext_postprocessed++;
			}
		}
		key_providers[provider_index].finish();
		strings_clear_collection();
		test_num_hashes = (uint32_t)num_cleartext_postprocessed;
		free(generated_keys);

		// Return to normal
		attack->format_index = format_index;
		free(thread_params); thread_params = NULL;
		num_thread_params = 0;

		is_test = TRUE;
	}
	else
		is_test = FALSE;
}
////////////////////////////////////////////////////////////////////////////////////////////

extern int64_t num_key_space;
PUBLIC int64_t get_key_space_batch()
{
	int64_t _result = 0;
	int i = 0;

	for(; i < num_attack_in_batch; i++)
	{
		// We use num_key_space as the key_space can vary (for example: wordlist)
		int64_t _current = (i == current_attack_index) ? num_key_space : batch[i].key_space;

		if(_current == KEY_SPACE_UNKNOW)
		{
			_result = KEY_SPACE_UNKNOW;
			break;
		}
		else
			_result += _current;
	}

	return _result;
}

PRIVATE void free_all_memory(int exclude_cache)
{
	// Free all memory used
	_aligned_free(bit_table);			bit_table = NULL;
	_aligned_free(table);				table = NULL;
	_aligned_free(same_hash_next);		same_hash_next = NULL;

	large_page_free(cbg_filter);		cbg_filter = NULL;
	free(cbg_table);					cbg_table = NULL;

	if (exclude_cache)
	{
		uint32_t bin_size = formats[cache_format_index].binary_size;
		uint32_t salt_size = formats[cache_format_index].salt_size;
		// Get good last_index
		size_t last_index = num_passwords_loaded - 1;
		for (; last_index && ((is_foundBit[last_index >> 5] >> (last_index & 31)) & 1); last_index--);
		// Erase found passwords copying from the end and overwrite
		for (size_t i = 0; i < last_index; i++)
			if ((is_foundBit[i >> 5] >> (i & 31)) & 1)
			{
				hash_ids32[i] = hash_ids32[last_index];
				memcpy(((BYTE*)binary_values) + i*bin_size, ((BYTE*)binary_values) + last_index*bin_size, bin_size);
				if (salt_size)
					memcpy(((BYTE*)salts_values) + i*salt_size, ((BYTE*)salts_values) + last_index*salt_size, salt_size);

				for (last_index--; last_index > i && ((is_foundBit[last_index >> 5] >> (last_index & 31)) & 1); last_index--);
			}
	}
	else
	{
		free(hash_ids32);					hash_ids32 = NULL;
		_aligned_free(binary_values);		binary_values = NULL;
		_aligned_free(salts_values);		salts_values = NULL;
	}
	
	free(found_keys);					found_keys = NULL;
	_aligned_free(salt_index);			salt_index = NULL;
	_aligned_free(same_salt_next);		same_salt_next = NULL;
	free(is_foundBit);					is_foundBit = NULL;
}
PUBLIC void release_all_cache()
{
	cache_had_hashes = FALSE;
	free_all_memory(FALSE);
}
// Mask and size for the table map. Use 12.5% full
PRIVATE void calculate_table_mask(uint32_t num_elem)
{
	size_table = 1;

	// Generate result with all bits less than
	// first bit in num_elem in 1
	while(size_table < num_elem)
		size_table = (size_table << 1) + 1;

	int repeat_size_table = 3;
	int repeat_size_bit_table = 0;

	if (3*__max(512, current_cpu.l3_cache_size)*1024/71 < num_elem)
	{
		repeat_size_table--;// 40 -> 20
		repeat_size_bit_table++;// 2.5
	}
	if (6*__max(512, current_cpu.l3_cache_size)*1024/51 < num_elem)
	{
		repeat_size_table--;// 20 -> 10
		repeat_size_bit_table++;// 2.5
	}
	if (12*__max(512, current_cpu.l3_cache_size)*1024/41 < num_elem)
	{
		repeat_size_table--;// 10 -> 5
		repeat_size_bit_table++;// 2.5
	}
	if (4*__max(512, current_cpu.l3_cache_size)*1024/2 < num_elem)
		repeat_size_bit_table++;// 2.5 -> 5

	// 3 bits more into account
	for(int i = 0; i < repeat_size_table; i++)
		size_table = (size_table << 1) + 1;

	size_bit_table = (size_table << 1) + 1;
	for (int i = 0; i < repeat_size_bit_table; i++)
		size_bit_table = (size_bit_table << 1) + 1;

	_BitScanReverse(&first_bit_size_bit_table, size_bit_table);
	_BitScanReverse(&first_bit_size_table, size_table);
	first_bit_size_bit_table++;
	first_bit_size_table++;

	size_table_see2[0] = size_table_see2[1] = size_table_see2[2] = size_table_see2[3] = size_table;
	size_bit_table_see2[0] = size_bit_table_see2[1] = size_bit_table_see2[2] = size_bit_table_see2[3] = size_bit_table;
}
PRIVATE void load_hashes(int format_index)
{
	assert(format_index >= 0 && format_index < num_formats);

	uint32_t current_index = 0, i;

	num_passwords_loaded = num_hashes_by_formats1[format_index] - num_hashes_found_by_format1[format_index];

	// Check if we can use the cache hashes
	if (cache_had_hashes && (cache_format_index != format_index || cache_total_hashes != num_hashes_by_formats1[format_index] || num_passwords_loaded > MAX_NUM_PASWORDS_LOADED))
		release_all_cache();

	num_passwords_loaded = __min(num_passwords_loaded, MAX_NUM_PASWORDS_LOADED);
	int64_t start_load = get_milliseconds();

	/////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Load the found hashes
	/////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (!cache_had_hashes)
	{
		// Create data structures needed.
		binary_values = _aligned_malloc(formats[format_index].binary_size * ((size_t)num_passwords_loaded), 4096);
		hash_ids32    = (uint32_t*)malloc(sizeof(uint32_t) * num_passwords_loaded);
	}
	is_foundBit = (uint32_t*)malloc(sizeof(uint32_t) * (num_passwords_loaded / 32 + 1));
	memset(is_foundBit, FALSE, sizeof(uint32_t) * (num_passwords_loaded / 32 + 1));
	// Data for keys found
	num_passwords_found = 0;
	current_num_keys = 0;
	capacity = __max(num_passwords_loaded/256, 1024);
	found_keys = (FoundKey*)malloc(sizeof(FoundKey) * ((size_t)capacity));

	num_diff_salts = 0;

	if(formats[format_index].salt_size)// Salted hash
	{
		if (!cache_had_hashes)
			salts_values   = _aligned_malloc(formats[format_index].salt_size * ((size_t)num_passwords_loaded), 4096);
		salt_index     = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);
		same_salt_next = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(same_salt_next, 0xff, sizeof(uint32_t) * num_passwords_loaded);
	}
	else if(format_index == LM_INDEX)// Non-salted hash
	{
		calculate_table_mask(num_passwords_loaded);
		table          = (uint32_t*) _aligned_malloc(sizeof(uint32_t) * (size_table+1), 4096);
		bit_table      = (uint32_t*) _aligned_malloc((size_bit_table/32+1) * sizeof(uint32_t), 4096);
		same_hash_next = (uint32_t*) _aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(bit_table, 0, (size_bit_table/32+1) * sizeof(uint32_t));
		memset(table, 0xff, sizeof(uint32_t) * (size_table+1));
		memset(same_hash_next, 0xff, sizeof(uint32_t) * num_passwords_loaded);
	}

	if(cache_had_hashes)
	{
		for (current_index = 0; current_index < num_passwords_loaded; current_index++)
		{
			if (formats[format_index].salt_size)// Salted hash
			{
				// Check if salt exist
				for (i = 0; i < num_diff_salts; i++)
					if (!memcmp((BYTE*)salts_values + ((size_t)current_index)*formats[format_index].salt_size,
								(BYTE*)salts_values + ((size_t)i)            *formats[format_index].salt_size, formats[format_index].salt_size))
					{// salt already exist
						uint32_t last_index = salt_index[i];
						while (same_salt_next[last_index] != NO_ELEM)
							last_index = same_salt_next[last_index];

						same_salt_next[last_index] = current_index;
						break;
					}

				if (i == num_diff_salts)// salt not exist
				{
					salt_index[num_diff_salts] = current_index;
					num_diff_salts++;
				}
			}
			else if (format_index == LM_INDEX)// Non-salted hash
			{
				BYTE* bin = (BYTE*)binary_values + ((size_t)current_index)*formats[format_index].binary_size;
				uint32_t value_map = ((uint32_t*)bin)[formats[format_index].value_map_index0];
				
				bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
				// Put the password in the table map
				if (table[value_map & size_table] == NO_ELEM)
				{
					table[value_map & size_table] = current_index;
				}
				else
				{
					uint32_t last_index = table[value_map & size_table];
					while (same_hash_next[last_index] != NO_ELEM)
						last_index = same_hash_next[last_index];

					same_hash_next[last_index] = current_index;
				}
			}
		}
	}
	else
	{
		sqlite3_stmt* select_not_cracked;
		sqlite3_prepare_v2(db, "SELECT Bin,ID FROM Hash WHERE Type=?;", -1, &select_not_cracked, NULL);
		sqlite3_bind_int64(select_not_cracked, 1, formats[format_index].db_id);

		while (sqlite3_step(select_not_cracked) == SQLITE_ROW)
		{
			assert(current_index <= num_passwords_loaded);
			uint32_t hash_id = (uint32_t)sqlite3_column_int64(select_not_cracked, 1);
			// Check if hash is already found
			if (load_fam(hash_id) != NO_ELEM) continue;
			// TODO: If below assert don't work then recalculate FAM
			assert(current_index < num_passwords_loaded);
			hash_ids32[current_index] = hash_id;

			// Load binary from database
			BYTE* bin = (BYTE*)sqlite3_column_blob(select_not_cracked, 0);
			memcpy((BYTE*)binary_values + ((size_t)current_index) * formats[format_index].binary_size, bin, formats[format_index].binary_size);
			memcpy((BYTE*)salts_values + ((size_t)num_diff_salts) * formats[format_index].salt_size, bin + formats[format_index].binary_size, formats[format_index].salt_size);

			if (formats[format_index].salt_size)// Salted hash
			{
				// Check if salt exist
				for (i = 0; i < num_diff_salts; i++)
					if (!memcmp((BYTE*)salts_values + ((size_t)num_diff_salts)*formats[format_index].salt_size,
								(BYTE*)salts_values + ((size_t)i)             *formats[format_index].salt_size, formats[format_index].salt_size))
					{// salt already exist
						uint32_t last_index = salt_index[i];
						while (same_salt_next[last_index] != NO_ELEM)
							last_index = same_salt_next[last_index];

						same_salt_next[last_index] = current_index;
						break;
					}

				if (i == num_diff_salts)// salt not exist
				{
					salt_index[num_diff_salts] = current_index;
					num_diff_salts++;
				}
			}
			else if (format_index == LM_INDEX)// Non-salted hash
			{
				uint32_t value_map = ((uint32_t*)bin)[formats[format_index].value_map_index0];

				bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
				// Put the password in the table map
				if (table[value_map & size_table] == NO_ELEM)
				{
					table[value_map & size_table] = current_index;
				}
				else
				{
					uint32_t last_index = table[value_map & size_table];
					while (same_hash_next[last_index] != NO_ELEM)
						last_index = same_hash_next[last_index];

					same_hash_next[last_index] = current_index;
				}
			}

			current_index++;
			// Limit to MAX_NUM_PASWORDS_LOADED
			if (current_index >= num_passwords_loaded)
				break;
		}
		// More than 3 seconds loading
		if ((get_milliseconds() - start_load) > 3000)
			set_cache(format_index);

		sqlite3_finalize(select_not_cracked);
	}

	build_cbg_table(format_index, formats[format_index].value_map_index0, formats[format_index].value_map_index1);
	assert(current_index == num_passwords_loaded);	

	if (formats[format_index].optimize_hashes)
		formats[format_index].optimize_hashes();
}
typedef struct
{
	uint32_t keymic[4];
	unsigned char prf_buffer[128];
	unsigned char eapol[256+64];
	uint32_t  eapol_blocks;
	int           keyver;
} hccap_bin;
typedef struct {
	uint32_t salt[4];
	uint32_t rounds;
	uint32_t sign_extension_bug;
} BF_salt;
typedef struct {
	uint8_t salt[8];
	uint8_t saltlen;
	uint8_t prefix;		/** 0 when $1$ or 1 when $apr1$ or 2 for {smd5} which uses no prefix. **/
	uint8_t prefix_len;
	uint8_t unused;
} crypt_md5_salt;
typedef struct {
	uint32_t rounds;
	uint32_t saltlen;
	uint8_t salt[16];
} crypt_sha256_salt;

#include <time.h>
PRIVATE void load_hashes_test(int format_index)
{
	assert(format_index >= 0 && format_index < num_formats);
	backup_if_cached();

	uint32_t current_index = 0, i;

	num_passwords_loaded = test_num_hashes;

	// Create data structures needed.
	binary_values = _aligned_malloc(formats[format_index].binary_size * num_passwords_loaded, 4096);
	hash_ids32 = (uint32_t*)malloc(sizeof(uint32_t) * num_passwords_loaded);
	is_foundBit = (uint32_t*)malloc(sizeof(uint32_t) * (num_passwords_loaded / 32 + 1));
	memset(is_foundBit, FALSE, sizeof(uint32_t) * (num_passwords_loaded / 32 + 1));
	// Data for keys found
	num_passwords_found = 0;
	current_num_keys = 0;
	capacity = __max(num_passwords_loaded / 100, 512);
	found_keys = (FoundKey*)malloc(sizeof(FoundKey) * capacity);

	num_diff_salts = 0;

	if (formats[format_index].salt_size)// Salted hash
	{
		salts_values = _aligned_malloc(formats[format_index].salt_size * num_passwords_loaded, 4096);
		salt_index = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);
		same_salt_next = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);

		// Initialize table map
		for (i = 0; i < num_passwords_loaded; i++)
			same_salt_next[i] = NO_ELEM;
	}
	else if (format_index == LM_INDEX)// Non-salted hash
	{
		calculate_table_mask(num_passwords_loaded);
		table = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * (size_table + 1), 4096);
		bit_table = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * (size_bit_table / 32 + 1), 4096);
		same_hash_next = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(bit_table, 0, (size_bit_table / 32 + 1) * sizeof(uint32_t));
		memset(table, 0xff, sizeof(uint32_t) * (size_table + 1));
		memset(same_hash_next, 0xff, sizeof(uint32_t) * num_passwords_loaded);
	}

	// Seed the random-number generator with the current time so that the numbers will be different every time we run.
	srand((unsigned)time(NULL));

	for (current_index = 0; current_index < num_passwords_loaded; current_index++)
	{
		uint32_t value_map;
		char* bin_value = (char*)binary_values + current_index * formats[format_index].binary_size;
		char* salt_value = (char*)salts_values + num_diff_salts * formats[format_index].salt_size;

		char hex[1024];
		hash_format[format_index](test_cleartexts + current_index * MAX_KEY_LENGHT_SMALL, hex);
		formats[format_index].convert_to_binary(hex, bin_value, salt_value);

		value_map = ((int*)bin_value)[0];

		if (formats[format_index].salt_size)// Salted hash
		{
			// Check if salt exist
			for (i = 0; i < num_diff_salts; i++)
				if (!memcmp((char*)salts_values + num_diff_salts * formats[format_index].salt_size,
					(char*)salts_values + i * formats[format_index].salt_size, formats[format_index].salt_size))
				{// salt already exist
					uint32_t last_index = salt_index[i];
					while (same_salt_next[last_index] != NO_ELEM)
						last_index = same_salt_next[last_index];

					same_salt_next[last_index] = current_index;
					break;
				}

			if (i == num_diff_salts)// salt not exist
			{
				salt_index[num_diff_salts] = current_index;
				num_diff_salts++;
			}
		}
		else if (format_index == LM_INDEX)// Non-salted hash
		{
			bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
			// Put the password in the table map
			if (table[value_map & size_table] == NO_ELEM)
			{
				table[value_map & size_table] = current_index;
			}
			else
			{
				uint32_t last_index = table[value_map & size_table];
				while (same_hash_next[last_index] != NO_ELEM)
					last_index = same_hash_next[last_index];

				same_hash_next[last_index] = current_index;
			}
		}

		hash_ids32[current_index] = current_index;
	}
	if(format_index != LM_INDEX)
		build_cbg_table(format_index, formats[format_index].value_map_index0, formats[format_index].value_map_index1);

	if (formats[format_index].optimize_hashes)
		formats[format_index].optimize_hashes();
}
PRIVATE void load_hashes_benchmark(int format_index)
{
	assert(format_index >= 0 && format_index < num_formats);
	backup_if_cached();

	uint32_t current_index = 0, i;

	num_passwords_loaded = MAX_NUM_PASWORDS_LOADED;

	// Create data structures needed.
	binary_values =                 _aligned_malloc(formats[format_index].binary_size    * num_passwords_loaded, 4096);
	hash_ids32    = (uint32_t*)malloc(sizeof(uint32_t) * num_passwords_loaded);
	is_foundBit   = (uint32_t*)malloc(sizeof(uint32_t) * (num_passwords_loaded / 32 + 1));
	memset(is_foundBit, FALSE, sizeof(uint32_t) * (num_passwords_loaded / 32 + 1));
	// Data for keys found
	num_passwords_found = 0;
	current_num_keys = 0;
	capacity = __max(num_passwords_loaded/100, 512);
	found_keys = (FoundKey*)malloc(sizeof(FoundKey) * capacity);

	num_diff_salts = 0;

	if(formats[format_index].salt_size)// Salted hash
	{
		salts_values   = _aligned_malloc( formats[format_index].salt_size * num_passwords_loaded, 4096);
		salt_index     = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);
		same_salt_next = (uint32_t*)_aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);

		// Initialize table map
		for(i = 0; i < num_passwords_loaded; i++)
			same_salt_next[i] = NO_ELEM;
	}
	else if (format_index == LM_INDEX)// Non-salted hash
	{
		calculate_table_mask(num_passwords_loaded);
		table          = (uint32_t*) _aligned_malloc(sizeof(uint32_t) * (size_table+1), 4096);
		bit_table      = (uint32_t*) _aligned_malloc(sizeof(uint32_t) * (size_bit_table/32+1), 4096);
		same_hash_next = (uint32_t*) _aligned_malloc(sizeof(uint32_t) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(bit_table, 0, (size_bit_table/32+1) * sizeof(uint32_t));
		memset(table, 0xff, sizeof(uint32_t) * (size_table+1));
		memset(same_hash_next, 0xff, sizeof(uint32_t) * num_passwords_loaded);
	}

	// Seed the random-number generator with the current time so that the numbers will be different every time we run.
	srand( (unsigned)time( NULL ) );
	generate_random(binary_values, ((size_t)num_passwords_loaded) * formats[format_index].binary_size);
	generate_random(salts_values, ((size_t)num_passwords_loaded) * formats[format_index].salt_size);

	for(current_index = 0; current_index < num_passwords_loaded; current_index++)
	{
		// Fill values with random data
		uint32_t value_map;
		char* bin_value  = (char*)binary_values + current_index  * formats[format_index].binary_size;
		char* salt_value = (char*)salts_values  + num_diff_salts * formats[format_index].salt_size;

		// Handle non-random salts-binary
		switch (format_index)
		{
		case SHA256CRYPT_INDEX:
		{
			crypt_sha256_salt* sha256_salt = (crypt_sha256_salt*)salt_value;
			sha256_salt->saltlen = 8;
			sha256_salt->rounds = 5000;
			memset(sha256_salt->salt + sha256_salt->saltlen, 0, sizeof(sha256_salt->salt) - sha256_salt->saltlen);
		}
		break;
		case MD5CRYPT_INDEX:
			{
			crypt_md5_salt* md5_salt = (crypt_md5_salt*)salt_value;
			md5_salt->saltlen = 8;
			md5_salt->prefix = 0;
			md5_salt->prefix_len = 3;
			md5_salt->unused = 0;
			}
			break;
		case SSHA_INDEX:
			((uint8_t*)salt_value)[9] = 0x80;
			((uint8_t*)salt_value)[16] = 8;// Salt lenght
			break;
		case DCC_INDEX: case DCC2_INDEX:
			// 1/5 not random (simulate username)
			memset(salt_value, 2, formats[format_index].salt_size/5);
			((uint32_t*)salt_value)[10] = ((rand() % 19) + 9) << 4;
			break;
		case WPA_INDEX:
			((uint32_t*)salt_value)[15] = (64 + rand()%28 + 4) << 3;// Good lenght
			hccap_bin* wpa_bin = (hccap_bin*)bin_value;
			wpa_bin->keyver &= 1;// Random WPA/WPA2
			wpa_bin->eapol_blocks = (wpa_bin->eapol_blocks & 3) + 1;// Sane eapol_blocks
			break;
		case BCRYPT_INDEX:
			{
			BF_salt* bf_salt = (BF_salt*)salt_value;
			bf_salt->rounds = 1u << 5u;
			// for 4 hashes generated only 1 had sign_extension_bug
			bf_salt->sign_extension_bug = ((bf_salt->sign_extension_bug & 3) == 3);
			}
			break;
		}

		value_map = ((int*)bin_value)[0];
		
		if(formats[format_index].salt_size)// Salted hash
		{
			// Check if salt exist
			for(i = 0; i < num_diff_salts; i++)
				if(!memcmp( (char*)salts_values + num_diff_salts*formats[format_index].salt_size,
							(char*)salts_values +       i       *formats[format_index].salt_size, formats[format_index].salt_size))
				{// salt already exist
					uint32_t last_index = salt_index[i];
					while(same_salt_next[last_index] != NO_ELEM)
						last_index = same_salt_next[last_index];

					same_salt_next[last_index] = current_index;
					break;
				}

			if(i == num_diff_salts)// salt not exist
			{
				salt_index[num_diff_salts] = current_index;
				num_diff_salts++;
			}
		}
		else if (format_index == LM_INDEX)// Non-salted hash
		{
			bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
			// Put the password in the table map
			if(table[value_map & size_table] == NO_ELEM)
			{
				table[value_map & size_table] = current_index;
			}
			else
			{
				uint32_t last_index = table[value_map & size_table];
				while(same_hash_next[last_index] != NO_ELEM)
					last_index = same_hash_next[last_index];

				same_hash_next[last_index] = current_index;
			}
		}

		hash_ids32[current_index] = current_index;
	}

	build_cbg_table(format_index, formats[format_index].value_map_index0, formats[format_index].value_map_index1);

	if (formats[format_index].optimize_hashes)
		formats[format_index].optimize_hashes();
}
PUBLIC void password_was_found(uint32_t index, unsigned char* cleartext)
{
	if(is_benchmark) return;
	if(index >= num_passwords_loaded)
		return;

	HS_ENTER_MUTEX(&found_keys_mutex);
	if(is_test)
	{
		if (strcmp(cleartext, test_cleartexts + index * MAX_KEY_LENGHT_SMALL))
			test_errors_detected = TRUE;

		if (!((is_foundBit[index >> 5] >> (index & 31)) & 1))
		{
			is_foundBit[index >> 5] |= 1 << (index & 31);
			num_passwords_found++;

			if (num_passwords_found >= num_passwords_loaded)
			{
				continue_attack = FALSE;
				stop_universe = TRUE;
			}
		}
	}
	else
	{
		// TODO: Remove the password from the table
		if (!((is_foundBit[index >> 5] >> (index & 31)) & 1))
		{
			is_foundBit[index >> 5] |= 1 << (index & 31);

			num_passwords_found++;
			num_hashes_found_by_format1[batch[current_attack_index].format_index]++;

			if (num_passwords_found >= num_passwords_loaded)
			{
				continue_attack = FALSE;
				stop_universe = TRUE;
			}// IF salted AND found >= 20% THEN restart attack
			else if (formats[batch[current_attack_index].format_index].salt_size && num_passwords_found * 100ll / num_passwords_loaded >= 20ll)
			{
				attack_need_restart = TRUE;
				continue_attack = FALSE;
				// Put cache on
				if (formats[batch[current_attack_index].format_index].optimize_hashes)
					cache_had_hashes = FALSE;// Because 'void optimize_hashes()' may change layout of hashes
				else
					set_cache(batch[current_attack_index].format_index);
			}

			// If full->double capacity
			if (current_num_keys == capacity)
			{
				capacity *= 2;
				found_keys = realloc(found_keys, sizeof(FoundKey) * capacity);
			}
			found_keys[current_num_keys].hash_id = hash_ids32[index];
			found_keys[current_num_keys].elapsed = seconds_since_start(TRUE);
			strcpy(found_keys[current_num_keys].cleartext, cleartext);
			current_num_keys++;

			if (num_passwords_loaded > 10000000 && ((uint32_t)current_num_keys) >= num_passwords_loaded / 32)//3.1%
				save_needed = TRUE;
		}
	}
	
	HS_LEAVE_MUTEX(&found_keys_mutex);
}

PRIVATE CryptParam* crypto_params = NULL;
#ifdef HS_OPENCL_SUPPORT
PUBLIC OpenCL_Param** ocl_crypt_ptr_params = NULL;
#endif
PRIVATE void begin_crack(void* set_start_time)
{
	uint32_t i, j;
	int thread_id = 0;
	// Find best implementations. Assume there is at least one compatible
	perform_crypt_funtion* perform_crypt = NULL;
	generate_key_funtion* generate = NULL;
#ifdef HS_OPENCL_SUPPORT
	// For GPU compilation and then execution
	create_gpu_crypt_funtion* create_gpu_crypt = NULL;
	gpu_crypt_funtion** crypt_ptr_func = NULL;
#endif

	if(is_test)
		load_hashes_test(batch[current_attack_index].format_index);
	else if(is_benchmark)
		load_hashes_benchmark(batch[current_attack_index].format_index);
	else
		load_hashes(batch[current_attack_index].format_index);
	continue_attack = TRUE;
	stop_universe = FALSE;
	save_needed = FALSE;

	//num_keys_served_from_save  = 0;
	//num_keys_served_from_start += batch[current_attack_index].num_keys_served;
	set_num_keys_save_add_start(0, batch[current_attack_index].num_keys_served);

	key_providers[batch[current_attack_index].provider_index].resume(batch[current_attack_index].min_lenght, batch[current_attack_index].max_lenght, batch[current_attack_index].params, batch[current_attack_index].resume_arg, batch[current_attack_index].format_index);

	// GPUs
	num_threads = 0;

#ifdef HS_OPENCL_SUPPORT
	for(j = 0; j < LENGTH(formats[batch[current_attack_index].format_index].opencl_impls); j++)
	{
		create_gpu_crypt = formats[batch[current_attack_index].format_index].opencl_impls[j].perform_crypt;

		for(i = 0; i < LENGTH(key_providers[batch[current_attack_index].provider_index].impls); i++)
		{
			generate = key_providers[batch[current_attack_index].provider_index].impls[i].generate;
			if(formats[batch[current_attack_index].format_index].opencl_impls[j].protocol == key_providers[batch[current_attack_index].provider_index].impls[i].protocol)
				goto out_opencl;
			else
				generate = NULL;
		}
	}
out_opencl:
	if(generate)
	{
		// For GPU first create all params to execution (create opencl code, compile...)
		ocl_crypt_ptr_params = (OpenCL_Param**)calloc(num_gpu_devices, sizeof(OpenCL_Param*));
		crypt_ptr_func = (gpu_crypt_funtion**)malloc(sizeof(gpu_crypt_funtion*)*num_gpu_devices);

		for(i = 0; i < num_gpu_devices; i++)
			if (gpu_devices[i].flags & GPU_FLAG_IS_USED)
			{
				ocl_crypt_ptr_params[i] = (OpenCL_Param*)calloc(1, sizeof(OpenCL_Param));
				if (!create_gpu_crypt(ocl_crypt_ptr_params[i], i, generate, &(crypt_ptr_func[i])))
				{
					if(num_passwords_found < num_passwords_loaded)// Because we may do some cases in 'create_gpu_crypt(...)'
						send_message_gui(MESSAGE_ATTACK_GPU_FAIL);
					ocl_crypt_ptr_params[i] = NULL;
				}
			}
	}
#endif

	// CPU
	num_threads += app_num_threads;
	perform_crypt = NULL;
	generate = NULL;

	for(j = 0; j < LENGTH(formats[batch[current_attack_index].format_index].impls); j++)
	{
		perform_crypt = formats[batch[current_attack_index].format_index].impls[j].perform_crypt;

		for(i = 0; i < LENGTH(key_providers[batch[current_attack_index].provider_index].impls); i++)
		{
			generate = key_providers[batch[current_attack_index].provider_index].impls[i].generate;
			if(current_cpu.capabilites[formats[batch[current_attack_index].format_index].impls[j].needed_cap] && 
				formats[batch[current_attack_index].format_index].impls[j].protocol == key_providers[batch[current_attack_index].provider_index].impls[i].protocol)
				goto out;
		}
	}
out:
#ifdef HS_OPENCL_SUPPORT
	// Count total threads-----------------------------
	if(ocl_crypt_ptr_params && crypt_ptr_func)
		for(i = 0; i < num_gpu_devices; i++)
			if ((gpu_devices[i].flags & GPU_FLAG_IS_USED) && ocl_crypt_ptr_params[i])
				num_threads++;
#endif
	// If is LM charset not implemented in GPU->use CPU
	if(!app_num_threads && batch[current_attack_index].format_index == LM_INDEX && batch[current_attack_index].provider_index == CHARSET_INDEX)
		num_threads++;
	if (num_threads == 0)
	{
		num_threads = 1;
		app_num_threads = 1;
	}
	// Create per thread data
	num_thread_params = num_threads;
	thread_params = calloc(num_threads, key_providers[batch[current_attack_index].provider_index].per_thread_data_size);
	crypto_params = (CryptParam*)calloc(num_threads, sizeof(CryptParam));

#ifdef HS_OPENCL_SUPPORT
	// Then execute the GPU kernels
	if(ocl_crypt_ptr_params && crypt_ptr_func)
	{
		for(i = 0; i < num_gpu_devices; i++)
			if ((gpu_devices[i].flags & GPU_FLAG_IS_USED) && ocl_crypt_ptr_params[i])
			{
				ocl_crypt_ptr_params[i]->thread_id = thread_id;
				HS_NEW_THREAD(crypt_ptr_func[i], ocl_crypt_ptr_params[i]);
				thread_id++;
			}

		free(crypt_ptr_func);
	}
#endif
	// If is LM charset not implemented in GPU->use CPU
	if(!app_num_threads && batch[current_attack_index].format_index == LM_INDEX && batch[current_attack_index].provider_index == CHARSET_INDEX)
	{
		crypto_params[thread_id].gen = generate;
		crypto_params[thread_id].thread_id = thread_id;
		HS_NEW_THREAD(perform_crypt, crypto_params+thread_id);
		thread_id++;
	}
	else
		for (i = 0; i < app_num_threads; i++, thread_id++)
		{
			crypto_params[thread_id].gen = generate;
			crypto_params[thread_id].thread_id = thread_id;
			HS_NEW_THREAD(perform_crypt, crypto_params+thread_id);
		}

	save_time = get_milliseconds();
	if (set_start_time)
		start_time = get_milliseconds();

	send_message_gui(is_test ? MESSAGE_TESTING_INIT_COMPLETE : MESSAGE_ATTACK_INIT_COMPLETE);
	if (is_test)
	{
		// This is needed if the test fails
		uint32_t sleep_counter = test_sleep_time / 200;
		for (uint32_t i = 0; is_test && continue_attack && i < sleep_counter; i++)
			Sleep(200);

		// Wait for all the needed keys are generated
		while (is_test && continue_attack && get_num_keys_served() < hash_count_to_test[batch[current_attack_index].format_index])
			Sleep(200);

		if (is_test)
			continue_attack = FALSE;
	}
}

////////////////////////////////////////////////////////////////////////////////////
// File Mapping
////////////////////////////////////////////////////////////////////////////////////
PUBLIC void save_fam(uint64_t pos, uint32_t value);

#ifdef _WIN32
typedef struct {
	HANDLE h_file;
	HANDLE h_map_file;
	uint32_t* data;
	uint64_t offset;
	uint64_t file_size;
	HS_MUTEX mutex;
} FAM;// File Array Mapping

PRIVATE FAM hash2found_id;
PRIVATE void open_fam()
{
	hash2found_id.h_file = CreateFile(get_full_path("hash2found.raw"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Get file size
	DWORD high_size;
	DWORD low_size = GetFileSize(hash2found_id.h_file, &high_size);
	hash2found_id.file_size = (((uint64_t)high_size) << 32) | low_size;
	if (hash2found_id.file_size == 0)
	{
		uint32_t data = UINT32_MAX;
		uint32_t ignored;
		WriteFile(hash2found_id.h_file, &data, sizeof(data), &ignored, NULL);
		hash2found_id.file_size = sizeof(data);
	}

	// Create a file mapping object for the file
	hash2found_id.h_map_file = CreateFileMapping(hash2found_id.h_file,// current file handle
		NULL,           // default security
		PAGE_READWRITE, // read/write permission
		0,              // size of mapping object, high
		0,				// size of mapping object, low
		NULL);          // name of mapping object

	// Map the view and test the results.
	hash2found_id.offset = 0;
	hash2found_id.data = (uint32_t*)MapViewOfFile(hash2found_id.h_map_file,// handle to  mapping object
		FILE_MAP_ALL_ACCESS, // read/write
		0,                   // high-order 32  bits of file  offset
		0,					 // low-order 32  bits of file  offset
		hash2found_id.file_size >= current_system_info.granularity ? current_system_info.granularity : hash2found_id.file_size);      // number of bytes to map
}
PRIVATE void ensure_good_fam(uint64_t pos)
{
	assert(pos*4 < hash2found_id.file_size);

	if (pos < hash2found_id.offset || pos >= (hash2found_id.offset + current_system_info.granularity/4))
	{
		UnmapViewOfFile(hash2found_id.data);

		hash2found_id.offset = pos * 4 / current_system_info.granularity * current_system_info.granularity / 4;
		DWORD map_size = current_system_info.granularity;
		if (hash2found_id.offset * 4 + map_size > hash2found_id.file_size)
			map_size = (DWORD)(hash2found_id.file_size - hash2found_id.offset * 4);

		hash2found_id.data = (uint32_t*)MapViewOfFile(hash2found_id.h_map_file,// handle to  mapping object
			FILE_MAP_ALL_ACCESS,                      // read/write
			(DWORD)((hash2found_id.offset * 4) >> 32),// high-order 32  bits of file  offset
			(DWORD)(hash2found_id.offset * 4),        // low-order 32  bits of file  offset
			map_size);                                // number of bytes to map
	}
}
PUBLIC void resize_fam()
{
	uint64_t new_size = (total_num_hashes() + 1) * sizeof(uint32_t);
	if (new_size != hash2found_id.file_size)
	{
		UnmapViewOfFile(hash2found_id.data);
		CloseHandle(hash2found_id.h_map_file);

		// Set new size
		LONG size_high = new_size >> 32;
		SetFilePointer(hash2found_id.h_file, (LONG)new_size, &size_high, FILE_BEGIN);
		SetEndOfFile(hash2found_id.h_file);

		uint64_t old_size = hash2found_id.file_size / sizeof(uint32_t);
		CloseHandle(hash2found_id.h_file);

		// Initialize data
		open_fam();
		for (; old_size < new_size / sizeof(uint32_t); old_size++)
			save_fam(old_size, UINT32_MAX);
	}
}
#elif defined(ANDROID_MAP)
typedef struct {
	int fd;
	unsigned int granularity;
	uint32_t* data;
	uint32_t map_size;
	uint64_t offset;
	uint64_t file_size;
	HS_MUTEX mutex;
} FAM;// File Array Mapping

PRIVATE FAM hash2found_id;
PRIVATE void open_fam()
{
	hash2found_id.granularity = __max(64 * 1024, sysconf(_SC_PAGE_SIZE));
	hash2found_id.fd = open(get_full_path("hash2found.raw"), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	// Get file size
	struct stat sb;
	fstat(hash2found_id.fd, &sb);
	hash2found_id.file_size = sb.st_size;

	// Map the view and test the results.
	hash2found_id.offset = 0;
	hash2found_id.map_size = hash2found_id.file_size >= hash2found_id.granularity ? hash2found_id.granularity : hash2found_id.file_size;
	hash2found_id.data = mmap(NULL, hash2found_id.map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, hash2found_id.fd, hash2found_id.offset);
}
PRIVATE void ensure_good_fam(uint64_t pos)
{
	assert(pos * 4 < hash2found_id.file_size);

	if (pos < hash2found_id.offset || pos >= (hash2found_id.offset + hash2found_id.map_size / 4))
	{
		munmap(hash2found_id.data, hash2found_id.map_size);

		hash2found_id.offset = pos * 4 / hash2found_id.granularity * hash2found_id.granularity / 4;
		hash2found_id.map_size = hash2found_id.granularity;
		if (hash2found_id.offset * 4 + hash2found_id.map_size > hash2found_id.file_size)
			hash2found_id.map_size = hash2found_id.file_size - hash2found_id.offset * 4;

		hash2found_id.data = mmap(NULL, hash2found_id.map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, hash2found_id.fd, hash2found_id.offset);
	}
}
PUBLIC void resize_fam()
{
	uint64_t new_size = (total_num_hashes() + 1) * sizeof(uint32_t);
	if (new_size != hash2found_id.file_size)
	{
		// Close map and file
		munmap(hash2found_id.data, hash2found_id.map_size);

		// Set new size
		ftruncate(hash2found_id.fd, new_size);
		close(hash2found_id.fd);

		uint64_t old_size = hash2found_id.file_size / 4;

		// Initialize data
		open_fam();
		for (; old_size < new_size / 4; old_size++)
			save_fam(old_size, UINT32_MAX);
	}
}
PUBLIC void flush_fam()
{
	// Close map and file
	munmap(hash2found_id.data, hash2found_id.map_size);
	close(hash2found_id.fd);

	// Initialize data
	open_fam();
}
#else
typedef struct {
	int fd;
	uint32_t* data;
	uint64_t offset;
	uint64_t file_size;
	HS_MUTEX mutex;
} FAM;// File Array Mapping

PRIVATE FAM hash2found_id;
PRIVATE void open_fam()
{
	hash2found_id.fd = open(get_full_path("hash2found.raw"), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	// Get file size
	struct stat sb;
	fstat(hash2found_id.fd, &sb);
	hash2found_id.file_size = sb.st_size;

	// Map the view and load data.
	hash2found_id.offset = 0;
	hash2found_id.data = malloc(hash2found_id.file_size);
	read(hash2found_id.fd, hash2found_id.data, hash2found_id.file_size);
}
PRIVATE void ensure_good_fam(uint64_t pos)
{
	assert(pos * 4 < hash2found_id.file_size);
}
PUBLIC void resize_fam()
{
	uint64_t new_size = (total_num_hashes() + 1) * sizeof(uint32_t);
	if (new_size != hash2found_id.file_size)
	{
		if (new_size < hash2found_id.file_size)
		{
			// Set new size
			ftruncate(hash2found_id.fd, new_size);
			hash2found_id.file_size = new_size;
		}
		else
		{
			hash2found_id.data = realloc(hash2found_id.data, new_size);
			memset(hash2found_id.data + hash2found_id.file_size/4, 0xff, new_size - hash2found_id.file_size);
			hash2found_id.file_size = new_size;
			lseek(hash2found_id.fd, 0, SEEK_SET);
			write(hash2found_id.fd, hash2found_id.data, hash2found_id.file_size);
		}
	}
}
PUBLIC void flush_fam()
{
	lseek(hash2found_id.fd, 0, SEEK_SET);
	write(hash2found_id.fd, hash2found_id.data, hash2found_id.file_size);
}
#endif
PUBLIC void save_fam(uint64_t pos, uint32_t value) {
	ensure_good_fam(pos);
	hash2found_id.data[pos - hash2found_id.offset] = value;
}
PUBLIC uint32_t load_fam(uint64_t pos) {
	HS_ENTER_MUTEX(&hash2found_id.mutex);

	ensure_good_fam(pos);
	uint32_t result = hash2found_id.data[pos - hash2found_id.offset];

	HS_LEAVE_MUTEX(&hash2found_id.mutex);
	return result;
}
////////////////////////////////////////////////////////////////////////////////////

PRIVATE int qsort_compare(const void *arg1, const void *arg2)
{
	uint32_t id1 = ((uint32_t*)arg1)[0];
	uint32_t id2 = ((uint32_t*)arg2)[0];

	if (id1 < id2)
		return -1;
	if (id1 == id2)
		return 0;
	return 1;
}
PRIVATE void save_passwords_found()
{
	if(!is_benchmark && !is_test && current_num_keys > 0)
	{
		sqlite3_int64 attack_id = batch[current_attack_index].attack_db_id;
		uint32_t* slow_found_ids = malloc(2 * current_num_keys * sizeof(uint32_t));

		for (int i = 0; i < current_num_keys; i++)
		{
			sqlite3_reset(insert_found_hash);
			sqlite3_bind_int64(insert_found_hash, 1, found_keys[i].hash_id);
			sqlite3_bind_text(insert_found_hash , 2, found_keys[i].cleartext, -1, SQLITE_STATIC);
			sqlite3_bind_int(insert_found_hash  , 3, found_keys[i].elapsed);
			sqlite3_bind_int64(insert_found_hash, 4, attack_id);
			sqlite3_step(insert_found_hash);

			// Possible slow save
			slow_found_ids[2 * i + 0] = found_keys[i].hash_id;
			slow_found_ids[2 * i + 1] = (uint32_t)sqlite3_last_insert_rowid(db);
		}

		qsort(slow_found_ids, current_num_keys, 2 * sizeof(uint32_t), qsort_compare);

		// Insert
		for (int i = 0; i < current_num_keys; i++)
			save_fam(slow_found_ids[2 * i + 0], slow_found_ids[2 * i + 1]);

		free(slow_found_ids);
		current_num_keys = 0;
	}
}

PUBLIC int save_attack_state()
{
	int db_result;
	if(is_benchmark || is_test) return TRUE;

	key_providers[batch[current_attack_index].provider_index].save_resume_arg(batch[current_attack_index].resume_arg);

	db_result = BEGIN_TRANSACTION;
	//if(db_result != SQLITE_OK) return FALSE;

	sqlite3_reset(save_state_update);
	sqlite3_bind_int  (save_state_update, 1, seconds_since_start(TRUE));
	sqlite3_bind_int64(save_state_update, 2, batch[current_attack_index].attack_db_id);
	sqlite3_bind_text (save_state_update, 3, batch[current_attack_index].resume_arg, -1, SQLITE_STATIC);
	sqlite3_bind_int64(save_state_update, 4, get_num_keys_served());
	sqlite3_step(save_state_update);

	HS_ENTER_MUTEX(&found_keys_mutex);
	save_passwords_found();
	HS_LEAVE_MUTEX(&found_keys_mutex);

	END_TRANSACTION;

	save_time = get_milliseconds();

	//num_keys_served_from_start += num_keys_served_from_save;
	//num_keys_served_from_save = 0;
	add_num_keys_from_save_to_start();

	save_needed = FALSE;

	return TRUE;
}

PRIVATE void cleanup_crack()
{
	sqlite3_stmt* update_attack = NULL;
	// Free all memory used
	free_all_memory(cache_had_hashes);
	// Testing
	free(test_cleartexts); test_cleartexts = NULL;
	test_num_hashes = 0;

	if(!is_benchmark && !is_test)
	{
		if(continue_attack || num_passwords_found == num_passwords_loaded)// Finish attack
			sqlite3_prepare_v2(db, "UPDATE Attack SET End=datetime('now'),ElapsedTime=?1,ResumeArg='',NumKeysServed=?3 WHERE ID=?2;", -1, &update_attack, NULL);
		else// Stopped attack
		{
			sqlite3_prepare_v2(db, "UPDATE Attack SET ElapsedTime=?1,ResumeArg=?4,NumKeysServed=?3 WHERE ID=?2;", -1, &update_attack, NULL);
			key_providers[batch[current_attack_index].provider_index].save_resume_arg(batch[current_attack_index].resume_arg);
			sqlite3_bind_text(update_attack, 4, batch[current_attack_index].resume_arg, -1, SQLITE_STATIC);
		}
	}

	key_providers[batch[current_attack_index].provider_index].finish();

	if (!is_benchmark && !is_test)
	{
		sqlite3_bind_int(update_attack, 1, seconds_since_start(TRUE));
		sqlite3_bind_int64(update_attack, 2, batch[current_attack_index].attack_db_id);
		sqlite3_bind_int64(update_attack, 3, get_num_keys_served());
		sqlite3_step(update_attack);
		sqlite3_finalize(update_attack);
	}

	free(thread_params); thread_params = NULL;
	free(crypto_params); crypto_params = NULL;// Not sure why 'crypto_params = NULL;' wasn't used before
#ifdef HS_OPENCL_SUPPORT
	free(ocl_crypt_ptr_params); ocl_crypt_ptr_params = NULL;
#endif
}
PUBLIC void finish_thread()
{
	HS_ENTER_MUTEX(&found_keys_mutex);

	num_threads--;
	int is_last_thread = num_threads == 0;

	HS_LEAVE_MUTEX(&found_keys_mutex);

	if(is_last_thread)
	{
		int64_t key_space_before = 0;
		HS_ENTER_MUTEX(&found_keys_mutex);
		BEGIN_TRANSACTION;
		
		save_passwords_found();
		cleanup_crack();

		END_TRANSACTION;
		HS_LEAVE_MUTEX(&found_keys_mutex);

		// Calculate the key_space of the batch before
		for(int i = 0; i < current_attack_index; i++)
			key_space_before += batch[i].key_space;

		// TODO: test more this patch
		if(num_key_space < (get_num_keys_served() - key_space_before))
			num_key_space = get_num_keys_served() - key_space_before;

		batch[current_attack_index].key_space = num_key_space;
		int last_index = current_attack_index;

		if (is_test || is_benchmark)
			restore_backup_if_needed();

		// Next attack in the batch
		if (is_test)
		{
			is_test = FALSE;
			continue_attack = TRUE;

			send_message_gui((test_errors_detected || num_passwords_found != num_passwords_loaded) ? MESSAGE_TESTING_FAIL : MESSAGE_TESTING_SUCCEED);

#ifndef HS_TESTING
			void* set_start_time = (void*)TRUE;
			begin_crack(set_start_time);
#endif
		}
		else if (attack_need_restart)
		{
			attack_need_restart = FALSE;
			continue_attack = TRUE;
			save_needed = FALSE;

			send_message_gui(MESSAGE_FINISH_ATTACK);
			if (num_passwords_found >= num_passwords_loaded)
			{
				continue_attack = FALSE;
				stop_universe = TRUE;
				send_message_gui(MESSAGE_FINISH_BATCH);
			}
			else
			{
				resume_crack(batch_db_id, send_message_gui);
			}
		}
		else
		{
			batch[current_attack_index].is_ended = TRUE;
			while (current_attack_index < num_attack_in_batch && batch[current_attack_index].is_ended)
				current_attack_index++;

			if (continue_attack && current_attack_index < num_attack_in_batch)
			{
				// Number of keys trying in the batch
				//num_keys_served_from_start += num_keys_served_from_save;
				//num_keys_served_from_save = 0;
				add_num_keys_from_save_to_start();

				// Update the Begin of the attack
				sqlite3_stmt* update_attack;
				sqlite3_prepare_v2(db, "UPDATE Attack SET Begin=datetime('now') WHERE ID=?;", -1, &update_attack, NULL);
				sqlite3_bind_int64(update_attack, 1, batch[current_attack_index].attack_db_id);
				sqlite3_step(update_attack);
				sqlite3_finalize(update_attack);

				send_message_gui(MESSAGE_FINISH_ATTACK);
				begin_crack(NULL);
			}
			else
			{
				// Update all attacks in a batch if no more passwords
				if (num_passwords_found == num_passwords_loaded)
				{
					sqlite3_stmt* update_attack;
					sqlite3_prepare_v2(db, "UPDATE Attack SET End=datetime('now'),ElapsedTime=0,ResumeArg='',NumKeysServed=0 WHERE ID=?;", -1, &update_attack, NULL);

					for (int i = current_attack_index; i < num_attack_in_batch; i++)
					{
						sqlite3_reset(update_attack);
						sqlite3_bind_int64(update_attack, 1, batch[i].attack_db_id);
						sqlite3_step(update_attack);
					}

					sqlite3_finalize(update_attack);
				}
				current_attack_index = last_index;
				send_message_gui(MESSAGE_FINISH_BATCH);
			}
		}
	}
}

// Find best implementations.
PUBLIC int has_implementations_compatible(int format_index, int provider_index)
{
	int i, j;

	for(i = 0; i < LENGTH(formats[format_index].impls); i++)
		for(j = 0; j < LENGTH(key_providers[provider_index].impls); j++)
			if(current_cpu.capabilites[formats[format_index].impls[i].needed_cap] && formats[format_index].impls[i].protocol == key_providers[provider_index].impls[j].protocol)
				return TRUE;

	return FALSE;
}
PUBLIC void resume_crack(sqlite3_int64 db_id, callback_funtion psend_message_gui)
{
	sqlite3_stmt* select_attack;
	sqlite3_stmt* count_attacks_in_batch;
	int i = 0;

	batch_db_id = db_id;

	// Count number of attacks in batch
	sqlite3_prepare_v2(db, "SELECT count(*) FROM BatchAttack INNER JOIN Attack ON Attack.ID==BatchAttack.AttackID WHERE BatchAttack.BatchID=?;", -1, &count_attacks_in_batch, NULL);
	sqlite3_bind_int64(count_attacks_in_batch, 1, db_id);
	sqlite3_step(count_attacks_in_batch);
	num_attack_in_batch = sqlite3_column_int(count_attacks_in_batch, 0);
	sqlite3_finalize(count_attacks_in_batch);

	// Create batch data
	free(batch);
	current_attack_index = -1;
	batch = (AttackData*)malloc( sizeof(AttackData) * num_attack_in_batch);

	// Fill batch data
	sqlite3_prepare_v2(db, "SELECT Provider,Format,MinLenght,MaxLenght,Param,ResumeArg,ElapsedTime,Attack.ID,End,NumKeysServed FROM BatchAttack INNER JOIN Attack ON Attack.ID == BatchAttack.AttackID WHERE BatchAttack.BatchID=?;", -1, &select_attack, NULL);
	sqlite3_bind_int64(select_attack, 1, db_id);

	while(sqlite3_step(select_attack) == SQLITE_ROW)
	{
		// Key provider
		batch[i].provider_index = find_key_provider_index(sqlite3_column_int64(select_attack, 0));
		// Format
		batch[i].format_index   = find_format_index(sqlite3_column_int64(select_attack, 1));

		batch[i].min_lenght = sqlite3_column_int(select_attack, 2);
		batch[i].max_lenght = sqlite3_column_int(select_attack,3); 
		strcpy(batch[i].params,	sqlite3_column_text(select_attack, 4));
		strcpy(batch[i].resume_arg,	sqlite3_column_text(select_attack, 5));
		batch[i].secs_before_this_attack = sqlite3_column_int(select_attack, 6);
		batch[i].attack_db_id = sqlite3_column_int64(select_attack,7);
		batch[i].is_ended = sqlite3_column_type(select_attack, 8) != SQLITE_NULL;

		// TODO: Parch -> make this well
		if(batch[i].provider_index == WORDLIST_INDEX || (batch[i].provider_index == RULES_INDEX && RULE_GET_KEY_PROV_INDEX(batch[i].params) == WORDLIST_INDEX))
			batch[i].num_keys_served = sqlite3_column_int64(select_attack, 9);
		else
			batch[i].num_keys_served = 0;

		// Calculate key-space
		if(batch[i].is_ended)
			batch[i].key_space = 0;
		else
		{
			// Find first attack not finished
			if(current_attack_index == -1)
				current_attack_index = i;

			key_providers[batch[i].provider_index].resume(batch[i].min_lenght, batch[i].max_lenght, batch[i].params, batch[i].resume_arg, batch[i].format_index);
			batch[i].key_space = num_key_space;
			key_providers[batch[i].provider_index].finish();
		}

		i++;
	}
	
	sqlite3_finalize(select_attack);

	//num_keys_served_from_start = 0;
	//num_keys_served_from_save = 0;
	set_num_keys_zero();

	// If there are attack not finished
	if (current_attack_index != -1)
	{
		void* set_start_time = (void*)TRUE;
		send_message_gui = psend_message_gui;
		HS_NEW_THREAD(begin_crack, set_start_time);
	}
}

// Method to split charset into optimized chunks
void introduce_fast_lm(AttackData** batch, int* num_attack_in_batch);
PRIVATE void create_batch(int format_index, int key_prov_index, uint32_t min_lenght, uint32_t max_lenght, const char* provider_param)
{
	sqlite3_stmt* insert_new_batch;

	free(batch);
	num_attack_in_batch = 1;
	current_attack_index = 0;
	batch = (AttackData*)malloc( sizeof(AttackData) * num_attack_in_batch);
	batch[0].format_index = format_index;
	batch[0].provider_index = key_prov_index;

	// Check that lengths are in range
	batch[0].min_lenght = __min(__max(__min(max_lenght, min_lenght), key_providers[batch[0].provider_index].min_size), formats[batch[0].format_index].max_plaintext_lenght);
	batch[0].max_lenght = __min(max_lenght, formats[batch[0].format_index].max_plaintext_lenght);
	batch[0].num_keys_served = 0;

	// Put Params
	strcpy(batch[0].params, provider_param);
	sprintf(batch_name, "%s / %s", formats[format_index].name, key_providers[key_prov_index].name);
	sprintf(batch_description, "Length %i - %i", batch[0].min_lenght, batch[0].max_lenght);

	key_providers[key_prov_index].get_param_description(provider_param, batch_name+strlen(batch_name), batch[0].min_lenght, batch[0].max_lenght);

	batch[0].resume_arg[0] = 0;

	// Method to split charset into optimized chunks
	introduce_fast_lm(&batch, &num_attack_in_batch);

	// Insert batch data
	if(!is_benchmark)
	{
		sqlite3_prepare_v2(db, "INSERT INTO Batch (Name,Description) VALUES (?,?);", -1, &insert_new_batch, NULL);
		sqlite3_bind_text(insert_new_batch, 1, batch_name, -1, SQLITE_STATIC);
		sqlite3_bind_text(insert_new_batch, 2, batch_description, -1, SQLITE_STATIC);
		sqlite3_step(insert_new_batch);
		batch_db_id = sqlite3_last_insert_rowid(db);
		sqlite3_finalize(insert_new_batch);
	}
}
PUBLIC int new_crack(int format_index, int key_prov_index, int min_lenght, int max_lenght, char* provider_param, callback_funtion psend_message_gui, int use_rules)
{
	sqlite3_stmt* insert_new_atack;
	sqlite3_stmt* insert_batch_attack;
	int i;

	// TODO: Patch--> revisit to make well
	if(key_prov_index == WORDLIST_INDEX && provider_param == NULL)
		return FALSE;

	// Rules support
	if(format_index != LM_INDEX && use_rules)
	{
		if(!add_rules_to_param(provider_param, key_prov_index))
			return FALSE;// No rules
		key_prov_index = RULES_INDEX;
	}

	create_batch(format_index, key_prov_index, min_lenght, max_lenght, provider_param);

	// Save attackdata to db
	if(!is_benchmark)
	{
		sqlite3_prepare_v2(db, "INSERT INTO Attack (Provider,Format,Param,MinLenght,MaxLenght,ResumeArg) VALUES (?,?,?,?,?,?);", -1, &insert_new_atack, NULL);
		sqlite3_prepare_v2(db, "INSERT INTO BatchAttack (BatchID,AttackID) VALUES (?,?);", -1, &insert_batch_attack, NULL);
		for(i = 0; i < num_attack_in_batch; i++)
		{
			batch[i].is_ended = FALSE;
			batch[i].secs_before_this_attack = 0;

			sqlite3_reset(insert_new_atack);
			sqlite3_bind_int64(insert_new_atack, 1, key_providers[batch[i].provider_index].db_id);
			sqlite3_bind_int64(insert_new_atack, 2, formats[batch[i].format_index].db_id);
			sqlite3_bind_text (insert_new_atack, 3, batch[i].params, -1, SQLITE_STATIC);
			sqlite3_bind_int  (insert_new_atack, 4, batch[i].min_lenght);
			sqlite3_bind_int  (insert_new_atack, 5, batch[i].max_lenght);

			key_providers[batch[i].provider_index].resume(batch[i].min_lenght, batch[i].max_lenght, batch[i].params, batch[i].resume_arg, batch[i].format_index);
			batch[i].key_space = num_key_space;
			key_providers[batch[i].provider_index].save_resume_arg(batch[i].resume_arg);
			key_providers[batch[i].provider_index].finish();
			sqlite3_bind_text(insert_new_atack, 6, batch[i].resume_arg, -1, SQLITE_STATIC);

			sqlite3_step(insert_new_atack);
			batch[i].attack_db_id = sqlite3_last_insert_rowid(db);

			// Batch
			sqlite3_reset(insert_batch_attack);
			sqlite3_bind_int64(insert_batch_attack, 1, batch_db_id);
			sqlite3_bind_int64(insert_batch_attack, 2, batch[i].attack_db_id);
			sqlite3_step(insert_batch_attack);
		}
		sqlite3_finalize(insert_new_atack);
		sqlite3_finalize(insert_batch_attack);
	}
	else
	{
		for(i = 0; i < num_attack_in_batch; i++)
		{
			batch[i].is_ended = FALSE;
			batch[i].secs_before_this_attack = 0;

			key_providers[batch[i].provider_index].resume(batch[i].min_lenght, batch[i].max_lenght, batch[i].params, batch[i].resume_arg, batch[i].format_index);
			batch[i].key_space = num_key_space;
			key_providers[batch[i].provider_index].save_resume_arg(batch[i].resume_arg);
			key_providers[batch[i].provider_index].finish();
		}
	}
	generate_keys_for_testing();

	//num_keys_served_from_start = 0;
	//num_keys_served_from_save = 0;
	set_num_keys_zero();
	
	void* set_start_time = (void*)TRUE;
	send_message_gui = psend_message_gui;
	HS_NEW_THREAD(begin_crack, set_start_time);

	return TRUE;
}

void load_foundhashes_from_db();
PUBLIC void init_attack_data()
{
	HS_CREATE_MUTEX(&found_keys_mutex);

	sqlite3_prepare_v2(db, "UPDATE Attack SET ElapsedTime=?1,ResumeArg=?3,NumKeysServed=?4 WHERE ID=?2;" , -1, &save_state_update, NULL);
	sqlite3_prepare_v2(db, "INSERT INTO FindHash (HashID,ClearText,ElapsedFind,AttackUsed) VALUES (?,?,?,?);", -1, &insert_found_hash, NULL);

	HS_CREATE_MUTEX(&hash2found_id.mutex);
	open_fam();

	// Check if FAM is in a bad state. Trust data in DB
	if ((total_num_hashes() + 1) != hash2found_id.file_size / sizeof(uint32_t))
	{
		load_foundhashes_from_db();
	}
	else
	{
		// Count founds
		uint32_t totalFoundsWithFAM = 0;
		for (uint32_t i = 0; i < (total_num_hashes() + 1); i++)
			if (load_fam(i) != NO_ELEM)
				totalFoundsWithFAM++;

		if (totalFoundsWithFAM != total_num_hashes_found())
			load_foundhashes_from_db();
	}
}