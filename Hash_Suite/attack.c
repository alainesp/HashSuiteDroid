// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#include "common.h"
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <stdio.h>

#ifdef ANDROID
	#include <pthread.h>
#else
	#include <windows.h>
	#include <process.h>
#endif

// Mutex for thread-safe access
extern HS_MUTEX key_provider_mutex;

PUBLIC unsigned int MAX_NUM_PASWORDS_LOADED = 9999999;
PUBLIC int is_benchmark = FALSE;

// Number of threads used
PUBLIC unsigned int num_threads;
PUBLIC unsigned int app_num_threads;
// Used to stop the attack
PUBLIC int continue_attack;
PRIVATE callback_funtion* send_message_gui;
// Number of passwords currently loaded
PUBLIC unsigned int num_passwords_loaded;
// The binary values of the hashes
PUBLIC void* binary_values = NULL;
// His DB ids to save when cracked
PRIVATE sqlite3_int64* hash_ids = NULL;

////////////////////////////////////////////////////////////////////////////////////
// Table map for fast compare
////////////////////////////////////////////////////////////////////////////////////
PUBLIC unsigned int* table = NULL;
PUBLIC unsigned int* bit_table = NULL;
// If there are more than one password with the same hash point to next
PUBLIC unsigned int* same_hash_next = NULL;
PUBLIC unsigned int size_table;
PUBLIC unsigned int size_bit_table;
PUBLIC HS_ALIGN(16) unsigned int size_table_see2[4];
PUBLIC HS_ALIGN(16) unsigned int size_bit_table_see2[4];
PUBLIC unsigned int first_bit_size_bit_table;
PUBLIC unsigned int first_bit_size_table;

////////////////////////////////////////////////////////////////////////////////////
// Salted hash
////////////////////////////////////////////////////////////////////////////////////
PUBLIC void* salts_values = NULL;
PUBLIC unsigned int num_diff_salts;
PUBLIC unsigned int* salt_index = NULL;
PUBLIC unsigned int* same_salt_next = NULL;

////////////////////////////////////////////////////////////////////////////////////
// Found hashes
////////////////////////////////////////////////////////////////////////////////////
PRIVATE unsigned int num_passwords_found = 0;

typedef struct FoundKey
{
	unsigned char cleartext[MAX_KEY_LENGHT];
	unsigned int elapsed;
	unsigned int index;
}FoundKey;

PRIVATE FoundKey* found_keys = NULL;
PRIVATE int capacity;
PRIVATE int current_num_keys;

////////////////////////////////////////////////////////////////////////////////////
// General utilities
////////////////////////////////////////////////////////////////////////////////////
PUBLIC clock_t start_time;
PUBLIC clock_t save_time;

PRIVATE HS_MUTEX found_keys_mutex;
PRIVATE sqlite3_stmt* save_state_update;

////////////////////////////////////////////////////////////////////////////////////
// Batch
////////////////////////////////////////////////////////////////////////////////////
PRIVATE char batch_name[128];
PRIVATE char batch_description[64];
#ifdef ANDROID
PUBLIC sqlite3_int64 batch_db_id;
#else
PRIVATE sqlite3_int64 batch_db_id;
#endif
PUBLIC AttackData* batch = NULL;
PUBLIC int num_attack_in_batch;
PUBLIC int current_attack_index;

PUBLIC char* is_found = NULL;

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

// Mask and size for the table map. Use 12.5% full
PRIVATE void calculate_table_mask(unsigned int num_elem)
{
	int i;
	size_table = 1;

	// Generate result with all bits less than
	// first bit in num_elem in 1
	while(size_table < num_elem)
		size_table = (size_table << 1) + 1;

	// 3 bits more into account
	for(i = 0; i < 3; i++)
		size_table = (size_table << 1) + 1;

	size_bit_table = (size_table << 1) + 1;
	//size_bit_table = (size_bit_table << 1) + 1;

	_BitScanReverse(&first_bit_size_bit_table, size_bit_table);
	_BitScanReverse(&first_bit_size_table, size_table);
	first_bit_size_bit_table++;
	first_bit_size_table++;

	size_table_see2[0] = size_table_see2[1] = size_table_see2[2] = size_table_see2[3] = size_table;
	size_bit_table_see2[0] = size_bit_table_see2[1] = size_bit_table_see2[2] = size_bit_table_see2[3] = size_bit_table;
}
PRIVATE void load_hashes(int format_index)
{
	sqlite3_stmt* select_not_cracked, *count_hashes;
	unsigned int current_index = 0, i;

	sqlite3_prepare_v2(db, "SELECT count(*) FROM Hash WHERE Type=? AND ID NOT IN (SELECT ID FROM FindHash);", -1, &count_hashes, NULL);
	sqlite3_bind_int64(count_hashes, 1, formats[format_index].db_id);
	sqlite3_step(count_hashes);
	num_passwords_loaded = sqlite3_column_int(count_hashes, 0);
	num_passwords_loaded = __min(num_passwords_loaded, MAX_NUM_PASWORDS_LOADED);

	// Create data structures needed.
	binary_values =                 _aligned_malloc(formats[format_index].binary_size    * num_passwords_loaded, 4096);
	hash_ids      = (sqlite3_int64*)malloc(sizeof(sqlite3_int64) * num_passwords_loaded);
	is_found      = (char*)malloc(sizeof(char) * num_passwords_loaded);
	memset(is_found, FALSE, num_passwords_loaded);
	// Data for keys found
	num_passwords_found = 0;
	current_num_keys = 0;
	capacity = __max(num_passwords_loaded/100, 512);
	found_keys = (FoundKey*)malloc(sizeof(FoundKey) * capacity);

	num_diff_salts = 0;

	if(formats[format_index].salt_size)// Salted hash
	{
		salts_values   = _aligned_malloc( formats[format_index].salt_size * num_passwords_loaded, 4096);
		salt_index     = (unsigned int*)_aligned_malloc(sizeof(unsigned int) * num_passwords_loaded, 4096);
		same_salt_next = (unsigned int*)_aligned_malloc(sizeof(unsigned int) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(same_salt_next, 0xff, sizeof(unsigned int) * num_passwords_loaded);
	}
	else// Non-salted hash
	{
		calculate_table_mask(num_passwords_loaded);
		table          = (unsigned int*) _aligned_malloc(sizeof(unsigned int) * (size_table+1), 4096);
		bit_table      = (unsigned int*) _aligned_malloc((size_bit_table/32+1) * sizeof(unsigned int), 4096);
		same_hash_next = (unsigned int*) _aligned_malloc(sizeof(unsigned int) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(bit_table, 0, (size_bit_table/32+1) * sizeof(unsigned int));
		memset(table, 0xff, sizeof(unsigned int) * (size_table+1));
		memset(same_hash_next, 0xff, sizeof(unsigned int) * num_passwords_loaded);
	}

	sqlite3_prepare_v2(db, "SELECT Hex,ID FROM Hash WHERE Type=? AND ID NOT IN (SELECT ID FROM FindHash) LIMIT ?;", -1, &select_not_cracked, NULL);
	sqlite3_bind_int64(select_not_cracked, 1, formats[format_index].db_id);
	sqlite3_bind_int  (select_not_cracked, 2, MAX_NUM_PASWORDS_LOADED);

	while(sqlite3_step(select_not_cracked) == SQLITE_ROW)
	{
		unsigned int value_map = formats[format_index].convert_to_binary(sqlite3_column_text(select_not_cracked, 0), 
			(char*)binary_values + current_index  * formats[format_index].binary_size,
			(char*)salts_values  + num_diff_salts * formats[format_index].salt_size);
		
		if(formats[format_index].salt_size)// Salted hash
		{
			// Check if salt exist
			for(i = 0; i < num_diff_salts; i++)
				if(!memcmp( (char*)salts_values + num_diff_salts*formats[format_index].salt_size,
							(char*)salts_values +       i       *formats[format_index].salt_size, formats[format_index].salt_size))
				{// salt already exist
					unsigned int last_index = salt_index[i];
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
		else// Non-salted hash
		{
			bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
			// Put the password in the table map
			if(table[value_map & size_table] == NO_ELEM)
			{
				table[value_map & size_table] = current_index;
			}
			else
			{
				unsigned int last_index = table[value_map & size_table];
				while(same_hash_next[last_index] != NO_ELEM)
					last_index = same_hash_next[last_index];

				same_hash_next[last_index] = current_index;
			}
		}

		hash_ids[current_index] = sqlite3_column_int64(select_not_cracked, 1);

		current_index++;
	}

	sqlite3_finalize(count_hashes);
	sqlite3_finalize(select_not_cracked);
}
PRIVATE void load_hashes_benchmark(int format_index)
{
	unsigned int current_index = 0, i;

	num_passwords_loaded = MAX_NUM_PASWORDS_LOADED;

	// Create data structures needed.
	binary_values =                 _aligned_malloc(formats[format_index].binary_size    * num_passwords_loaded, 4096);
	hash_ids      = (sqlite3_int64*)malloc(sizeof(sqlite3_int64) * num_passwords_loaded);
	is_found      = (char*)malloc(sizeof(char) * num_passwords_loaded);
	memset(is_found, FALSE, num_passwords_loaded);
	// Data for keys found
	num_passwords_found = 0;
	current_num_keys = 0;
	capacity = __max(num_passwords_loaded/100, 512);
	found_keys = (FoundKey*)malloc(sizeof(FoundKey) * capacity);

	num_diff_salts = 0;

	if(formats[format_index].salt_size)// Salted hash
	{
		salts_values   = _aligned_malloc( formats[format_index].salt_size * num_passwords_loaded, 4096);
		salt_index     = (unsigned int*)_aligned_malloc(sizeof(unsigned int) * num_passwords_loaded, 4096);
		same_salt_next = (unsigned int*)_aligned_malloc(sizeof(unsigned int) * num_passwords_loaded, 4096);

		// Initialize table map
		for(i = 0; i < num_passwords_loaded; i++)
			same_salt_next[i] = NO_ELEM;
	}
	else// Non-salted hash
	{
		calculate_table_mask(num_passwords_loaded);
		table          = (unsigned int*) _aligned_malloc(sizeof(unsigned int) * (size_table+1), 4096);
		bit_table      = (unsigned int*) _aligned_malloc(sizeof(unsigned int) * (size_bit_table/32+1), 4096);
		same_hash_next = (unsigned int*) _aligned_malloc(sizeof(unsigned int) * num_passwords_loaded, 4096);

		// Initialize table map
		memset(bit_table, 0, (size_bit_table/32+1) * sizeof(unsigned int));
		memset(table, 0xff, sizeof(unsigned int) * (size_table+1));
		memset(same_hash_next, 0xff, sizeof(unsigned int) * num_passwords_loaded);
	}

	// Seed the random-number generator with the current time so that the numbers will be different every time we run.
	srand( (unsigned)time( NULL ) );

	for(current_index = 0; current_index < num_passwords_loaded; current_index++)
	{
		// Fill values with random data
		unsigned int value_map;
		char* bin_value  = (char*)binary_values + current_index  * formats[format_index].binary_size;
		char* salt_value = (char*)salts_values  + num_diff_salts * formats[format_index].salt_size;

		for(i = 0; i < formats[format_index].binary_size; i++)
			bin_value[i] = rand() & 0xFF;
		for(i = 0; i < formats[format_index].salt_size; i++)
			salt_value[i] = rand() & 0xFF;
		// 1/5 not random (simulate username)
		memset(salt_value, 2, formats[format_index].salt_size/5);
		if (format_index == DCC_INDEX || format_index == DCC2_INDEX)
			((unsigned int*)salt_value)[10] = ((rand() % 19) + 1) << 4;

		value_map = ((int*)bin_value)[0];
		
		if(formats[format_index].salt_size)// Salted hash
		{
			// Check if salt exist
			for(i = 0; i < num_diff_salts; i++)
				if(!memcmp( (char*)salts_values + num_diff_salts*formats[format_index].salt_size,
							(char*)salts_values +       i       *formats[format_index].salt_size, formats[format_index].salt_size))
				{// salt already exist
					unsigned int last_index = salt_index[i];
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
		else// Non-salted hash
		{
			bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
			// Put the password in the table map
			if(table[value_map & size_table] == NO_ELEM)
			{
				table[value_map & size_table] = current_index;
			}
			else
			{
				unsigned int last_index = table[value_map & size_table];
				while(same_hash_next[last_index] != NO_ELEM)
					last_index = same_hash_next[last_index];

				same_hash_next[last_index] = current_index;
			}
		}

		hash_ids[current_index] = current_index;
	}
}
PUBLIC void password_was_found(unsigned int index, unsigned char* cleartext)
{
	if(is_benchmark) return;
	if(index >= num_passwords_loaded) return;

	HS_ENTER_MUTEX(&found_keys_mutex);

	// TODO: Remove the password from the table
	if(!is_found[index])
	{
		is_found[index] = TRUE;

		num_passwords_found++;
		num_hashes_found_by_format[batch[current_attack_index].format_index]++;

		if(num_passwords_found >= num_passwords_loaded)
			continue_attack = FALSE;

		// If full->double capacity
		if(current_num_keys == capacity)
		{
			capacity*= 2;
			found_keys = realloc(found_keys, sizeof(FoundKey) * capacity);
		}
		found_keys[current_num_keys].index = index;
		found_keys[current_num_keys].elapsed = SECONDS_SINCE(start_time);
		strcpy(found_keys[current_num_keys].cleartext, cleartext);
		current_num_keys++;
	}

	HS_LEAVE_MUTEX(&found_keys_mutex);
}

extern void* thread_params;// This is defined in key_provider.c
extern unsigned int num_thread_params;
PRIVATE CryptParam* crypto_params = NULL;
PRIVATE void begin_crack(callback_funtion psend_message_gui)
{
	unsigned int i, j;
	int thread_id = 0;
	// Find best implementations. Assume there is at least one compatible
	perform_crypt_funtion* perform_crypt = NULL;
	generate_key_funtion* generate = NULL;
#ifdef HS_OPENCL_SUPPORT
	// For GPU compilation and then execution
	create_gpu_crypt_funtion* create_gpu_crypt = NULL;
	OpenCL_Param** crypt_ptr_params = NULL;
	gpu_crypt_funtion** crypt_ptr_func = NULL;
#endif

	send_message_gui = psend_message_gui;

	if(is_benchmark)
		load_hashes_benchmark(batch[current_attack_index].format_index);
	else
		load_hashes(batch[current_attack_index].format_index);
	continue_attack = TRUE;

	num_keys_served_from_save  = 0;
	num_keys_served_from_start += batch[current_attack_index].num_keys_served;

	key_providers[batch[current_attack_index].provider_index].resume(batch[current_attack_index].min_lenght, batch[current_attack_index].max_lenght, batch[current_attack_index].params, batch[current_attack_index].resume_arg, batch[current_attack_index].format_index);

	// GPUs
	num_threads = 0;

#ifdef HS_OPENCL_SUPPORT
	for(j = 0; j < LENGHT(formats[batch[current_attack_index].format_index].opencl_impls); j++)
	{
		create_gpu_crypt = formats[batch[current_attack_index].format_index].opencl_impls[j].perform_crypt;

		for(i = 0; i < LENGHT(key_providers[batch[current_attack_index].provider_index].impls); i++)
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
		crypt_ptr_params = (OpenCL_Param**)malloc(sizeof(OpenCL_Param*)*num_gpu_devices);
		crypt_ptr_func = (gpu_crypt_funtion**)malloc(sizeof(gpu_crypt_funtion*)*num_gpu_devices);

		for(i = 0; i < num_gpu_devices; i++)
			if(gpu_devices[i].is_used)
				crypt_ptr_params[i] = create_gpu_crypt(i, generate, &(crypt_ptr_func[i]));
	}
#endif

	// CPU
	num_threads += app_num_threads;
	perform_crypt = NULL;
	generate = NULL;

	for(j = 0; j < LENGHT(formats[batch[current_attack_index].format_index].impls); j++)
	{
		perform_crypt = formats[batch[current_attack_index].format_index].impls[j].perform_crypt;

		for(i = 0; i < LENGHT(key_providers[batch[current_attack_index].provider_index].impls); i++)
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
	if(crypt_ptr_params && crypt_ptr_func)
		for(i = 0; i < num_gpu_devices; i++)
			if(gpu_devices[i].is_used && crypt_ptr_params[i])
				num_threads++;
#endif
	// If is LM charset not implemented in GPU->use CPU
	if(!app_num_threads && batch[current_attack_index].format_index == LM_INDEX && batch[current_attack_index].provider_index == CHARSET_INDEX)
		num_threads++;
	// Create per thread data
	num_thread_params = num_threads;
	thread_params = calloc(num_threads, key_providers[batch[current_attack_index].provider_index].per_thread_data_size);
	crypto_params = (CryptParam*)calloc(num_threads, sizeof(CryptParam));

#ifdef HS_OPENCL_SUPPORT
	// Then execute the GPU kernels
	if(crypt_ptr_params && crypt_ptr_func)
	{
		for(i = 0; i < num_gpu_devices; i++)
			if(gpu_devices[i].is_used && crypt_ptr_params[i])
			{
				crypt_ptr_params[i]->thread_id = thread_id;
				_beginthread(crypt_ptr_func[i], 0, crypt_ptr_params[i]);
				thread_id++;
			}

		free(crypt_ptr_params);
		free(crypt_ptr_func);
	}
#endif
	// If is LM charset not implemented in GPU->use CPU
	if(!app_num_threads && batch[current_attack_index].format_index == LM_INDEX && batch[current_attack_index].provider_index == CHARSET_INDEX)
	{
		crypto_params[thread_id].gen = generate;
		crypto_params[thread_id].thread_id = thread_id;
		_beginthread(perform_crypt, 0, crypto_params+thread_id);
		thread_id++;
	}
	else
		for (i = 0; i < app_num_threads; i++, thread_id++)
		{
			crypto_params[thread_id].gen = generate;
			crypto_params[thread_id].thread_id = thread_id;
			_beginthread(perform_crypt, 0, crypto_params+thread_id);
		}

	save_time = clock();
}

PRIVATE void save_passwords_found()
{
	int i;
	sqlite3_stmt* insert_found_hash;

	if(!is_benchmark && current_num_keys > 0)
	{
		sqlite3_prepare_v2(db, "INSERT INTO FindHash (ID,ClearText,ElapsedFind,AttackUsed) VALUES (?,?,?,?);", -1, &insert_found_hash, NULL);

		for(i = 0; i < current_num_keys; i++)
		{
			sqlite3_reset(insert_found_hash);
			sqlite3_bind_int64(insert_found_hash, 1, hash_ids[found_keys[i].index]);
			sqlite3_bind_text (insert_found_hash, 2, found_keys[i].cleartext, -1, SQLITE_STATIC);
			sqlite3_bind_int  (insert_found_hash, 3, found_keys[i].elapsed);
			sqlite3_bind_int64(insert_found_hash, 4, batch[current_attack_index].attack_db_id);
			sqlite3_step(insert_found_hash);
		}

		current_num_keys = 0;
		sqlite3_finalize(insert_found_hash);
	}
}
PUBLIC int save_attack_state()
{
	int db_result;
	if(is_benchmark) return TRUE;

	key_providers[batch[current_attack_index].provider_index].save_resume_arg(batch[current_attack_index].resume_arg);

	db_result = BEGIN_TRANSACTION;
	//if(db_result != SQLITE_OK) return FALSE;

	sqlite3_reset(save_state_update);
	sqlite3_bind_int  (save_state_update, 1, SECONDS_SINCE(start_time) + batch[current_attack_index].secs_before_this_attack);
	sqlite3_bind_int64(save_state_update, 2, batch[current_attack_index].attack_db_id);
	sqlite3_bind_text (save_state_update, 3, batch[current_attack_index].resume_arg, -1, SQLITE_STATIC);
	sqlite3_bind_int64(save_state_update, 4, get_num_keys_served());
	sqlite3_step(save_state_update);

	HS_ENTER_MUTEX(&found_keys_mutex);
	save_passwords_found();
	HS_LEAVE_MUTEX(&found_keys_mutex);

	END_TRANSACTION;

	save_time = clock();

	HS_ENTER_MUTEX(&key_provider_mutex);
	num_keys_served_from_start += num_keys_served_from_save;
	num_keys_served_from_save = 0;
	HS_LEAVE_MUTEX(&key_provider_mutex);

	return TRUE;
}

PRIVATE void cleanup_crack()
{
	sqlite3_stmt* update_attack = NULL;
	// Free all memory used
	_aligned_free(bit_table);			bit_table		= NULL;
	_aligned_free(table);				table			= NULL;
	_aligned_free(same_hash_next);		same_hash_next	= NULL;

	free(hash_ids);						hash_ids		= NULL;
	_aligned_free(binary_values);		binary_values	= NULL;
	free(found_keys);					found_keys		= NULL;
	_aligned_free(salts_values);		salts_values	= NULL;
	_aligned_free(salt_index);			salt_index		= NULL;
	_aligned_free(same_salt_next);		same_salt_next	= NULL;
	free(is_found);						is_found		= NULL;

	if(!is_benchmark)
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

	if(is_benchmark) return;

	sqlite3_bind_int  (update_attack, 1, SECONDS_SINCE(start_time) + batch[current_attack_index].secs_before_this_attack);
	sqlite3_bind_int64(update_attack, 2, batch[current_attack_index].attack_db_id);
	sqlite3_bind_int64(update_attack, 3, get_num_keys_served());
	sqlite3_step(update_attack);
	sqlite3_finalize(update_attack);

	free(thread_params);
	free(crypto_params);
	thread_params = NULL;
}
PUBLIC void finish_thread()
{
	int last_index, i;

	HS_ENTER_MUTEX(&found_keys_mutex);

	num_threads--;

	if(!num_threads)
	{
		int64_t key_space_before = 0;
		BEGIN_TRANSACTION;
		/*int first_error = TRUE;
		while(BEGIN_TRANSACTION == SQLITE_BUSY)
		{
			sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
			if(first_error)
			{
				first_error = FALSE;
				send_message_gui(MESSAGE_ERROR_IN_DB);
			}
			Sleep(1000);
		}*/
		//if(!first_error)

		save_passwords_found();
		cleanup_crack();

		END_TRANSACTION;

		// Calculate the key_space of the batch before
		for(i = 0; i < current_attack_index; i++)
			key_space_before += batch[i].key_space;

		// TODO: test more this patch
		if(num_key_space < get_num_keys_served() - key_space_before)
			num_key_space = get_num_keys_served() - key_space_before;

		batch[current_attack_index].key_space = num_key_space;
		last_index = current_attack_index;
		// Next attack in the batch
		batch[current_attack_index].is_ended = TRUE;
		while(current_attack_index < num_attack_in_batch && batch[current_attack_index].is_ended)
			current_attack_index++;

		if(continue_attack && current_attack_index < num_attack_in_batch)
		{
			HS_ENTER_MUTEX(&key_provider_mutex);

			// Number of keys trying in the batch
			num_keys_served_from_start += num_keys_served_from_save;
			num_keys_served_from_save = 0;
			send_message_gui(MESSAGE_FINISH_ATTACK);
			begin_crack(send_message_gui);

			HS_LEAVE_MUTEX(&key_provider_mutex);
		}
		else
		{
			current_attack_index = last_index;
			send_message_gui(MESSAGE_FINISH_BATCH);
		}
	}

	HS_LEAVE_MUTEX(&found_keys_mutex);
}

// Find best implementations.
PUBLIC int has_implementations_compatible(int format_index, int provider_index)
{
	int i, j;

	for(i = 0; i < LENGHT(formats[format_index].impls); i++)
		for(j = 0; j < LENGHT(key_providers[provider_index].impls); j++)
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
			key_providers[batch[i].provider_index].resume(batch[i].min_lenght, batch[i].max_lenght, batch[i].params, batch[i].resume_arg, batch[i].format_index);
			batch[i].key_space = num_key_space;
			key_providers[batch[i].provider_index].finish();
		}

		// Find first attack not finished
		if(current_attack_index == -1 && !batch[i].is_ended)
			current_attack_index = i;

		i++;
	}
	
	sqlite3_finalize(select_attack);

	num_keys_served_from_start = 0;
	num_keys_served_from_save = 0;

	// If there are attack not finished
	if(current_attack_index != -1)
		begin_crack(psend_message_gui);

	start_time = clock();
}

// Method to split charset into optimized chunks
void introduce_fast_lm(AttackData** batch, int* num_attack_in_batch);
PRIVATE void create_batch(int format_index, int key_prov_index, int min_lenght, int max_lenght, const char* provider_param)
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
	batch[0].max_lenght = __min(__min(max_lenght, formats[batch[0].format_index].max_plaintext_lenght), MAX_KEY_LENGHT);
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

	// TODO: Parch--> revisit to make well
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

	num_keys_served_from_start = 0;
	num_keys_served_from_save = 0;
	
	begin_crack(psend_message_gui);
	start_time = clock();

	return TRUE;
}

PUBLIC void init_attack_data()
{
	HS_CREATE_MUTEX(&found_keys_mutex);

	sqlite3_prepare_v2(db, "UPDATE Attack SET ElapsedTime=?1,ResumeArg=?3,NumKeysServed=?4 WHERE ID=?2;", -1, &save_state_update, NULL);
}