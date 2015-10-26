// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2015 by Alain Espinosa. See LICENSE.

#include <string.h>
#include <jni.h>
#include <pthread.h>
#include <stdio.h>

//#define HS_PROFILING

#include "../../../Hash_Suite/Interface.h"

#ifdef HS_PROFILING
	#include "../../android-ndk-profiler/prof.h"
#endif

#ifdef HS_TESTING
PRIVATE char test_param[512];
PRIVATE int m_is_cracking = FALSE;
#endif

PRIVATE char buffer_str[512];

PRIVATE JavaVM* cached_jvm;
PRIVATE jclass cls = NULL;
PRIVATE jmethodID mid_finish_attack = NULL;
PRIVATE jmethodID mid_finish_batch = NULL;
PRIVATE jmethodID mid_attack_begin = NULL;
PRIVATE int benchmark_init_complete = FALSE;
PRIVATE void receive_message(int message)
{
	switch(message)
	{
	case MESSAGE_ATTACK_INIT_COMPLETE:
		benchmark_init_complete = TRUE;
		if(!is_benchmark)
		{
			JNIEnv *env = NULL;
			cached_jvm->AttachCurrentThread(&env, NULL);
			env->CallStaticVoidMethod(cls, mid_attack_begin);
			cached_jvm->DetachCurrentThread();
		}
		break;
	case MESSAGE_FINISH_BATCH:
		if(!is_benchmark)
		{
			JNIEnv *env = NULL;
			cached_jvm->AttachCurrentThread(&env, NULL);
			env->CallStaticVoidMethod(cls, mid_finish_batch);
			env->DeleteGlobalRef(cls);
			cls = NULL;
			cached_jvm->DetachCurrentThread();
#ifdef HS_TESTING
			m_is_cracking = FALSE;
#endif
		}
#ifdef HS_PROFILING
		moncleanup();// End profiling
#endif
		break;
	case MESSAGE_FINISH_ATTACK:
		if(!is_benchmark)
		{
			JNIEnv *env = NULL;
			cached_jvm->AttachCurrentThread(&env, NULL);
			env->CallStaticVoidMethod(cls, mid_finish_attack);
			cached_jvm->DetachCurrentThread();
		}
		break;
	}
}

// To search into accounts
enum SearchOption
{
	SEARCH_NONE = 0,
	SEARCH_USERNAME = 1,
	SEARCH_CLEARTEXT = 2,
	SEARCH_HASH = 3
};
// To sort accounts
enum SortOption
{
	SORT_NONE = 0,
	SORT_ASC = 1,
	SOR_DESC = 2
};

// Some constants
#define UNKNOW_CLEARTEXT	0
#define NO_BG_COLOR			0
#define PARTIAL_CLEARTEXT	1
#define FOUND_CLEARTEXT		2
#define FOUND_DISABLE		3
#define FOUND_EXPIRE		4
#define HEADER_COLOR		5
#define BG_COLOR_GPU		6
#define BG_COLOR_CPU		7

#define PRIV_BITS_SHIFT		8
#define ITEM_DATA_MASK		0xFF

// Constructs the query to retrieve accounts
PRIVATE int GetQuery2LoadHashes(sqlite3_stmt** m_select_hashes, int format_index, int filter_by_tag, char* tag, SearchOption search_option, char* search_word, int show_last_attack, int show_only_found,
		SortOption sort_option, int sort_index, int num_hashes_show, int offset)
{
	sqlite3_stmt* m_count_hashes;
	const char* _col_name[] = {"UserName", "Hex", "ClearText"};
	char buffer_query[1024];
	int num_matches;

	// If changed this string GOTO and change also the line:
	if(format_index == LM_INDEX)// Give LM a special treatment
		sprintf(buffer_query, "SELECT UserName,(Hash1.Hex || Hash2.Hex) AS Hex,(CASE WHEN FindHash1.ClearText NOTNULL THEN FindHash1.ClearText ELSE \"????????????????\" END || CASE WHEN FindHash2.ClearText NOTNULL THEN FindHash2.ClearText ELSE \"????????????????\" END) AS ClearText,Account.Fixed,Account.Privilege FROM ((((((AccountLM INNER JOIN Account ON AccountLM.ID==Account.ID INNER JOIN Hash AS Hash1 ON Hash1.ID==AccountLM.LM1) %s JOIN FindHash AS FindHash1 ON FindHash1.ID==Hash1.ID) INNER JOIN Hash AS Hash2 ON Hash2.ID==AccountLM.LM2 %s JOIN FindHash AS FindHash2 ON FindHash2.ID==Hash2.ID)", show_only_found?"INNER":"LEFT", show_only_found?"INNER":"LEFT");
	else
		sprintf(buffer_query, "SELECT UserName,Hex,(CASE WHEN FindHash.ClearText NOTNULL THEN FindHash.ClearText ELSE \"????????????????????????????????\" END),Account.Fixed,Account.Privilege FROM (((((Hash INNER JOIN Account ON Account.Hash==Hash.ID) %s JOIN FindHash ON FindHash.ID==Hash.ID)", show_only_found?"INNER":"LEFT");

	if(show_last_attack)
	{
		if(format_index == LM_INDEX)
			strcat(buffer_query, " INNER JOIN Attack ON Attack.ID==FindHash1.AttackUsed)");
		else
			strcat(buffer_query, " INNER JOIN Attack ON Attack.ID==FindHash.AttackUsed)");
	}
	else
		strcat(buffer_query, ")");

	if(filter_by_tag)
		strcat(buffer_query, " INNER JOIN TagAccount ON TagAccount.AccountID==Account.ID) INNER JOIN Tag ON Tag.ID==TagAccount.TagID");
	else
		strcat(buffer_query, ")");

	if(format_index == LM_INDEX)// Give LM a special treatment
		sprintf(buffer_query + strlen(buffer_query), ") WHERE 1==1");
	else
		sprintf(buffer_query + strlen(buffer_query), ") WHERE Type=%lli", formats[format_index].db_id);

	if(show_last_attack)
		sprintf(buffer_query + strlen(buffer_query), " AND Attack.ID in (SELECT max(ID) FROM Attack WHERE Format=%lli)", formats[format_index].db_id);

	if(filter_by_tag)
		sprintf(buffer_query + strlen(buffer_query), " AND Name=='%s'", tag);

	if(search_option && strlen(search_word))
	{
		switch(search_option)
		{
		case SEARCH_USERNAME:// Search username
			sprintf(buffer_query + strlen(buffer_query), " AND UserName LIKE '%%%s%%'", search_word);
			break;
		case SEARCH_CLEARTEXT:// Search cleartext
			if(format_index == LM_INDEX)// Give LM a special treatment
				sprintf(buffer_query + strlen(buffer_query), " AND (FindHash1.ClearText LIKE '%%%s%%' OR FindHash2.ClearText LIKE '%%%s%%')", search_word, search_word);
			else
				sprintf(buffer_query + strlen(buffer_query), " AND ClearText LIKE '%%%s%%'", search_word);
			break;
		case SEARCH_HASH:// Search hash
			if(format_index == LM_INDEX)// Give LM a special treatment
			{
				strcpy(buffer_str, search_word);
				memmove(buffer_str+17, buffer_str+16, 16);
				buffer_str[16] = 0;
				sprintf(buffer_query + strlen(buffer_query), " AND (Hash1.Hex LIKE '%s' AND Hash2.Hex LIKE '%s')", buffer_str, buffer_str+17);
			}
			else
				sprintf(buffer_query + strlen(buffer_query), " AND Hex LIKE '%s'", search_word);
			break;
		}
	}

	// Count matches
	if(!filter_by_tag && !(search_option && strlen(search_word)) && !show_only_found && !show_last_attack)
	{
		num_matches = num_user_by_formats[format_index];
		// TODO: use more cache here
	}
	else
	{
		sprintf(buffer_str, "SELECT count(*) %s;", strstr(buffer_query, "FROM"));
		sqlite3_prepare_v2(db, buffer_str, -1, &m_count_hashes, NULL);
		sqlite3_step(m_count_hashes);
		num_matches = sqlite3_column_int(m_count_hashes, 0);
		sqlite3_finalize(m_count_hashes);
	}
	//SET_EDIT_NUM_DIGIT(ID_SEARCH_MATCHES, m_num_matches);
	//m_current_page_hash = CLIP_RANGE(m_current_page_hash, 0, NumPages(m_num_matches, m_num_hashes_show) - 1);

	if(sort_option)
	{
		strcat(buffer_query, " ORDER BY ");
		strcat(buffer_query, _col_name[sort_index]);

		if(sort_option == SORT_ASC)
			strcat(buffer_query, " COLLATE NOCASE ASC");
		else
			strcat(buffer_query, " COLLATE NOCASE DESC");
	}

	// Prepare real query
	strcat(buffer_query, " LIMIT ? OFFSET ?;");
	sqlite3_prepare_v2(db, buffer_query, -1, m_select_hashes, NULL);

	sqlite3_bind_int(*m_select_hashes, 1, num_hashes_show);
	sqlite3_bind_int(*m_select_hashes, 2, offset);

	return num_matches;
}

extern "C"
{
// Cache VM
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* jvm, void *reserved)
{
	cached_jvm = jvm;
	return JNI_VERSION_1_6;
}

// Initialize Hash Suite
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_initAll(JNIEnv* env, jclass, jstring files_path)
{
	const char* path = env->GetStringUTFChars(files_path, NULL);
	init_all(path);
	env->ReleaseStringUTFChars(files_path, path);
}

// In_Out
PRIVATE ImportParam m_imp_param;
PRIVATE jmethodID mid_select_format;
PRIVATE int select_format(char* line, int* valid_formats)
{
	JNIEnv *env = NULL;
	cached_jvm->AttachCurrentThread(&env, NULL);
	jintArray valid_formats_obj = env->NewIntArray(num_formats);
	env->SetIntArrayRegion(valid_formats_obj, 0, num_formats, valid_formats);
	int result = env->CallStaticIntMethod(cls, mid_select_format, env->NewStringUTF(line), valid_formats_obj);
	cached_jvm->DetachCurrentThread();

	return result;
}
PRIVATE void* import_native(void* param)
{
	importers[0].function((ImportParam*)param);

	return NULL;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_ImportHashes(JNIEnv* env, jclass, jstring file_path)
{
	m_imp_param.isEnded = FALSE;
	const char* path = env->GetStringUTFChars(file_path, NULL);
	strcpy(m_imp_param.filename, path);
	env->ReleaseStringUTFChars(file_path, path);
	m_imp_param.select_format = select_format;

	if(!cls)
	{
		jclass localRefCls = env->FindClass("com/hashsuite/droid/MainActivity");
		cls = (jclass)env->NewGlobalRef((jobject)localRefCls);// Create a global reference
		env->DeleteLocalRef(localRefCls);// The local reference is no longer useful
	}
	mid_select_format = env->GetStaticMethodID(cls, "SelectConflictingFormat", "(Ljava/lang/String;[I)I");

	pthread_t hs_pthread_id;
	pthread_create(&hs_pthread_id, NULL, import_native, &m_imp_param);
}

#define IMPORT_IS_ENDED		0
#define IMPORT_USERS_ADDED	1
#define IMPORT_LINES_SKIPED 2
#define IMPORT_COMPLETITION 3
#define IMPORT_FORMATS_DATA 4
JNIEXPORT jint JNICALL Java_com_hashsuite_droid_MainActivity_GetImportResultInt(JNIEnv* env, jclass, jint index)
{
	switch(index)
	{
	case IMPORT_IS_ENDED:
		return m_imp_param.isEnded;
	case IMPORT_USERS_ADDED:
			return m_imp_param.result.num_users_added;
	case IMPORT_LINES_SKIPED:
			return m_imp_param.result.lines_skiped;
	case IMPORT_COMPLETITION:
			return m_imp_param.completition;
	}

	index -= IMPORT_FORMATS_DATA;
	int format_index = index / 3;
	if(index >= 0 && format_index < num_formats)
	{
		switch(index % 3)
		{
		case 0:
			return m_imp_param.result.formats_stat[format_index].num_hash_added;
		case 1:
			return m_imp_param.result.formats_stat[format_index].num_hash_disable;
		case 2:
			return m_imp_param.result.formats_stat[format_index].num_hash_exist;
		}

	}

	return -1;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_ImportHashesStop(JNIEnv* env, jclass)
{
	continue_import = FALSE;
}
void import_db(const char* filename);
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_ImportDB(JNIEnv* env, jclass, jstring file_path)
{
	const char* path = env->GetStringUTFChars(file_path, NULL);
	import_db(path);
	env->ReleaseStringUTFChars(file_path, path);
	db = NULL;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_Export(JNIEnv* env, jclass, jstring dir_path, jint index)
{
	if(index >=0 && index < num_exporters)
	{
		const char* path = env->GetStringUTFChars(dir_path, NULL);
		sprintf(buffer_str, "%s/%s", path, exporters[index].defaultFileName);
		env->ReleaseStringUTFChars(dir_path, path);

		exporters[index].function(buffer_str);
	}
}

// Hashes stats
PRIVATE int num_matches = 0;
// Set a field and delete the local reference
PRIVATE void setObjectField_ReleaseLocalRef(JNIEnv* env, jobject obj, jfieldID fieldID, jobject value)
{
	env->SetObjectField(obj, fieldID, value);
	env->DeleteLocalRef(value);
}
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_HashesFragment_GetFormats(JNIEnv* env, jclass)
{
	jobjectArray result = env->NewObjectArray(num_formats, env->FindClass("java/lang/String"), NULL);

	for (int i = 0; i < num_formats; ++i)
		env->SetObjectArrayElement(result, i, env->NewStringUTF(formats[i].name));

	return result;
}

JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_GPUInfo_GetGpusInfo(JNIEnv* env, jclass complexClass)
{
	jfieldID fid_name = env->GetFieldID(complexClass, "name", "Ljava/lang/String;");
	jfieldID fid_driver_version = env->GetFieldID(complexClass, "driver_version", "Ljava/lang/String;");
	jfieldID fid_cores = env->GetFieldID(complexClass, "cores", "I");
	jfieldID fid_frequency = env->GetFieldID(complexClass, "frequency", "I");
	jfieldID fid_vendor_icon = env->GetFieldID(complexClass, "vendor_icon", "I");

	jobjectArray result = env->NewObjectArray(num_gpu_devices, complexClass, NULL);

	for (int i = 0; i < num_gpu_devices; ++i)
	{
		jobject gpu_obj = env->AllocObject(complexClass);

		setObjectField_ReleaseLocalRef(env, gpu_obj, fid_name, env->NewStringUTF(gpu_devices[i].name));
		setObjectField_ReleaseLocalRef(env, gpu_obj, fid_driver_version, env->NewStringUTF(gpu_devices[i].driver_version));
		env->SetIntField(gpu_obj, fid_cores, gpu_devices[i].cores);
		env->SetIntField(gpu_obj, fid_frequency, gpu_devices[i].max_clock_frequency);
		env->SetIntField(gpu_obj, fid_vendor_icon, gpu_devices[i].vendor_icon);

		env->SetObjectArrayElement(result, i, gpu_obj);
	}

	return result;
}
PRIVATE jchar* ascii_to_jchar(jchar* out , char* str, size_t len)
{
	for (unsigned int i = 0; i < len; ++i)
		out[i] = str[i];

	return out;
}
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_Account_GetHashes(JNIEnv* env, jclass complexClass, jint format_index, jint num_hashes_show, jint offset)
{
	sqlite3_stmt* m_select_hashes;
	jfieldID fid_username = env->GetFieldID(complexClass, "username", "Ljava/lang/String;");
	//jfieldID fid_hash = env->GetFieldID(complexClass, "hash", "Ljava/lang/String;");
	jfieldID fid_cleartext = env->GetFieldID(complexClass, "cleartext", "Ljava/lang/String;");
	jfieldID fid_flag = env->GetFieldID(complexClass, "flag", "I");

	num_matches = GetQuery2LoadHashes(&m_select_hashes, format_index, FALSE, NULL, SEARCH_NONE, NULL, FALSE, FALSE, SORT_NONE, 0, num_hashes_show, offset);
	int index = 0;
	jobject* accounts_objs = (jobject*)malloc(num_hashes_show*sizeof(jobject));

	while(sqlite3_step(m_select_hashes) == SQLITE_ROW)
	{
		accounts_objs[index] = env->AllocObject(complexClass);

		size_t username_len = strlen((const char*)sqlite3_column_text(m_select_hashes, 0));
		setObjectField_ReleaseLocalRef(env, accounts_objs[index], fid_username, env->NewString(ascii_to_jchar((jchar*)buffer_str, (char*)sqlite3_column_text(m_select_hashes, 0), username_len), username_len));
		//setObjectField_ReleaseLocalRef(env, accounts_objs[index], fid_hash, env->NewStringUTF((const char*)sqlite3_column_text(m_select_hashes, 1)));

		strcpy(buffer_str, (char*)sqlite3_column_text(m_select_hashes, 2));
		int _is_fixed  = sqlite3_column_int(m_select_hashes, 3);
		int _privilege = sqlite3_column_int(m_select_hashes, 4);

		// Categorize cleartext
		int _item_data = FOUND_CLEARTEXT;
		if(_is_fixed == FIXED_DISABLE)
			_item_data = FOUND_DISABLE;
		else if(_is_fixed == FIXED_EXPIRE)
			_item_data = FOUND_EXPIRE;
		else if(strstr(buffer_str, "????????????????????????????????"))
			_item_data = UNKNOW_CLEARTEXT;
		else if(strstr(buffer_str, "????????????????"))
			_item_data = PARTIAL_CLEARTEXT;

		env->SetIntField(accounts_objs[index], fid_flag, _item_data | (_privilege << PRIV_BITS_SHIFT));
		size_t cleartext_len = strlen(buffer_str);
		setObjectField_ReleaseLocalRef(env, accounts_objs[index], fid_cleartext, env->NewString(ascii_to_jchar((jchar*)(buffer_str+32), buffer_str, cleartext_len), cleartext_len));

		index++;
	}

	sqlite3_finalize(m_select_hashes);

	jobjectArray result = env->NewObjectArray(index, complexClass, NULL);

	for (int i = 0; i < index; ++i)
		env->SetObjectArrayElement(result, i, accounts_objs[i]);

	free(accounts_objs);

	return result;
}
JNIEXPORT jint JNICALL Java_com_hashsuite_droid_MainActivity_GetNumMatches(JNIEnv* env, jclass)
{
	return num_matches;
}
JNIEXPORT jstring JNICALL Java_com_hashsuite_droid_MainActivity_ShowHashesStats(JNIEnv* env, jclass, jint format_index, jint width)
{
	jstring result;
	if (format_index >= 0 && format_index < num_formats && num_hashes_by_formats[format_index] > 0)
	{
		sprintf(buffer_str, width ? "Hash Suite Droid [%i/%i %i%% found]" : "%i/%i %i%% found"
					, num_hashes_found_by_format[format_index], num_hashes_by_formats[format_index], num_hashes_found_by_format[format_index]*100/num_hashes_by_formats[format_index]);
		result = env->NewStringUTF(buffer_str);
	}
	else
		result = env->NewStringUTF("Hash Suite Droid [0/0 0%]");

	return result;
}
JNIEXPORT jint JNICALL Java_com_hashsuite_droid_MainActivity_GetNumHash2Crack(JNIEnv* env, jclass, jint format_index)
{
	if (format_index >= 0 && format_index < num_formats)
		return num_hashes_by_formats[format_index] - num_hashes_found_by_format[format_index];

	return 0;
}

void clear_db_accounts();
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_clearAllAccounts(JNIEnv* env, jclass)
{
	clear_db_accounts();
}

// Attacks management
PRIVATE jfieldID fid_num_passwords_loaded;
PRIVATE jfieldID fid_key_served;
PRIVATE jfieldID fid_key_space_batch;
PRIVATE jfieldID fid_progress;

PRIVATE jfieldID fid_password_per_sec;
PRIVATE jfieldID fid_time_begin;
PRIVATE jfieldID fid_time_total;
PRIVATE jfieldID fid_work_done;
PRIVATE jfieldID fid_finish_time;

PRIVATE void start_attack_cache(JNIEnv* env, int num_threads, jint gpus_used)
{
	app_num_threads = num_threads;
	for (int i = 0;  i < num_gpu_devices; ++i)
		if((gpus_used >> i) & 1)
			gpu_devices[i].flags |= GPU_FLAG_IS_USED;
		else
			GPU_SET_FLAG_DISABLE(gpu_devices[i].flags, GPU_FLAG_IS_USED);

	jclass complexClass = env->FindClass("com/hashsuite/droid/AttackStatusData");
	fid_progress = env->GetFieldID(complexClass, "progress", "I");

	fid_num_passwords_loaded = env->GetFieldID(complexClass, "num_passwords_loaded", "Ljava/lang/String;");
	fid_key_served = env->GetFieldID(complexClass, "key_served", "Ljava/lang/String;");
	fid_key_space_batch = env->GetFieldID(complexClass, "key_space_batch", "Ljava/lang/String;");

	fid_password_per_sec = env->GetFieldID(complexClass, "password_per_sec", "Ljava/lang/String;");
	fid_time_begin = env->GetFieldID(complexClass, "time_begin", "Ljava/lang/String;");
	fid_time_total = env->GetFieldID(complexClass, "time_total", "Ljava/lang/String;");
	fid_work_done = env->GetFieldID(complexClass, "work_done", "Ljava/lang/String;");
	fid_finish_time = env->GetFieldID(complexClass, "finish_time", "Ljava/lang/String;");

	if(!cls)
	{
		jclass localRefCls = env->FindClass("com/hashsuite/droid/MainActivity");
		cls = (jclass)env->NewGlobalRef((jobject)localRefCls);// Create a global reference
		env->DeleteLocalRef(localRefCls);// The local reference is no longer useful
	}
	mid_finish_attack = env->GetStaticMethodID(cls, "ChangeCurrentAttackCallBack", "()V");
	mid_finish_batch = env->GetStaticMethodID(cls, "FinishBatchCallBack", "()V");
	mid_attack_begin = env->GetStaticMethodID(cls, "AttackBeginCallBack", "()V");
}
#include "../../../Hash_Suite/gui_utils.h"
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_StartAttack(JNIEnv* env, jclass, jint format_index, jint provider_index, jint num_threads, jint min_size, jint max_size, jstring param, jint use_rules, jint rules_on, jint gpus_used)
{
	start_attack_cache(env, num_threads, gpus_used);

#ifdef HS_TESTING
	if(is_testing)
		use_rules = testing_use_rules;
	else if(use_rules)
		for (int i = 0;  i < num_rules; ++i)
			rules[i].checked = (rules_on >> i) & 1;
#else
	if(use_rules)
		for (int i = 0;  i < num_rules; ++i)
			rules[i].checked = (rules_on >> i) & 1;
#endif

	if(provider_index == CHARSET_INDEX || provider_index == KEYBOARD_INDEX)
	{
#ifdef HS_TESTING
		if(is_testing)
		{
			switch (provider_index)
			{
				case CHARSET_INDEX:
					strcpy(buffer_str, test_param);
					if(check_only_lenght < 0)
					{
						min_size = 0;
						max_size = (formats[format_index].salt_size ? 3 : 4) - 1;
					}
					else
					{
						min_size = check_only_lenght;
						max_size = check_only_lenght;
					}
					break;
				default:
					break;
			}
			//MAX_NUM_PASWORDS_LOADED = 1;
		}
#endif
		new_crack(format_index, provider_index, min_size, max_size, buffer_str, &receive_message, use_rules);
	}
	else
	{
#ifdef HS_TESTING
		if(is_testing)
		{
			switch (provider_index)
			{
				case WORDLIST_INDEX:
					sprintf(buffer_str, "%lli", wordlist_id);
					break;
				default:
					break;
			}
			new_crack(format_index, provider_index, min_size, max_size, buffer_str, &receive_message, use_rules);
		}
		else
		{
			char* c_param = (char*)env->GetStringUTFChars(param, NULL);
			new_crack(format_index, provider_index, min_size, max_size, c_param, &receive_message, use_rules);
			env->ReleaseStringUTFChars(param, c_param);
		}
#else
		char* c_param = (char*)env->GetStringUTFChars(param, NULL);
		new_crack(format_index, provider_index, min_size, max_size, c_param, &receive_message, use_rules);
		env->ReleaseStringUTFChars(param, c_param);
#endif
	}

#ifdef HS_PROFILING
	/* Begin profiling */
	setenv("CPUPROFILE_FREQUENCY", "10000", 1); /* Change to 10 interrupts per millisecond */
	monstartup("libHashSuiteNative.so");
#endif
}
// Used to check state of OpenCL Rules compilation
extern OpenCL_Param** ocl_crypt_ptr_params;
JNIEXPORT jint JNICALL Java_com_hashsuite_droid_MainActivity_GetRulesGPUStatus(JNIEnv* env, jclass)
{
	int kernel_sizes = 0;
	int current_compiled_at = 0;
	int in_use_devices = 0;

	if(ocl_crypt_ptr_params)
		for (int i = 0;  i < num_gpu_devices; ++i)
			if(ocl_crypt_ptr_params[i])
			{
				in_use_devices++;
				for (int j = 0; j <= 27; ++j)
				{
					if(ocl_crypt_ptr_params[i]->rules.binaries_size[j])
					{
						kernel_sizes += (int)(ocl_crypt_ptr_params[i]->rules.binaries_size[j]/1024);
						current_compiled_at++;
					}
					else
						break;
				}
			}

	int percent = in_use_devices ? (current_compiled_at*100/(in_use_devices*28)) : 0;
	return kernel_sizes + (percent<<24);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_ResumeAttack(JNIEnv* env, jclass, jlong db_id, jint num_threads, jint gpus_used)
{
	start_attack_cache(env, num_threads, gpus_used);

	resume_crack(db_id, receive_message);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_StopAttack(JNIEnv* env, jclass)
{
	continue_attack = FALSE;
}
JNIEXPORT jstring JNICALL Java_com_hashsuite_droid_MainActivity_GetAttackDescription(JNIEnv* env, jclass)
{
	int index = current_attack_index;
	sprintf(buffer_str, "%s", key_providers[batch[index].provider_index].name);
	key_providers[batch[index].provider_index].get_param_description(batch[index].params, buffer_str+strlen(buffer_str), batch[index].min_lenght, batch[index].max_lenght);

	return env->NewStringUTF(buffer_str);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_AttackStatusData_UpdateStatus(JNIEnv* env, jobject status)
{
	int progress = 0;
	char tmp_buffer[16];

	int64_t _key_served = get_num_keys_served();
	int64_t _key_space = get_key_space_batch();

	itoaWithDigitGrouping(num_passwords_loaded, buffer_str);
	env->SetObjectField(status, fid_num_passwords_loaded, env->NewStringUTF(buffer_str));
	itoaWithDigitGrouping(_key_served, buffer_str);
	env->SetObjectField(status, fid_key_served, env->NewStringUTF(buffer_str));

	if(KEY_SPACE_UNKNOW == _key_space)
	{
		strcpy(buffer_str, "Unknown");
		progress = -1;
	}
	else
	{
		itoaWithDigitGrouping(_key_space, buffer_str);
		// Calculate the progress
		if(_key_space < 1024)
			progress = _key_served * 1024 / _key_space;
		else
			progress = _key_served / (_key_space >> 10);

		if(progress < 1)
			progress = 1;
	}
	env->SetObjectField(status, fid_key_space_batch, env->NewStringUTF(buffer_str));

	env->SetObjectField(status, fid_password_per_sec, env->NewStringUTF(password_per_sec(tmp_buffer)));
	env->SetObjectField(status, fid_time_begin, env->NewStringUTF(get_time_from_begin(FALSE)));
	env->SetObjectField(status, fid_time_total, env->NewStringUTF(get_time_from_begin(TRUE)));
	env->SetObjectField(status, fid_work_done, env->NewStringUTF(get_work_done()));
	env->SetObjectField(status, fid_finish_time, env->NewStringUTF(finish_time()));

	env->SetIntField(status, fid_progress, progress);
}
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_ResumeAttackData_GetAttacks2Resume(JNIEnv* env, jclass complexClass)
{
	sqlite3_stmt* _select_resume_attack;
	sqlite3_prepare_v2(db, "SELECT ID,Name FROM Batch WHERE EXISTS (SELECT * FROM Attack INNER JOIN BatchAttack ON BatchAttack.AttackID=Attack.ID WHERE End ISNULL AND BatchAttack.BatchID==Batch.ID);", -1, &_select_resume_attack, NULL);

	jfieldID fid_name = env->GetFieldID(complexClass, "name", "Ljava/lang/String;");
	jfieldID fid_id = env->GetFieldID(complexClass, "id", "J");

	int resume_count = 0;
	int max_num_resume = 16;
	jobject* resume_objs = (jobject*)malloc(max_num_resume*sizeof(jobject));

	while(sqlite3_step(_select_resume_attack) == SQLITE_ROW)
	{
		if(resume_count == max_num_resume)
		{
			max_num_resume *= 2;
			resume_objs = (jobject*)realloc(resume_objs, max_num_resume*sizeof(jobject));
		}

		resume_objs[resume_count] = env->AllocObject(complexClass);

		setObjectField_ReleaseLocalRef(env, resume_objs[resume_count], fid_name, env->NewStringUTF((const char*)sqlite3_column_text(_select_resume_attack, 1)));
		env->SetLongField(resume_objs[resume_count], fid_id, sqlite3_column_int64(_select_resume_attack, 0));

		resume_count++;
	}
	sqlite3_finalize(_select_resume_attack);

	jobjectArray result = env->NewObjectArray(resume_count, complexClass, NULL);

	for (int i = 0; i < resume_count; ++i)
		env->SetObjectArrayElement(result, i, resume_objs[i]);

	free(resume_objs);

	return result;
}
extern sqlite3_int64 batch_db_id;
JNIEXPORT jlong JNICALL Java_com_hashsuite_droid_MainActivity_GetAttackID(JNIEnv* env, jclass)
{
	return batch_db_id;//batch[current_attack_index].attack_db_id;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_SaveAttackState(JNIEnv* env, jclass)
{
	save_attack_state();
}

// Settings
JNIEXPORT int JNICALL Java_com_hashsuite_droid_MainActivity_GetSetting(JNIEnv* env, jclass, jint id, jint default_value)
{
	return get_setting(id, default_value);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_SaveSetting(JNIEnv* env, jclass, jint id, jint value_to_save)
{
	save_setting(id, value_to_save);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_SaveSettingsToDB(JNIEnv* env, jclass)
{
	save_settings_to_db();
}

// Benchmark
PRIVATE unsigned int bench_thread(JNIEnv* env, jclass my_class, jclass thread_cls, jmethodID thread_sleep, jmethodID SetBenchData_id, jmethodID complete_benchmark_id);

JNIEXPORT jint JNICALL Java_com_hashsuite_droid_MainActivity_GetBenchmarkDuration(JNIEnv* env, jclass)
{
	int duration = 0;

	for(int format_index = 0; format_index < num_formats; format_index++)
		for(int i = 0; i < formats[format_index].lenght_bench_values; i++)
			duration++;

	return duration * m_benchmark_time * (1+num_gpu_devices);
}
JNIEXPORT jintArray JNICALL Java_com_hashsuite_droid_MainActivity_GetBenchmarkValues(JNIEnv* env, jclass, jint format_index)
{
	jintArray bench_balues = env->NewIntArray(formats[format_index].lenght_bench_values);
	env->SetIntArrayRegion(bench_balues, 0, formats[format_index].lenght_bench_values, formats[format_index].bench_values);

	return bench_balues;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_Benchmark(JNIEnv* env, jclass my_class)
{
	performing_bench = TRUE;
	is_benchmark = TRUE;

	jclass thread_cls = env->FindClass("java/lang/Thread");
	jmethodID thread_sleep = env->GetStaticMethodID(thread_cls, "sleep", "(J)V");
	jmethodID SetBenchData_id = env->GetStaticMethodID(my_class, "SetBenchData", "(Ljava/lang/String;II)V");
	jmethodID complete_benchmark_id = env->GetStaticMethodID(my_class, "OnCompleteBenchmark", "()V");

	bench_thread(env, my_class, thread_cls, thread_sleep, SetBenchData_id, complete_benchmark_id);

	MAX_NUM_PASWORDS_LOADED = 9999999;
	is_benchmark = FALSE;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_BenchmarkStop(JNIEnv* env, jclass my_class)
{
	performing_bench = FALSE;
}

// Wordlist
#define WORDLIST_NORMAL			0
#define WORDLIST_TO_DOWNLOAD	1
#define WORDLIST_DOWNLOADING	2

JNIEXPORT jlong JNICALL Java_com_hashsuite_droid_MainActivity_SaveWordlist(JNIEnv* env, jclass, jstring path, jstring name, jlong file_lenght)
{
	sqlite3_stmt* _insert_wordlist;
	sqlite3_prepare_v2(db, "INSERT INTO WordList (Name,FileName,Length,State) VALUES (?,?,?,0);", -1, &_insert_wordlist, NULL);
	sqlite3_stmt* _select_existing_wordlist, *_update_existing_wordlist;
	sqlite3_prepare_v2(db, "SELECT ID FROM WordList WHERE State=? AND Name=?;", -1, &_select_existing_wordlist, NULL);
	sqlite3_prepare_v2(db, "UPDATE WordList SET State=?,FileName=?,Length=? WHERE ID=?;", -1, &_update_existing_wordlist, NULL);

	const char* wordlist_path = env->GetStringUTFChars(path, NULL);
	const char* wordlist_name = env->GetStringUTFChars(name, NULL);

	jlong db_id = -1;
	// Add the wordlist to db
	if( is_wordlist_supported(wordlist_path, NULL) )
	{
		sqlite3_bind_text (_insert_wordlist, 1, wordlist_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text (_insert_wordlist, 2, wordlist_path, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(_insert_wordlist, 3, file_lenght);

		// Check if it is a file to download
		if(sqlite3_step(_insert_wordlist) != SQLITE_DONE)
		{
			sqlite3_reset(_select_existing_wordlist);
			sqlite3_bind_int  (_select_existing_wordlist, 1, WORDLIST_TO_DOWNLOAD);
			sqlite3_bind_text (_select_existing_wordlist, 2, wordlist_name, -1, SQLITE_TRANSIENT);
			// If have same name and length->is the wordlist
			if(sqlite3_step(_select_existing_wordlist) == SQLITE_ROW)
			{
				db_id = sqlite3_column_int64(_select_existing_wordlist, 0);
				sqlite3_reset(_update_existing_wordlist);
				sqlite3_bind_int  (_update_existing_wordlist, 1, WORDLIST_NORMAL);
				sqlite3_bind_text (_update_existing_wordlist, 2, wordlist_path, -1, SQLITE_TRANSIENT);
				sqlite3_bind_int64(_update_existing_wordlist, 3, file_lenght);
				sqlite3_bind_int64(_update_existing_wordlist, 4, db_id);
				sqlite3_step(_update_existing_wordlist);
			}
		}
		else
			db_id = sqlite3_last_insert_rowid(db);
	}
	env->ReleaseStringUTFChars(path, wordlist_path);
	env->ReleaseStringUTFChars(name, wordlist_name);

	sqlite3_finalize(_update_existing_wordlist);
	sqlite3_finalize(_select_existing_wordlist);
	sqlite3_finalize(_insert_wordlist);

	return db_id;
}
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_WordlistData_GetWordlists(JNIEnv* env, jclass complexClass)
{
	sqlite3_stmt* _select_wordlists;
	// Get all wordlist from db
	sqlite3_prepare_v2(db, "SELECT Name,FileName,Length,ID FROM WordList WHERE State=?;", -1, &_select_wordlists, NULL);
	sqlite3_bind_int(_select_wordlists, 1, WORDLIST_NORMAL);
	int m_wordlist_count = 0;

	jfieldID fid_name = env->GetFieldID(complexClass, "name", "Ljava/lang/String;");
	jfieldID fid_size = env->GetFieldID(complexClass, "size", "Ljava/lang/String;");
	jfieldID fid_id = env->GetFieldID(complexClass, "id", "J");

	int max_num_wordlist = 16;
	jobject* wordlist_data_objs = (jobject*)malloc(max_num_wordlist*sizeof(jobject));

	while(sqlite3_step(_select_wordlists) == SQLITE_ROW)
	{
		// Check if file exist
		FILE* _wordlist = fopen((char*)sqlite3_column_text(_select_wordlists, 1), "r");
		if(_wordlist)
		{
			fclose(_wordlist);

			if(m_wordlist_count == max_num_wordlist)
			{
				max_num_wordlist *= 2;
				wordlist_data_objs = (jobject*)realloc(wordlist_data_objs, max_num_wordlist*sizeof(jobject));
			}

			wordlist_data_objs[m_wordlist_count] = env->AllocObject(complexClass);

			setObjectField_ReleaseLocalRef(env, wordlist_data_objs[m_wordlist_count], fid_name, env->NewStringUTF((const char*)sqlite3_column_text(_select_wordlists, 0)));
			filelength2string(sqlite3_column_int64(_select_wordlists, 2), buffer_str);
			setObjectField_ReleaseLocalRef(env, wordlist_data_objs[m_wordlist_count], fid_size, env->NewStringUTF((const char*)buffer_str));
			env->SetLongField(wordlist_data_objs[m_wordlist_count], fid_id, sqlite3_column_int64(_select_wordlists, 3));

			m_wordlist_count++;
		}
	}
	sqlite3_finalize(_select_wordlists);

	jobjectArray result = env->NewObjectArray(m_wordlist_count, complexClass, NULL);

	for (int i = 0; i < m_wordlist_count; ++i)
		env->SetObjectArrayElement(result, i, wordlist_data_objs[i]);

	free(wordlist_data_objs);

	return result;
}

JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_SavePhrases(JNIEnv* env, jclass, jstring path, jstring name, jlong file_lenght)
{
	sqlite3_stmt* _insert_wordlist;
	sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO PhrasesWordList (ID,Name,FileName,Length) VALUES (1,?,?,?);", -1, &_insert_wordlist, NULL);
	const char* wordlist_path = env->GetStringUTFChars(path, NULL);
	const char* wordlist_name = env->GetStringUTFChars(name, NULL);

	// Add the wordlist to db
	if( is_wordlist_supported(wordlist_path, NULL) )
	{
		sqlite3_bind_text (_insert_wordlist, 1, wordlist_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text (_insert_wordlist, 2, wordlist_path, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(_insert_wordlist, 3, file_lenght);
		sqlite3_step(_insert_wordlist);
	}

	env->ReleaseStringUTFChars(path, wordlist_path);
	env->ReleaseStringUTFChars(name, wordlist_name);
	sqlite3_finalize(_insert_wordlist);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_setPhrasesMaxWords(JNIEnv* env, jclass complexClass, jint max_num_words)
{
	PHRASES_MAX_WORDS_READ = max_num_words;
}

// Charset
PRIVATE jobjectArray get_nameid_arrays(JNIEnv* env, jclass complexClass, const char* table)
{
	sqlite3_stmt* _select_charsets;
	sprintf(buffer_str, "SELECT Name,ID FROM %s ORDER BY ID;", table);
	// Get all wordlist from db
	sqlite3_prepare_v2(db, buffer_str, -1, &_select_charsets, NULL);
	int m_charset_count = 0;

	jfieldID fid_name = env->GetFieldID(complexClass, "name", "Ljava/lang/String;");
	jfieldID fid_id = env->GetFieldID(complexClass, "id", "J");

	int max_num_charset = 16;
	jobject* charset_data_objs = (jobject*)malloc(max_num_charset*sizeof(jobject));

	while(sqlite3_step(_select_charsets) == SQLITE_ROW)
	{
		if(m_charset_count == max_num_charset)
		{
			max_num_charset *= 2;
			charset_data_objs = (jobject*)realloc(charset_data_objs, max_num_charset*sizeof(jobject));
		}

		charset_data_objs[m_charset_count] = env->AllocObject(complexClass);

		setObjectField_ReleaseLocalRef(env, charset_data_objs[m_charset_count], fid_name, env->NewStringUTF((const char*)sqlite3_column_text(_select_charsets, 0)));
		env->SetLongField(charset_data_objs[m_charset_count], fid_id, sqlite3_column_int64(_select_charsets, 1));

		m_charset_count++;
	}
	sqlite3_finalize(_select_charsets);

	jobjectArray result = env->NewObjectArray(m_charset_count, complexClass, NULL);

	for (int i = 0; i < m_charset_count; ++i)
		env->SetObjectArrayElement(result, i, charset_data_objs[i]);

	free(charset_data_objs);

	return result;
}
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_NameIDData_getCharsets(JNIEnv* env, jclass complexClass)
{
	return get_nameid_arrays(env, complexClass, "Charset");
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_NameIDData_clearCharset(JNIEnv* env, jclass complexClass)
{
	buffer_str[0] = 0;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_NameIDData_addCharset(JNIEnv* env, jclass complexClass, jlong charset_id)
{
	sqlite3_stmt* _select_charsets;
	// Get all wordlist from db
	sqlite3_prepare_v2(db, "SELECT Value FROM Charset WHERE ID=?;", -1, &_select_charsets, NULL);
	sqlite3_bind_int64(_select_charsets, 1, charset_id);

	if(sqlite3_step(_select_charsets) == SQLITE_ROW)
		strcat(buffer_str, (const char*)sqlite3_column_text(_select_charsets, 0));

	sqlite3_finalize(_select_charsets);
}

// Keyboards
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_NameIDData_getKeyboards(JNIEnv* env, jclass complexClass)
{
	return get_nameid_arrays(env, complexClass, "Keyboard");
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_NameIDData_setKeyboardLayout(JNIEnv* env, jclass complexClass, jlong keyboard_id)
{
	sqlite3_stmt* _select_charsets;
	// Get all wordlist from db
	sqlite3_prepare_v2(db, "SELECT Chars FROM Keyboard WHERE ID=?;", -1, &_select_charsets, NULL);
	sqlite3_bind_int64(_select_charsets, 1, keyboard_id);

	if(sqlite3_step(_select_charsets) == SQLITE_ROW)
		strcpy(buffer_str, (const char*)sqlite3_column_text(_select_charsets, 0));

	sqlite3_finalize(_select_charsets);
}

// Downloader
JNIEXPORT jobjectArray JNICALL Java_com_hashsuite_droid_WordlistData_getWordlists2Download(JNIEnv* env, jclass complexClass)
{
	sqlite3_stmt* _select_wordlists;
	sqlite3_prepare_v2(db, "SELECT Name,Url,Length,ID FROM WordList WHERE State=?;", -1, &_select_wordlists, NULL);

	int m_wordlist_count = 0;
	int max_num_wordlist = 16;
	jobject* wordlist_data_objs = (jobject*)malloc(max_num_wordlist*sizeof(jobject));

	jfieldID fid_name = env->GetFieldID(complexClass, "name", "Ljava/lang/String;");
	jfieldID fid_size = env->GetFieldID(complexClass, "size", "Ljava/lang/String;");
	jfieldID fid_url  = env->GetFieldID(complexClass, "url", "Ljava/lang/String;");
	jfieldID fid_id   = env->GetFieldID(complexClass, "id", "J");

	sqlite3_bind_int(_select_wordlists, 1, WORDLIST_TO_DOWNLOAD);
	while(sqlite3_step(_select_wordlists) == SQLITE_ROW)
	{
		if(m_wordlist_count == max_num_wordlist)
		{
			max_num_wordlist *= 2;
			wordlist_data_objs = (jobject*)realloc(wordlist_data_objs, max_num_wordlist*sizeof(jobject));
		}

		wordlist_data_objs[m_wordlist_count] = env->AllocObject(complexClass);

		setObjectField_ReleaseLocalRef(env, wordlist_data_objs[m_wordlist_count], fid_name, env->NewStringUTF((const char*)sqlite3_column_text(_select_wordlists, 0)));
		filelength2string(sqlite3_column_int64(_select_wordlists, 2), buffer_str);
		setObjectField_ReleaseLocalRef(env, wordlist_data_objs[m_wordlist_count], fid_size, env->NewStringUTF((const char*)buffer_str));
		setObjectField_ReleaseLocalRef(env, wordlist_data_objs[m_wordlist_count], fid_url, env->NewStringUTF((const char*)sqlite3_column_text(_select_wordlists, 1)));
		env->SetLongField(wordlist_data_objs[m_wordlist_count], fid_id, sqlite3_column_int64(_select_wordlists, 3));

		m_wordlist_count++;
	}
	sqlite3_finalize(_select_wordlists);

	jobjectArray result = env->NewObjectArray(m_wordlist_count, complexClass, NULL);

	for (int i = 0; i < m_wordlist_count; ++i)
		env->SetObjectArrayElement(result, i, wordlist_data_objs[i]);

	free(wordlist_data_objs);

	return result;
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_WordlistData_setWordlistStateDownloading(JNIEnv* env, jclass, jlong id)
{
	sqlite3_stmt* update_wordlist;
	sqlite3_prepare_v2(db, "UPDATE WordList SET State=? WHERE ID=?;", -1, &update_wordlist, NULL);

	sqlite3_bind_int  (update_wordlist, 1, WORDLIST_DOWNLOADING);
	sqlite3_bind_int64(update_wordlist, 2, id);
	sqlite3_step(update_wordlist);

	sqlite3_finalize(update_wordlist);
}
JNIEXPORT void JNICALL Java_com_hashsuite_droid_WordlistData_finishWordlistDownload(JNIEnv* env, jclass, jlong db_id, jstring path, jlong file_lenght)
{
	sqlite3_stmt*_update_existing_wordlist;
	sqlite3_prepare_v2(db, "UPDATE WordList SET State=?,FileName=?,Length=? WHERE ID=?;", -1, &_update_existing_wordlist, NULL);

	const char* wordlist_path = env->GetStringUTFChars(path, NULL);

	sqlite3_bind_int  (_update_existing_wordlist, 1, WORDLIST_NORMAL);
	sqlite3_bind_text (_update_existing_wordlist, 2, wordlist_path, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(_update_existing_wordlist, 3, file_lenght);
	sqlite3_bind_int64(_update_existing_wordlist, 4, db_id);
	sqlite3_step(_update_existing_wordlist);

	env->ReleaseStringUTFChars(path, wordlist_path);
	sqlite3_finalize(_update_existing_wordlist);
}

}
