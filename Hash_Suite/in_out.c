// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#include "common.h"
#include "sqlite3.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef _WIN32
	#include <io.h>
#endif

#ifdef HS_IMPORT_FROM_SYSTEM
	#include <Windows.h>
	#include <LM.h>
#endif

// Prepare statements
PRIVATE sqlite3_stmt* insert_account;
PRIVATE sqlite3_stmt* insert_account_lm;
PRIVATE sqlite3_stmt* select_account;
PRIVATE sqlite3_stmt* insert_tag_account;
PRIVATE sqlite3_stmt* insert_hash;
PRIVATE sqlite3_stmt* select_hash;

PRIVATE fpos_t lenght_of_file;
PRIVATE fpos_t pos_in_file;

PUBLIC int continue_import;

// Insert tag if not exists and return his id
PRIVATE sqlite3_int64 insert_when_necesary_tag(const char* tag)
{
	sqlite3_stmt* insert_tag = NULL, *select_tag = NULL;
	sqlite3_int64 tag_id;

	// Insert tag
	sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO TAG (Name) VALUES (?);", -1, &insert_tag, NULL);
	sqlite3_bind_text(insert_tag, 1, tag, -1, SQLITE_STATIC);
	sqlite3_step(insert_tag);
	sqlite3_finalize(insert_tag);
	// Load tag id
	sqlite3_prepare_v2(db, "SELECT ID FROM Tag WHERE Name=?;", -1, &select_tag, NULL);
	sqlite3_bind_text(select_tag, 1, tag, -1, SQLITE_STATIC);
	sqlite3_step(select_tag);
	tag_id = sqlite3_column_int64(select_tag, 0);
	sqlite3_finalize(select_tag);

	return tag_id;
}
// Insert a new account and tag it
PRIVATE sqlite3_int64 insert_tagged_account(const char* user_name, sqlite3_int64 tag_id, sqlite3_int64 hash_id, ImportResult* stat, int format_index)
{
	sqlite3_int64 account_id;

	// Insert account
	sqlite3_reset(insert_account);
	sqlite3_bind_text (insert_account, 1, user_name, -1, SQLITE_STATIC);
	sqlite3_bind_int64(insert_account, 2, hash_id);

	if(sqlite3_step(insert_account) == SQLITE_DONE)// account inserted
	{
		account_id = sqlite3_last_insert_rowid(db);
		stat->num_users_added++;

		num_user_by_formats[format_index]++;
	}
	else// account already exist
	{
		sqlite3_reset(select_account);
		sqlite3_bind_text (select_account, 1, user_name, -1, SQLITE_STATIC);
		sqlite3_bind_int64(select_account, 2, hash_id);
		sqlite3_step(select_account);

		account_id = sqlite3_column_int64(select_account, 0);
	}

	// Insert tag_account
	sqlite3_reset(insert_tag_account);
	sqlite3_bind_int64(insert_tag_account, 1, tag_id);
	sqlite3_bind_int64(insert_tag_account, 2, account_id);
	sqlite3_step(insert_tag_account);

	return account_id;
}
// insert a hash if not exist
PRIVATE sqlite3_int64 insert_hash_if_necesary(const char* hex, sqlite3_int64 format_id, ImportResultFormat* hash_stat)
{
	sqlite3_int64 hash_id;

	// Insert hash
	sqlite3_reset(insert_hash);
	sqlite3_bind_text(insert_hash, 1, hex, -1, SQLITE_STATIC);
	sqlite3_bind_int64(insert_hash, 2, format_id);

	// Not exist
	if(sqlite3_step(insert_hash) == SQLITE_DONE)
	{
		hash_id = sqlite3_last_insert_rowid(db);

		hash_stat->num_hash_added++;

		num_hashes_by_formats[find_format_index(format_id)]++;
	}
	else
	{
		// Select Hash
		sqlite3_reset(select_hash);
		sqlite3_bind_text (select_hash, 1, hex, -1, SQLITE_STATIC);
		sqlite3_bind_int64(select_hash, 2, format_id);
		sqlite3_step(select_hash);
		hash_id = sqlite3_column_int64(select_hash, 0);

		hash_stat->num_hash_exist++;
	}

	return hash_id;
}

////////////////////////////////////////////////////////////////////////////////////
// Import hashes in pwdump format
////////////////////////////////////////////////////////////////////////////////////
PRIVATE void import_pwdump(ImportParam* param)
{
	char buffer[1024];
	char* user_name = NULL, *rid = NULL, *lm = NULL, *ntlm = NULL, *next_token = NULL;
	char lm_part[17];
	sqlite3_int64 tag_id, hash_id, hash_id2, account_id;
	FILE* file = NULL;
	continue_import = TRUE;

	// All values to zero
	memset(&param->result, 0, sizeof(param->result));
	lm_part[16] = 0;// Null terminate it

	file = fopen(param->filename, "r");

	if(file != NULL)
	{
		lenght_of_file = _filelengthi64( fileno(file) );

		BEGIN_TRANSACTION;

		tag_id = insert_when_necesary_tag(param->tag);

		while( fgets(buffer, sizeof(buffer), file) && continue_import )
		{
			user_name = strtok_s(buffer, ":", &next_token);
			rid       = strtok_s( NULL , ":", &next_token);
			lm        = strtok_s( NULL , ":", &next_token);
			ntlm      = strtok_s( NULL , ":\n\r", &next_token);

			if(user_name && rid && lm && ntlm)
			{
				// If is empty password and load from fgdump->convert
				if(!strcmp(lm, "NO PASSWORD*********************") && !strcmp(ntlm, "NO PASSWORD*********************"))
				{
					strcpy(lm  , "AAD3B435B51404EEAAD3B435B51404EE");
					strcpy(ntlm, "31D6CFE0D16AE931B73C59D7E0C089C0");
				}
				// Need at least a valid ntlm
				if(valid_hex_string(ntlm, 32))
				{
					// Insert hash ntlm
					hash_id = insert_hash_if_necesary(_strupr(ntlm), formats[NTLM_INDEX].db_id, param->result.formats_stat + NTLM_INDEX);
					// Insert tagged account
					account_id = insert_tagged_account(user_name, tag_id, hash_id, &param->result, NTLM_INDEX);

					if(valid_hex_string(_strupr(lm), 32) && (strcmp(lm, "AAD3B435B51404EEAAD3B435B51404EE") || !strcmp(ntlm, "31D6CFE0D16AE931B73C59D7E0C089C0")))
					{
						// Insert hash lm
						strncpy(lm_part, lm, 16);
						hash_id  = insert_hash_if_necesary(lm_part, formats[LM_INDEX].db_id, param->result.formats_stat + LM_INDEX);

						strncpy(lm_part, lm + 16, 16);
						hash_id2 = insert_hash_if_necesary(lm_part, formats[LM_INDEX].db_id, param->result.formats_stat + LM_INDEX);

						// Insert account lm
						sqlite3_reset(insert_account_lm);
						sqlite3_bind_int64(insert_account_lm, 1, account_id);
						sqlite3_bind_int64(insert_account_lm, 2, hash_id);
						sqlite3_bind_int64(insert_account_lm, 3, hash_id2);
						sqlite3_step(insert_account_lm);

						num_user_by_formats[LM_INDEX]++;
					}
					else
						param->result.formats_stat[LM_INDEX].num_hash_disable++;
				}
				else
					param->result.lines_skiped++;
			}
			else
				param->result.lines_skiped++;

			fgetpos(file, &pos_in_file);
			param->completition = (int)(pos_in_file * 100 /lenght_of_file);
		}

		END_TRANSACTION;
		
		fclose(file);
	}

	param->isEnded = TRUE;
}

////////////////////////////////////////////////////////////////////////////////////
// Import hashes in cachedump format
////////////////////////////////////////////////////////////////////////////////////
PRIVATE void import_cachedump_general(ImportParam* param, int db_index)
{
	char buffer[1024];
	char* user_name = NULL, *mscash = NULL, *next_token = NULL;
	sqlite3_int64 tag_id, hash_id;
	FILE* file = NULL;
	char cipher_text[19+1+32+1];
	continue_import = TRUE;

	// All values to zero
	memset(&param->result, 0, sizeof(param->result));

	file = fopen(param->filename, "r");

	if(file != NULL)
	{
		lenght_of_file = _filelengthi64( fileno(file) );

		BEGIN_TRANSACTION;

		tag_id = insert_when_necesary_tag(param->tag);

		while( fgets(buffer, sizeof(buffer), file)  && continue_import)
		{
			user_name = strtok_s(buffer, ":"	, &next_token);
			mscash    = strtok_s( NULL , ":\n\r", &next_token);

			if(user_name && mscash && valid_hex_string(mscash, 32) && strlen(user_name) <= 19)
			{
				sprintf(cipher_text,"%s:%s", user_name, _strupr(mscash));
				// Insert hash mscash
				hash_id = insert_hash_if_necesary(cipher_text, formats[db_index].db_id, param->result.formats_stat + db_index);

				// Insert tagged account
				insert_tagged_account(user_name, tag_id, hash_id, &param->result, db_index);
			}
			else
				param->result.lines_skiped++;

			fgetpos(file, &pos_in_file);
			param->completition = (int)(pos_in_file * 100 /lenght_of_file);
		}

		END_TRANSACTION;
		
		fclose(file);
	}

	param->isEnded = TRUE;
}
PRIVATE void import_dcc(ImportParam* param)
{
	import_cachedump_general(param, MSCASH_INDEX);
}

#ifdef INCLUDE_DCC2
PRIVATE void import_dcc2(ImportParam* param)
{
	import_cachedump_general(param, DCC2_INDEX);
}
#endif

////////////////////////////////////////////////////////////////////////////////////
// Import hashes from local machine
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_IMPORT_FROM_SYSTEM
// Exit codes
#define EXIT_NORMAL				0
#define EXIT_BAD_PARAM			1
#define EXIT_NO_OPEN_LSASS		2
#define EXIT_NO_ALLOC			3
#define EXIT_NO_WRITE			4
#define EXIT_NO_THREAD			5
#define EXIT_NO_DEBUG			6
#define EXIT_NO_SCMANAGER		7
#define EXIT_NO_OPEN_SERVICE	8
#define EXIT_NO_START_SERVICE	9
#define EXIT_NO_RANDOM			10
#define EXIT_NO_SHARE_FOUND		11
#define EXIT_NO_PIPE			30
#define EXIT_BAD_PATH			31

#define MY_ACCOUNT_DISABLE	4

// Message is composed
// hash: 32 bytes | username_lenght: 2 bytes | username in Unicode
#define SIZE_MESSAGE (32+sizeof(USHORT))
// Crypt
PRIVATE unsigned char secret_key[32];// secret key
PRIVATE HANDLE hashdump_program;

PRIVATE void update_account_status(char* machine_name)
{
	char username[256];
	wchar_t server[64];
	wchar_t* server_ptr = NULL;
	// Enumerate users
	LPUSER_INFO_1 pBuf = NULL;
	DWORD entries_read = 0;
	DWORD total_entries = 0;
	DWORD resume_handle = 0;
	NET_API_STATUS nStatus;
	DWORD i;
	// DB management
	sqlite3_stmt* _select_account;
	sqlite3_stmt* _update_account_fixed;
	sqlite3_stmt* _update_account_priv;

	// Not local-host
	if(strcmp(machine_name, current_system_info.machine_name))
	{
		mbstowcs(server, machine_name, sizeof(server)/sizeof(wchar_t));
		server_ptr = server;
	}

	// Select account
	sqlite3_prepare_v2(db, "SELECT Account.ID FROM Account INNER JOIN TagAccount ON TagAccount.AccountID==Account.ID INNER JOIN Tag ON Tag.ID==TagAccount.TagID WHERE Tag.Name==? AND UserName==?;", -1, &_select_account, NULL);
	sqlite3_prepare_v2(db, "UPDATE Account SET Fixed=1 WHERE ID=?;", -1, &_update_account_fixed, NULL);
	sqlite3_prepare_v2(db, "UPDATE Account SET Privilege=? WHERE ID=?;", -1, &_update_account_priv, NULL);
	BEGIN_TRANSACTION;

	do// Enumerate users
	{
		nStatus = NetUserEnum(server_ptr, 1, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entries_read, &total_entries, &resume_handle);

		// If the call succeeds,
		if((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			// Loop through the entries.
			for (i = 0; i < entries_read; i++)
			{
				// If something change
				if(pBuf[i].usri1_priv != USER_PRIV_USER || (pBuf[i].usri1_flags & UF_ACCOUNTDISABLE))
				{
					wcstombs(username, pBuf[i].usri1_name, sizeof(username));

					sqlite3_reset(_select_account);
					sqlite3_bind_text(_select_account, 1, machine_name, -1, SQLITE_TRANSIENT);
					sqlite3_bind_text(_select_account, 2, username, -1, SQLITE_TRANSIENT);
					while(sqlite3_step(_select_account) == SQLITE_ROW)// Find accounts
					{
						int64_t account_id = sqlite3_column_int64(_select_account, 0);
						// Put Privilege
						if(pBuf[i].usri1_priv != USER_PRIV_USER)
						{
							sqlite3_reset(_update_account_priv);
							sqlite3_bind_int  (_update_account_priv, 1, pBuf[i].usri1_priv);
							sqlite3_bind_int64(_update_account_priv, 2, account_id);
							sqlite3_step(_update_account_priv);
						}
						// Put disable
						if(pBuf[i].usri1_flags & UF_ACCOUNTDISABLE)
						{
							sqlite3_reset(_update_account_fixed);
							sqlite3_bind_int64(_update_account_fixed, 1, account_id);
							sqlite3_step(_update_account_fixed);
						}
					}
				}
			}
		}

		// Free the allocated buffer.
		if(pBuf)
		{
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	}
	while (nStatus == ERROR_MORE_DATA);// Continue to call NetUserEnum while there are more entries.

	END_TRANSACTION;
	sqlite3_finalize(_update_account_priv);
	sqlite3_finalize(_update_account_fixed);
	sqlite3_finalize(_select_account);
}
PRIVATE DWORD named_pipe_thread(char* pipe_name, char* machine_name, ImportResult* result)
{
	char buffer[4096];
	unsigned char shared_key[32];
	unsigned int nonce[2];
	unsigned int block_counter = 0;
	DWORD exit_code = 0;
	HANDLE hFile;
	DWORD cbRead;
	unsigned int i;
	int to_process = 0, data_to_read, to_decrypt;
	// Inserting
	sqlite3_int64 tag_id, hash_id, hash_id2, account_id;

	int nError = 2, wait_count = 0;
	while (nError == 2 && wait_count < 100)// Wait 30 sec for pipe server to be ready
		if (!WaitNamedPipe(pipe_name, 300))
		{
			// If hashdump terminate execution->do not try to connect
			GetExitCodeProcess(hashdump_program, &exit_code);
			if(exit_code != STILL_ACTIVE)
				return exit_code;
			// Error 2 means the pipe is not yet available, keep trying
			nError = GetLastError();
			wait_count++;
			Sleep(300);
		}
		else
			nError = 0;

	if(nError == ERROR_BAD_NETPATH) return EXIT_BAD_PATH;

	hFile = CreateFile(pipe_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);	
	while(GetLastError() == ERROR_PIPE_BUSY)
	{ 
		Sleep(300);
		hFile = CreateFile(pipe_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);	
	}

	if(hFile == INVALID_HANDLE_VALUE) return EXIT_NO_PIPE;

	BEGIN_TRANSACTION;
	tag_id = insert_when_necesary_tag(machine_name);

	// Read public key
	data_to_read = ReadFile(hFile, buffer, 32+8, &cbRead, NULL) || GetLastError() == ERROR_MORE_DATA;
	// Calculate shared_key
	crypto_scalarmult_curve25519(shared_key, secret_key, (unsigned char*)buffer);
	memcpy(nonce, buffer+32, 8);
	// Read data and Decrypt
	data_to_read = ReadFile(hFile, buffer, sizeof(buffer), &cbRead, NULL) || GetLastError() == ERROR_MORE_DATA;
	for(i = 0; i < cbRead/64; i++, block_counter++)
		salsa20_crypt_block(buffer+i*64, nonce, (unsigned int*)shared_key, block_counter);
	to_decrypt = cbRead%64;
	cbRead -= to_decrypt;
	// Message is composed
	// hash: 32 bytes | account_flag: 1 byte | username_lenght: 2 bytes | username in Unicode
	while (data_to_read)
	{
		// Received a valid message - decode it
		char* _buffer_ptr = buffer;
		to_process += cbRead;
		// While have a full account data->process
		while(to_process >= SIZE_MESSAGE && to_process >= SIZE_MESSAGE+*((USHORT*)(_buffer_ptr+32)))
		{
			char lm[40];
			char ntlm[40];
			DWORD* dwdata = (DWORD*)_buffer_ptr;
			char* p = lm;

			// Convert the Unicode username to ASCII
			char user_name[256];
			USHORT username_lenght = *((USHORT*)(_buffer_ptr+32));
			wcstombs(user_name, (const wchar_t*)(_buffer_ptr+SIZE_MESSAGE), username_lenght/2);
			user_name[username_lenght/2] = 0;

			// Get LM hash
			for(i = 16; i < 32; i++, p += 2)
				sprintf(p, "%02X", _buffer_ptr[i] & 0xFF);

			// Get NTLM hash
			p = ntlm;
			for(i = 0; i < 16; i++, p += 2)
				sprintf(p, "%02X", _buffer_ptr[i]  & 0xFF);

			// Insert hash ntlm
			hash_id = insert_hash_if_necesary(ntlm, formats[NTLM_INDEX].db_id, result->formats_stat + NTLM_INDEX);
			// Insert tagged account
			account_id = insert_tagged_account(user_name, tag_id, hash_id, result, NTLM_INDEX);

			if(strcmp(lm, "AAD3B435B51404EEAAD3B435B51404EE") || !strcmp(ntlm, "31D6CFE0D16AE931B73C59D7E0C089C0"))
			{
				char lm_part[17];
				lm_part[16] = 0;// Null terminate it
				// Insert hash lm
				strncpy(lm_part, lm, 16);
				hash_id  = insert_hash_if_necesary(lm_part, formats[LM_INDEX].db_id, result->formats_stat + LM_INDEX);

				strncpy(lm_part, lm + 16, 16);
				hash_id2 = insert_hash_if_necesary(lm_part, formats[LM_INDEX].db_id, result->formats_stat + LM_INDEX);

				// Insert account lm
				sqlite3_reset(insert_account_lm);
				sqlite3_bind_int64(insert_account_lm, 1, account_id);
				sqlite3_bind_int64(insert_account_lm, 2, hash_id);
				sqlite3_bind_int64(insert_account_lm, 3, hash_id2);
				sqlite3_step(insert_account_lm);

				num_user_by_formats[LM_INDEX]++;
			}
			else
				result->formats_stat[LM_INDEX].num_hash_disable++;

			// Next
			_buffer_ptr += SIZE_MESSAGE+username_lenght;
			to_process -=  SIZE_MESSAGE+username_lenght;
		}
		// Move unprocessed data from end to begin and read more
		memmove(buffer, _buffer_ptr, to_process+to_decrypt);
		// Read data and Decrypt
		data_to_read = ReadFile(hFile, buffer+to_process+to_decrypt, sizeof(buffer)-to_process-to_decrypt, &cbRead, NULL) || GetLastError() == ERROR_MORE_DATA;
		cbRead += to_decrypt;
		for(i = 0; i < cbRead/64; i++, block_counter++)
			salsa20_crypt_block(buffer+to_process+i*64, nonce, (unsigned int*)shared_key, block_counter);
		to_decrypt = cbRead%64;
		cbRead -= to_decrypt;
	}

	END_TRANSACTION;
	CloseHandle(hFile);

	return EXIT_NORMAL;
}
PRIVATE void import_hash_dump(ImportParam* param, BOOL is_local)
{
	char buffer[512];
	char hash_dump_param[256];
	unsigned char public_key[32];// public key
	char hex_public_key[64+1];// public key in hexadecimal
	// Process to starts
	SHELLEXECUTEINFO shell_info;
	DWORD exit_code;
	HCRYPTPROV hprov;
	int i;

	// All values to zero
	memset(&param->result, 0, sizeof(param->result));
	param->completition = IMPORT_COMPLETITION_UNKNOW;

	// Crypt
	if(!CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT|CRYPT_SILENT))
		goto exit;
	if(!CryptGenRandom(hprov, 32, secret_key))// Generate secret key
		goto exit;
	CryptReleaseContext(hprov, 0);

	crypto_scalarmult_curve25519_base(public_key, secret_key);// Generate public key
	for(i = 0; i < 32; i++)
		sprintf(hex_public_key+2*i, "%02X", public_key[i]  & 0xFF);

	// Select x64 or x86 program
#ifdef _M_X64
	sprintf(buffer, "%s", get_full_path("Tools\\Hashes_Dump_64.exe"));
#else
	if(current_system_info.is_64bits)
		sprintf(buffer, "%s", get_full_path("Tools\\Hashes_Dump_64.exe"));
	else
		sprintf(buffer, "%s", get_full_path("Tools\\Hashes_Dump_32.exe"));
#endif
	if(is_local)
		sprintf(hash_dump_param, "%s", hex_public_key);
	else
		sprintf(hash_dump_param, "%s %s", hex_public_key, param->tag);
	// Start the child process.
	shell_info.cbSize = sizeof(shell_info);
	shell_info.fMask = SEE_MASK_NOCLOSEPROCESS;
	shell_info.hwnd = NULL;
	shell_info.lpVerb = NULL;
	shell_info.lpFile = buffer;
	shell_info.lpParameters = hash_dump_param;
	shell_info.lpDirectory = NULL;
	shell_info.nShow = SW_HIDE;

	ShellExecuteEx(&shell_info);
	hashdump_program = shell_info.hProcess;

	if(is_local)
		sprintf(buffer, "\\\\.\\pipe\\%s", hex_public_key);
	else
		sprintf(buffer, "\\\\%s\\pipe\\%s", param->tag, hex_public_key);
	exit_code = named_pipe_thread(buffer, param->tag, &param->result);

	if(exit_code != EXIT_NORMAL)
	{
		sprintf(buffer, "Cause: ");
		switch(exit_code)
		{
		case EXIT_BAD_PARAM:
			strcat(buffer, "Bad parameter.");
			break;
		case EXIT_NO_OPEN_LSASS:
			strcat(buffer, "Find/open LSASS process fails.");
			break;
		case EXIT_NO_ALLOC:
			strcat(buffer, "Allocation of memory in LSASS process fails.");
			break;
		case EXIT_NO_WRITE:
			strcat(buffer, "Write to memory in LSASS process fails.");
			break;
		case EXIT_NO_THREAD:
			strcat(buffer, "Start thread in LSASS process fails.");
			break;
		case EXIT_NO_DEBUG:
			strcat(buffer, "Can not enable the debug privilege (do you have administrator privilege?).");
			break;
		case EXIT_NO_SCMANAGER:
			strcat(buffer, "Access to Service Manager fails.");
			break;
		case EXIT_NO_OPEN_SERVICE:
			strcat(buffer, "Open Hash Dump service fails.");
			break;
		case EXIT_NO_START_SERVICE:
			strcat(buffer, "Start Hash Dump service fails.");
			break;
		case EXIT_NO_RANDOM:
			strcat(buffer, "Can not access random generator.");
			break;
		case EXIT_NO_SHARE_FOUND:
			strcat(buffer, "Can not found a writeable share in remote machine.");
			break;
		case EXIT_NO_PIPE:
			strcat(buffer, "Can not connect to pipe to read data.");
			break;
		case EXIT_BAD_PATH:
			strcat(buffer, "Remote machine can not be found.");
			break;
		default:
			strcat(buffer, "Unknown.");
			break;
		}
		MessageBox(NULL, buffer, "Import accounts fails", MB_OK|MB_ICONERROR);
	}

	CloseHandle(shell_info.hProcess);
	update_account_status(param->tag);
exit:
	param->completition = 100;
	param->isEnded = TRUE;
}

PRIVATE void import_hashes_from_localhost(ImportParam* param)
{
	import_hash_dump(param, TRUE);
}
PRIVATE void import_hashes_from_remote(ImportParam* param)
{
	import_hash_dump(param, FALSE);
}
#endif

// Export found passwords
PRIVATE int callback_found(void *file, int argc, char **argv, char **azColName)
{
	fprintf((FILE*)file, "%s:%s\n", argv[0], argv[1]);
	return 0;
}
PRIVATE void export_found_passwords(const char* filename)
{
	FILE* file = fopen(filename,"w");

	if(file != NULL)
	{
		fprintf(file, "------------------\n");
		fprintf(file, "UserName:Password \n");
		fprintf(file, "------------------\n");

		sqlite3_exec(db, "SELECT UserName,ClearText FROM (FindHash INNER JOIN Account ON Account.Hash==FindHash.ID) "
						 "UNION SELECT UserName,(FindHash1.ClearText || FindHash2.ClearText) AS ClearText FROM "
						 "(Account INNER JOIN AccountLM ON Account.ID==AccountLM.ID INNER JOIN FindHash AS FindHash1 ON FindHash1.ID==AccountLM.LM1 "
						 "INNER JOIN FindHash AS FindHash2 ON FindHash2.ID==AccountLM.LM2) WHERE Account.Hash NOT IN "
						 "(SELECT ID FROM FindHash) ORDER BY UserName;", callback_found, file, NULL);

		fclose(file);
	}
}
// Export found passwords as wordlist
PRIVATE int callback_found_wordlist(void *file, int argc, char **argv, char **azColName)
{
	fprintf((FILE*)file, "%s\n", argv[0]);
	return 0;
}
PRIVATE void export_found_passwords_wordlist(const char* filename)
{
	FILE* file = fopen(filename,"w");

	if(file != NULL)
	{
		sqlite3_exec(db, "SELECT ClearText FROM FindHash;", callback_found_wordlist, file, NULL);
		fclose(file);
	}
}

// Export as pwdump format
PRIVATE int callback_pwdump(void *file, int argc, char **argv, char **azColName)
{
	fprintf((FILE*)file, "%s:1000:%s:%s:::\n", argv[0], argv[1], argv[2]);
	return 0;
}
PRIVATE void export_pwdump(const char* filename)
{
	FILE* file = fopen(filename, "w");

	if(file != NULL)
	{
		char buffer_sql[512];
		sprintf(buffer_sql, "SELECT UserName,((CASE WHEN HashLM1.Hex NOTNULL THEN HashLM1.Hex ELSE 'AAD3B435B51404EE' END) || "
			"(CASE WHEN HashLM2.Hex NOTNULL THEN HashLM2.Hex ELSE 'AAD3B435B51404EE' END)),HashNTLM.Hex FROM "
			"(Account INNER JOIN Hash AS HashNTLM ON Account.Hash==HashNTLM.ID LEFT JOIN AccountLM ON AccountLM.ID==Account.ID "
			"LEFT JOIN Hash AS HashLM1 ON HashLM1.ID==AccountLM.LM1 LEFT JOIN Hash AS HashLM2 ON HashLM2.ID==AccountLM.LM2) "
			"WHERE HashNTLM.Type==%i;", (int)formats[NTLM_INDEX].db_id);

		sqlite3_exec(db, buffer_sql, callback_pwdump, file, NULL);

		fclose(file);
	}
}
// Export as cachedump
PRIVATE int callback_dcc(void *file, int argc, char **argv, char **azColName)
{
	char* dcc_hash = strchr(argv[1], ':');
	fprintf((FILE*)file, "%s:%s\n", argv[0], dcc_hash + 1);
	return 0;
}
PRIVATE void export_dcc(const char* filename)
{
	FILE* file = fopen(filename, "w");

	if(file != NULL)
	{
		char buffer_sql[512];
		sprintf(buffer_sql, "SELECT UserName,Hex FROM Account INNER JOIN Hash ON Account.Hash==Hash.ID WHERE Hash.Type==%i;", (int)formats[DCC_INDEX].db_id);

		sqlite3_exec(db, buffer_sql, callback_dcc, file, NULL);

		fclose(file);
	}
}
// Export our database to an external file
PUBLIC void export_db(const char* filename)
{
	unsigned char buffer[1024*4];
	// Open files
	FILE* db_out = fopen(filename, "wb");
	FILE* db_file = fopen(get_full_path(DB_FILE), "rb");

	// Copy the file
	if(db_out && db_file)
	{
		size_t num_read = fread(buffer, 1, sizeof(buffer), db_file);
		while (num_read)
		{
			fwrite(buffer, 1, num_read, db_out);
			num_read = fread(buffer, 1, sizeof(buffer), db_file);
		}

		fclose(db_file);
		fclose(db_out);
	}
}
#ifdef ANDROID
PUBLIC void import_db(const char* filename)
{
	unsigned char buffer[1024*4];
	// Open files
	FILE* db_in = fopen(filename, "rb");
	FILE* db_file = fopen(get_full_path(DB_FILE), "wb");

	// Copy the file
	if(db_in && db_file)
	{
		size_t num_read = fread(buffer, 1, sizeof(buffer), db_in);
		while (num_read)
		{
			fwrite(buffer, 1, num_read, db_file);
			num_read = fread(buffer, 1, sizeof(buffer), db_in);
		}

		fclose(db_file);
		fclose(db_in);
	}
}
#endif

// Registers all importers/exporters
PUBLIC void register_in_out()
{
	// Prepare statements
	sqlite3_prepare_v2(db, "INSERT INTO Account (UserName,Hash) VALUES (?,?);", -1, &insert_account, NULL);
	sqlite3_prepare_v2(db, "INSERT INTO AccountLM (ID,LM1,LM2) VALUES (?,?,?);"       , -1, &insert_account_lm, NULL);
	sqlite3_prepare_v2(db, "SELECT ID FROM Account WHERE UserName=? AND Hash=?;"      , -1, &select_account, NULL);
	sqlite3_prepare_v2(db, "INSERT INTO TagAccount (TagID, AccountID) VALUES (?, ?);" , -1, &insert_tag_account, NULL);
	sqlite3_prepare_v2(db, "INSERT INTO Hash (Hex, Type) VALUES (?, ?);"              , -1, &insert_hash, NULL);
	sqlite3_prepare_v2(db, "SELECT ID FROM Hash WHERE Hex=? AND Type=?;"              , -1, &select_hash, NULL);
}

PUBLIC Importer importers[] = {
#ifdef HS_IMPORT_FROM_SYSTEM
	{35, "Local accounts." ,  NULL , "Import NTLM and LM hashes from local machine (requires administrator privilege).", import_hashes_from_localhost, IMPORT_PARAM_NONE},// Import local accounts
	{36, "Remote accounts.",  NULL , "Import NTLM/LM hashes from remote machine (requires admin privilege on remote machine).", import_hashes_from_remote, IMPORT_PARAM_MACHINE_NAME},// Import remote accounts
#endif
	{37, "Pwdump file."    , ".txt", "Import NTLM and LM hashes from a file created with pwdump program."	 , import_pwdump, IMPORT_PARAM_FILENAME},// Import pwdump format
	{37, "Cachedump file." , ".txt", "Import DCC (MSCASH) hashes from a file created with cachedump program.", import_dcc, IMPORT_PARAM_FILENAME}
#ifdef INCLUDE_DCC2
	,{37,"Cachedump file." , ".txt", "Import DCC2 (MSCASH2) hashes from a file created with cachedump program.", import_dcc2, IMPORT_PARAM_FILENAME}
#endif
	// TODO: Import from SAM and SYSKEY, Scheduler and others...
};

PUBLIC Exporter exporters[] = {
	{38, "Found passwords.", "found_passwords.txt", "Export all passwords already found by the program.", export_found_passwords},// Export found passwords
	{38, "Found passwords as wordlist.", "found_passwords_wordlist.txt", "Export all passwords already found by the program as a wordlist.", export_found_passwords_wordlist},// Export found passwords as wordlist
	{38, "Pwdump format."	, "passwords.txt"      , "Export NTLM and LM hashes in pwdump file format.", export_pwdump},
	{38, "Cachedump format.", "passwords.txt"      , "Export DCC hashes in cachedump file format.", export_dcc}
#ifdef ANDROID
	,{38, "Hash Suite Database.", "config.db"      , "Export Hash Suite Database.", export_db}
#endif
	// TODO: Export others...
};

PUBLIC int num_importers = LENGHT(importers);
PUBLIC int num_exporters = LENGHT(exporters);
