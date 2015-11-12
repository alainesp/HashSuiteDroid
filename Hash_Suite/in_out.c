// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "sqlite3.h"
#include <stdio.h>
#include <string.h>
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
#ifdef HS_TESTING
	PUBLIC sqlite3_stmt* insert_account;
#else
	PRIVATE sqlite3_stmt* insert_account;
#endif
PUBLIC sqlite3_stmt* insert_account_lm;
PRIVATE sqlite3_stmt* select_account;
PRIVATE sqlite3_stmt* insert_tag_account;
PRIVATE sqlite3_stmt* insert_hash;
PRIVATE sqlite3_stmt* select_hash;

PRIVATE fpos_t lenght_of_file;
PRIVATE fpos_t pos_in_file;

PUBLIC int continue_import;

// Insert tag if not exists and return his id
PUBLIC sqlite3_int64 insert_when_necesary_tag(const char* tag)
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
PUBLIC sqlite3_int64 insert_hash_if_necesary(const char* hex, sqlite3_int64 format_id, ImportResultFormat* hash_stat)
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

PUBLIC sqlite3_int64 insert_hash_account(ImportParam* param, const char* user_name, const char* ciphertext, int db_index, sqlite3_int64 tag_id)
{
	// Insert hash
	sqlite3_int64 hash_id = insert_hash_if_necesary(ciphertext, formats[db_index].db_id, param->result.formats_stat + db_index);

	// Insert tagged account
	return insert_tagged_account(user_name, tag_id, hash_id, &param->result, db_index);
}

////////////////////////////////////////////////////////////////////////////////////
// Import hashes from file
////////////////////////////////////////////////////////////////////////////////////
PRIVATE void import_wpa_from_pcap_file(ImportParam* param);
PRIVATE void import_wpa_from_hccap_file(ImportParam* param);

PRIVATE void import_file_general(ImportParam* param)
{
	char buffer[1024];
	char line[1024];
	int is_valid_line[MAX_NUM_FORMATS];
	int is_rejected[MAX_NUM_FORMATS];
	continue_import = TRUE;

	// Check if is a PCAP capture file
	size_t len = strlen(param->filename);
	if (!memcmp(param->filename + len - 5, ".pcap", 5) || !memcmp(param->filename + len - 4, ".cap", 4))
	{
		import_wpa_from_pcap_file(param);
		return;
	}
	if (!memcmp(param->filename + len - 6, ".hccap", 6))
	{
		import_wpa_from_hccap_file(param);
		return;
	}

	// All values to zero
	memset(&param->result, 0, sizeof(param->result));
	memset(is_rejected, 0, sizeof(is_rejected));

	FILE* file = fopen(param->filename, "r");

	if (file != NULL)
	{
		lenght_of_file = _filelengthi64(fileno(file));

		BEGIN_TRANSACTION;

		sqlite3_int64 tag_id = insert_when_necesary_tag(param->tag);

		while (fgets(buffer, sizeof(buffer), file) && continue_import)
		{
			int valid_formats = 0;
			int valid_format_index = 0;
			char* next_token = NULL;

			strcpy(line, buffer);
			char* user_name = strtok_s(buffer, ":\n\r", &next_token);
			char* p0 = strtok_s(NULL, ":\n\r", &next_token);
			char* p1 = strtok_s(NULL, ":\n\r", &next_token);
			char* p2 = strtok_s(NULL, ":\n\r", &next_token);

			// Check if format support this line
			memset(is_valid_line, 0, sizeof(is_valid_line));
			for (int i = 0; i < num_formats; i++)
			{
				is_valid_line[i] = formats[i].is_valid_line(user_name, p0, p1, p2);
				if (is_valid_line[i])
				{
					valid_formats++;
					valid_format_index = i;
				}
			}
			if (valid_formats > 1)
				for (int i = 0; i < num_formats; i++)
					if (is_valid_line[i])
					{
						if (is_rejected[i])
						{
							is_valid_line[i] = FALSE;
							valid_formats--;
						}
						else
							valid_format_index = i;
					}
			// Line supported by various formats
			if (valid_formats > 1)
			{
				valid_format_index = param->select_format(line, is_valid_line);
				if (valid_format_index >= 0 && valid_format_index < num_formats)
					valid_formats = 1;			

				for (int i = 0; i < num_formats; i++)
					if (is_valid_line[i] && i != valid_format_index)
						is_rejected[i] = TRUE;
			}
			
			if (valid_formats == 1)
				formats[valid_format_index].add_hash_from_line(param, user_name, p0, p1, p2, tag_id);
			else
				param->result.lines_skiped++;

			fgetpos(file, &pos_in_file);
			param->completition = (int)(pos_in_file * 100 / lenght_of_file);
		}

		END_TRANSACTION;

		fclose(file);
	}

	param->isEnded = TRUE;
}

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
			strcat(buffer, "Can not find a writable share on the remote machine.");
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
		MessageBox(NULL, buffer, "Import accounts failed", MB_OK|MB_ICONERROR);
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

////////////////////////////////////////////////////////////////////////////////////
// WPA
////////////////////////////////////////////////////////////////////////////////////
#define LINKTYPE_ETHERNET       1
#define LINKTYPE_IEEE802_11     105
#define LINKTYPE_PRISM_HEADER   119
#define LINKTYPE_RADIOTAP_HDR   127
#define LINKTYPE_PPI_HDR        192
// PCAP main file header
typedef struct pcap_hdr_s
{
	uint32_t magic_number;   /* magic number 0xA1B2C3D4 (or 0xD4C3B2A1 if file in BE format) */
	uint16_t version_major;  /* major version number 0x0200 */
	uint16_t version_minor;  /* minor version number 0x0400 */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
}
pcap_hdr_t;
// PCAP packet header
typedef struct pcaprec_hdr_s
{
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
}
pcaprec_hdr_t;
// Ok, here are the struct we need to decode 802.11 for JtR
typedef struct ether_frame_hdr_s {
	uint16_t frame_ctl;
	uint16_t duration;
	uint8_t  addr1[6];
	uint8_t  addr2[6];
	uint8_t  addr3[6];
	uint16_t seq;
//	int8   addr[6]; // optional (if X then it is set)
//	uint16 qos_ctl; // optional (if X then it is set)
//	uint16 ht_ctl;  // optional (if X then it is set)
//	int8   body[1];
} ether_frame_hdr_t;

typedef struct ether_frame_ctl_s { // bitmap of the ether_frame_hdr_s.frame_ctl
	uint16_t version  : 2;
	uint16_t type     : 2;
	uint16_t subtype  : 4;
	uint16_t toDS     : 1;
	uint16_t fromDS   : 1;
	uint16_t morefrag : 1;
	uint16_t retry    : 1;
	uint16_t powman   : 1;
	uint16_t moredata : 1;
	uint16_t protfram : 1;
	uint16_t order    : 1;
} ether_frame_ctl_t;
typedef struct ether_beacon_tag_s {
	uint8_t  tagtype;
	uint8_t  taglen;
	uint8_t  tag[1];
	// we have to 'walk' from 1 tag to next, since the tag itself is
	// var length.
} ether_beacon_tag_t;

// This is the structure for a 802.11 control 'beacon' packet.
// NOTE, we only use this packet to get the ESSID.
typedef struct ether_beacon_data_s {
	uint32_t time1;
	uint32_t time2;
	uint16_t interval;
	uint16_t caps;
	// ok, now here we have a array of 'tagged params'.
	// these are variable sized, so we have to 'specially' walk them.
	ether_beacon_tag_t tags[1];
} ether_beacon_data_t;
// THIS is the structure for the EAPOL data within the packet.
typedef struct ether_auto_802_1x_s {
	uint8_t ver; // 1 ?
	uint8_t key;
	uint16_t length;  // in BE format
	uint8_t key_descr; // should be 2 for EAPOL RSN KEY ?

	struct {
		uint16_t KeyDescr	: 3; //
		uint16_t KeyType	: 1; // 1 is pairwise key
		uint16_t KeyIdx	: 2; // should be 0
		uint16_t Install	: 1; // should be 0
		uint16_t KeyACK	: 1; // 1=set 0=nope
		uint16_t KeyMIC	: 1; // 1 set, 0 nope
		uint16_t Secure	: 1;
		uint16_t Error	: 1;
		uint16_t Reqst	: 1;
		uint16_t EncKeyDat: 1;
	}key_info;

	uint8_t key_len;
	uint8_t replay_cnt[8];
	uint8_t wpa_nonce[32];
	uint8_t wpa_keyiv[16];
	uint8_t wpa_keyrsc[8];
	uint8_t wpa_keyid[8];
	uint8_t wpa_keymic[16];
	uint16_t wpa_keydatlen;
} ether_auto_802_1x_t;

// This type structure is used to keep track of EAPOL packets, as they are read
// from a PCAP file.  we need to get certain 'paired' packets, to be able to create
// the input file for JtR (i.e. the 4-way to make the hash input for JtR). The packets
// that are needed are:   msg1 and msg2  or msg2 and msg3.  These MUST be paired, and
// matched to each other.  The match 'rules' are:
// the packets MUST be sequential (only eapol messages being looked at, so sequential epol's)
// if the match is a msg1-msg2, then both MUST have exact same If a msg1-msg2 pair,
//   they BOTH must have the exact same ether_auto_802_1x_t.replay_cnt
// if the match is a msg2-msg3, then the msg2 ether_auto_802_1x_t.replay_cnt must be exactly
//   one less than the ether_auto_802_1x_t.replay_cnt in the msg3.
// if any of the above 3 rules (actually only 2 of the 3, since the msg1-msg2 and msg2-msg3
//   rules are only used in proper context), then we do NOT have a valid 4-way.
// During run, every time we see a msg1, we 'forget' all other packets.  When we see a msg2,
//   we forget all msg3 and msg4's.  Also, for a msg2, we see if we have a msg1.  If so, we
//   see if that msg1 satisfies the replay_cnt rule.  If that is the case, then we have a
//   'possible' valid 4-way. We do write the results.  However, at this time, we are not
//   100% 'sure' we have a valid 4-way.  We CAN get a msg1/msg2 pair, even if the AP trying
//   to validate, did not know the password.  If all we see is the msg1/msg2, then we do not
//   KNOW for sure, if that AP was able to validate itself.   If there was a msg1 but it did
//   not match, we simply drop it.  Finally, when we get a msg3, we dump the msg1 and msg4's.
//   We check for a msg2 that is valid.  If the msg2 is valid, then we are SURE that we have
//   a valid 4-way.  The msg3 would not be sent, unless the router was happy that the
//   the connecting AP knows the PW, unless the router was written to always 'fake' reply,
//   but that is likely against 802.11 rules.  The only thing I could think might do this,
//   is some honey-pot router, looking for hackers. A real router is not going to give a
//   msg3 unless the 4-way is going along fine.
typedef struct WPA4way_s {
	char essid[36];
	uint8_t bssid_bin[6];
	uint8_t *packet1;
	uint8_t *packet2;
	uint8_t *orig_2;
	uint8_t *packet3;
	int fully_cracked;
	int eapol_sz;
}WPA4way_t;
// this struct IS the struct in JtR. So we load it up, the do a base-64 convert to save.
typedef struct
{
	char          essid[36];  // Note, we do not 'write' this one, it is the salt.
	unsigned char mac1[6];    // the base-64 data we write, starts from this element forward.
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];
	unsigned char eapol[256];
	int           eapol_size;
	int           keyver;
	unsigned char keymic[16];
} hccap_t;

PRIVATE void HandleBeacon(uint8_t* packet, pcaprec_hdr_t* pkt_hdr, WPA4way_t** wpa_ptr, int* nwpa, int* MAX_ESSIDS)
{
	WPA4way_t* wpa = *wpa_ptr;
	ether_frame_hdr_t *pkt = (ether_frame_hdr_t*)packet;

	ether_beacon_data_t *pDat = (ether_beacon_data_t*)&packet[sizeof(ether_frame_hdr_t)];
	ether_beacon_tag_t *tag = pDat->tags;
	uint8_t *pFinal = &packet[pkt_hdr->incl_len];
	char essid[36] = { 0 };

	// addr1 should be broadcast
	// addr2 is source addr (should be same as BSSID)
	// addr3 is BSSID (routers MAC)

	// ok, walk the tags
	while (((uint8_t*)tag) < pFinal)
	{
		char *x = (char*)tag;
		if (tag->tagtype == 0 && tag->taglen < sizeof(essid))
			memcpy(essid, tag->tag, tag->taglen);
		x += tag->taglen + 2;
		tag = (ether_beacon_tag_t *)x;
	}
	for (int i = 0; i < (*nwpa); ++i)
		if (!memcmp(pkt->addr3, wpa[i].bssid_bin, 6) && !strcmp(essid, wpa[i].essid))
			return;

	memset(wpa + nwpa[0], 0, sizeof(WPA4way_t));
	strcpy(wpa[*nwpa].essid, essid);
	memcpy(wpa[*nwpa].bssid_bin, pkt->addr3, 6);
	nwpa[0]++;
	if (nwpa[0] >= MAX_ESSIDS[0])
	{
		MAX_ESSIDS[0] *= 2;
		wpa_ptr[0] = realloc(wpa, MAX_ESSIDS[0]*sizeof(WPA4way_t));
	}
}
// These 2 functions output data properly for JtR, in base-64 format. These
// were taken from hccap2john.c source, and modified for this project.
PRIVATE const char cpItoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
PRIVATE int code_block(unsigned char *in, unsigned char b, char *cp)
{
	int cnt = 0;
	*cp++ = cpItoa64[in[0] >> 2];
	*cp++ = cpItoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	if (b) {
		*cp++ = cpItoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*cp++ = cpItoa64[in[2] & 0x3f];
		++cnt;
	} else
		*cp++ = cpItoa64[((in[1] & 0x0f) << 2)];
	*cp = 0;
	return cnt+3;
}
PRIVATE void DumpKey(WPA4way_t* wpa, int one_three, int bIsQOS, ImportParam* param, sqlite3_int64 tag_id)
{
	ether_auto_802_1x_t *auth13, *auth2;
	uint8_t *p = (uint8_t*)wpa->packet2;
	uint8_t *pkt2 = p;
	uint8_t *p13;
	hccap_t	hccap;
	int i;
	char TmpKey[1024], *cp = TmpKey;

	cp += sprintf (cp, "%s#", wpa->essid);
	if (!wpa->packet2) { return; }
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ether_frame_hdr_t);
	auth2 = (ether_auto_802_1x_t*)p;
	if (one_three==1)
	{
		if (!wpa->packet1) { return; }
		p = wpa->packet1;	 
	} else  {					 
		if (!wpa->packet3) { return; }
		p = wpa->packet3;
	}
	p13 = p;
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ether_frame_hdr_t);
	auth13 = (ether_auto_802_1x_t*)p;

	memset(&hccap, 0, sizeof(hccap_t));
	hccap.keyver = auth2->key_info.KeyDescr;
	memcpy(hccap.mac1, ((ether_frame_hdr_t*)pkt2)->addr1, 6);
	memcpy(hccap.mac2, ((ether_frame_hdr_t*)(p13))->addr1, 6);
	memcpy(hccap.nonce1, auth2->wpa_nonce, 32);
	memcpy(hccap.nonce2, auth13->wpa_nonce, 32);
	memcpy(hccap.keymic, auth2->wpa_keymic, 16);
	p = wpa->orig_2;
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ether_frame_hdr_t);
	auth2 = (ether_auto_802_1x_t*)p;
	memset(auth2->wpa_keymic, 0, 16);
	memcpy(hccap.eapol, auth2, wpa->eapol_sz);
	hccap.eapol_size = wpa->eapol_sz;

	uint8_t* w = (uint8_t*)&hccap;
	for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
		cp += code_block(&w[i], 1, cp);
	cp += code_block(&w[i], 0, cp);

	insert_hash_account(param, wpa->essid, TmpKey, WPA_INDEX, tag_id);
}
PRIVATE void Handle4Way(int bIsQOS, uint8_t* packet, pcaprec_hdr_t* pkt_hdr, ImportParam* param, sqlite3_int64 tag_id, WPA4way_t* wpa, int nwpa)
{
	ether_frame_hdr_t *pkt = (ether_frame_hdr_t*)packet;
	int i, ess = -1;
	uint8_t orig_2[512];
	uint8_t *p = packet + sizeof(ether_frame_hdr_t);
	int msg = 0;

	// ok, first thing, find the beacon.  If we can NOT find the beacon, then
	// do not proceed.  Also, if we find the becon, we may determine that
	// we already HAVE fully cracked this
	for (i = 0; i < nwpa; ++i)
		if (!memcmp(pkt->addr3, wpa[i].bssid_bin, 6))
		{
			ess = i;
			break;
		}

	if (ess == -1) return;
	if (wpa[ess].fully_cracked)
		return;  // no reason to go on.

	memcpy(orig_2, packet, pkt_hdr->orig_len);

	// Ok, after pkt,  uint16 QOS control (should be 00 00)
	if (bIsQOS)
		p += 2;
	// we are now at Logical-Link Control. (8 bytes long).
	// LLC check not needed here any more.  We do it in the packet cracker section, b4
	// calling this function.  We just need to skip the 8 byte LLC.
	//if (memcmp(p, "\xaa\xaa\x3\0\0\0\x88\x8e", 8)) return; // not a 4way
	p += 8;
	// p now points to the 802.1X Authentication structure.
	ether_auto_802_1x_t* auth = (ether_auto_802_1x_t*)p;
	SWAP_ENDIANNESS16(auth->length, auth->length);

	if (!auth->key_info.KeyACK)// msg 2 or 4
	{
		if (auth->key_info.Secure)
		{
			// msg = 4;
			// is this useful?
			return;
		}
		else
			msg = 2;
	} else {
		if (auth->key_info.Install)
			msg = 3;
		else
			msg = 1;
	}

	// Ok, we look for a 1 followed immediately by a 2 which have exact same replay_cnt, we have
	// a 'likely' key. Or we want a 2 followed by a 3 that are 1 replay count apart)  which means
	// we DO have a key.  The 3 is not returned unless the 2 (which came from the client), IS
	// valid. So, we get the anonce from either the 1 or the 3 packet.

	// for our first run, we output ALL valid keys found in the file. That way, I can validate that
	// any keys which were produced by aircrack-ng are 'valid' or not.  aircrack-ng WILL generate some
	// invalid keys.  Also, I want to flag "unknown" keys as just that, unk.  These are 1-2's which
	// do not have valid 3 4's.  They 'may' be valid, but may also be a client with the wrong password.
	switch (msg)
	{
	case 1:
			if (wpa[ess].packet1) free(wpa[ess].packet1);
			wpa[ess].packet1 = (uint8_t*)malloc(sizeof(uint8_t)* pkt_hdr->orig_len);

			memcpy(wpa[ess].packet1, packet, pkt_hdr->orig_len);
			if (wpa[ess].packet2) free(wpa[ess].packet2);  wpa[ess].packet2 = NULL;
			if (wpa[ess].orig_2)  free(wpa[ess].orig_2);   wpa[ess].orig_2 = NULL;
			if (wpa[ess].packet3) free(wpa[ess].packet3);  wpa[ess].packet3 = NULL;
		break;
	case 2:// Some sanitiy checks
			if (pkt_hdr->orig_len < sizeof(ether_frame_hdr_t)+(bIsQOS ? 10 : 8))
				return;

			// see if we have a msg1 that 'matches'.
			if (wpa[ess].packet3) free(wpa[ess].packet3);  wpa[ess].packet3 = NULL;
			if (wpa[ess].packet2) free(wpa[ess].packet2);  wpa[ess].packet2 = NULL;
			if (wpa[ess].orig_2)  free(wpa[ess].orig_2);   wpa[ess].orig_2 = NULL;
			wpa[ess].packet2 = (uint8_t*)malloc(sizeof(uint8_t)* pkt_hdr->orig_len);
			wpa[ess].orig_2  = (uint8_t*)malloc(sizeof(uint8_t)* pkt_hdr->orig_len);

			memcpy(wpa[ess].packet2, packet, pkt_hdr->orig_len);
			memcpy(wpa[ess].orig_2, orig_2, pkt_hdr->orig_len);

			// This is canonical for any encapsulations
			wpa[ess].eapol_sz = auth->length + 4;
			break;
	case 3:// see if we have a msg2 that 'matches',  which is 1 less than our replay count.
			wpa[ess].packet3 = (uint8_t*)malloc(sizeof(uint8_t)* pkt_hdr->orig_len);

			memcpy(wpa[ess].packet3, packet, pkt_hdr->orig_len);
			if (wpa[ess].packet2)
			{
				p = (uint8_t*)wpa[ess].packet2;
				if (bIsQOS)
					p += 2;
				p += 8;
				p += sizeof(ether_frame_hdr_t);
				ether_auto_802_1x_t* auth2 = (ether_auto_802_1x_t*)p;

				uint64_t auth2_replay_cnt = 0;
				uint64_t auth3_replay_cnt = 0;
				for (int i = 0; i < 8; i++)
				{
					auth2_replay_cnt += ((uint64_t)auth2->replay_cnt[i]) << (56 - 8*i);
					auth3_replay_cnt += ((uint64_t)auth->replay_cnt [i]) << (56 - 8*i);;
				}
				if (auth2_replay_cnt + 1 == auth3_replay_cnt)
				{
					ether_auto_802_1x_t *auth1;
					if (wpa[ess].packet1)
					{
						p = (uint8_t*)wpa[ess].packet1;
						if (bIsQOS)
							p += 2;
						p += 8;
						p += sizeof(ether_frame_hdr_t);
						auth1 = (ether_auto_802_1x_t*)p;
					}
					// If we saw the first packet, its nonce must
					// match the third's nonce and we are 100% sure.
					// If we didn't see it, we are only 99% sure.
					if (!wpa[ess].packet1 || !memcmp(auth1->wpa_nonce, auth->wpa_nonce, 32))
					{
						DumpKey(wpa+ess, 3, bIsQOS, param, tag_id);
						wpa[ess].fully_cracked = 1;
					}
				}
			}
			// clear this, so we do not hit the same 3 packet and output exact same 2/3 combo.
			if (wpa[ess].packet1) free(wpa[ess].packet1);  wpa[ess].packet1 = NULL;
			if (wpa[ess].packet3) free(wpa[ess].packet3);  wpa[ess].packet3 = NULL;
			if (wpa[ess].packet2) free(wpa[ess].packet2);  wpa[ess].packet2 = NULL;
			if (wpa[ess].orig_2)  free(wpa[ess].orig_2);   wpa[ess].orig_2 = NULL;
		break;
	}
}
// Ok, this function is the main packet processor.  NOTE, when we are done
// reading packets (i.e. we have done what we want), we return 0, and
// the program will exit gracefully.  It is not an error, it is just an
// indication we have completed (or that the data we want is not here).
PRIVATE int GetNextPacketAndProcess(FILE* in, int bROT, uint8_t* full_packet, uint32_t link_type, ImportParam* param, sqlite3_int64 tag_id
	, WPA4way_t** wpa_ptr, int* nwpa, int* MAX_ESSIDS)
{
	ether_frame_hdr_t *pkt;
	ether_frame_ctl_t *ctl;
	unsigned int frame_skip = 0;
	uint8_t* packet;

	// GetNextPacket--------------------------
	size_t read_size;
	pcaprec_hdr_t pkt_hdr;

	if (fread(&pkt_hdr, 1, sizeof(pkt_hdr), in) != sizeof(pkt_hdr)) return 0;

	if (bROT)
	{
		SWAP_ENDIANNESS(pkt_hdr.ts_sec  , pkt_hdr.ts_sec);
		SWAP_ENDIANNESS(pkt_hdr.ts_usec , pkt_hdr.ts_usec);
		SWAP_ENDIANNESS(pkt_hdr.incl_len, pkt_hdr.incl_len);
		SWAP_ENDIANNESS(pkt_hdr.orig_len, pkt_hdr.orig_len);
	}

	read_size = fread(full_packet, 1, pkt_hdr.incl_len, in);

	if(read_size != pkt_hdr.incl_len) return 0;
	//-------------------------------------------

	packet = full_packet;

	// Skip Prism frame if present
	if (link_type == LINKTYPE_PRISM_HEADER)
	{
		if (packet[7] == 0x40)
			frame_skip = 64;
		else
		{
			frame_skip = *(unsigned int*)&packet[4];
		}
		if (frame_skip < 8 || frame_skip >= pkt_hdr.incl_len)
			return 0;
		packet += frame_skip;
		pkt_hdr.incl_len -= frame_skip;
		pkt_hdr.orig_len -= frame_skip;
	}

	// Skip Radiotap frame if present
	if (link_type == LINKTYPE_RADIOTAP_HDR)
	{
		frame_skip = *(unsigned short*)&packet[2];

		if (frame_skip == 0 || frame_skip >= pkt_hdr.incl_len)
			return 0;
		packet += frame_skip;
		pkt_hdr.incl_len -= frame_skip;
		pkt_hdr.orig_len -= frame_skip;
	}

	// Skip PPI frame if present
	if (link_type == LINKTYPE_PPI_HDR)
	{
		frame_skip = *(unsigned short*)&packet[2];

		if(frame_skip <= 0 || frame_skip >= pkt_hdr.incl_len)
			return 0;

		// Kismet logged broken PPI frames for a period
		if (frame_skip == 24 && *(unsigned short*)&packet[8] == 2)
			frame_skip = 32;

		if (frame_skip == 0 || frame_skip >= pkt_hdr.incl_len)
			return 0;
		packet += frame_skip;
		pkt_hdr.incl_len -= frame_skip;
		pkt_hdr.orig_len -= frame_skip;
	}

	// our data is in *packet with pkt_hdr being the pcap packet header for this packet.
	pkt = (ether_frame_hdr_t*)packet;
	ctl = (ether_frame_ctl_t *)&pkt->frame_ctl;

	if (ctl->type == 0 && ctl->subtype == 8) { // beacon  Type 0 is management, subtype 8 is beacon
		HandleBeacon(packet, &pkt_hdr, wpa_ptr, nwpa, MAX_ESSIDS);
		return 1;
	}
	// if not beacon, then only look data, looking for EAPOL 'type'
	if (ctl->type == 2) { // type 2 is data
		uint8_t *p = packet;
		int bQOS = (ctl->subtype & 8) != 0;
		if ((ctl->toDS ^ ctl->fromDS) != 1)// eapol will ONLY be direct toDS or direct fromDS.
			return 1;
		// Ok, find out if this is a EAPOL packet or not.

		p += sizeof(ether_frame_hdr_t);
		if (bQOS)
			p += 2;
		// p now points to the start of the LLC (logical link control) structure.
		// this is 8 bytes long, and the last 2 bytes are the 'type' field.  What
		// we are looking for is 802.11X authentication packets. These are 0x888e
		// in value.  We are running from an LE point of view, so should look for 0x8e88
		p += 6;
		if (*((uint16_t*)p) == 0x8e88)
			Handle4Way(bQOS, packet, &pkt_hdr, param, tag_id, wpa_ptr[0], nwpa[0]);	// this packet was a eapol packet.
	}

	return 1;
}
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC              "\xAE\x78\xD1\xFF"

#define IVS2_EXTENSION          "ivs"
#define IVS2_VERSION             1

//BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID      0x0001

//ESSID var. length; alone, or with BSSID
#define IVS2_ESSID      0x0002

//wpa structure, const. length; alone, or with BSSID
#define IVS2_WPA        0x0004

//IV+IDX+KEYSTREAM, var. length; alone or with BSSID
#define IVS2_XOR        0x0008

/* [IV+IDX][i][l][XOR_1]..[XOR_i][weight]                                                        *
 * holds i possible keystreams for the same IV with a length of l for each keystream (l max 32)  *
 * and an array "int weight[16]" at the end                                                      */
#define IVS2_PTW        0x0010

//unencrypted packet
#define IVS2_CLR        0x0020

struct ivs2_filehdr
{
    unsigned short version;
};
struct ivs2_pkthdr
{
    unsigned short  flags;
    unsigned short  len;
};
// WPA handshake in ivs2 format
struct ivs2_WPA_hdsk
{
    unsigned char stmac[6];                      /* supplicant MAC               */
    unsigned char snonce[32];                    /* supplicant nonce             */
    unsigned char anonce[32];                    /* authenticator nonce          */
    unsigned char keymic[16];                    /* eapol frame MIC              */
    unsigned char eapol[256];                    /* eapol frame contents         */
    int eapol_size;                              /* eapol frame size             */
    int keyver;                                  /* key version (TKIP / AES)     */
    int state;                                   /* handshake completion         */
};
// Convert WPA handshakes from aircrack-ng (airodump-ng) IVS2 to JtR format
PRIVATE int convert_ivs(FILE *f_in, ImportParam* param, sqlite3_int64 tag_id)
{
	struct ivs2_filehdr fivs2;
	struct ivs2_pkthdr ivs2;
	struct ivs2_WPA_hdsk *wivs2;
	hccap_t hccap;
	unsigned int i;
	unsigned char buffer[66000];
	size_t length, pos;
	unsigned int pktlen;
	unsigned char bssid[6];
	int bssidFound = 0;
	char essid[500];
	int essidFound = 0;
	unsigned char *p, *w;

	fseek(f_in, 0, SEEK_END);
	length = ftell(f_in);
	fseek(f_in, 0, SEEK_SET);

	if (fread(buffer, 1, 4, f_in) != 4) 
		return 1;

	if (memcmp(buffer, IVSONLY_MAGIC, 4) == 0) 
		return(1);

	if (memcmp(buffer, IVS2_MAGIC, 4) != 0) 
		return(1);

	if (fread(&fivs2, 1, sizeof(struct ivs2_filehdr), f_in) != (size_t) sizeof(struct ivs2_filehdr))
		return(1);

	if (fivs2.version > IVS2_VERSION)
		return(1);

	pos = ftell(f_in);

	while (pos < length) {
		if (fread(&ivs2, 1, sizeof(struct ivs2_pkthdr), f_in) != sizeof(struct ivs2_pkthdr))
			return 1;

		pos += sizeof(struct ivs2_pkthdr);

		pktlen = (unsigned int)ivs2.len;
		if (pktlen + pos > length)
			return 1;

		if (fread(&buffer, 1, pktlen, f_in) != pktlen)
			return 1;

		// Show "packet" headers
		// printf("%ld : %d - %02x\n", pos, pktlen, (unsigned int)ivs2.flags);
		p = buffer;
		if (ivs2.flags & IVS2_BSSID)
		{
			memcpy(bssid, p, 6);
			p += 6;

			bssidFound = 1;
		}
		if (ivs2.flags & IVS2_ESSID)
		{
			unsigned int ofs = (unsigned int)(p - buffer);
			unsigned int len = pktlen - ofs;

			if (len <= 0 || len + 1 > sizeof(essid))
				return 1;

			memcpy(essid, p, len);
			essid[len] = 0;

			essidFound = 1;

			p += len;
		}

		if (ivs2.flags & IVS2_WPA)
		{
			int ofs = (int)(p - buffer);
			int len = pktlen - ofs;

			if (len != sizeof(struct ivs2_WPA_hdsk))
				return 1;

			if (!bssidFound)
				return 1;

			if (!essidFound)
				return 1;

			wivs2 = (struct ivs2_WPA_hdsk*)p;

			memset(&hccap, 0, sizeof(hccap_t));
			hccap.keyver = wivs2->keyver;

			memcpy(hccap.mac1, bssid, 6);
			memcpy(hccap.mac2, wivs2->stmac, 6);

			memcpy(hccap.nonce1, wivs2->snonce, 32);
			memcpy(hccap.nonce2, wivs2->anonce, 32);
			memcpy(hccap.keymic, wivs2->keymic, 16);
			hccap.eapol_size = wivs2->eapol_size;
			memcpy(hccap.eapol, wivs2->eapol, wivs2->eapol_size);

			// print struct in base64 format
			w = (unsigned char*)&hccap;
			unsigned char TmpKey[1024];
			unsigned char* cp = TmpKey;

			cp += sprintf (cp, "%s#", essid);
			for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
				cp += code_block(&w[i], 1, cp);
			cp += code_block(&w[i], 0, cp);

			insert_hash_account(param, essid, TmpKey, WPA_INDEX, tag_id);

			p += len;
		}

		pos += pktlen;
	}

	return 0;
}
PRIVATE void import_wpa_from_pcap_file(ImportParam* param)
{
	continue_import = TRUE;

	// All values to zero
	memset(&param->result, 0, sizeof(param->result));

	FILE* file = fopen(param->filename, "rb");

	if (file)
	{
		lenght_of_file = _filelengthi64(fileno(file));
		BEGIN_TRANSACTION;
		sqlite3_int64 tag_id = insert_when_necesary_tag(param->tag);

		pcap_hdr_t main_hdr;
		int bROT;

		if (fread(&main_hdr, 1, sizeof(pcap_hdr_t), file) == sizeof(pcap_hdr_t))
		{
			if (main_hdr.magic_number == 0xa1b2c3d4)
				bROT = 0;
			else if (main_hdr.magic_number == 0xd4c3b2a1)
				bROT = 1;
			else {
				convert_ivs(file, param, tag_id);
				goto release_resources;
			}

			if (bROT)
			{
				SWAP_ENDIANNESS(main_hdr.network, main_hdr.network);
			}

			switch (main_hdr.network)
			{
			case LINKTYPE_IEEE802_11: case LINKTYPE_PRISM_HEADER: case LINKTYPE_RADIOTAP_HDR: case LINKTYPE_PPI_HDR:
				break;
			default:
				goto release_resources;
			}

			uint8_t full_packet[65535];
			int nwpa = 0;
			int MAX_ESSIDS = 100;
			WPA4way_t* wpa = (WPA4way_t*)malloc(MAX_ESSIDS*sizeof(WPA4way_t));
			while (GetNextPacketAndProcess(file, bROT, full_packet, main_hdr.network, param, tag_id, &wpa, &nwpa, &MAX_ESSIDS))
			{
				fgetpos(file, &pos_in_file);
				param->completition = (int)(pos_in_file * 100 / lenght_of_file);
			}
			for (int i = 0; i < nwpa; i++)
			{
				if (wpa[i].packet1) free(wpa[i].packet1);
				if (wpa[i].packet3) free(wpa[i].packet3);
				if (wpa[i].packet2) free(wpa[i].packet2);
				if (wpa[i].orig_2)  free(wpa[i].orig_2); 
			}
			free(wpa);
		}

release_resources:
		END_TRANSACTION;
		fclose(file);
	}

	param->completition = 100;
	param->isEnded = TRUE;
}

PRIVATE void import_wpa_from_hccap_file(ImportParam* param)
{
	continue_import = TRUE;

	// All values to zero
	memset(&param->result, 0, sizeof(param->result));

	FILE* file = fopen(param->filename, "rb");

	if (file)
	{
		lenght_of_file = _filelengthi64(fileno(file));
		BEGIN_TRANSACTION;
		sqlite3_int64 tag_id = insert_when_necesary_tag(param->tag);
		hccap_t wpa;

		while (fread(&wpa, sizeof(wpa), 1, file))
		{
			fgetpos(file, &pos_in_file);
			param->completition = (int)(pos_in_file * 100 / lenght_of_file);

			if (wpa.eapol_size < 256 && strlen(wpa.essid) < 36)
			{
				// Convert to string
				char TmpKey[1024], *cp = TmpKey;
				cp += sprintf(cp, "%s#", wpa.essid);

				uint8_t* w = (uint8_t*)&wpa;
				int i;
				for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
					cp += code_block(&w[i], 1, cp);
				cp += code_block(&w[i], 0, cp);

				insert_hash_account(param, wpa.essid, TmpKey, WPA_INDEX, tag_id);
			}
		}
			
		END_TRANSACTION;
		fclose(file);
	}

	param->completition = 100;
	param->isEnded = TRUE;
}
////////////////////////////////////////////////////////////////////////////////////
// Export found passwords
////////////////////////////////////////////////////////////////////////////////////
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
// Export WPA
PRIVATE int callback_wpa(void *file, int argc, char **argv, char **azColName)
{
	fprintf((FILE*)file, "$WPAPSK$%s\n", argv[0]);
	return 0;
}
PRIVATE void export_wpa(const char* filename)
{
	FILE* file = fopen(filename, "w");

	if(file != NULL)
	{
		char buffer_sql[128];
		sprintf(buffer_sql, "SELECT Hex FROM Hash WHERE Hash.Type==%i;", (int)formats[WPA_INDEX].db_id);

		sqlite3_exec(db, buffer_sql, callback_wpa, file, NULL);

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
	sqlite3_prepare_v2(db, "INSERT INTO Account (UserName,Hash) VALUES (?,?);"		  , -1, &insert_account, NULL);
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
	{37, "From file.", NULL, "Import hashes from a file automatically detecting hash type.", import_file_general, IMPORT_PARAM_FILENAME },
	{47, "Wifi captures.", "*.pcap;*.cap", "Import WPA hashes from a Pcap, Wireshark or Aircrack capture file.", import_wpa_from_pcap_file, IMPORT_PARAM_FILENAME }
	// TODO: Import from SAM and SYSKEY, Scheduler and others...
};

PUBLIC Exporter exporters[] = {
	{38, "Found passwords.", "found_passwords.txt", "Export all passwords already found by the program.", export_found_passwords},// Export found passwords
	{38, "Found passwords as wordlist.", "found_passwords_wordlist.txt", "Export all passwords already found by the program as a wordlist.", export_found_passwords_wordlist},// Export found passwords as wordlist
	{38, "Pwdump format."	, "passwords.txt"      , "Export NTLM and LM hashes in pwdump file format.", export_pwdump},
	{38, "Cachedump format.", "passwords.txt"      , "Export DCC hashes in cachedump file format.", export_dcc},
	{38, "WPA hashes."	    , "wpa_hashes.txt"     , "Export WPA hashes in a format used by other crackers.", export_wpa}
#ifdef ANDROID
	,{38, "Hash Suite Database.", "config.db"      , "Export Hash Suite Database.", export_db}
#endif
	// TODO: Export others...
};

PUBLIC int num_importers = LENGHT(importers);
PUBLIC int num_exporters = LENGHT(exporters);
