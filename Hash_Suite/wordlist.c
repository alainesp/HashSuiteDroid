// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014,2016 by Alain Espinosa. See LICENSE.

#include "common.h"
#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
	#include <windows.h>
	#include <io.h>
	#define HS_COPY_REG	uint64_t
#else
	#include <pthread.h>
	#define HS_COPY_REG	uint32_t
#endif

#define HS_COPY_SIZE sizeof(HS_COPY_REG)

extern int64_t num_key_space;
extern uint32_t max_lenght;
extern uint32_t min_lenght;
extern unsigned char current_key[];
extern uint32_t current_key_lenght;
extern fpos_t* thread_params;
extern uint32_t num_thread_params;

extern HS_MUTEX key_provider_mutex;

PRIVATE unsigned char* wordlist_buffer = NULL;
#define WORDLIST_BUFFER_SIZE 4096
PRIVATE uint32_t buffer_pos = 0;
PRIVATE size_t buffer_count = 0;
PRIVATE int end_of_file = FALSE;
PUBLIC double wordlist_completition = 0;

typedef struct WORDLIST_FUNCS
{
	void (*init)(const char* params, const char* resume_arg);
	int (*getline)(unsigned char* current_key, int max_lenght);
	void (*calculate_completition)();
	fpos_t (*get_position)();
}
WORDLIST_FUNCS;

PRIVATE WORDLIST_FUNCS wordlist_func;

PRIVATE __forceinline void COPY_GENERATE_KEY_PROTOCOL_NTLM_KEY(uint32_t* nt_buffer, const unsigned char* key, uint32_t NUM_KEYS, uint32_t index)
{
	uint32_t j = 0;

	for(; j < current_key_lenght/2; j++)	
		nt_buffer[j*NUM_KEYS+index] = ((uint32_t)key[2*j]) | ((uint32_t)key[2*j+1]) << 16;
												
	nt_buffer[j*NUM_KEYS+index] = (current_key_lenght & 1) ? ((uint32_t)key[2*j]) | 0x800000 : 0x80;
	nt_buffer[14*NUM_KEYS+index] = current_key_lenght << 4;	
												
	for (j++; j < 14; j++)
		nt_buffer[j*NUM_KEYS + index] = 0;
}

PRIVATE int getline_uint0(uint32_t* buffer_in, uint32_t* buffer_out, uint32_t max_lenght)
{
	uint32_t key_index = 0;
	uint32_t key_chars = buffer_in[0];
	int key_chars_positive = (key_chars & 0xFEFEFEFE) >> 1;
	uint32_t max_index = max_lenght / 4;
	uint32_t flag = 1 << 16;

	// Cycle until end of line
	// A modified version of hasless(x,14)
	while( !((key_chars_positive - 0x08080808) & (~key_chars_positive) & 0x80808080) && key_index < max_index )
	{
		// Read word
		buffer_out[key_index] = key_chars;
		key_index++;
		key_chars = buffer_in[key_index];
		key_chars_positive = (key_chars & 0xFEFEFEFE) >> 1;// make positive
	}

	int size_part = -1;
	if((key_chars & 0xFF000000) <= (13<<24))size_part=0;
	if((key_chars & 0x00FF0000) <= (13<<16))size_part=8;
	if((key_chars & 0x0000FF00) <= (13<<8 ))size_part=16;
	if((key_chars & 0x000000FF) <= (13<<0 ))size_part=24;
	// Is overflow?
	if (key_index >= max_index)
	{
		int max_size_part = (3 - (max_lenght & 3)) * 8;
		if (max_size_part > size_part)
		{
			size_part = max_size_part;
			flag = 0;
		}
	}

	buffer_out[key_index]=(key_chars & (0x00FFFFFF>>size_part));

	return key_index*4 + (24-size_part)/8 + flag;
}
/////////////////////////////////////////////////////////////////////////////////////
// Plaintext wordlists
/////////////////////////////////////////////////////////////////////////////////////
PRIVATE FILE* wordlist = NULL;
PRIVATE fpos_t wordlist_lenght;
PRIVATE fpos_t current_pos;

PRIVATE void init_plaintext(const char* params, const char* resume_arg)
{
	wordlist_buffer = (unsigned char*)malloc(WORDLIST_BUFFER_SIZE+4);

	wordlist = (params) ? fopen(params, "rb") : NULL;

	// Get file length
	if(wordlist != NULL)
		wordlist_lenght = _filelengthi64( fileno(wordlist) );
	
	// Getting approximate key-space
	num_key_space = wordlist_lenght / 11;

	// Resume
	if(wordlist && resume_arg && strlen(resume_arg))
	{
		int64_t _big_pos;
		sscanf(resume_arg, "%lli", &_big_pos);
		current_pos = _big_pos;
		fsetpos(wordlist, &current_pos);
	}
	
	buffer_count = fread(wordlist_buffer, 1, WORDLIST_BUFFER_SIZE, wordlist);
	buffer_pos = 0;
	end_of_file = buffer_count <= 0;
}
PRIVATE int getline_plaintext(unsigned char* current_key, int max_lenght)
{
	int length = 0;

	// All keys generated
	if(!wordlist || end_of_file) return -1;

	//copy line: Optimized version
	if ((buffer_pos + max_lenght) < buffer_count)
	{
		uint32_t length_flag = getline_uint0((uint32_t*)(wordlist_buffer + buffer_pos), (uint32_t*)current_key, max_lenght);
		length = length_flag & 0xffff;
		buffer_pos += length + (length_flag >> 16);
		// Handle Windows convention
		if (buffer_pos >= 1 && wordlist_buffer[buffer_pos - 1] == '\r' && wordlist_buffer[buffer_pos] == '\n')
			buffer_pos++;
	}
	else//copy line: General version
		for(; length < max_lenght; buffer_pos++, length++)
		{
			// If encounter end of buffer-> read new data in buffer
			if(buffer_pos >= buffer_count)
			{
				buffer_count = fread(wordlist_buffer, 1, WORDLIST_BUFFER_SIZE, wordlist);
				buffer_pos = 0;
				if(buffer_count <= 0)
				{
					end_of_file = TRUE;
					break;//end of file
				}
			}

			if(wordlist_buffer[buffer_pos] <= 13)// End of line
			{
				buffer_pos++;
				for(; buffer_pos < buffer_count && wordlist_buffer[buffer_pos] <= 13; buffer_pos++);
				break;
			}

			current_key[length] = wordlist_buffer[buffer_pos];
		}

	current_key[length] = 0;
	return length;
}
PRIVATE void calculate_completition_plaintext()
{
	wordlist_completition = 0;
	if(wordlist != NULL)
	{
		fgetpos(wordlist, &current_pos);
		current_pos = current_pos - buffer_count + buffer_pos;
		if(current_pos)
			wordlist_completition = (double)wordlist_lenght / (double)current_pos;// We use double and parenthesis to prevent buffer overflows
	}
}
PRIVATE fpos_t get_position_plaintext()
{
	if(wordlist != NULL)
	{
		fgetpos(wordlist, &current_pos);
		current_pos += buffer_pos;
		return current_pos-buffer_count;
	}
	return 0;
}
PRIVATE void finish_plaintext()
{
	if(wordlist != NULL)
		fclose(wordlist);

	wordlist = NULL;

	free(wordlist_buffer);
}


/////////////////////////////////////////////////////////////////////////////////////
// Zip files
/////////////////////////////////////////////////////////////////////////////////////
#include "compress/zlib/unzip.h"

#ifdef _WIN32
#define USEWIN32IOAPI
#include "compress/zlib/iowin32.h"
#endif

PRIVATE unzFile uf = NULL;
PRIVATE unz64_file_pos file_pos;
uLong unzGetUncompressedLength(unzFile file);

PRIVATE void init_zip(const char* params, const char* resume_arg)
{
#ifdef USEWIN32IOAPI
	zlib_filefunc64_def ffunc;
#endif
	int err;

	wordlist_buffer = (unsigned char*)malloc(WORDLIST_BUFFER_SIZE+4);

#ifdef USEWIN32IOAPI
	fill_win32_filefunc64A(&ffunc);
	uf = unzOpen2_64(params, &ffunc);
#else
	uf = unzOpen64(params);
#endif
	// Get file length
	wordlist_lenght = unzGetUncompressedLength(uf);
	// Getting approximate key-space
	num_key_space = wordlist_lenght / 11;

	err = unzOpenCurrentFilePassword(uf, NULL);
	// Resume
	if(uf != NULL && resume_arg && strlen(resume_arg))
	{
		fpos_t pos = 0;
		int64_t tmp_pos;
		sscanf(resume_arg, "%lli", &tmp_pos);
		current_pos = tmp_pos;

		while (pos < current_pos)
		{
			buffer_count = unzReadCurrentFile(uf, wordlist_buffer, WORDLIST_BUFFER_SIZE);
			pos += buffer_count;

			// Open other file
			while(!buffer_count)
			{
				unzCloseCurrentFile(uf);
				unzGoToNextFile(uf);
				unzOpenCurrentFilePassword(uf, NULL);
				buffer_count = unzReadCurrentFile(uf, wordlist_buffer, WORDLIST_BUFFER_SIZE);
				pos += buffer_count;
			}
		}
		buffer_pos = (uint32_t)(pos - current_pos);
	}
	else
	{
		batch[current_attack_index].num_keys_served = 0;

		buffer_count = unzReadCurrentFile(uf, wordlist_buffer, WORDLIST_BUFFER_SIZE);
		buffer_pos = 0;
	}
	end_of_file = err != UNZ_OK || buffer_count < 0;
}
PRIVATE int getline_zip(unsigned char* current_key, int max_lenght)
{
	int length = 0;

	// All keys generated
	if(end_of_file) return -1;

	//copy line: Optimized version
	if ((buffer_pos + max_lenght) < buffer_count)
	{
		uint32_t length_flag = getline_uint0((uint32_t*)(wordlist_buffer + buffer_pos), (uint32_t*)current_key, max_lenght);
		length = length_flag & 0xffff;
		buffer_pos += length + (length_flag >> 16);
		// Handle Windows convention
		if (buffer_pos >= 1 && wordlist_buffer[buffer_pos - 1] == '\r' && wordlist_buffer[buffer_pos] == '\n')
			buffer_pos++;
	}
	else//copy line: General version
		for(; length < max_lenght; buffer_pos++, length++)
		{
			// If encounter end of buffer --> read new data in buffer
			if(buffer_pos >= buffer_count)
			{
				buffer_count = unzReadCurrentFile(uf, wordlist_buffer, WORDLIST_BUFFER_SIZE);
				// Open other file
				while(!buffer_count)
				{
					unzCloseCurrentFile(uf);
					if(unzGoToNextFile (uf) == UNZ_END_OF_LIST_OF_FILE)
					{
						end_of_file = TRUE;
						break;//end of file
					}
					unzOpenCurrentFilePassword(uf, NULL);
					buffer_count = unzReadCurrentFile(uf, wordlist_buffer, WORDLIST_BUFFER_SIZE);
				}
				buffer_pos = 0;
			}

			if(wordlist_buffer[buffer_pos] <= 13)// End of line
			{
				buffer_pos++;
				for(; buffer_pos < buffer_count && wordlist_buffer[buffer_pos] <= 13; buffer_pos++);
				break;
			}

			current_key[length] = wordlist_buffer[buffer_pos];
		}

	current_key[length] = 0;
	return length;
}
PRIVATE void calculate_completition_zip()
{
	wordlist_completition = 0;
	current_pos = unztell64(uf);
	if (end_of_file)
		wordlist_completition = 1;
	else if(current_pos)
		wordlist_completition = (double)wordlist_lenght / (double)current_pos;// We use double and parenthesis to prevent buffer overflows
}
PRIVATE fpos_t get_position_zip()
{
	current_pos = unztell64(uf);
	if (end_of_file)
		current_pos = wordlist_lenght;
	else
		current_pos -= buffer_count - buffer_pos;
	return current_pos;
}
PRIVATE void finish_zip()
{
	if(uf != NULL)
		unzClose(uf);
	uf = NULL;

	free(wordlist_buffer);
}

/////////////////////////////////////////////////////////////////////////////////////
// GZ files
/////////////////////////////////////////////////////////////////////////////////////
PRIVATE gzFile gz_file;

PRIVATE void init_gz(const char* params, const char* resume_arg)
{
	wordlist_buffer = (unsigned char*)malloc(WORDLIST_BUFFER_SIZE+4);
	
	// Get file length
	wordlist = (params) ? fopen(params, "rb") : NULL;
	if(wordlist != NULL)
		wordlist_lenght = _filelengthi64( fileno(wordlist) );
	fclose(wordlist);
	wordlist = NULL;

	// Open file as gz
	gz_file = gzopen(params, "rb");

	// Getting approximate key-space
	num_key_space = wordlist_lenght / 3;

	// Resume
	if(gz_file != NULL && resume_arg && strlen(resume_arg))
	{
		fpos_t pos = 0;
		int64_t tmp_pos;
		sscanf(resume_arg, "%lli", &tmp_pos);
		current_pos = tmp_pos;

		while (pos < current_pos)
		{
			buffer_count = gzread(gz_file, wordlist_buffer, WORDLIST_BUFFER_SIZE);
			pos += buffer_count;
		}
		buffer_pos = (uint32_t)(pos - current_pos);
	}
	else
	{
		batch[current_attack_index].num_keys_served = 0;

		buffer_count = gzread(gz_file, wordlist_buffer, WORDLIST_BUFFER_SIZE);
		buffer_pos = 0;
		current_pos = 0;
	}
	end_of_file = buffer_count <= 0;
}
PRIVATE int getline_gz(unsigned char* current_key, int max_lenght)
{
	int length = 0;

	// All keys generated
	if(!gz_file || end_of_file) return -1;

	//copy line: Optimized version
	if ((buffer_pos + max_lenght) < buffer_count)
	{
		uint32_t length_flag = getline_uint0((uint32_t*)(wordlist_buffer + buffer_pos), (uint32_t*)current_key, max_lenght);
		length = length_flag & 0xffff;
		buffer_pos += length + (length_flag >> 16);
		// Handle Windows convention
		if (buffer_pos >= 1 && wordlist_buffer[buffer_pos - 1] == '\r' && wordlist_buffer[buffer_pos] == '\n')
			buffer_pos++;
	}
	else//copy line: General version
		for(; length < max_lenght; buffer_pos++, length++)
		{
			// If encounter end of buffer-> read new data in buffer
			if(buffer_pos >= buffer_count)
			{
				current_pos += buffer_count;
				buffer_count = gzread(gz_file, wordlist_buffer, WORDLIST_BUFFER_SIZE);
				if(buffer_count <= 0)
				{
					end_of_file = TRUE;
					break;//end of file
				}
				buffer_pos = 0;
			}

			if(wordlist_buffer[buffer_pos] <= 13)// End of line
			{
				buffer_pos++;
				for(; buffer_pos < buffer_count && wordlist_buffer[buffer_pos] <= 13; buffer_pos++);
				break;
			}

			current_key[length] = wordlist_buffer[buffer_pos];
		}

	current_key[length] = 0;
	return length;
}
PRIVATE void calculate_completition_gz()
{
#ifdef __ANDROID__
	if ((wordlist_lenght*4) > current_pos)
		wordlist_completition = (double)(wordlist_lenght*4) / (double)current_pos;
	else
		wordlist_completition = 1;
#else
	wordlist_completition = 0;
	if(gz_file != NULL)
	{
		z_off_t _pos = gzoffset(gz_file);
		if(_pos > 0)
			wordlist_completition = (double)wordlist_lenght / (double)_pos;// We use double and parenthesis to prevent buffer overflows
	}
#endif
}
PRIVATE fpos_t get_position_gz()
{
	return current_pos;
}
PRIVATE void finish_gz()
{
	if(gz_file != NULL)
#ifdef __ANDROID__
		gzclose(gz_file);
#else
		gzclose_r(gz_file);
#endif

	gz_file = NULL;

	free(wordlist_buffer);
}

/////////////////////////////////////////////////////////////////////////////////////
// BZ2 files
/////////////////////////////////////////////////////////////////////////////////////
#include "compress/libbz2/bzlib.h"
PRIVATE BZFILE* bz_file;
PRIVATE int     bzerror;

PRIVATE void init_bz2(const char* params, const char* resume_arg)
{
	wordlist_buffer = (unsigned char*)malloc(WORDLIST_BUFFER_SIZE+4);

	// Open file
	wordlist = (params) ? fopen(params, "rb") : NULL;
	// Get file length
	if(wordlist != NULL)
		wordlist_lenght = _filelengthi64( fileno(wordlist) );

	// Getting approximate key-space
	num_key_space = wordlist_lenght / 3;

	bz_file = BZ2_bzReadOpen( &bzerror, wordlist, FALSE, FALSE, NULL, 0 );
	if ( bzerror != BZ_OK )
	{
		BZ2_bzReadClose( &bzerror, bz_file );
		fclose(wordlist);
		wordlist = NULL;
	}

	// Resume
	if(wordlist != NULL && resume_arg && strlen(resume_arg))
	{
		fpos_t pos = 0;
		int64_t tmp_pos;
		sscanf(resume_arg, "%lli", &tmp_pos);
		current_pos = tmp_pos;

		while (pos < current_pos)
		{
			buffer_count = BZ2_bzRead(&bzerror, bz_file, wordlist_buffer, WORDLIST_BUFFER_SIZE);
			pos += buffer_count;
		}
		buffer_pos = (uint32_t)(pos - current_pos);
	}
	else
	{
		batch[current_attack_index].num_keys_served = 0;

		buffer_count = BZ2_bzRead(&bzerror, bz_file, wordlist_buffer, WORDLIST_BUFFER_SIZE);
		buffer_pos = 0;
		current_pos = 0;
	}
	end_of_file = bzerror < 0  || buffer_count <= 0;// Have and error
}
PRIVATE int getline_bz2(unsigned char* current_key, int max_lenght)
{
	int length = 0;

	// All keys generated
	if(!wordlist || end_of_file) return -1;

	//copy line: Optimized version
	if ((buffer_pos + max_lenght) < buffer_count)
	{
		uint32_t length_flag = getline_uint0((uint32_t*)(wordlist_buffer + buffer_pos), (uint32_t*)current_key, max_lenght);
		length = length_flag & 0xffff;
		buffer_pos += length + (length_flag >> 16);
		// Handle Windows convention
		if (buffer_pos >= 1 && wordlist_buffer[buffer_pos - 1] == '\r' && wordlist_buffer[buffer_pos] == '\n')
			buffer_pos++;
	}
	else//copy line: General version
		for(; length < max_lenght; buffer_pos++, length++)
		{
			// If encounter end of buffer-> read new data in buffer
			if(buffer_pos >= buffer_count)
			{
				current_pos += buffer_count;
				buffer_count = BZ2_bzRead( &bzerror, bz_file, wordlist_buffer, WORDLIST_BUFFER_SIZE);
				if(buffer_count <= 0 || bzerror < 0)
				{
					end_of_file = TRUE;
					break;//end of file
				}
				buffer_pos = 0;
			}

			if(wordlist_buffer[buffer_pos] <= 13)// End of line
			{
				buffer_pos++;
				for(; buffer_pos < buffer_count && wordlist_buffer[buffer_pos] <= 13; buffer_pos++);
				break;
			}

			current_key[length] = wordlist_buffer[buffer_pos];
		}

	current_key[length] = 0;
	return length;
}
PRIVATE void finish_bz2()
{
	if(wordlist != NULL)
	{
		BZ2_bzReadClose(&bzerror, bz_file);
		fclose(wordlist);
	}
	wordlist = NULL;

	free(wordlist_buffer);
}
PRIVATE void calculate_completition_bz2()
{
	wordlist_completition = 0;
	if(wordlist != NULL)
	{
		fpos_t _pos;
		fgetpos(wordlist, &_pos);
		if(_pos)
			wordlist_completition = (double)wordlist_lenght / (double)_pos;// We use double and parenthesis to prevent buffer overflows
	}
}
PRIVATE fpos_t get_position_bz2()
{
	return current_pos;
}

#ifdef HS_USE_COMPRESS_WORDLISTS
/////////////////////////////////////////////////////////////////////////////////////
// 7zip files
/////////////////////////////////////////////////////////////////////////////////////
#include "compress/7z/7z.h"
#include "compress/7z/7zFile.h"
#include "compress/7z/7zAlloc.h"
#include "compress/7z/7zCrc.h"

PRIVATE CFileInStream archiveStream_7z;
PRIVATE CLookToRead lookStream_7z;				/* implements ILookInStream interface */
PRIVATE CSzArEx db_7z;							/* 7z archive database structure */
PRIVATE ISzAlloc allocImp_7z;					/* memory functions for main pool */
PRIVATE ISzAlloc allocTempImp_7z;				/* memory functions for temporary pool */

PRIVATE UInt32 blockIndex_7z = 0xFFFFFFFF;		/* it can have any value before first call (if outBuffer = 0) */
PRIVATE size_t offset = 0;
PRIVATE size_t outBufferSize = 0;
PRIVATE uint32_t file_index = 0;
PRIVATE int first_read_done;

PRIVATE void init_7zip(const char* params, const char* resume_arg)
{
	wordlist_buffer = NULL;/* it must be 0 before first call for each new archive. */
	end_of_file = FALSE;
	wordlist_lenght = 0;
	num_key_space = 0;
	first_read_done = FALSE;
	offset = 0;

	// 7zip init
	allocImp_7z.Alloc = SzAlloc;
	allocImp_7z.Free = SzFree;
	allocTempImp_7z.Alloc = SzAllocTemp;
	allocTempImp_7z.Free = SzFreeTemp;

	if (InFile_Open(&archiveStream_7z.file, params))
		end_of_file = TRUE;

	FileInStream_CreateVTable(&archiveStream_7z);
	LookToRead_CreateVTable(&lookStream_7z, False);

	lookStream_7z.realStream = &archiveStream_7z.s;
	LookToRead_Init(&lookStream_7z);

	CrcGenerateTable();

	SzArEx_Init(&db_7z);
	if (SzArEx_Open(&db_7z, &lookStream_7z.s, &allocImp_7z, &allocTempImp_7z) == SZ_OK)
	{
		UInt32 i;
		file_index = 0;

		for(i = 0; i < db_7z.db.NumFiles; i++)
			wordlist_lenght += ((CSzFileItem*)(db_7z.db.Files+i))->Size;

		num_key_space = wordlist_lenght / 11;
	}
	else
		end_of_file = TRUE;

	// Resume
	if(!end_of_file && resume_arg && strlen(resume_arg))
	{
		fpos_t pos = 0;
		int64_t tmp_pos;
		sscanf(resume_arg, "%lli", &tmp_pos);
		current_pos = tmp_pos;
		
		// Find the file
		for(file_index = 0; file_index < db_7z.db.NumFiles; file_index++)
			if ((pos + ((CSzFileItem*)(db_7z.db.Files + file_index))->Size) < (UInt64)current_pos)
				pos += ((CSzFileItem*)(db_7z.db.Files + file_index))->Size;
			else
				break;

		SzArEx_Extract(&db_7z, &lookStream_7z.s, file_index, &blockIndex_7z, &wordlist_buffer, &outBufferSize, &offset, &buffer_count, &allocImp_7z, &allocTempImp_7z);
			
		buffer_pos = (uint32_t)(current_pos - pos);
		first_read_done = TRUE;
	}
	else
	{
		batch[current_attack_index].num_keys_served = 0;

		buffer_pos = 0;
		current_pos = 0;
	}
}
PRIVATE int getline_7zip(unsigned char* current_key, int max_lenght)
{
	int length = 0;

	// All keys generated
	if(end_of_file) return -1;

	if(!first_read_done)
	{
		offset = 0;
		SzArEx_Extract(&db_7z, &lookStream_7z.s, file_index, &blockIndex_7z, &wordlist_buffer, &outBufferSize, &offset, &buffer_count, &allocImp_7z, &allocTempImp_7z);
		first_read_done = TRUE;
	}

	// Copy line
	for(; length < max_lenght; buffer_pos++, length++)
	{
		// If encounter end of buffer-> read new data in buffer
		if(buffer_pos >= buffer_count)
		{
			file_index++;
			buffer_pos = 0;

			if(file_index >= db_7z.db.NumFiles)
			{
				end_of_file = TRUE;
				break;//end of file
			}
			else
			{
				IAlloc_Free(&allocImp_7z, wordlist_buffer);
				wordlist_buffer = NULL;

				SzArEx_Extract(&db_7z, &lookStream_7z.s, file_index, &blockIndex_7z, &wordlist_buffer, &outBufferSize, &offset, &buffer_count, &allocImp_7z, &allocTempImp_7z);
			}
		}

		if(wordlist_buffer[buffer_pos] <= 13)// End of line
		{
			buffer_pos++;
			for(; buffer_pos < buffer_count && wordlist_buffer[buffer_pos] <= 13; buffer_pos++);
			break;
		}

		current_key[length] = wordlist_buffer[buffer_pos];
	}

	current_key[length] = 0;
	return length;
}
PRIVATE void calculate_completition_7zip()
{
	uint32_t i;
	int64_t _pos = buffer_pos;
	wordlist_completition = 0;

	for(i = 0; i < file_index; i++)
		_pos += ((CSzFileItem*)(db_7z.db.Files+i))->Size;

	if(_pos)
		wordlist_completition = (double)wordlist_lenght / (double)_pos;// We use double and parenthesis to prevent buffer overflows
}
PRIVATE fpos_t get_position_7zip()
{
	uint32_t i;
	fpos_t _pos = buffer_pos;

	for(i = 0; i < file_index; i++)
		_pos += ((CSzFileItem*)(db_7z.db.Files+i))->Size;

	return _pos;
}
PRIVATE void finish_7zip()
{
	IAlloc_Free(&allocImp_7z, wordlist_buffer);

	SzArEx_Free(&db_7z, &allocImp_7z);
	File_Close(&archiveStream_7z.file);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////
// Common
/////////////////////////////////////////////////////////////////////////////////////

PUBLIC int is_wordlist_supported(const char* file_path, char* error_message)
{
	size_t ext_pos = strlen(file_path);

	// Is a supported compressed format?
	if(!strcmp(".zip", file_path + ext_pos-4) || !strcmp(".gz", file_path + ext_pos-3) || !strcmp(".tgz", file_path + ext_pos-4) ||
		!strcmp(".bz2", file_path + ext_pos-4) || !strcmp(".7z", file_path + ext_pos-3))
		return TRUE;

	/////////////////////////////////////////////////////////////////////////////////////////
	// Check if is plaintext
	/////////////////////////////////////////////////////////////////////////////////////////
	// The algorithm works by dividing the set of byte-codes [0..255] into three categories:
	// - The white list of textual byte-codes:
	//		9 (TAB), 10 (LF), 13 (CR), 32 (SPACE) to 255.
	// - The gray list of tolerated byte-codes:
	//		7 (BEL), 8 (BS), 11 (VT), 12 (FF), 26 (SUB), 27 (ESC).
	// - The black list of undesired, non-textual byte-codes:
	//		0 (NUL) to 6, 14 to 31.
	//
	// If a file contains at least one byte that belongs to the white list and no byte that belongs
	// to the black list, then the file is categorized as plain text; otherwise, it is categorized 
	// as binary. (The boundary case, when the file is empty, automatically falls into the latter 
	// category.)
	wordlist = fopen(file_path, "rb");
	if(wordlist	!=	NULL)
	{
		size_t i;
		int result = TRUE;

		wordlist_buffer = (char*)malloc(8192);
		buffer_count = fread(wordlist_buffer, 1, 8192, wordlist);
		fclose(wordlist);
		wordlist = NULL;

		for(i = 0; i < buffer_count; i++)
		{
			if(wordlist_buffer[i] >= 0 && wordlist_buffer[i] <= 6)
			{
				result = FALSE;
				break;
			}
			if(wordlist_buffer[i] >= 14 && wordlist_buffer[i] <= 31)
			{
				result = FALSE;
				break;
			}
		}

		free(wordlist_buffer);

		if(error_message && !result)
			strcpy(error_message, "Hash Suite only supports .zip, .gz, .tgz, .bz2, .7z and plaintext wordlists files.");

		return result;
	}

	return FALSE;
}
PUBLIC void wordlist_save_resume_arg(char* resume_arg)
{
	uint32_t i;
	int64_t small_pos = LLONG_MAX;
	resume_arg[0] = 0;

	if (thread_params)
	{
		HS_ENTER_MUTEX(&key_provider_mutex);

		// Find the most old saved data
		for (i = 0; i < num_thread_params; i++)
			if (small_pos > thread_params[i])
				small_pos = thread_params[i];

		// Save current candidate
		sprintf(resume_arg, "%lli", small_pos);

		HS_LEAVE_MUTEX(&key_provider_mutex);
	}
}
// Common initialization function
PRIVATE void wordlist_resume_common(int pmin_lenght, int pmax_lenght, char* params, const char* resume_arg, const char* query)
{
	size_t ext_pos = 0;

	// Get the wordlist filename
	const char* _filename;
	sqlite3_stmt* _select_wordlists;
	sqlite3_prepare_v2(db, query, -1, &_select_wordlists, NULL);
	sqlite3_bind_int(_select_wordlists, 1, atoi(params));
	sqlite3_step(_select_wordlists);
	_filename = (const char*)sqlite3_column_text(_select_wordlists, 0);

	wordlist_lenght = 0;

	max_lenght = pmax_lenght;
	min_lenght = pmin_lenght;

	// TODO: Find file type well: read magic numbers
	ext_pos = strlen(_filename);

	if(!strcmp(".zip", _filename + ext_pos-4))
	{
		wordlist_func.init = init_zip;
		wordlist_func.getline = getline_zip;
		wordlist_func.calculate_completition = calculate_completition_zip;
		wordlist_func.get_position = get_position_zip;

		key_providers[WORDLIST_INDEX].finish = finish_zip;
	}
	else if(!strcmp(".gz", _filename + ext_pos-3) || !strcmp(".tgz", _filename + ext_pos-4))
	{
		wordlist_func.init = init_gz;
		wordlist_func.getline = getline_gz;
		wordlist_func.calculate_completition = calculate_completition_gz;
		wordlist_func.get_position = get_position_gz;

		key_providers[WORDLIST_INDEX].finish = finish_gz;
	}
	else if(!strcmp(".bz2", _filename + ext_pos-4))
	{
		wordlist_func.init = init_bz2;
		wordlist_func.getline = getline_bz2;
		wordlist_func.calculate_completition = calculate_completition_bz2;
		wordlist_func.get_position = get_position_bz2;

		key_providers[WORDLIST_INDEX].finish = finish_bz2;
	}
#ifdef HS_USE_COMPRESS_WORDLISTS
	else if(!strcmp(".7z", _filename + ext_pos-3))
	{
		wordlist_func.init = init_7zip;
		wordlist_func.getline = getline_7zip;
		wordlist_func.calculate_completition = calculate_completition_7zip;
		wordlist_func.get_position = get_position_7zip;

		key_providers[WORDLIST_INDEX].finish = finish_7zip;
	}
#endif
	else
	{
		wordlist_func.init = init_plaintext;
		wordlist_func.getline = getline_plaintext;
		wordlist_func.calculate_completition = calculate_completition_plaintext;
		wordlist_func.get_position = get_position_plaintext;

		key_providers[WORDLIST_INDEX].finish = finish_plaintext;
	}

	wordlist_func.init(_filename, resume_arg);
	sqlite3_finalize(_select_wordlists);
}
PUBLIC void wordlist_resume(int pmin_lenght, int pmax_lenght, char* params, const char* resume_arg, int format_index)
{
	wordlist_resume_common(pmin_lenght, pmax_lenght, params, resume_arg, "SELECT FileName FROM WordList WHERE ID=?;");
}

void convert_utf8_2_coalesc(unsigned char* key, uint32_t* nt_buffer, uint32_t max_number, uint32_t len);

PUBLIC int wordlist_gen_ntlm(uint32_t* nt_buffer, uint32_t max_number, int thread_id)
{
	uint32_t i = 0;
	int result = max_number;

	HS_ENTER_MUTEX(&key_provider_mutex);

	thread_params[thread_id] = wordlist_func.get_position();

	for(; i < max_number; i++)
	{
		int line_lenght = wordlist_func.getline(current_key, max_lenght);
		// All keys generated
		if(line_lenght < 0)
		{
			result = i; break;
		}
		
		current_key_lenght = line_lenght;
		COPY_GENERATE_KEY_PROTOCOL_NTLM_KEY(nt_buffer, current_key, max_number, i);
	}

	// Getting approximate key-space
	wordlist_func.calculate_completition();
	num_key_space = (int64_t)((get_num_keys_served() + result) * wordlist_completition);

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return result;
}
PUBLIC int wordlist_gen_utf8_lm(unsigned char* keys, uint32_t max_number, int thread_id)
{
	int result = max_number;

	memset(keys, 0, max_number*8);

	HS_ENTER_MUTEX(&key_provider_mutex);

	thread_params[thread_id] = wordlist_func.get_position();

	for(uint32_t i = 0; i < max_number; i++, keys += 8)
	{
		int line_lenght = wordlist_func.getline(current_key, max_lenght);
		// All keys generated
		if(line_lenght < 0)
		{
			result = i; break;
		}

		current_key_lenght = line_lenght;
		strncpy(keys, _strupr(current_key), max_lenght);
	}
	// Getting approximate key-space
	wordlist_func.calculate_completition();
	num_key_space = (int64_t)((get_num_keys_served() + result) * wordlist_completition);

	HS_LEAVE_MUTEX(&key_provider_mutex);
	return result;
}
PUBLIC int wordlist_gen_utf8(unsigned char* keys, uint32_t max_number, int thread_id)
{
	uint32_t i = 0;
	HS_ENTER_MUTEX(&key_provider_mutex);

	thread_params[thread_id] = wordlist_func.get_position();

	for(; i < max_number; i++, keys += MAX_KEY_LENGHT_SMALL)
		if(wordlist_func.getline(keys, max_lenght) < 0)// All keys generated
			break;

	// Getting approximate key-space
	wordlist_func.calculate_completition();
	num_key_space = (int64_t)((get_num_keys_served() + i) * wordlist_completition);

	HS_LEAVE_MUTEX(&key_provider_mutex);	
	return i;
}
PUBLIC int wordlist_gen_utf8_coalesc_le(uint32_t* nt_buffer, uint32_t max_number, int thread_id)
{
	uint32_t i = 0;
	int last_max_length = FALSE;
	HS_ENTER_MUTEX(&key_provider_mutex);

	thread_params[thread_id] = wordlist_func.get_position();

	for (; i < max_number; i++)
	{
		int line_lenght = wordlist_func.getline(current_key, max_lenght);
		// All keys generated
		if (line_lenght < 0)
			break;
		// Eliminate false "" keys
		if (line_lenght == 0 && last_max_length)
			i--;
		else// Copy key to nt_buffer
			convert_utf8_2_coalesc(current_key, nt_buffer + i, max_number, line_lenght);

		last_max_length = line_lenght == max_lenght;
	}

	// Getting approximate key-space
	wordlist_func.calculate_completition();
	num_key_space = (int64_t)((get_num_keys_served() + i) * wordlist_completition);

	HS_LEAVE_MUTEX(&key_provider_mutex);
	return i;
}

PUBLIC void wordlist_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght)
{
	// Get the wordlist filename
	sqlite3_stmt* _select_wordlists;
	sqlite3_prepare_v2(db, "SELECT Name FROM WordList WHERE ID=?;", -1, &_select_wordlists, NULL);
	sqlite3_bind_int(_select_wordlists, 1, atoi(provider_param));
	sqlite3_step(_select_wordlists);

	const char* filename = (const char*)sqlite3_column_text(_select_wordlists, 0);
	if (filename)
		sprintf(description, " [%.20s%s]", filename, strlen(filename) > 20 ? "..." : "");
	else
		description[0] = 0;

	sqlite3_finalize(_select_wordlists);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Sentence key-provider
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PUBLIC uint32_t* word_pos = NULL;
PUBLIC unsigned char* words = NULL;
PUBLIC uint32_t num_words = 0;
PRIVATE int current_sentence[MAX_KEY_LENGHT_SMALL];
PUBLIC uint32_t PHRASES_MAX_WORDS_READ = 410;

#define WORD_POS_MASK		0x07ffffff
#define GET_WORD_POS(x)		(word_pos[(x)] & WORD_POS_MASK)
#define GET_WORD_LEN(x)		(word_pos[(x)] >> 27)

PUBLIC void sentence_resume(int pmin_lenght, int pmax_lenght, char* params, const char* resume_arg, int format_index)
{
	wordlist_resume_common(pmin_lenght, pmin_lenght, params, NULL, "SELECT FileName FROM PhrasesWordList WHERE ID=?;");

	// Support only this max number of words
	PHRASES_MAX_WORDS_READ = __min(PHRASES_MAX_WORDS_READ, WORD_POS_MASK-1);

	// Calculate size
	int64_t num_word_pos_max = __max(10, __min(num_key_space, PHRASES_MAX_WORDS_READ));
	int64_t words_size_max = __max(270, __min(wordlist_lenght, PHRASES_MAX_WORDS_READ * 12));
	// Create the wordlist in memory
	word_pos = (uint32_t*)_aligned_malloc(num_word_pos_max*sizeof(uint32_t), 4096);
	unsigned char* last_word = words = (unsigned char*)_aligned_malloc(words_size_max, 4096);

	memset(current_sentence, 0, sizeof(current_sentence));
	// Resume
	if(resume_arg && strlen(resume_arg))
	{
		const char* resume_pos = resume_arg;
		PHRASES_MAX_WORDS_READ = atoi(resume_pos);
		resume_pos = strchr(resume_pos, ' ') + 1;
		
		for(current_key_lenght = 0; resume_pos-1; current_key_lenght++, resume_pos = strchr(resume_pos, ' ') + 1)
			current_sentence[current_key_lenght] = atoi(resume_pos);
	}

	int line_lenght = wordlist_func.getline(last_word, formats[format_index].max_plaintext_lenght);
	num_words = 0;

	// Read line by line
	while(line_lenght >= 0 && num_words < PHRASES_MAX_WORDS_READ && (last_word - words) < WORD_POS_MASK)
	{
		if(line_lenght)
		{
			word_pos[num_words] = ((uint32_t)(last_word - words)) | (((uint32_t)line_lenght) << 27);
			last_word += line_lenght + 1;
			num_words++;
			// Resize if overflow
			if((last_word - words + formats[format_index].max_plaintext_lenght) >= words_size_max)
			{
				words_size_max = (int64_t)(words_size_max*1.3);
				words = (unsigned char*)_aligned_realloc(words, words_size_max, 4096);
				last_word = words + GET_WORD_POS(num_words-1) + line_lenght + 1;
			}

			// Resize if overflow
			if(num_words >= num_word_pos_max)
			{
				num_word_pos_max = (int64_t)(num_words*1.3);
				word_pos = (uint32_t*)_aligned_realloc(word_pos, num_word_pos_max*sizeof(uint32_t), 4096);
			}
		}
		// Next line
		line_lenght = wordlist_func.getline(last_word, formats[format_index].max_plaintext_lenght);
	}

	key_providers[WORDLIST_INDEX].finish();

	current_key_lenght = __max(2, min_lenght);
	max_lenght = __max(current_key_lenght, max_lenght);

	// Calculate keyspace------------------------------------------------------
	num_key_space = 0;
	int64_t pow_num = 1;

	// Take into account resume attacks
	uint32_t i;
	for (i = 0; i < (current_key_lenght-1); i++, pow_num *= num_words)
		// Protects against integer overflow
		if (pow_num > 0x3FFFFFFFFFFFFFFF / num_words)
		{
			num_key_space = KEY_SPACE_UNKNOW;
			break;
		}
	if (num_key_space != KEY_SPACE_UNKNOW)
	{
		for (i = 0; i < current_key_lenght; i++, pow_num /= num_words)
			num_key_space -= current_sentence[i] * pow_num;

		pow_num = 1;
		for (i = 0; i < current_key_lenght; i++, pow_num *= num_words)
			// Protects against integer overflow
			if (pow_num > 0x3FFFFFFFFFFFFFFF / num_words)
			{
				num_key_space = KEY_SPACE_UNKNOW;
				break;
			}

		if (num_key_space != KEY_SPACE_UNKNOW)
			num_key_space += pow_num;
	}
	//--------------------------------------------------------------------------
}

PUBLIC int sentence_gen_ntlm(uint32_t* nt_buffer, uint32_t max_number, int thread_id)
{
	int* save_sentence = ((int*)thread_params) + 32*thread_id;
	unsigned char phrase[MAX_KEY_LENGHT_SMALL+4];
	int my_max_number = max_number;
	int current_sentence1[MAX_KEY_LENGHT_SMALL];
	uint32_t current_key_lenght1;

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
		save_sentence[31] = current_key_lenght;
		memcpy(save_sentence, current_sentence, current_key_lenght*sizeof(int));
		memcpy(current_sentence1, current_sentence, max_lenght*sizeof(int));

		// Sum
		uint32_t i = current_key_lenght - 1;
		while(my_max_number)
		{
			current_sentence[i] += my_max_number%num_words;
			my_max_number /= num_words;

			if ((uint32_t)current_sentence[i] >= num_words)
			{
				my_max_number++;
				current_sentence[i] -= num_words;
			}

			// Increase length
			if(my_max_number && --i >= current_key_lenght)
			{
				memmove(current_sentence+1, current_sentence, current_key_lenght*sizeof(int));
				current_sentence[0] = 0;
				current_key_lenght++;
				my_max_number--;
				i = 0;
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);

	memset(nt_buffer + max_number, 0, 13 * max_number * sizeof(uint32_t));
	// Optimized path
	if ((current_sentence1[current_key_lenght1 - 1] + max_number) < num_words)
	{
		unsigned char* key = phrase;
		uint32_t key_lenght = 0;

		// Create sentence
		for (uint32_t j = 0; j < (current_key_lenght1-1); j++)
		{
			uint32_t word_pos_j = GET_WORD_POS(current_sentence1[j]);
			uint32_t lenght_j = GET_WORD_LEN(current_sentence1[j]);

			key_lenght += lenght_j;

			// Copy only words that fit
			if (key_lenght <= 27)
			{
				// Copy word
				for (uint32_t k = 0; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
					((HS_COPY_REG*)key)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];

				key += lenght_j;
			}
			else
				key_lenght -= lenght_j;
		}

		// Convert to NTLM
		for (uint32_t j = 0; j < key_lenght / 2; j++)
		{
			uint32_t value = ((uint32_t)phrase[2 * j]) | ((uint32_t)phrase[2 * j + 1]) << 16;

			for (uint32_t i = j*max_number; i < (max_number + j*max_number); i++)
				nt_buffer[i] = value;
		}
		// The big cycle
		uint32_t last_word_index = current_sentence1[current_key_lenght1 - 1];
		for (uint32_t i = 0; i < max_number; i++, last_word_index++)
		{
			// Create sentence
			uint32_t word_pos_j = GET_WORD_POS(last_word_index);
			uint32_t lenght_j = GET_WORD_LEN(last_word_index);

			uint32_t key_lenght_final = key_lenght + lenght_j;

			// Copy only words that fit
			if (key_lenght_final <= 27)
			{
				// Copy word
				((HS_COPY_REG*)key)[0] = ((HS_COPY_REG*)(words + word_pos_j))[0];
				if (lenght_j > HS_COPY_SIZE)
					for (uint32_t k = 1; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
						((HS_COPY_REG*)key)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];
			}
			else
				key_lenght_final -= lenght_j;

			// Convert to NTLM
			uint32_t j;
			for (j = key_lenght / 2; j < key_lenght_final / 2; j++)
				nt_buffer[j*max_number + i] = ((uint32_t)phrase[2 * j]) | ((uint32_t)phrase[2 * j + 1]) << 16;
			// Last part
			nt_buffer[j*max_number + i] = (key_lenght_final & 1) ? ((uint32_t)phrase[2 * j]) | 0x800000 : 0x80;
			// Lenght
			nt_buffer[14 * max_number + i] = key_lenght_final << 4;
		}
	}
	else// General path
		for (uint32_t i = 0; i < max_number; i++)
		{
			unsigned char* key = phrase;
			uint32_t key_lenght = 0;

			// Create sentence
			for (uint32_t j = 0; j < current_key_lenght1; j++)
			{
				uint32_t word_pos_j = GET_WORD_POS(current_sentence1[j]);
				uint32_t lenght_j = GET_WORD_LEN(current_sentence1[j]);

				key_lenght += lenght_j;

				// Copy only words that fit
				if(key_lenght <= 27)
				{
					// Copy word
					for (uint32_t k = 0; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
						((HS_COPY_REG*)key)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];

					key += lenght_j;
				}
				else
					key_lenght -= lenght_j;
			}
			// Convert to NTLM
			uint32_t j;
			for (j = 0; j < key_lenght / 2; j++)
				nt_buffer[j*max_number + i] = ((uint32_t)phrase[2 * j]) | ((uint32_t)phrase[2 * j + 1]) << 16;
			// Last part
			nt_buffer[j*max_number + i] = (key_lenght & 1) ? ((uint32_t)phrase[2 * j]) | 0x800000 : 0x80;
			// Lenght
			nt_buffer[14 * max_number + i] = key_lenght << 4;

			// Next key
			j = current_key_lenght1 - 1;
			while(++current_sentence1[j] == num_words)
			{
				current_sentence1[j] = 0;

				if(--j >= current_key_lenght1)
				{
					current_key_lenght1++;
					if(current_key_lenght1 > max_lenght)
						return i;
					else
					{
						memmove(current_sentence1+1, current_sentence1, (current_key_lenght-1)*sizeof(int));
						current_sentence1[0] = 0;
					}
					break;
				}	
			}
		}

	return max_number;
}
PUBLIC int sentence_gen_utf8(unsigned char* keys, uint32_t max_number, int thread_id)
{
	int* save_sentence = ((int*)thread_params) + 32*thread_id;
	uint32_t current_key_lenght1;
	int my_max_number = max_number;
	int current_sentence1[MAX_KEY_LENGHT_SMALL];

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
		save_sentence[31] = current_key_lenght;
		memcpy(save_sentence, current_sentence, current_key_lenght*sizeof(int));
		memcpy(current_sentence1, current_sentence, max_lenght*sizeof(int));

		// Sum
		uint32_t i = current_key_lenght - 1;
		while(my_max_number)
		{
			current_sentence[i] += my_max_number%num_words;
			my_max_number /= num_words;

			if ((uint32_t)current_sentence[i] >= num_words)
			{
				my_max_number++;
				current_sentence[i] -= num_words;
			}

			// Increase length
			if(my_max_number && --i >= current_key_lenght)
			{
				memmove(current_sentence+1, current_sentence, current_key_lenght*sizeof(int));
				current_sentence[0] = 0;
				current_key_lenght++;
				my_max_number--;
				i = 0;
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);

	for (uint32_t i = 0; i < max_number; i++)
	{
		unsigned char* key_normal = keys + i*MAX_KEY_LENGHT_SMALL;
		uint32_t key_lenght_normal = 0;

		// Create sentence
		for (uint32_t j = 0; j < current_key_lenght1; j++)
		{
			uint32_t word_pos_j = GET_WORD_POS(current_sentence1[j]);
			uint32_t lenght_j   = GET_WORD_LEN(current_sentence1[j]);

			key_lenght_normal += lenght_j;

			// Copy only words that fit
			if(key_lenght_normal <= 27)
			{
				// Copy word
				for (uint32_t k = 0; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
					((HS_COPY_REG*)key_normal)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];

				key_normal += lenght_j;
			}
			else
				key_lenght_normal -= lenght_j;
		}
		
		// End
		keys[i*MAX_KEY_LENGHT_SMALL+key_lenght_normal] = 0;

		// Next key
		uint32_t j = current_key_lenght1 - 1;
		while(++current_sentence1[j] == num_words)
		{
			current_sentence1[j] = 0;

			if(--j >= current_key_lenght1)
			{
				current_key_lenght1++;
				if(current_key_lenght1 > max_lenght)
					return i;
				else
				{
					memmove(current_sentence1+1, current_sentence1, (current_key_lenght-1)*sizeof(int));
					current_sentence1[0] = 0;
				}
				break;
			}	
		}
	}

	return max_number;
}
PUBLIC int sentence_gen_utf8_coalesc_le(uint32_t* nt_buffer, uint32_t max_number, int thread_id)
{
	int* save_sentence = ((int*)thread_params) + 32 * thread_id;
	unsigned char phrase[MAX_KEY_LENGHT_BIG + 4];
	uint32_t current_key_lenght1;
	int my_max_number = max_number;
	int current_sentence1[MAX_KEY_LENGHT_SMALL];

	HS_ENTER_MUTEX(&key_provider_mutex);

	if (current_key_lenght > max_lenght)
	{
		HS_LEAVE_MUTEX(&key_provider_mutex);
		return 0;
	}
	else
	{
		// Copy all
		current_key_lenght1 = current_key_lenght;
		save_sentence[31] = current_key_lenght;
		memcpy(save_sentence, current_sentence, current_key_lenght*sizeof(int));
		memcpy(current_sentence1, current_sentence, max_lenght*sizeof(int));

		// Sum
		uint32_t i = current_key_lenght - 1;
		while (my_max_number)
		{
			current_sentence[i] += my_max_number%num_words;
			my_max_number /= num_words;

			if ((uint32_t)current_sentence[i] >= num_words)
			{
				my_max_number++;
				current_sentence[i] -= num_words;
			}

			// Increase length
			if (my_max_number && --i >= current_key_lenght)
			{
				memmove(current_sentence + 1, current_sentence, current_key_lenght*sizeof(int));
				current_sentence[0] = 0;
				current_key_lenght++;
				my_max_number--;
				i = 0;
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);

	memset(nt_buffer + max_number, 0, 6 * max_number*sizeof(uint32_t));
	// Optimized path
	if ((current_sentence1[current_key_lenght1 - 1] + max_number) < num_words)
	{
		unsigned char* key = phrase;
		uint32_t key_lenght = 0;

		// Create sentence
		for (uint32_t j = 0; j < (current_key_lenght1-1); j++)
		{
			uint32_t word_pos_j = GET_WORD_POS(current_sentence1[j]);
			uint32_t lenght_j = GET_WORD_LEN(current_sentence1[j]);

			key_lenght += lenght_j;

			// Copy only words that fit
			if (key_lenght <= 27)
			{
				// Copy word
				for (uint32_t k = 0; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
					((HS_COPY_REG*)key)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];

				key += lenght_j;
			}
			else
				key_lenght -= lenght_j;
		}

		// Copy key to UTF8 coalesc
		for (uint32_t j = 0; j < key_lenght / 4; j++)
		{
			uint32_t value = ((uint32_t*)phrase)[j];

			for (uint32_t i = 0; i < max_number; i++)
				nt_buffer[j*max_number + i] = value;
		}

		uint32_t last_word_index = current_sentence1[current_key_lenght1 - 1];
		for (uint32_t i = 0; i < max_number; i++, last_word_index++)
		{
			// Create sentence
			uint32_t word_pos_j = GET_WORD_POS(last_word_index);
			uint32_t lenght_j = GET_WORD_LEN(last_word_index);

			uint32_t key_lenght_final = key_lenght + lenght_j;

			// Copy only words that fit
			if (key_lenght_final <= 27)
			{
				// Copy word
				((HS_COPY_REG*)key)[0] = ((HS_COPY_REG*)(words + word_pos_j))[0];
				if (lenght_j > HS_COPY_SIZE)
					for (uint32_t k = 1; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
						((HS_COPY_REG*)key)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];
			}
			else
				key_lenght_final -= lenght_j;

			// Copy key to UTF8 coalesc
			for (uint32_t j = key_lenght / 4; j < key_lenght_final / 4; j++)
				nt_buffer[j*max_number + i] = ((uint32_t*)phrase)[j];

			nt_buffer[7 * max_number + i] = key_lenght_final << 3;// len
			uint32_t val;
			switch (key_lenght_final & 3)
			{
			case 0:
				val = 0x80;
				break;
			case 1:
				val = 0x8000;
				val |= ((uint32_t)phrase[4 * (key_lenght_final / 4) + 0]);
				break;
			case 2:
				val = 0x800000;
				val |= ((uint32_t)phrase[4 * (key_lenght_final / 4) + 0]);
				val |= ((uint32_t)phrase[4 * (key_lenght_final / 4) + 1]) << 8;
				break;
			case 3:
				val = 0x80000000;
				val |= ((uint32_t)phrase[4 * (key_lenght_final / 4) + 0]);
				val |= ((uint32_t)phrase[4 * (key_lenght_final / 4) + 1]) << 8;
				val |= ((uint32_t)phrase[4 * (key_lenght_final / 4) + 2]) << 16;
				break;
			}
			nt_buffer[(key_lenght_final / 4)*max_number + i] = val;
		}
	}
	else
		for (uint32_t i = 0; i < max_number; i++)
		{
			unsigned char* key = phrase;
			uint32_t key_lenght = 0;

			// Create sentence
			for (uint32_t j = 0; j < current_key_lenght1; j++)
			{
				uint32_t word_pos_j = GET_WORD_POS(current_sentence1[j]);
				uint32_t lenght_j = GET_WORD_LEN(current_sentence1[j]);

				key_lenght += lenght_j;

				// Copy only words that fit
				if (key_lenght <= 27)
				{
					// Copy word
					for (uint32_t k = 0; k < (lenght_j + (HS_COPY_SIZE - 1)) / HS_COPY_SIZE; k++)
						((HS_COPY_REG*)key)[k] = ((HS_COPY_REG*)(words + word_pos_j))[k];

					key += lenght_j;
				}
				else
					key_lenght -= lenght_j;
			}

			// Copy key to UTF8 coalesc
			for (uint32_t j = 0; j < key_lenght / 4; j++)
				nt_buffer[j*max_number + i] = ((uint32_t*)phrase)[j];

			uint32_t val = 0x80 << (8 * (key_lenght & 3));
			for (uint32_t k = 0; k < (key_lenght & 3); k++)
				val |= ((uint32_t)phrase[4 * (key_lenght / 4) + k]) << (8 * k);

			nt_buffer[(key_lenght / 4)*max_number+i] = val;
			nt_buffer[7 * max_number+i] = key_lenght << 3;// len

			// Next key
			uint32_t j = current_key_lenght1 - 1;
			while (++current_sentence1[j] == num_words)
			{
				current_sentence1[j] = 0;

				if (--j >= current_key_lenght1)
				{
					current_key_lenght1++;
					if (current_key_lenght1 > max_lenght)
						return i;
					else
					{
						memmove(current_sentence1 + 1, current_sentence1, (current_key_lenght - 1)*sizeof(int));
						current_sentence1[0] = 0;
					}
					break;
				}
			}
		}

	return max_number;
}
PUBLIC int sentence_gen_ocl(int* current_sentence1, uint32_t max_number, int thread_id)
{
	int* save_sentence = ((int*)thread_params) + 32*thread_id;

	HS_ENTER_MUTEX(&key_provider_mutex);

	if(current_key_lenght > max_lenght)
	{
		HS_LEAVE_MUTEX(&key_provider_mutex);
		return 0;
	}
	else
	{
		// Copy all
		current_sentence1[0] = max_number;
		current_sentence1[1] = current_key_lenght;
		save_sentence[31] = current_key_lenght;
		memcpy(current_sentence1+2, current_sentence, max_lenght*sizeof(int));
		memcpy(save_sentence, current_sentence, current_key_lenght*sizeof(int));

		// Sum
		uint32_t i = current_key_lenght - 1;
		while(max_number)
		{
			max_number += current_sentence[i];
			current_sentence[i] = max_number%num_words;
			max_number /= num_words;

			// Increase length
			if(max_number && --i >= current_key_lenght)
			{
				uint32_t pow = 1;
				uint32_t exceed_served = 0;
				for (i = current_key_lenght - 1; i < current_key_lenght; i--, pow*=num_words)
					exceed_served += current_sentence[i]*pow;

				exceed_served += (max_number-1)*pow;
				current_sentence1[0] -= exceed_served;
				// Support only one length in each call
				current_key_lenght++;
				memset(current_sentence, 0, current_key_lenght*sizeof(int));
				break;
			}
		}
	}

	HS_LEAVE_MUTEX(&key_provider_mutex);

	return 1;
}

PUBLIC void sentence_save_resume_arg(char* resume_arg)
{
	uint32_t save_key_lenght = UINT_MAX;
	uint32_t old_index = 0, i, j;
	int* buffer = (int*)thread_params;
	resume_arg[0] = 0;

	if (thread_params)
	{
		HS_ENTER_MUTEX(&key_provider_mutex);

		// Find the most old saved data
		for (i = 0; i < num_thread_params; i++)
		{
			uint32_t thread_key_lenght = buffer[32 * i + 31];
			if (thread_key_lenght < save_key_lenght)
			{
				save_key_lenght = thread_key_lenght;
				old_index = i;
			}
			if (thread_key_lenght == save_key_lenght)
			for (j = 0; j < thread_key_lenght; j++)
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

		if (save_key_lenght)
		{
			// Save current candidate
			sprintf(resume_arg, "%i", num_words);
			for (i = 0; i < save_key_lenght; i++)
				sprintf(resume_arg + strlen(resume_arg), " %i", buffer[32 * old_index + i]);
		}

		HS_LEAVE_MUTEX(&key_provider_mutex);
	}
}
PUBLIC void sentence_finish()
{
	_aligned_free(word_pos);
	_aligned_free(words);

	word_pos = NULL;
	words = NULL;
}
PUBLIC void sentence_get_description(const char* provider_param, char* description, int min_lenght, int max_lenght)
{
	// Get the wordlist filename
	const char* filename;
	sqlite3_stmt* _select_wordlists;
	sqlite3_prepare_v2(db, "SELECT Name FROM PhrasesWordList WHERE ID=?;", -1, &_select_wordlists, NULL);
	sqlite3_bind_int(_select_wordlists, 1, atoi(provider_param));
	sqlite3_step(_select_wordlists);
	filename = (const char*)sqlite3_column_text(_select_wordlists, 0);

	// If not executing
	if(!words) num_words = PHRASES_MAX_WORDS_READ;

	if(min_lenght == max_lenght)
		sprintf(description, " of %i words [%i from %.20s%s]", min_lenght, num_words, filename, strlen(filename) > 20 ? "...": "");
	else
		sprintf(description, " of %i-%i words [%i from %.20s%s]", min_lenght, max_lenght, num_words, filename, strlen(filename) > 20 ? "...": "");

	sqlite3_finalize(_select_wordlists);
}
