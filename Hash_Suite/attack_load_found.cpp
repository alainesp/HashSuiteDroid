// This file is part of Hash Suite password cracker,
// Copyright (c) 2020 by Alain Espinosa. See LICENSE.

#include "common.h"
#include <vector>
#include <algorithm>

extern "C" PUBLIC void load_foundhashes_from_db()
{
	// Initialize FAM
	resize_fam();
	for (uint32_t i = 0; i < (total_num_hashes() + 1); i++)
		save_fam(i, UINT32_MAX);

	// Load from DB
	sqlite3_stmt* foundHashesSTMT;
	sqlite3_prepare_v2(db, "SELECT PK,HashID FROM FindHash;", -1, &foundHashesSTMT, NULL);
	std::vector<std::pair<uint32_t, uint32_t>> founds;
	founds.reserve(total_num_hashes_found());

	while (sqlite3_step(foundHashesSTMT) == SQLITE_ROW)
	{
		uint32_t foundhash_id = (uint32_t)sqlite3_column_int64(foundHashesSTMT, 0);
		uint32_t hash_id = (uint32_t)sqlite3_column_int64(foundHashesSTMT, 1);
		founds.push_back(std::pair<uint32_t, uint32_t>(hash_id, foundhash_id));
	}
	sqlite3_finalize(foundHashesSTMT);

	// sort by hash_id
	std::sort(founds.begin(), founds.end());

	// Save to FAM
	for (auto found : founds)
		save_fam(found.first, found.second);
}