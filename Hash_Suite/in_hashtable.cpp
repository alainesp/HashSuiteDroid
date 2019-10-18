// This file is part of Hash Suite password cracker,
// Copyright (c) 2018 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "sqlite3.h"
#include <tuple>
#include <algorithm>
#include <vector>

extern "C" sqlite3_stmt* select_hash1;

constexpr uint32_t L_MAX = 7;
template<uint32_t NUM_ELEMS_BUCKET, typename T, typename HASHER> class CuckooBGLinear : private HASHER
{
private:
	T* data;
	uint16_t* cache;
	uint32_t num_buckets;
	uint32_t num_elems;
	static_assert(NUM_ELEMS_BUCKET >= 2 && NUM_ELEMS_BUCKET <= 4, "To use only 2 bits");

	/////////////////////////////////////////////////////////////////////
	// Utilities
	/////////////////////////////////////////////////////////////////////
	__forceinline uint64_t hash_elem(const T& elem) const noexcept
	{
		return HASHER::operator()(elem);
	}
	__forceinline uint64_t hash_elem(const uint32_t* bin) const noexcept
	{
		return uint64_t(bin[0]) | uint64_t(bin[1]) << 32;
	}
	__forceinline bool cmp_elems(const T& elem, const uint32_t* binary, uint32_t bin_size) const noexcept
	{
		if (elem.h0 != binary[0] || elem.h1 != binary[1])
			return false;

		if (bin_size <= 8)
			return true;

		sqlite3_reset(select_hash1);
		sqlite3_bind_int64(select_hash1, 1, elem.db_id);
		sqlite3_step(select_hash1);
		uint32_t* bin = (uint32_t*)sqlite3_column_blob(select_hash1, 0);
		return memcmp(binary + 2, bin + 2, bin_size - 8) == 0;
	}

	// Given a value "word", produces an integer in [0,p) without division.
	// The function is as fair as possible in the sense that if you iterate
	// through all possible values of "word", then you will generate all
	// possible outputs as uniformly as possible.
	static __forceinline uint32_t fastrange32(uint32_t word, uint32_t p)
	{
		return (uint32_t)(((uint64_t)word * (uint64_t)p) >> 32);
	}
	static __forceinline uint64_t fastrange64(uint64_t word, uint64_t p)
	{
#ifdef __SIZEOF_INT128__ // then we know we have a 128-bit int
		return (uint64_t)(((__uint128_t)word * (__uint128_t)p) >> 64);
#elif defined(_MSC_VER) && defined(_WIN64)
		// supported in Visual Studio 2005 and better
		return __umulh(word, p);
#else
		return word % p; // fallback
#endif // __SIZEOF_INT128__
	}

	/////////////////////////////////////////////////////////////////////
	// Cache coded utilities
	/////////////////////////////////////////////////////////////////////
	//
	// Unlucky  Bucket is   Element        
	// bucket   Reversed    Distance     Labels
	// -------  ----------  --------    -------- 
	//   |          |       |      |    |      |
	//   b7         b6      b5 b4 b3    b2 b1 b0
	// 0b00'000'000
	__forceinline uint32_t Get_Label(uint32_t pos) const noexcept
	{
		return cache[pos] & 0b00'000'111;
	}
	__forceinline uint32_t Get_Label(uint32_t pos, uint16_t* cache_ptr) const noexcept
	{
		return cache_ptr[pos] & 0b00'000'111;
	}
	__forceinline bool Is_Empty(uint32_t pos) const noexcept
	{
		return Get_Label(pos) == 0;
	}
	__forceinline bool Is_Empty(uint32_t pos, uint16_t* cache_ptr) const noexcept
	{
		return Get_Label(pos, cache_ptr) == 0;
	}
	__forceinline void Set_Empty(uint32_t pos) noexcept
	{
		cache[pos] &= 0b11'000'000;
	}
	__forceinline void Copy_Elem(uint32_t dest, uint32_t source) noexcept
	{
		cache[dest] = (cache[dest] & 0b11'000'000) | (cache[source] & 0xFF3F);
	}
	__forceinline void UpdateFlag(uint32_t pos, uint32_t distance_to_base, bool is_reverse) noexcept
	{
		cache[pos] = (cache[pos] & 0xFFC7) | (is_reverse ? 0b00'100'000 : 0) | (distance_to_base << 3);
	}
	__forceinline void UpdateFlag(uint32_t pos, uint32_t distance_to_base, bool is_reverse_item, uint32_t label, uint32_t hash) noexcept
	{
		cache[pos] = (hash & 0xFF00) | (cache[pos] & 0b11'000'000) | (is_reverse_item ? 0b00'100'000 : 0) | (distance_to_base << 3) | label;
	}
	__forceinline bool Is_Item_In_Reverse_Bucket(uint32_t pos) const noexcept
	{
		return cache[pos] & 0b00'100'000;
	}
	__forceinline uint32_t GetFlagDistance(uint32_t pos) const noexcept
	{
		return (cache[pos] >> 3) & 0b11;
	}
	__forceinline bool Is_Unlucky_Bucket(uint32_t pos) const noexcept
	{
		return cache[pos] & 0b10'000'000;
	}
	__forceinline void Set_Unlucky_Bucket(uint32_t pos) noexcept
	{
		cache[pos] |= 0b10'000'000;
	}
	__forceinline bool Is_Reversed_Window(uint32_t pos) const noexcept
	{
		return cache[pos] & 0b01'000'000;
	}
	__forceinline void Set_Reversed(uint32_t pos) noexcept
	{
		cache[pos] |= 0b01'000'000;
	}
	/////////////////////////////////////////////////////////////////////
	// Insertion algorithm utilities
	/////////////////////////////////////////////////////////////////////
	std::pair<uint32_t, uint32_t> Calculate_Minimum(uint32_t bucket_pos) const noexcept
	{
		uint32_t minimum = Get_Label(bucket_pos);
		uint32_t pos = bucket_pos;

		for (uint32_t i = 1; minimum && i < NUM_ELEMS_BUCKET; i++)
		{
			uint32_t label_value = Get_Label(bucket_pos + i);
			if (minimum > label_value)
			{
				minimum = label_value;
				pos = bucket_pos + i;
			}
		}

		return std::make_pair(minimum, pos);
	}
	__forceinline uint32_t Belong_to_Bucket(uint32_t elem_pos) const noexcept
	{
		if (Is_Empty(elem_pos))
			return UINT32_MAX;

		return elem_pos + (Is_Item_In_Reverse_Bucket(elem_pos) ? NUM_ELEMS_BUCKET - 1 : 0) - GetFlagDistance(elem_pos);
	}
	uint32_t Count_Empty(uint32_t pos) const noexcept
	{
		uint32_t count = Is_Empty(pos) ? 1 : 0;

		for (uint32_t i = 1; i < NUM_ELEMS_BUCKET; i++)
			if (Is_Empty(pos + i))
				count++;

		return count;
	}
	uint32_t Count_Elems_In_Bucket_Non_Reversed(uint32_t bucket_pos) const noexcept
	{
		uint32_t count = 0;
		if (!Is_Item_In_Reverse_Bucket(bucket_pos) && 0 == GetFlagDistance(bucket_pos))
			count = 1;

		for (uint32_t i = 1; i < NUM_ELEMS_BUCKET; i++)
		{
			uint32_t pos = bucket_pos + i;

			if (!Is_Item_In_Reverse_Bucket(pos) && i == GetFlagDistance(pos))
				count++;
		}

		return count;
	}
	void Reverse_Bucket(uint32_t bucket_pos) noexcept
	{
		Set_Reversed(bucket_pos);

		uint32_t j = NUM_ELEMS_BUCKET - 1;
		for (uint32_t i = 0; i < NUM_ELEMS_BUCKET; i++)
			if (Belong_to_Bucket(bucket_pos + i) == bucket_pos)// Elems belong to our bucket
			{
				for (; !Is_Empty(bucket_pos - j); j--)
				{
				}// Find empty space

				Copy_Elem(bucket_pos - j, bucket_pos + i);
				Set_Empty(bucket_pos + i);
				data[bucket_pos - j] = data[bucket_pos + i];
				UpdateFlag(bucket_pos - j, NUM_ELEMS_BUCKET - 1 - j, true);
			}
	}

	uint32_t Find_Empty_Pos_Hopscotch(uint32_t bucket_pos, uint32_t bucket_init) noexcept
	{
		uint32_t empty_pos = UINT32_MAX;

		//////////////////////////////////////////////////////////////////
		// Then try to reverse the bucket
		//////////////////////////////////////////////////////////////////
		if (!Is_Reversed_Window(bucket_pos) && bucket_pos >= NUM_ELEMS_BUCKET)
		{
			uint32_t count_empty = Count_Empty(bucket_pos + 1 - NUM_ELEMS_BUCKET);
			if (count_empty)
			{
				uint32_t count_elems = Count_Elems_In_Bucket_Non_Reversed(bucket_pos);

				if (Belong_to_Bucket(bucket_pos) == bucket_pos)
				{
					if (count_empty > 0)
						count_empty++;
				}

				// TODO: Check this when only one element
				if (count_empty > count_elems)
				{
					Reverse_Bucket(bucket_pos);

					uint32_t min1, pos1;
					bucket_init = bucket_pos + (Is_Reversed_Window(bucket_pos) ? (1 - NUM_ELEMS_BUCKET) : 0);
					std::tie(min1, pos1) = Calculate_Minimum(bucket_init);
					if (min1 == 0)
						return pos1;
				}
			}
		}

		//////////////////////////////////////////////////////////////////
		// Then try to reverse elems
		//////////////////////////////////////////////////////////////////
		if (bucket_init >= 2 * NUM_ELEMS_BUCKET)
			for (uint32_t i = 0; i < NUM_ELEMS_BUCKET; i++)
			{
				uint32_t pos_elem = bucket_init + i;
				if (!Is_Item_In_Reverse_Bucket(pos_elem))
				{
					uint32_t bucket_elem = pos_elem - GetFlagDistance(pos_elem);

					if (bucket_elem != bucket_pos)
					{
						uint32_t count_empty = Count_Empty(bucket_elem + 1 - NUM_ELEMS_BUCKET);
						if (count_empty)
						{
							uint32_t count_elems = Count_Elems_In_Bucket_Non_Reversed(bucket_elem);

							if (Belong_to_Bucket(bucket_elem) == bucket_elem)
							{
								if (count_empty > 0)
									count_empty++;
							}

							// TODO: Check this when only one element
							if (count_empty >= count_elems)
							{
								Reverse_Bucket(bucket_elem);

								uint32_t min1, pos1;
								//bucket_init = Calculate_Position_Paged(bucket_pos, (Is_Reversed_Window(bucket_pos) ? (1 - NUM_ELEMS_BUCKET) : 0));
								std::tie(min1, pos1) = Calculate_Minimum(bucket_init);
								if (min1 == 0)
									return pos1;

								break;
							}
						}
					}
				}
			}

		//////////////////////////////////////////////////////////////////
		// Then try to hopscotch for an empty space
		//////////////////////////////////////////////////////////////////
		uint32_t max_dist_to_move = NUM_ELEMS_BUCKET - 1;
		for (uint32_t i = 0; i <= max_dist_to_move /*&& i < CUCKOO_PAGE_SIZE*/; i++)
		{
			if (Is_Empty(bucket_init + i))
			{
				// Find element to move
				uint32_t pos_blank = bucket_init + i;
				while ((pos_blank - bucket_init) >= NUM_ELEMS_BUCKET)
				{
					uint32_t pos_swap = pos_blank + 1 - NUM_ELEMS_BUCKET;

					for (; (pos_blank - pos_swap) > (NUM_ELEMS_BUCKET - 1 - GetFlagDistance(pos_swap)); pos_swap++)
					{
					}// TODO: Use a list with the options to not recalculate again

					 // Swap elements
					data[pos_blank] = data[pos_swap];
					Copy_Elem(pos_blank, pos_swap);
					UpdateFlag(pos_blank, GetFlagDistance(pos_swap) + (pos_blank - pos_swap), Is_Item_In_Reverse_Bucket(pos_swap));

					pos_blank = pos_swap;
				}

				return pos_blank;
			}
			uint32_t current_max_move = i + NUM_ELEMS_BUCKET - 1 - GetFlagDistance(bucket_init + i);
			if (current_max_move > max_dist_to_move)
				max_dist_to_move = current_max_move;
		}

		return empty_pos;
	}
	void rehash(uint32_t new_num_buckets) noexcept
	{
		if (new_num_buckets <= num_buckets)
			return;

		std::vector<T> secondary_tmp;
		secondary_tmp.reserve(num_elems / 8);// reserve 12.5%
		bool need_rehash = true;

		while (need_rehash)
		{
			need_rehash = false;

			uint32_t old_num_buckets = num_buckets;
			num_buckets = new_num_buckets;
			new_num_buckets += std::max(1u, new_num_buckets / 128u);// add 0.8%

																	// Realloc data
			data = (T*)realloc(data, (num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(T));
			cache = (uint16_t*)realloc(cache, (num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(uint16_t));

			// Initialize cache
			if (old_num_buckets)
				memset(cache + old_num_buckets + NUM_ELEMS_BUCKET - 1, 0, (num_buckets - old_num_buckets) * sizeof(uint16_t));
			else
				memset(cache, 0, (num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(uint16_t));
			num_elems = 0;

			// Moves items from old end to new end
			for (uint32_t i = old_num_buckets + NUM_ELEMS_BUCKET - 2; i > 0; i--)
			{
				if (!Is_Empty(i))
				{
					uint64_t hash = hash_elem(data[i]);
					uint32_t bucket1_pos = fastrange32((uint32_t)hash, num_buckets);
					bool item_is_moved = false;

					// Try to insert primary
					if (bucket1_pos > i)
					{
						uint32_t min1, pos1;
						std::tie(min1, pos1) = Calculate_Minimum(bucket1_pos);
						if (min1 == 0)
						{
							UpdateFlag(pos1, pos1 - bucket1_pos, false, 1, (uint32_t)(hash >> 32));
							// Put elem
							data[pos1] = data[i];
							num_elems++;
							item_is_moved = true;
						}
					}

					// Not moved -> put in temporary list
					if (!item_is_moved)
						secondary_tmp.push_back(data[i]);
				}
				// Clean position
				cache[i] = 0;
			}

			// First element
			if (!Is_Empty(0))
				secondary_tmp.push_back(data[0]);
			cache[0] = 0;

			// Insert other elements
			while (!secondary_tmp.empty() && !need_rehash)
			{
				if (insert(secondary_tmp.back()))
					secondary_tmp.pop_back();
				else
					need_rehash = true;
			}
		}
	}
	uint32_t get_grow_factor() const noexcept
	{
		uint32_t new_num_buckets = num_buckets + std::max(1u, num_buckets / 16u);// grow the number of buckets (6.25%)
		if (new_num_buckets < num_buckets)
			new_num_buckets = UINT32_MAX - NUM_ELEMS_BUCKET + 1;

		return new_num_buckets;
	}
public:
	CuckooBGLinear() noexcept : data(nullptr), cache(nullptr), num_elems(0), num_buckets(0), HASHER()
	{}

	CuckooBGLinear(uint32_t expected_num_elems) noexcept : num_elems(0), num_buckets(expected_num_elems), HASHER()
	{
		data = (T*)malloc((num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(T));
		cache = (uint16_t*)malloc((num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(uint16_t));
		memset(cache, 0, (num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(uint16_t));
	}
	~CuckooBGLinear()
	{
		if (data) free(data);
		if (cache) free(cache);

		data = nullptr;
		cache = nullptr;
		num_elems = 0;
		num_buckets = 0;
	}
	uint32_t capacity() const noexcept
	{
		return num_buckets;
	}
	uint32_t size() const noexcept
	{
		return num_elems;
	}
	void clear() noexcept
	{
		num_elems = 0;
		memset(cache, 0, (num_buckets + NUM_ELEMS_BUCKET - 1) * sizeof(uint16_t));
	}

	void reserve(uint32_t new_capacity) noexcept
	{
		rehash(new_capacity);
	}

	void insert_grow(const T& to_insert_elem) noexcept
	{
		if (num_elems * 100ull >= 99ull * num_buckets)
			rehash(get_grow_factor());

		T elem = to_insert_elem;
		// TODO: break infinity cycle when -> num_buckets=UINT32_MAX
		while (!insert(elem))
			rehash(get_grow_factor());
	}
	bool insert(T& elem) noexcept
	{
		while (true)
		{
			uint64_t hash = hash_elem(elem);

			// Calculate positions given hash
			uint32_t bucket1_pos = fastrange32((uint32_t)hash, num_buckets);
			uint32_t bucket2_pos = fastrange32(hash >> 32, num_buckets);

			//_mm_prefetch((char*)(cache1 + bucket1_pos), _MM_HINT_T0);
			//_mm_prefetch((char*)(cache1 + bucket2_pos), _MM_HINT_T0);
			bool is_reversed_bucket1 = Is_Reversed_Window(bucket1_pos);
			bool is_reversed_bucket2 = Is_Reversed_Window(bucket2_pos);
			uint32_t bucket1_init = bucket1_pos + (is_reversed_bucket1 ? (1 - NUM_ELEMS_BUCKET) : 0);
			uint32_t bucket2_init = bucket2_pos + (is_reversed_bucket2 ? (1 - NUM_ELEMS_BUCKET) : 0);

			// Find minimun label
			uint32_t min1 = Get_Label(bucket1_init);
			uint32_t min2 = Get_Label(bucket2_init);
			uint32_t pos1 = bucket1_init;
			uint32_t pos2 = bucket2_init;
			for (uint32_t i = 1; i < NUM_ELEMS_BUCKET /*&& (min1 || min2)*/; i++)
			{
				uint32_t current_pos1 = bucket1_init + i;
				uint32_t current_pos2 = bucket2_init + i;
				uint32_t label_value1 = Get_Label(current_pos1);
				uint32_t label_value2 = Get_Label(current_pos2);
				if (min1 > label_value1)
				{
					min1 = label_value1;
					pos1 = current_pos1;
				}
				if (min2 > label_value2)
				{
					min2 = label_value2;
					pos2 = current_pos2;
				}
			}

			//////////////////////////////////////////////////////////////////
			// No secondary added, no unlucky bucket added
			//////////////////////////////////////////////////////////////////
			// First bucket had free space
			if (min1 == 0)
			{
				UpdateFlag(pos1, pos1 - bucket1_init, is_reversed_bucket1, std::min(min2 + 1, L_MAX), (uint32_t)(hash >> 32));
				// Put elem
				data[pos1] = elem;
				num_elems++;
				return true;
			}

			uint32_t empty_pos = Find_Empty_Pos_Hopscotch(bucket1_pos, bucket1_init);
			if (empty_pos != UINT32_MAX)
			{
				is_reversed_bucket1 = Is_Reversed_Window(bucket1_pos);
				bucket1_init = bucket1_pos + (is_reversed_bucket1 ? (1 - NUM_ELEMS_BUCKET) : 0);
				UpdateFlag(empty_pos, empty_pos - bucket1_init, is_reversed_bucket1, std::min(min2 + 1, L_MAX), (uint32_t)(hash >> 32));

				// Put elem
				data[empty_pos] = elem;
				num_elems++;
				return true;
			}

			///////////////////////////////////////////////////////////////////
			// Secondary added, Unlucky bucket added
			//////////////////////////////////////////////////////////////////
			if (min2 == 0)
			{
				Set_Unlucky_Bucket(bucket1_pos);
				UpdateFlag(pos2, pos2 - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX), (uint32_t)hash);
				// Put elem
				data[pos2] = elem;
				num_elems++;
				return true;
			}

			if (num_elems * 10 > 9 * num_buckets)// > 90%
			{
				empty_pos = Find_Empty_Pos_Hopscotch(bucket2_pos, bucket2_init);

				if (empty_pos != UINT32_MAX)
				{
					Set_Unlucky_Bucket(bucket1_pos);
					is_reversed_bucket2 = Is_Reversed_Window(bucket2_pos);
					bucket2_init = bucket2_pos + (is_reversed_bucket2 ? (1 - NUM_ELEMS_BUCKET) : 0);
					UpdateFlag(empty_pos, empty_pos - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX), (uint32_t)hash);

					// Put elem
					data[empty_pos] = elem;
					num_elems++;
					return true;
				}
			}

			// Terminating condition
			if (std::min(min1, min2) >= L_MAX)
				return false;

			if (min1 <= min2)// Selected pos in first bucket
			{
				UpdateFlag(pos1, pos1 - bucket1_init, is_reversed_bucket1, std::min(min2 + 1, L_MAX), (uint32_t)(hash >> 32));
				// Put elem
				T victim = data[pos1];
				data[pos1] = elem;
				elem = victim;
			}
			else
			{
				Set_Unlucky_Bucket(bucket1_pos);
				UpdateFlag(pos2, pos2 - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX), (uint32_t)hash);
				// Put elem
				T victim = data[pos2];
				data[pos2] = elem;
				elem = victim;
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////////
	// Check if an element exist
	///////////////////////////////////////////////////////////////////////////////
	T* find_hash(const void* bin, uint32_t bin_size) const noexcept
	{
		uint64_t hash = hash_elem((const uint32_t*)bin);

		// Check first bucket
		uint32_t pos = fastrange32((uint32_t)hash, num_buckets);

		uint16_t c0 = cache[pos];

		uint16_t h = uint16_t(hash >> 32);
		if (((c0 ^ h) & 0xFF00) == 0 && cmp_elems(data[pos], (uint32_t*)bin, bin_size) && (c0 & 0b111))
			return data+pos;

		uint32_t reverse_sum = /*Is_Reversed_Window(pos)*/c0 & 0b01'000'000 ? -1 : 1;

		uint16_t cc = cache[pos + reverse_sum];
		if (((cc ^ h) & 0xFF00) == 0 && cmp_elems(data[pos + reverse_sum], (uint32_t*)bin, bin_size) && (cc & 0b111))
			return data + (pos + reverse_sum);
		if (NUM_ELEMS_BUCKET > 2)
		{
			cc = cache[pos + 2 * reverse_sum];
			if (((cc ^ h) & 0xFF00) == 0 && cmp_elems(data[pos + 2 * reverse_sum], (uint32_t*)bin, bin_size) && (cc & 0b111))
				return data + (pos + 2*reverse_sum);
		}
		if (NUM_ELEMS_BUCKET > 3)
		{
			cc = cache[pos + 3 * reverse_sum];
			if (((cc ^ h) & 0xFF00) == 0 && cmp_elems(data[pos + 3 * reverse_sum], (uint32_t*)bin, bin_size) && (cc & 0b111))
				return data + (pos + 3*reverse_sum);
		}

		// Check second bucket
		if (c0 & 0b10'000'000)//Is_Unlucky_Bucket(pos)
		{
			pos = fastrange32(hash >> 32, num_buckets);

			cc = cache[pos];

			h = uint16_t(hash);
			if (((cc ^ h) & 0xFF00) == 0 && (cc & 0b111) && cmp_elems(data[pos], (uint32_t*)bin, bin_size))
				return data + pos;

			reverse_sum = /*Is_Reversed_Window(pos)*/cc & 0b01'000'000 ? -1 : 1;

			cc = cache[pos + reverse_sum];
			if (((cc ^ h) & 0xFF00) == 0 && (cc & 0b111) && cmp_elems(data[pos + reverse_sum], (uint32_t*)bin, bin_size))
				return data + (pos + reverse_sum);
			if (NUM_ELEMS_BUCKET > 2)
			{
				cc = cache[pos + 2 * reverse_sum];
				if (((cc ^ h) & 0xFF00) == 0 && (cc & 0b111) && cmp_elems(data[pos + 2 * reverse_sum], (uint32_t*)bin, bin_size))
					return data + (pos + 2*reverse_sum);
			}
			if (NUM_ELEMS_BUCKET > 3)
			{
				cc = cache[pos + 3 * reverse_sum];
				if (((cc ^ h) & 0xFF00) == 0 && (cc & 0b111) && cmp_elems(data[pos + 3 * reverse_sum], (uint32_t*)bin, bin_size))
					return data + (pos + 3*reverse_sum);
			}
		}

		return nullptr;
	}
};

struct HashCache
{
	uint32_t h0;
	uint32_t h1;
	uint32_t db_id;
};
struct HashCacheHasher
{
	__forceinline uint64_t operator()(const HashCache& elem) const noexcept
	{
		return uint64_t(elem.h0) | uint64_t(elem.h1) << 32;
	}
};

CuckooBGLinear<4, HashCache, HashCacheHasher> exist_hashes[MAX_NUM_FORMATS];
PRIVATE void load_hashes(int format_index)
{
	sqlite3_stmt* select_not_cracked;
	sqlite3_prepare_v2(db, "SELECT Bin,ID FROM Hash WHERE Type=?;", -1, &select_not_cracked, NULL);
	sqlite3_bind_int64(select_not_cracked, 1, formats[format_index].db_id);

	HashCache tmp;
	while (sqlite3_step(select_not_cracked) == SQLITE_ROW)
	{
		tmp.db_id = (uint32_t)sqlite3_column_int64(select_not_cracked, 1);

		// Load binary from database
		uint32_t* bin = (uint32_t*)sqlite3_column_blob(select_not_cracked, 0);
		tmp.h0 = bin[0];
		tmp.h1 = bin[1];

		// Insert elem
		exist_hashes[format_index].insert_grow(tmp);
	}

	sqlite3_finalize(select_not_cracked);
}
PUBLIC extern "C" uint32_t exist_hashes_find(int format_index, void* binary, uint32_t expected_num_hashes)
{
	// Not used
	if (exist_hashes[format_index].capacity() == 0)
	{
		uint32_t new_capacity = expected_num_hashes + num_hashes_by_formats1[format_index];
		new_capacity += new_capacity / 8;
		if (new_capacity < expected_num_hashes)
			new_capacity = UINT32_MAX - 3;
		exist_hashes[format_index].reserve(std::max(125u, new_capacity));
		load_hashes(format_index);
	}

	HashCache* data_ptr = exist_hashes[format_index].find_hash(binary, formats[format_index].binary_size + formats[format_index].salt_size);
	return data_ptr ? data_ptr->db_id : NO_ELEM;
}
PUBLIC extern "C" void exist_hashes_insert(int format_index, void* binary, uint32_t db_id)
{
	HashCache tmp;
	memcpy(&tmp, binary, 8);
	tmp.db_id = db_id;
	exist_hashes[format_index].insert_grow(tmp);
}
PUBLIC extern "C" void exist_hashes_release()
{
	for (int i = 0; i < num_formats; i++)
		exist_hashes[i].~CuckooBGLinear();
}