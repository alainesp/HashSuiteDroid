// This file is part of Hash Suite password cracker,
// Copyright (c) 2018 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "xxhash.h"
#include <tuple>
#include <vector>
#include <algorithm>

template<uint32_t STRING_SIZE> struct Elem
{
	//uint8_t cache;
	uint8_t str[STRING_SIZE];
	uint8_t counter[4];
};

template<uint32_t NUM_ELEMS_BUCKET, size_t STRING_SIZE> class CBG_Positive
{
private:
	uint8_t* data1;
	uint32_t* optimize_counters;
	uint32_t num_buckets;
	uint32_t num_elems;
	static constexpr uint32_t L_MAX = 7;
	static constexpr size_t SIZE_ELEM_SAVE = STRING_SIZE + 1 + sizeof(uint32_t);
	static_assert(NUM_ELEMS_BUCKET >= 2 && NUM_ELEMS_BUCKET <= 4, "To use only 2 bits");

	/////////////////////////////////////////////////////////////////////
	// Utilities
	/////////////////////////////////////////////////////////////////////
	__forceinline uint64_t hash_elem(const uint8_t* elem) const noexcept
	{
		return XXH64(elem, STRING_SIZE, 0);
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
		return data1[pos*SIZE_ELEM_SAVE] & 0b00'000'111;
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
		data1[pos*SIZE_ELEM_SAVE] &= 0b11'000'000;
	}
	__forceinline void Copy_Elem1(uint32_t dest, uint32_t source) noexcept
	{
		data1[dest*SIZE_ELEM_SAVE] = (data1[dest*SIZE_ELEM_SAVE] & 0b11'000'000) | (data1[source*SIZE_ELEM_SAVE] & 0x3F);
		memcpy(data1 + dest*SIZE_ELEM_SAVE + 1, data1 + source*SIZE_ELEM_SAVE + 1, SIZE_ELEM_SAVE - 1);
	}
	__forceinline void UpdateFlag(uint32_t pos, uint32_t distance_to_base, bool is_reverse) noexcept
	{
		data1[pos*SIZE_ELEM_SAVE] = (data1[pos*SIZE_ELEM_SAVE] & 0xFFC7) | (is_reverse ? 0b00'100'000 : 0) | (distance_to_base << 3);
	}
	__forceinline void UpdateFlag(uint32_t pos, uint32_t distance_to_base, bool is_reverse_item, uint32_t label) noexcept
	{
		data1[pos*SIZE_ELEM_SAVE] = (data1[pos*SIZE_ELEM_SAVE] & 0b11'000'000) | (is_reverse_item ? 0b00'100'000 : 0) | (distance_to_base << 3) | label;
	}
	__forceinline bool Is_Item_In_Reverse_Bucket(uint32_t pos) const noexcept
	{
		return data1[pos*SIZE_ELEM_SAVE] & 0b00'100'000;
	}
	__forceinline uint32_t GetFlagDistance(uint32_t pos) const noexcept
	{
		return (data1[pos*SIZE_ELEM_SAVE] >> 3) & 0b11;
	}
	__forceinline bool Is_Unlucky_Bucket(uint32_t pos) const noexcept
	{
		return data1[pos*SIZE_ELEM_SAVE] & 0b10'000'000;
	}
	__forceinline void Set_Unlucky_Bucket(uint32_t pos) noexcept
	{
		data1[pos*SIZE_ELEM_SAVE] |= 0b10'000'000;
	}
	__forceinline bool Is_Reversed_Window(uint32_t pos) const noexcept
	{
		return data1[pos*SIZE_ELEM_SAVE] & 0b01'000'000;
	}
	__forceinline void Set_Reversed(uint32_t pos) noexcept
	{
		data1[pos*SIZE_ELEM_SAVE] |= 0b01'000'000;
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

				Copy_Elem1(bucket_pos - j, bucket_pos + i);
				Set_Empty(bucket_pos + i);
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
					Copy_Elem1(pos_blank, pos_swap);
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

		std::vector<Elem<STRING_SIZE>> secondary_tmp;
		secondary_tmp.reserve(num_elems / 8);// reserve 12.5%
		bool need_rehash = true;

		while (need_rehash)
		{
			need_rehash = false;

			uint32_t old_num_buckets = num_buckets;
			num_buckets = new_num_buckets;
			new_num_buckets += std::max(1u, new_num_buckets / 128u);// add 0.8%

			// Realloc data
			data1 = (uint8_t*)realloc(data1, (num_buckets + NUM_ELEMS_BUCKET - 1) * SIZE_ELEM_SAVE);

			// Initialize cache
			if (old_num_buckets)
				memset(data1 + (old_num_buckets + NUM_ELEMS_BUCKET - 1) * SIZE_ELEM_SAVE, 0, (num_buckets - old_num_buckets) * SIZE_ELEM_SAVE);
			else
				memset(data1, 0, (num_buckets + NUM_ELEMS_BUCKET - 1) * SIZE_ELEM_SAVE);
			num_elems = 0;

			// Moves items from old end to new end
			Elem<STRING_SIZE> tmp;
			for (uint32_t i = old_num_buckets + NUM_ELEMS_BUCKET - 2; i > 0; i--)
			{
				if (!Is_Empty(i))
				{
					LoadElemFrom(i, &tmp);
					uint64_t hash = hash_elem(tmp.str);
					uint32_t bucket1_pos = fastrange32((uint32_t)hash, num_buckets);
					bool item_is_moved = false;

					// Try to insert primary
					if (bucket1_pos > i)
					{
						uint32_t min1, pos1;
						std::tie(min1, pos1) = Calculate_Minimum(bucket1_pos);
						if (min1 == 0)
						{
							UpdateFlag(pos1, pos1 - bucket1_pos, false, 1);
							// Put elem
							SaveElemTo(pos1, &tmp);
							num_elems++;
							item_is_moved = true;
						}
					}

					// Not moved -> put in temporary list
					if (!item_is_moved)
						secondary_tmp.push_back(tmp);
				}
				// Clean position
				data1[i*SIZE_ELEM_SAVE] = 0;
			}

			// First element
			if (!Is_Empty(0))
			{
				LoadElemFrom(0, &tmp);
				secondary_tmp.push_back(tmp);
			}
			data1[0] = 0;

			// Insert other elements
			while (!secondary_tmp.empty() && !need_rehash)
			{
				tmp = secondary_tmp.back();
				if (insert(&tmp))
					secondary_tmp.pop_back();
				else
				{
					secondary_tmp.pop_back();
					secondary_tmp.push_back(tmp);
					need_rehash = true;
				}
			}
		}
	}
	uint32_t get_grow_factor(uint32_t num_loaded, uint32_t num_founds) const noexcept
	{
		uint64_t new_num_buckets = ((uint64_t)num_elems) * ((uint64_t)num_founds) / std::max(1u, num_loaded);
		new_num_buckets = new_num_buckets + std::max(1ull, new_num_buckets / 8u);// grow the number of buckets (12.5%)

		uint64_t grow_normal = (uint64_t)num_buckets + (uint64_t)std::max(1u, num_buckets / 8u);// grow the number of buckets (12.5%)
		new_num_buckets = std::max(new_num_buckets, grow_normal);
		if (num_loaded < num_founds / 8u)// 12.5%
			new_num_buckets = std::min(new_num_buckets, std::max(num_elems * 3ull, grow_normal));

		return (uint32_t)std::min(0xffffffffull - NUM_ELEMS_BUCKET, new_num_buckets);
	}
	__forceinline void SaveElemTo(uint32_t pos, const Elem<STRING_SIZE>* elem) noexcept
	{
		memcpy(data1 + pos*SIZE_ELEM_SAVE + 1, elem, SIZE_ELEM_SAVE - 1);
	}
	__forceinline void LoadElemFrom(uint32_t pos, Elem<STRING_SIZE>* elem) const noexcept
	{
		memcpy(elem, data1 + pos*SIZE_ELEM_SAVE + 1, SIZE_ELEM_SAVE - 1);
	}
	__forceinline void IncrementCounter(uint32_t pos) noexcept
	{
		((uint32_t*)(data1 + pos*SIZE_ELEM_SAVE + STRING_SIZE + 1))[0]++;
	}
	__forceinline uint32_t GetCounter(uint32_t pos) const noexcept
	{
		return ((uint32_t*)(data1 + pos*SIZE_ELEM_SAVE + STRING_SIZE + 1))[0];
	}
public:
	CBG_Positive() noexcept : data1(nullptr), optimize_counters(nullptr), num_elems(0), num_buckets(0)
	{}

	CBG_Positive(uint32_t expected_num_elems) noexcept : num_elems(0), num_buckets(expected_num_elems)
	{
		data1 = (uint8_t*)malloc((num_buckets + NUM_ELEMS_BUCKET - 1) * SIZE_ELEM);
		memset(data1, 0, (num_buckets + NUM_ELEMS_BUCKET - 1) * SIZE_ELEM);
	}
	~CBG_Positive()
	{
		if (data1) free(data1);
		if (optimize_counters) free(optimize_counters);

		data1 = nullptr;
		optimize_counters = nullptr;
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
		memset(data1, 0, (num_buckets + NUM_ELEMS_BUCKET - 1) * SIZE_ELEM);
	}

	void reserve(uint32_t new_capacity) noexcept
	{
		rehash(new_capacity);
	}

	void insert_grow(const uint8_t* to_insert_elem, uint32_t num_loaded, uint32_t num_founds) noexcept
	{
		if (num_elems * 100ull >= 98ull * num_buckets)
			rehash(get_grow_factor(num_loaded, num_founds));

		Elem<STRING_SIZE> elem;
		memcpy(elem.str, to_insert_elem, STRING_SIZE);
		*((uint32_t*)elem.counter) = 1u;
		// TODO: break infinity cycle when -> num_buckets=UINT32_MAX
		while (!insert(&elem))
			rehash(get_grow_factor(num_loaded, num_founds));
	}
	bool insert(Elem<STRING_SIZE>* elem) noexcept
	{
		while (true)
		{
			uint64_t hash = hash_elem(elem->str);

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
				UpdateFlag(pos1, pos1 - bucket1_init, is_reversed_bucket1, std::min(min2 + 1, L_MAX));
				// Put elem
				SaveElemTo(pos1, elem);
				num_elems++;
				return true;
			}

			uint32_t empty_pos = Find_Empty_Pos_Hopscotch(bucket1_pos, bucket1_init);
			if (empty_pos != UINT32_MAX)
			{
				is_reversed_bucket1 = Is_Reversed_Window(bucket1_pos);
				bucket1_init = bucket1_pos + (is_reversed_bucket1 ? (1 - NUM_ELEMS_BUCKET) : 0);
				UpdateFlag(empty_pos, empty_pos - bucket1_init, is_reversed_bucket1, std::min(min2 + 1, L_MAX));

				// Put elem
				SaveElemTo(empty_pos, elem);
				num_elems++;
				return true;
			}

			///////////////////////////////////////////////////////////////////
			// Secondary added, Unlucky bucket added
			//////////////////////////////////////////////////////////////////
			if (min2 == 0)
			{
				Set_Unlucky_Bucket(bucket1_pos);
				UpdateFlag(pos2, pos2 - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX));
				// Put elem
				SaveElemTo(pos2, elem);
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
					UpdateFlag(empty_pos, empty_pos - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX));

					// Put elem
					SaveElemTo(empty_pos, elem);
					num_elems++;
					return true;
				}
			}

			// Terminating condition
			if (std::min(min1, min2) >= L_MAX)
				return false;

			if (min1 <= min2)// Selected pos in first bucket
			{
				UpdateFlag(pos1, pos1 - bucket1_init, is_reversed_bucket1, std::min(min2 + 1, L_MAX));
				// Put elem
				Elem<STRING_SIZE> victim;
				LoadElemFrom(pos1, &victim);
				SaveElemTo(pos1, elem);
				*elem = victim;
			}
			else
			{
				Set_Unlucky_Bucket(bucket1_pos);
				UpdateFlag(pos2, pos2 - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX));
				// Put elem
				Elem<STRING_SIZE> victim;
				LoadElemFrom(pos2, &victim);
				SaveElemTo(pos2, elem);
				*elem = victim;
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////////
	// Check if an element exist
	///////////////////////////////////////////////////////////////////////////////
	void count(const uint8_t* elem1, uint32_t num_loaded, uint32_t num_founds) noexcept
	{
		if (!num_buckets)
		{
			reserve(128);
			insert_grow(elem1, num_loaded, num_founds);
			return;
		}

		uint64_t hash = hash_elem(elem1);

		// Check first bucket
		uint32_t pos = fastrange32((uint32_t)hash, num_buckets);

		uint8_t c0 = data1[pos*SIZE_ELEM_SAVE];

		if (!memcmp(data1 + pos*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (c0 & 0b111))
		{
			IncrementCounter(pos);
			return;
		}

		uint32_t reverse_sum = /*Is_Reversed_Window(pos)*/c0 & 0b01'000'000 ? -1 : 1;

		if (!memcmp(data1 + (pos + reverse_sum)*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (data1[(pos + reverse_sum)*SIZE_ELEM_SAVE] & 0b111))
		{
			IncrementCounter(pos+ reverse_sum);
			return;
		}
		if (NUM_ELEMS_BUCKET > 2)
		{
			if (!memcmp(data1 + (pos + 2 * reverse_sum)*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (data1[(pos + 2 * reverse_sum)*SIZE_ELEM_SAVE] & 0b111))
			{
				IncrementCounter(pos + 2 * reverse_sum);
				return;
			}
		}
		if (NUM_ELEMS_BUCKET > 3)
		{
			if (!memcmp(data1 + (pos + 3 * reverse_sum)*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (data1[(pos + 3 * reverse_sum)*SIZE_ELEM_SAVE] & 0b111))
			{
				IncrementCounter(pos + 3 * reverse_sum);
				return;
			}
		}

		// Check second bucket
		if (c0 & 0b10'000'000)//Is_Unlucky_Bucket(pos)
		{
			pos = fastrange32(hash >> 32, num_buckets);

			c0 = data1[pos*SIZE_ELEM_SAVE];

			if (!memcmp(data1 + pos*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (c0 & 0b111))
			{
				IncrementCounter(pos);
				return;
			}

			reverse_sum = /*Is_Reversed_Window(pos)*/c0 & 0b01'000'000 ? -1 : 1;

			if (!memcmp(data1 + (pos + reverse_sum)*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (data1[(pos + reverse_sum)*SIZE_ELEM_SAVE] & 0b111))
			{
				IncrementCounter(pos + reverse_sum);
				return;
			}
			if (NUM_ELEMS_BUCKET > 2)
			{
				if (!memcmp(data1 + (pos + 2 * reverse_sum)*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (data1[(pos + 2 * reverse_sum)*SIZE_ELEM_SAVE] & 0b111))
				{
					IncrementCounter(pos + 2*reverse_sum);
					return;
				}
			}
			if (NUM_ELEMS_BUCKET > 3)
			{
				if (!memcmp(data1 + (pos + 3 * reverse_sum)*SIZE_ELEM_SAVE + 1, elem1, STRING_SIZE) && (data1[(pos + 3 * reverse_sum)*SIZE_ELEM_SAVE] & 0b111))
				{
					IncrementCounter(pos + 3*reverse_sum);
					return;
				}
			}
		}

		insert_grow(elem1, num_loaded, num_founds);
	}

	uint32_t GetMaxCount() const noexcept
	{
		uint32_t max_count = 0;

		for (uint32_t i = 0; i < num_elems; i++)
		{
			uint32_t counter = optimize_counters[i];
			if (max_count < counter)
				max_count = counter;
		}

		return max_count;
	}
	uint32_t CountCount(uint32_t* count_parts_by_count) const noexcept
	{
		for (uint32_t i = 0; i < num_elems; i++)
				count_parts_by_count[optimize_counters[i]]++;

		return num_elems;
	}
	void SortFP(uint32_t* count_parts_by_count, uint32_t* sorted_parts_pos, uint8_t* sorted_parts_size) const noexcept
	{
		for (uint32_t i = 0; i < num_elems; i++)
		{
			uint32_t part_count = optimize_counters[i];
			uint32_t sorted_position = count_parts_by_count[part_count];
			count_parts_by_count[part_count]++;

			sorted_parts_pos[sorted_position] = i;
			sorted_parts_size[sorted_position] = STRING_SIZE;
		}
	}
	void copy(uint8_t* key, uint32_t pos) const noexcept
	{
		memcpy(key, data1 + pos*STRING_SIZE, STRING_SIZE);
	}

	void OptimizeMemoryUse()
	{
		num_elems = 0;
		// Count valid elems
		if (num_buckets)
			for (uint32_t i = 0; i < (num_buckets + NUM_ELEMS_BUCKET - 1); i++)
				if (!Is_Empty(i) && GetCounter(i) > 1)
					num_elems++;

		// Create data
		optimize_counters = (uint32_t*)malloc(num_elems * sizeof(uint32_t));
		uint8_t* new_data = (uint8_t*)malloc(num_elems * STRING_SIZE);

		// Fill data
		num_elems = 0;
		if (num_buckets)
			for (uint32_t i = 0; i < (num_buckets + NUM_ELEMS_BUCKET - 1); i++)
				if (!Is_Empty(i) && GetCounter(i) > 1)
				{
					optimize_counters[num_elems] = GetCounter(i);
					memcpy(new_data + num_elems*STRING_SIZE, data1 + i*SIZE_ELEM_SAVE + 1, STRING_SIZE);
					num_elems++;
				}

		free(data1);
		data1 = new_data;
	}
};

class FingerprintHelper
{
private:
	static constexpr int MAX_STRING_SIZE = 28;
	uint32_t t01[256];
	uint32_t t02[256*256];
	CBG_Positive<4,  3> t03;
	CBG_Positive<4,  4> t04;
	CBG_Positive<4,  5> t05;
	CBG_Positive<4,  6> t06;
	CBG_Positive<4,  7> t07;
	CBG_Positive<4,  8> t08;
	CBG_Positive<4,  9> t09;
	CBG_Positive<4, 10> t10;
	CBG_Positive<4, 11> t11;
	CBG_Positive<4, 12> t12;
	CBG_Positive<4, 13> t13;
	CBG_Positive<4, 14> t14;
	CBG_Positive<4, 15> t15;
	CBG_Positive<4, 16> t16;
	CBG_Positive<4, 17> t17;
	CBG_Positive<4, 18> t18;
	CBG_Positive<4, 19> t19;
	CBG_Positive<4, 20> t20;
	CBG_Positive<4, 21> t21;
	CBG_Positive<4, 22> t22;
	CBG_Positive<4, 23> t23;
	CBG_Positive<4, 24> t24;
	CBG_Positive<4, 25> t25;
	CBG_Positive<4, 26> t26;
	CBG_Positive<4, 27> t27;
	
public:
	FingerprintHelper() noexcept
	{
		memset(t01, 0, sizeof(t01));
		memset(t02, 0, sizeof(t02));
	}

	void add_key(const uint8_t* key, uint32_t len, uint32_t num_loaded, uint32_t num_founds) noexcept
	{
		switch (len)
		{
		case  1: t01[*key]++; break;
		case  2: t02[(((uint32_t)key[0]) << 8) | key[1]]++; break;
		case  3: t03.count(key, num_loaded, num_founds); break;
		case  4: t04.count(key, num_loaded, num_founds); break;
		case  5: t05.count(key, num_loaded, num_founds); break;
		case  6: t06.count(key, num_loaded, num_founds); break;
		case  7: t07.count(key, num_loaded, num_founds); break;
		case  8: t08.count(key, num_loaded, num_founds); break;
		case  9: t09.count(key, num_loaded, num_founds); break;
		case 10: t10.count(key, num_loaded, num_founds); break;
		case 11: t11.count(key, num_loaded, num_founds); break;
		case 12: t12.count(key, num_loaded, num_founds); break;
		case 13: t13.count(key, num_loaded, num_founds); break;
		case 14: t14.count(key, num_loaded, num_founds); break;
		case 15: t15.count(key, num_loaded, num_founds); break;
		case 16: t16.count(key, num_loaded, num_founds); break;
		case 17: t17.count(key, num_loaded, num_founds); break;
		case 18: t18.count(key, num_loaded, num_founds); break;
		case 19: t19.count(key, num_loaded, num_founds); break;
		case 20: t20.count(key, num_loaded, num_founds); break;
		case 21: t21.count(key, num_loaded, num_founds); break;
		case 22: t22.count(key, num_loaded, num_founds); break;
		case 23: t23.count(key, num_loaded, num_founds); break;
		case 24: t24.count(key, num_loaded, num_founds); break;
		case 25: t25.count(key, num_loaded, num_founds); break;
		case 26: t26.count(key, num_loaded, num_founds); break;
		case 27: t27.count(key, num_loaded, num_founds); break;
		
		default:
			break;
		}
	}
	uint32_t GetMaxCount() const noexcept
	{
		uint32_t max_count = 0;
		for (uint32_t i = 0; i < 256; i++)
			if (t01[i] > max_count)
				max_count = t01[i];

		for (uint32_t i = 0; i < 256*256; i++)
			if (t02[i] > max_count)
				max_count = t02[i];

		max_count = std::max(max_count, t03.GetMaxCount());
		max_count = std::max(max_count, t04.GetMaxCount());
		max_count = std::max(max_count, t05.GetMaxCount());
		max_count = std::max(max_count, t06.GetMaxCount());
		max_count = std::max(max_count, t07.GetMaxCount());
		max_count = std::max(max_count, t08.GetMaxCount());
		max_count = std::max(max_count, t09.GetMaxCount());
		max_count = std::max(max_count, t10.GetMaxCount());
		max_count = std::max(max_count, t11.GetMaxCount());
		max_count = std::max(max_count, t12.GetMaxCount());
		max_count = std::max(max_count, t13.GetMaxCount());
		max_count = std::max(max_count, t14.GetMaxCount());
		max_count = std::max(max_count, t15.GetMaxCount());
		max_count = std::max(max_count, t16.GetMaxCount());
		max_count = std::max(max_count, t17.GetMaxCount());
		max_count = std::max(max_count, t18.GetMaxCount());
		max_count = std::max(max_count, t19.GetMaxCount());
		max_count = std::max(max_count, t20.GetMaxCount());
		max_count = std::max(max_count, t21.GetMaxCount());
		max_count = std::max(max_count, t22.GetMaxCount());
		max_count = std::max(max_count, t23.GetMaxCount());
		max_count = std::max(max_count, t24.GetMaxCount());
		max_count = std::max(max_count, t25.GetMaxCount());
		max_count = std::max(max_count, t26.GetMaxCount());
		max_count = std::max(max_count, t27.GetMaxCount());

		return max_count;
	}
	uint32_t CountCount(uint32_t* count_parts_by_count) const noexcept
	{
		uint32_t num_elems = 0;

		for (uint32_t i = 0; i < 256; i++)
			if (t01[i])
			{
				num_elems++;
				count_parts_by_count[t01[i]]++;
			}
		for (uint32_t i = 0; i < 256*256; i++)
			if (t02[i])
			{
				num_elems++;
				count_parts_by_count[t02[i]]++;
			}

		num_elems += t03.CountCount(count_parts_by_count);
		num_elems += t04.CountCount(count_parts_by_count);
		num_elems += t05.CountCount(count_parts_by_count);
		num_elems += t06.CountCount(count_parts_by_count);
		num_elems += t07.CountCount(count_parts_by_count);
		num_elems += t08.CountCount(count_parts_by_count);
		num_elems += t09.CountCount(count_parts_by_count);
		num_elems += t10.CountCount(count_parts_by_count);
		num_elems += t11.CountCount(count_parts_by_count);
		num_elems += t12.CountCount(count_parts_by_count);
		num_elems += t13.CountCount(count_parts_by_count);
		num_elems += t14.CountCount(count_parts_by_count);
		num_elems += t15.CountCount(count_parts_by_count);
		num_elems += t16.CountCount(count_parts_by_count);
		num_elems += t17.CountCount(count_parts_by_count);
		num_elems += t18.CountCount(count_parts_by_count);
		num_elems += t19.CountCount(count_parts_by_count);
		num_elems += t20.CountCount(count_parts_by_count);
		num_elems += t21.CountCount(count_parts_by_count);
		num_elems += t22.CountCount(count_parts_by_count);
		num_elems += t23.CountCount(count_parts_by_count);
		num_elems += t24.CountCount(count_parts_by_count);
		num_elems += t25.CountCount(count_parts_by_count);
		num_elems += t26.CountCount(count_parts_by_count);
		num_elems += t27.CountCount(count_parts_by_count);

		return num_elems;
	}
	void SortFP(uint32_t* count_parts_by_count, uint32_t* sorted_parts_pos, uint8_t* sorted_parts_size) const noexcept
	{
		for (uint32_t i = 0; i < 256; i++)
			if (t01[i])
			{
				uint32_t part_count = t01[i];
				uint32_t sorted_position = count_parts_by_count[part_count];
				count_parts_by_count[part_count]++;

				sorted_parts_pos[sorted_position] = i;
				sorted_parts_size[sorted_position] = 1;
			}
		for (uint32_t i = 0; i < 256*256; i++)
			if (t02[i])
			{
				uint32_t part_count = t02[i];
				uint32_t sorted_position = count_parts_by_count[part_count];
				count_parts_by_count[part_count]++;

				sorted_parts_pos[sorted_position] = i;
				sorted_parts_size[sorted_position] = 2;
			}

		t03.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t04.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t05.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t06.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t07.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t08.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t09.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t10.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t11.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t12.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t13.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t14.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t15.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t16.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t17.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t18.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t19.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t20.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t21.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t22.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t23.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t24.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t25.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t26.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
		t27.SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
	}
	void CopyStringFP(uint8_t* key, uint32_t pos, uint8_t size) const noexcept
	{
		switch (size)
		{
		case  1: key[0] = (uint8_t)pos; break;
		case  2: key[0] = (uint8_t)(pos >> 8); key[1] = (uint8_t)pos; break;
		case  3: t03.copy(key, pos); break;
		case  4: t04.copy(key, pos); break;
		case  5: t05.copy(key, pos); break;
		case  6: t06.copy(key, pos); break;
		case  7: t07.copy(key, pos); break;
		case  8: t08.copy(key, pos); break;
		case  9: t09.copy(key, pos); break;
		case 10: t10.copy(key, pos); break;
		case 11: t11.copy(key, pos); break;
		case 12: t12.copy(key, pos); break;
		case 13: t13.copy(key, pos); break;
		case 14: t14.copy(key, pos); break;
		case 15: t15.copy(key, pos); break;
		case 16: t16.copy(key, pos); break;
		case 17: t17.copy(key, pos); break;
		case 18: t18.copy(key, pos); break;
		case 19: t19.copy(key, pos); break;
		case 20: t20.copy(key, pos); break;
		case 21: t21.copy(key, pos); break;
		case 22: t22.copy(key, pos); break;
		case 23: t23.copy(key, pos); break;
		case 24: t24.copy(key, pos); break;
		case 25: t25.copy(key, pos); break;
		case 26: t26.copy(key, pos); break;
		case 27: t27.copy(key, pos); break;

		default:
			break;
		}

		key[size] = 0;
	}

	void OptimizeMemoryUse(uint32_t len)
	{
		switch (len)
		{
		case  1: case  2: break;

		case  3: t03.OptimizeMemoryUse(); break;
		case  4: t04.OptimizeMemoryUse(); break;
		case  5: t05.OptimizeMemoryUse(); break;
		case  6: t06.OptimizeMemoryUse(); break;
		case  7: t07.OptimizeMemoryUse(); break;
		case  8: t08.OptimizeMemoryUse(); break;
		case  9: t09.OptimizeMemoryUse(); break;
		case 10: t10.OptimizeMemoryUse(); break;
		case 11: t11.OptimizeMemoryUse(); break;
		case 12: t12.OptimizeMemoryUse(); break;
		case 13: t13.OptimizeMemoryUse(); break;
		case 14: t14.OptimizeMemoryUse(); break;
		case 15: t15.OptimizeMemoryUse(); break;
		case 16: t16.OptimizeMemoryUse(); break;
		case 17: t17.OptimizeMemoryUse(); break;
		case 18: t18.OptimizeMemoryUse(); break;
		case 19: t19.OptimizeMemoryUse(); break;
		case 20: t20.OptimizeMemoryUse(); break;
		case 21: t21.OptimizeMemoryUse(); break;
		case 22: t22.OptimizeMemoryUse(); break;
		case 23: t23.OptimizeMemoryUse(); break;
		case 24: t24.OptimizeMemoryUse(); break;
		case 25: t25.OptimizeMemoryUse(); break;
		case 26: t26.OptimizeMemoryUse(); break;
		case 27: t27.OptimizeMemoryUse(); break;

		default:
			break;
		}
	}
};

//#define LOAD_FROM_WORLIST
#include <memory>
PUBLIC void generate_fingerprint_words(HASH_TABLE_FINGERPRINT* fp)
{
	fp->status = FINGERPRINT_STATUS_LOADING_DATA;

#ifdef LOAD_FROM_WORLIST
	FILE* fwordlist = fopen("E:\\found_2017.txt", "rb");
	uint32_t num_founds = 2'956'633'347u;
	uint8_t cleartext[29];
#else
	sqlite3_stmt* found_passwords;
	sqlite3_prepare_v2(db, "SELECT ClearText FROM FindHash;", -1, &found_passwords, NULL);
	// Find the number of found passwords
	uint32_t num_founds = total_num_hashes_found();
#endif

	// Init
	fp->percent = 0;
	fp->num_parts = 0;
	auto fp_data = std::make_unique<FingerprintHelper>();

	uint32_t num_loaded = 0;
#ifdef LOAD_FROM_WORLIST
	for (uint32_t num_char = 1; num_char <= 27; num_char++)
	{
		fseek(fwordlist, 0, SEEK_SET);
		num_loaded = 0;

		while (fp->status == FINGERPRINT_STATUS_LOADING_DATA && fgets((char*)cleartext, sizeof(cleartext), fwordlist))
		{
			cleartext[28] = 0;
			uint32_t len = (uint32_t)strlen((const char*)cleartext);
			if (len < 2) continue;
			len -= 1;
			cleartext[len] = 0;

			if(len >= num_char)
				for (uint32_t i = 0; i < (len - num_char + 1); i++)
					fp_data->add_key(cleartext + i, num_char, num_loaded, num_founds);

			num_loaded += len + 1;
			fp->percent = (((num_char-1ull)*num_founds + num_loaded) * 100ull) / num_founds / 27ull;
		}
		fp_data->OptimizeMemoryUse(num_char);
	}
	fclose(fwordlist);
#else
	while (fp->status == FINGERPRINT_STATUS_LOADING_DATA && sqlite3_step(found_passwords) == SQLITE_ROW)
	{
		const unsigned char* cleartext = sqlite3_column_text(found_passwords, 0);
		uint32_t len = (uint32_t)strlen((const char*)cleartext);

		for (uint32_t num_char = 1; num_char <= len; num_char++)
			for (uint32_t i = 0; i < (len - num_char + 1); i++)
				fp_data->add_key(cleartext + i, num_char, num_loaded, num_founds);

		num_loaded++;
		fp->percent = num_loaded * 100ull / num_founds;
	}
	sqlite3_finalize(found_passwords);

	for (uint32_t num_char = 1; num_char <= 27; num_char++)
		fp_data->OptimizeMemoryUse(num_char);
#endif

	fp->status = FINGERPRINT_STATUS_COUNTING;

	// Sort parts by count using Counting Sort-----------------------------
	uint32_t max_count = fp_data->GetMaxCount();
	uint32_t* count_parts_by_count = (uint32_t*)calloc(max_count + 1, sizeof(uint32_t));
	// Count
	fp->num_parts = fp_data->CountCount(count_parts_by_count);

	// Organized the positions by count
	uint32_t position = 0;
	for (uint32_t i = max_count; i > 0; i--)
	{
		uint32_t count = count_parts_by_count[i];
		count_parts_by_count[i] = position;
		position += count;
	}

	fp->status = FINGERPRINT_STATUS_SORTING;
	// Now perform the actual sort coping the strings
	uint32_t* sorted_parts_pos = (uint32_t*)malloc(sizeof(uint32_t) * fp->num_parts);
	uint8_t* sorted_parts_size = (uint8_t*)malloc(fp->num_parts);
	fp_data->SortFP(count_parts_by_count, sorted_parts_pos, sorted_parts_size);
	// Release other fp data
	free(count_parts_by_count);

	fp->status = FINGERPRINT_STATUS_SAVING_DATA;
	// Save to file------------------------------------
	FILE* file = fopen(fp->out_file, "wb");
	unsigned char part_tmp[MAX_KEY_LENGHT_SMALL];
	fp->file_size = 0;
	for (uint32_t i = 0; i < fp->num_parts; i++)
	{
		fp_data->CopyStringFP(part_tmp, sorted_parts_pos[i], sorted_parts_size[i]);
		fp->file_size += sorted_parts_size[i] + 1;
		fprintf(file, "%s\n", part_tmp);

		fp->percent = (uint32_t)(i * 100ull / fp->num_parts);
	}

	free(sorted_parts_pos);
	free(sorted_parts_size);

	// Generate something in any case
	if (fp->num_parts < 2)
	{
		fprintf(file, "no\npassword\nfound\n");
	}

	fclose(file);

	fp->status = FINGERPRINT_STATUS_END;
}