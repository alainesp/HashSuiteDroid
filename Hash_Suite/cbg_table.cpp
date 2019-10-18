// This file is part of Hash Suite password cracker,
// Copyright (c) 2018 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"
#include <tuple>
#include <algorithm>
#undef min
#undef max

#ifdef _WIN32
PRIVATE void* large_page_alloc(size_t size)
{
	void* ptr = NULL;

	// Check if large page is needed
	if (current_system_info.is_large_page_enable && size >= current_system_info.large_page_size)
		ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);

	// Normal allocation
	if (ptr == NULL)
		ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	return ptr;
}
PUBLIC extern "C" void large_page_free(void* ptr)
{
	if (ptr)
		VirtualFree(ptr, 0, MEM_RELEASE);
}
#else
// TODO: Implement this
PRIVATE void* large_page_alloc(size_t size)
{
	return _aligned_malloc(size, 64);
}
PUBLIC extern "C" void large_page_free(void* ptr)
{
	if(ptr)
		_aligned_free(ptr);
}
#endif

constexpr uint32_t L_MAX = 7;
template<size_t NUM_ELEMS_BUCKET, typename T> class CuckooBGLinear
{
private:
	T* data1;
	uint16_t* cache1;
	uint32_t buckets_mask;
	size_t num_elems;
	static_assert(NUM_ELEMS_BUCKET >= 2 && NUM_ELEMS_BUCKET <= 4, "To use only 2 bits");

	uint32_t size_elem;
	uint32_t hash_pos0;
	uint32_t hash_pos1;

	/////////////////////////////////////////////////////////////////////
	// Utilities
	/////////////////////////////////////////////////////////////////////
	__forceinline uint64_t hash_elem(const T elem) const noexcept
	{
		uint32_t* bin = (uint32_t*)binary_values;
		return ((uint64_t)(bin[elem*size_elem + hash_pos0])) | (((uint64_t)(bin[elem*size_elem + hash_pos1])) << 32);
	}

	// Given a value "word", produces an integer in [0,p) without division.
	// The function is as fair as possible in the sense that if you iterate
	// through all possible values of "word", then you will generate all
	// possible outputs as uniformly as possible.
	__forceinline uint32_t fastrange32(uint32_t word)
	{
		return word & buckets_mask;
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
	__forceinline uint32_t Get_Label(size_t pos) const noexcept
	{
		return cache1[pos] & 0b00'000'111;
	}
	__forceinline uint32_t Get_Label(size_t pos, uint16_t* cache_ptr) const noexcept
	{
		return cache_ptr[pos] & 0b00'000'111;
	}
	__forceinline bool Is_Empty(size_t pos) const noexcept
	{
		return Get_Label(pos) == 0;
	}
	__forceinline bool Is_Empty(size_t pos, uint16_t* cache_ptr) const noexcept
	{
		return Get_Label(pos, cache_ptr) == 0;
	}
	__forceinline void Set_Empty(size_t pos) noexcept
	{
		cache1[pos] &= 0b11'000'000;
	}
	__forceinline void Copy_Elem(size_t dest, size_t source) noexcept
	{
		cache1[dest] = (cache1[dest] & 0b11'000'000) | (cache1[source] & 0xFF3F);
	}
	__forceinline void UpdateFlag(size_t pos, uint32_t distance_to_base, bool is_reverse) noexcept
	{
		cache1[pos] = (cache1[pos] & 0xFFC7) | (is_reverse ? 0b00'100'000 : 0) | (distance_to_base << 3);
	}
	__forceinline void UpdateFlag(size_t pos, uint32_t distance_to_base, bool is_reverse_item, uint32_t label, uint32_t hash) noexcept
	{
		cache1[pos] = (hash & 0xFF00) | (cache1[pos] & 0b11'000'000) | (is_reverse_item ? 0b00'100'000 : 0) | (distance_to_base << 3) | label;
	}
	__forceinline bool Is_Item_In_Reverse_Bucket(size_t pos) const noexcept
	{
		return cache1[pos] & 0b00'100'000;
	}
	__forceinline uint32_t GetFlagDistance(size_t pos) const noexcept
	{
		return (cache1[pos] >> 3) & 0b11;
	}
	__forceinline bool Is_Unlucky_Bucket(size_t pos) const noexcept
	{
		return cache1[pos] & 0b10'000'000;
	}
	__forceinline void Set_Unlucky_Bucket(size_t pos) noexcept
	{
		cache1[pos] |= 0b10'000'000;
	}
	__forceinline bool Is_Reversed_Window(size_t pos) const noexcept
	{
		return cache1[pos] & 0b01'000'000;
	}
	__forceinline void Set_Reversed(size_t pos) noexcept
	{
		cache1[pos] |= 0b01'000'000;
	}
	/////////////////////////////////////////////////////////////////////
	// Insertion algorithm utilities
	/////////////////////////////////////////////////////////////////////
	std::pair<uint32_t, size_t> Calculate_Minimum(size_t bucket_pos) const noexcept
	{
		uint32_t minimum = Get_Label(bucket_pos);
		size_t pos = bucket_pos;

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
	__forceinline size_t Belong_to_Bucket(size_t elem_pos) const noexcept
	{
		if (Is_Empty(elem_pos))
			return SIZE_MAX;

		return elem_pos + (Is_Item_In_Reverse_Bucket(elem_pos) ? NUM_ELEMS_BUCKET - 1 : 0) - GetFlagDistance(elem_pos);
	}
	uint32_t Count_Empty(size_t pos) const noexcept
	{
		uint32_t count = Is_Empty(pos) ? 1 : 0;

		for (uint32_t i = 1; i < NUM_ELEMS_BUCKET; i++)
			if (Is_Empty(pos + i))
				count++;

		return count;
	}
	uint32_t Count_Elems_In_Bucket_Non_Reversed(size_t bucket_pos) const noexcept
	{
		uint32_t count = 0;
		if (!Is_Item_In_Reverse_Bucket(bucket_pos) && 0 == GetFlagDistance(bucket_pos))
			count = 1;

		for (uint32_t i = 1; i < NUM_ELEMS_BUCKET; i++)
		{
			size_t pos = bucket_pos + i;

			if (!Is_Item_In_Reverse_Bucket(pos) && i == GetFlagDistance(pos))
				count++;
		}

		return count;
	}
	void Reverse_Bucket(size_t bucket_pos) noexcept
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
				data1[bucket_pos - j] = data1[bucket_pos + i];
				UpdateFlag(bucket_pos - j, NUM_ELEMS_BUCKET - 1 - j, true);
			}
	}

	size_t Find_Empty_Pos_Hopscotch(size_t bucket_pos, size_t bucket_init) noexcept
	{
		size_t empty_pos = SIZE_MAX;

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

					uint32_t min1;
					size_t pos1;
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
				size_t pos_elem = bucket_init + i;
				if (!Is_Item_In_Reverse_Bucket(pos_elem))
				{
					size_t bucket_elem = pos_elem - GetFlagDistance(pos_elem);

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

								uint32_t min1;
								size_t pos1;
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
				size_t pos_blank = bucket_init + i;
				while ((pos_blank - bucket_init) >= NUM_ELEMS_BUCKET)
				{
					size_t pos_swap = pos_blank + 1 - NUM_ELEMS_BUCKET;

					for (; (pos_blank - pos_swap) > (NUM_ELEMS_BUCKET - 1 - GetFlagDistance(pos_swap)); pos_swap++)
					{
					}// TODO: Use a list with the options to not recalculate again

					 // Swap elements
					data1[pos_blank] = data1[pos_swap];
					Copy_Elem(pos_blank, pos_swap);
					UpdateFlag(pos_blank, GetFlagDistance(pos_swap) + (uint32_t)(pos_blank - pos_swap), Is_Item_In_Reverse_Bucket(pos_swap));

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
public:
	CuckooBGLinear(uint32_t size_elem, uint32_t hash_pos0, uint32_t hash_pos1) noexcept : data1(nullptr), cache1(nullptr), num_elems(0), buckets_mask(0), 
		size_elem(size_elem), hash_pos0(hash_pos0), hash_pos1(hash_pos1)
	{}

	~CuckooBGLinear()
	{
		free(data1);
		free(cache1);

		data1 = nullptr;
		cache1 = nullptr;
		num_elems = 0;
		buckets_mask = 0;
	}

	void reserve(uint32_t new_capacity_mask) noexcept
	{
		free(data1);
		large_page_free(cache1);

		num_elems = 0;
		buckets_mask = new_capacity_mask;
		size_t num_buckets = ((size_t)new_capacity_mask) + 1;

		data1 = (T*)malloc(num_buckets * sizeof(T));
		cache1 = (uint16_t*)large_page_alloc(num_buckets * sizeof(uint16_t));
		memset(cache1, 0, num_buckets * sizeof(uint16_t));

		for (uint32_t i = 1; i < NUM_ELEMS_BUCKET; i++)
			Set_Reversed(num_buckets-i);
	}

	bool insert(T elem) noexcept
	{
		while (true)
		{
			uint64_t hash = hash_elem(elem);

			// Calculate positions given hash
			size_t bucket1_pos = fastrange32((uint32_t)hash);
			size_t bucket2_pos = fastrange32(hash >> 32);

			bool is_reversed_bucket1 = Is_Reversed_Window(bucket1_pos);
			bool is_reversed_bucket2 = Is_Reversed_Window(bucket2_pos);
			size_t bucket1_init = bucket1_pos + (is_reversed_bucket1 ? (1 - NUM_ELEMS_BUCKET) : 0);
			size_t bucket2_init = bucket2_pos + (is_reversed_bucket2 ? (1 - NUM_ELEMS_BUCKET) : 0);

			// Find minimun label
			uint32_t min1 = Get_Label(bucket1_init);
			uint32_t min2 = Get_Label(bucket2_init);
			size_t pos1 = bucket1_init;
			size_t pos2 = bucket2_init;
			for (size_t i = 1; i < NUM_ELEMS_BUCKET /*&& (min1 || min2)*/; i++)
			{
				size_t current_pos1 = bucket1_init + i;
				size_t current_pos2 = bucket2_init + i;
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
				UpdateFlag(pos1, (uint32_t)(pos1 - bucket1_init), is_reversed_bucket1, std::min(min2 + 1, L_MAX), (uint32_t)(hash >> 32));
				// Put elem
				data1[pos1] = elem;
				num_elems++;
				return true;
			}

			size_t empty_pos = Find_Empty_Pos_Hopscotch(bucket1_pos, bucket1_init);
			if (empty_pos != SIZE_MAX)
			{
				is_reversed_bucket1 = Is_Reversed_Window(bucket1_pos);
				bucket1_init = bucket1_pos + (is_reversed_bucket1 ? (1 - NUM_ELEMS_BUCKET) : 0);
				UpdateFlag(empty_pos, (uint32_t)(empty_pos - bucket1_init), is_reversed_bucket1, std::min(min2 + 1, L_MAX), (uint32_t)(hash >> 32));

				// Put elem
				data1[empty_pos] = elem;
				num_elems++;
				return true;
			}

			///////////////////////////////////////////////////////////////////
			// Secondary added, Unlucky bucket added
			//////////////////////////////////////////////////////////////////
			if (min2 == 0)
			{
				Set_Unlucky_Bucket(bucket1_pos);
				UpdateFlag(pos2, (uint32_t)(pos2 - bucket2_init), is_reversed_bucket2, std::min(min1 + 1, L_MAX), (uint32_t)hash);
				// Put elem
				data1[pos2] = elem;
				num_elems++;
				return true;
			}

			//if (num_elems * 10 > 9 * num_buckets)// > 90%
			//{
			//	empty_pos = Find_Empty_Pos_Hopscotch(bucket2_pos, bucket2_init);

			//	if (empty_pos != UINT32_MAX)
			//	{
			//		Set_Unlucky_Bucket(bucket1_pos);
			//		is_reversed_bucket2 = Is_Reversed_Window(bucket2_pos);
			//		bucket2_init = bucket2_pos + (is_reversed_bucket2 ? (1 - NUM_ELEMS_BUCKET) : 0);
			//		UpdateFlag(empty_pos, empty_pos - bucket2_init, is_reversed_bucket2, std::min(min1 + 1, L_MAX), (uint32_t)hash);

			//		// Put elem
			//		data1[empty_pos] = elem;
			//		num_elems++;
			//		return true;
			//	}
			//}

			// Terminating condition
			if (std::min(min1, min2) >= L_MAX)
				return false;

			if (min1 <= min2)// Selected pos in first bucket
			{
				UpdateFlag(pos1, (uint32_t)(pos1 - bucket1_init), is_reversed_bucket1, std::min(min2 + 1, L_MAX), (uint32_t)(hash >> 32));
				// Put elem
				T victim = data1[pos1];
				data1[pos1] = elem;
				elem = victim;
			}
			else
			{
				Set_Unlucky_Bucket(bucket1_pos);
				UpdateFlag(pos2, (uint32_t)(pos2 - bucket2_init), is_reversed_bucket2, std::min(min1 + 1, L_MAX), (uint32_t)hash);
				// Put elem
				T victim = data1[pos2];
				data1[pos2] = elem;
				elem = victim;
			}
		}
	}

	std::pair<uint16_t*, uint32_t*>  generate_fast_data()
	{
		uint16_t last_cache = 0;
		size_t num_buckets = ((size_t)buckets_mask) + 1;

		cbg_count_moved = 0;
		cbg_count_unlucky = 0;

		// Create the fast compare bit
		for (size_t i = 0; i < num_buckets; i++)
		{
			cache1[i] &= 0xFF;

			if (Belong_to_Bucket(i + (Is_Reversed_Window(i) ? -1 : 1)) == i)
			{
				cache1[i] |= 0x100;
				cbg_count_moved++;
			}
		}

		for (size_t i = 0; i < num_buckets; i++)
		{
			if (Is_Empty(i))
				data1[i] = NO_ELEM;
			else
			{
				uint64_t hash = hash_elem(data1[i]);
				uint32_t bucket1_pos = fastrange32((uint32_t)hash);

				uint16_t cache = ((bucket1_pos == Belong_to_Bucket(i)) ? (hash >> 32) : hash) & 0xFFF8;
				last_cache = cache;
			}
			if (Is_Unlucky_Bucket(i))
				cbg_count_unlucky++;

			cache1[i] = last_cache | ((cache1[i] & 0x100) ? 0b100 : 0) | (Is_Unlucky_Bucket(i) ? 0b10 : 0) | (Is_Reversed_Window(i) ? 0b1 : 0);
		}

		auto result = std::make_pair(cache1, data1);
		cache1 = nullptr;
		data1 = nullptr;
		return result;
	}
};

PUBLIC extern "C" void build_cbg_table(int format_index, uint32_t value_map_index0, uint32_t value_map_index1)
{
	if (num_passwords_loaded && formats[format_index].salt_size==0)
	{
		CuckooBGLinear<2, uint32_t> table(formats[format_index].binary_size / 4, value_map_index0, value_map_index1);

		uint64_t table_size = ceil_power_2(num_passwords_loaded);
		// Require less than 90% use
		if(table_size*9ull < num_passwords_loaded*10ull)
			table_size *= 2;

		// Memory status
#ifdef _WIN32
		MEMORYSTATUSEX memx;
		memx.dwLength = sizeof(memx);
		GlobalMemoryStatusEx(&memx);
#else
		struct {
			uint64_t ullAvailPhys = UINT64_MAX;
		} memx;
#endif

		while (table_size < num_passwords_loaded*4ull)//25%
		{
			// Don't grow if growing surpass L3 cache size
			if (table_size*sizeof(uint16_t)/1024 <= current_cpu.l3_cache_size && table_size*sizeof(uint16_t)/512 > current_cpu.l3_cache_size)
				break;

			// Don't grow if growing surpass RAM size
			if ((table_size*2+1)*6 > memx.ullAvailPhys)
				break;

			table_size *= 2;
		}

		table_size = __max(2048, table_size);// 4k: one page
		table_size = __min(0x1'0000'0000ull, table_size);// 32bits max

		bool repeat_generation = true;
		while (repeat_generation)
		{
			repeat_generation = false;
			table.reserve((uint32_t)(table_size-1));

			for (uint32_t i = 0; i < num_passwords_loaded; i++)
				if (!table.insert(i))
				{
					table_size *= 2;
					repeat_generation = true;
					break;
				}
		}

		cbg_mask = (uint32_t)(table_size - 1);
		std::tie(cbg_filter, cbg_table) = table.generate_fast_data();
	}
}

#include <random>
PUBLIC extern "C" void generate_random(uint8_t* values, size_t size)
{
	if (size)
	{
		std::random_device good_random;
		std::mt19937 r(good_random());

		for (size_t i = 0; i < size / 4; i++)
			((uint32_t*)values)[i] = r();

		if (size & 3)
		{
			for (size_t i = 0; i < (size & 3); i++)
				values[size / 4 * 4 + i] = r();
		}
	}
}
