struct init_data_t
{
	bool m_is_loaded;
	NTSTATUS m_status;
};

namespace hooks
{
	uintptr_t original = 0;

	__int64 __fastcall sl_query_license_value
	(
		__int64 a1,
		const UNICODE_STRING* a2,
		ULONG* type_ptr,
		__int64 a4,
		unsigned int a5,
		unsigned int* a6
	)
	{
		if (type_ptr)
		{
			if (*type_ptr == 0x13371488)
			{
				auto data_ptr = *reinterpret_cast<init_data_t**>(reinterpret_cast<uintptr_t>(type_ptr) + 0x10);

				if (MmIsAddressValid(data_ptr))
				{
					data_ptr->m_is_loaded = true;
					data_ptr->m_status = STATUS_SUCCESS;
				}
			}
		}

		return reinterpret_cast<decltype(&sl_query_license_value)>(original)(a1, a2, type_ptr, a4, a5, a6);
	}
}

NTSTATUS NTAPI DriverEntry()
{
	ulong_t clipsp_size = 0;
	const auto clipsp_address = utils::get_module(FNV("clipsp.sys"), clipsp_size);

	hooks::original = FIND_PATTERN_SECTION(clipsp_address, "PAGE", "40 53 56 57 41");

	ulong_t ksecdd_size = 0;
	const auto ksecdd_address = utils::get_module(FNV("ksecdd.sys"), ksecdd_size);

	auto ksecdd_table_ref = FIND_PATTERN_SECTION(ksecdd_address, "PAGE", "48 8D 35 ? ? ? ? 49 8D 4B 10");

	if (!ksecdd_table_ref)
	{
		ksecdd_table_ref = FIND_PATTERN_SECTION(ksecdd_address, "PAGE", "48 8D 35 ? ? ? ? 33 C0");
	}

	const auto ksecdd_table_ptr = utils::resolve_rel_address(ksecdd_table_ref, 0x3, 0x7);

	auto data_section_ptr = ksecdd_table_ptr + 0x58;

	auto sl_query_license_value_ref = FIND_PATTERN_SECTION(utils::ntoskrnl_ptr, "PAGE", "48 8B 05 ? ? ? ? 48 85 C0 74 29");

	if (!sl_query_license_value_ref)
	{
		sl_query_license_value_ref = FIND_PATTERN_SECTION(utils::ntoskrnl_ptr, "PAGE", "48 8B 05 ? ? ? ? 48 85 C0 74 23 4C 8B 54 24 70");
	}

	auto sl_query_license_value_ptr = utils::resolve_rel_address(sl_query_license_value_ref, 0x3, 0x7);

	uint8_t shellcode[] = 
	{ 
		0x48, 0xB8, 0x88, 0x14, 0x37, 0x13, 0x88, 0x14, 0x37, 0x13, // mov rax, value
		0xFF, 0xE0,													// jmp rax
		0x00, 0x00, 0x00, 0x00										// zeros
	};
	
	*reinterpret_cast<uintptr_t*>(
		reinterpret_cast<uintptr_t>(&shellcode) + 0x2) = reinterpret_cast<uintptr_t>(&hooks::sl_query_license_value);

	_memcpy(reinterpret_cast<void*>(data_section_ptr), &shellcode, sizeof(shellcode));

	auto pte = utils::get_pte_address(data_section_ptr);
	pte->u.hard.nx_bit = 0;

	_InterlockedExchange64(reinterpret_cast<LONG64*>(sl_query_license_value_ptr), data_section_ptr);

	return STATUS_SUCCESS;
}