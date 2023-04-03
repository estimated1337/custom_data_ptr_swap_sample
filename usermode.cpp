struct init_data_t
{
	bool m_is_loaded;
	NTSTATUS m_status;
};

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtQueryLicenseValue(PUNICODE_STRING ValueName, PULONG Type, PVOID Data,
	ULONG DataSize, PULONG ResultDataSize);

bool is_driver_loaded() 
{
	init_data_t init_data;
	_memset(&init_data, 0, sizeof(init_data));

	ULONG type = 0x13371488;
	ULONG size_;

	UNICODE_STRING name;
	utils::init_unicode_string(&name, L"0");

	NtQueryLicenseValue(&name, &type, &init_data, sizeof(init_data), &size_);

	return init_data.m_status == STATUS_SUCCESS && init_data.m_is_loaded;
}