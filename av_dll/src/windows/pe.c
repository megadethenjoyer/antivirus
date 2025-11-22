#include <common.h>

#pragma pack( push, 1 )
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
struct unwind_func {
    uint32_t begin_rva;
    uint32_t end_rva;

    uint32_t unwind_rva;
};

// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_info
struct unwind_info {
    uint8_t version: 3;
    uint8_t flags: 5;

    uint8_t prologue_size;
    uint8_t unwind_code_count;
    uint8_t frame_reg: 4;
    uint8_t frame_reg_offset: 4;
};
#pragma pack( pop )

IMAGE_NT_HEADERS *get_nt_headers( uint8_t *image ) {
	IMAGE_DOS_HEADER *dos = ( IMAGE_DOS_HEADER * )( image );
	if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
		return NULL;
	}

	IMAGE_NT_HEADERS *nt = ( IMAGE_NT_HEADERS * )( image + dos->e_lfanew );
	if ( nt->Signature != IMAGE_NT_SIGNATURE ) {
		return NULL;
	}

    return nt;
}

size_t pe_get_image_size( uint8_t *image ) {
    IMAGE_NT_HEADERS *nt = get_nt_headers( image );
    assert( nt );
    if ( nt == NULL ) {
        return 0;
    }

	return nt->OptionalHeader.SizeOfImage;
}

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
bool pe_verify_sig( const wchar_t *path ) {
    WINTRUST_FILE_INFO file_data = { 0 };
    file_data.cbStruct = sizeof( WINTRUST_FILE_INFO );
    file_data.pcwszFilePath = path;

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trust_data = { 0 };

    trust_data.cbStruct = sizeof( WINTRUST_DATA );

    // Disable WVT UI.
    trust_data.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

    trust_data.pFile = &file_data;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    LSTATUS verify_status = WinVerifyTrust( NULL, &policy_guid, &trust_data );


    // Release.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust( NULL, &policy_guid, &trust_data );

    return verify_status == ERROR_SUCCESS;

}

uint8_t *pe_get_function_base( HMODULE module, uint8_t *instr ) {
    uint8_t *base = ( uint8_t * )( module );

    IMAGE_NT_HEADERS *nt = get_nt_headers( base );
    assert( nt );
    if ( nt == NULL ) {
        return NULL;
    }

    IMAGE_DATA_DIRECTORY exception_dir = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXCEPTION ];

    size_t unwind_count = exception_dir.Size / sizeof( struct unwind_func );
    struct unwind_func *unwind_funcs = ( struct unwind_func * )( base + exception_dir.VirtualAddress );

    for ( size_t i = 0; i < unwind_count; i++ ) {
        struct unwind_func *func = &unwind_funcs[ i ];

        uint8_t *begin = base + func->begin_rva;
        uint8_t *end   = base + func->end_rva;

        if ( instr >= begin && instr < end ) {
            return begin;
        }
    }

    return NULL;
}
