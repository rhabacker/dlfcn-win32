/* required for non Windows builds, must be set in front of the first system include */
#define _GNU_SOURCE

#include <dlfcn.h>

#include <stdio.h>
#include <string.h>

static int verbose = 0;

typedef enum {
    Pass = 1,
    PassWithoutSymbol = 2,
    Fail = 0,
    NoInfo = -1,
} ExpectedResult;

typedef void (* func) (void);

void print_dl_info(Dl_info *info)
{
    printf("filename: %s base: %p symbol name: '%s' addr: %p\n", info->dli_fname, info->dli_fbase, info->dli_sname, info->dli_saddr);
}

/**
 * @brief check information returned by dladdr
 * @param addr address to check
 * @param addrsym
 * @param expected check against expected result
 * @return 0 check passed
 * @return 1 check failed
 */
int check_dladdr( void *addr, char *addrsym, ExpectedResult expected_result )
{
    Dl_info info;
    int result = dladdr( addr, &info );
    int passed = 0;
    if (!result)
    {
        passed = expected_result == NoInfo;
        printf( "check address %p which has symbol '%s' -> %s\n", addr, addrsym, passed ? "passed" : "failed" );
        if (verbose)
            fprintf( stderr,"could not get symbol information for address %p\n", addr );
        return !passed;
    }
    else
    {
        int sym_match  = info.dli_sname && strcmp( addrsym, info.dli_sname ) == 0;
        int addr_match  = addr == info.dli_saddr;
        passed = (expected_result == Pass && sym_match && addr_match)
                 || (expected_result == PassWithoutSymbol && addr_match)
                 || (expected_result == Fail && !(sym_match && addr_match));
        printf( "check address %p with has symbol '%s' -> %s\n",addr, addrsym, passed ? "passed" : "failed" );
        if (verbose)
            print_dl_info( &info );
        return !passed;
    }
}

/**
 * @brief return address from a symbol located in a shared lilbrary
 * @param libname librray to get the address from
 * @param addrsym symbol to get the address for
 * @return pointer to symbol address or NULL
 */
void *get_symbol_address( char *libname, char *sym )
{
    void *library = NULL;
    void *addr = NULL;

    library = dlopen( libname, RTLD_GLOBAL );
    if ( library == NULL )
    {
        fprintf( stderr, "could not open '%s'\n", libname );
        return NULL;
    }

    addr = dlsym( library, sym );
    dlclose( library );
    if (!addr)
        fprintf( stderr, "could not get address for symbol '%s'\n", sym );
    return addr;
}

/**
 * @brief check address from a symbol located in a shared lilbrary
 * @param libname librray to get the address from
 * @param addrsym symbol to get the address for
 * @param should_match result should match the given values
 * @return 0 check passed
 * @return 1 check failed
 */
int check_dladdr_by_dlopen( char *libname, char *sym, int should_match )
{
    void *addr = get_symbol_address( libname, sym);
    if (!addr)
        return 1;
    return check_dladdr( addr, sym, should_match );
}

#ifdef _WIN32
#define HMODULE void*
#define HANDLE void*
#define LPCVOID void*
#define LPCSTR char*
#define DWORD long
#define SIZE_T long

#ifdef _MSC_VER
#define STDCALL __stdcall
#else
#define STDCALL __attribute__((__stdcall__))
#endif

/* link to import thunk */
HMODULE STDCALL GetModuleHandleA (LPCSTR lpModuleName);
/* link to directly to iat */
__declspec(dllimport) HMODULE STDCALL LoadLibraryExA (LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
SIZE_T STDCALL VirtualQuery (LPCVOID lpAddress, LPCVOID lpBuffer, SIZE_T dwLength);
#define PassWithoutSymbolOnWin PassWithoutSymbol
#else
#define PassWithoutSymbolOnWin Pass
#endif


int main(int argc, char **argv)
{
    int  result = 0;
    if (argc == 2)
        verbose = 1;

    /* null pointer */
    result = check_dladdr((void*)0, "null" , NoInfo);
    /* invalid pointer */
    result |= check_dladdr((void*)0x125, "invalid pointer" , Fail);
    /* -ldl */
    result |= check_dladdr( ((void*)dladdr), "dladdr" , Pass );
    /* -ldl */
    result |= check_dladdr( (void*)dlopen, "dlopen", Pass );
    /* -lglibc */
    result |= check_dladdr( (void*)vsnprintf, "vsnprintf", PassWithoutSymbolOnWin );
    /* test-dladdr */
    result |= check_dladdr( (void*)main, "main", PassWithoutSymbolOnWin );
    /* offsets */
    result |= check_dladdr( (char*)dladdr-6, "dladdr-6", Fail );
    /* offsets */
    result |= check_dladdr( (char*)dladdr+6, "dladdr+6", Fail );
    /* invalid address on import thunk */
    unsigned char buffer[6] = "\xFF\x25\x00\x00\x00\x00";
    result |= check_dladdr( buffer, "invalid import thunk", NoInfo );

#ifdef _WIN32
    /* last entry in iat */
    result |= check_dladdr( (char*)VirtualQuery, "VirtualQuery", Pass );
    /* links to import thunk table */
    result |= check_dladdr ( (void*)GetModuleHandleA, "GetModuleHandleA", Pass );
    result |= check_dladdr_by_dlopen( "kernel32.dll", "GetModuleHandleA", Pass );

    /* links directly to Import allocation table */
    result |= check_dladdr ( (void*)LoadLibraryExA, "LoadLibraryExA", Pass );
    result |= check_dladdr_by_dlopen( "kernel32.dll", "LoadLibraryExA", Pass );
#endif
    return result;
}
