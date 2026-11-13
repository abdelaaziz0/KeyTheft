#ifndef WINSTUB_H
#define WINSTUB_H
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long ULONG_PTR;
typedef unsigned short USHORT;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BOOLEAN;
typedef DWORD ACCESS_MASK;
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef void *PVOID;
typedef void **PPVOID;
typedef void *HANDLE;
typedef HANDLE *PHANDLE;
typedef DWORD *PDWORD;
typedef ULONG *PULONG;
typedef HANDLE HKEY;
typedef HANDLE HMODULE;
typedef HANDLE SC_HANDLE;
typedef HANDLE HLOCAL;
typedef long LSTATUS;
typedef long NTSTATUS_;

#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define INVALID_FILE_SIZE ((DWORD)0xFFFFFFFF)
#define ERROR_SUCCESS 0
#define ERROR_SERVICE_ALREADY_RUNNING 1056
#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 3
#define CREATE_ALWAYS 2
#define FILE_ATTRIBUTE_NORMAL 0x80
#define PROCESS_DUP_HANDLE 0x0040
#define KEY_READ 0x20019
#define TOKEN_ADJUST_PRIVILEGES 0x20
#define TOKEN_QUERY 8
#define SE_PRIVILEGE_ENABLED 2
#define SC_MANAGER_CONNECT 1
#define SERVICE_QUERY_STATUS 4
#define SERVICE_START 16
#define SC_STATUS_PROCESS_INFO 0
#define SERVICE_RUNNING 4
#define DUPLICATE_SAME_ACCESS 2

typedef struct _LUID { DWORD LowPart; LONG HighPart; } LUID;
typedef struct _TP { DWORD PrivilegeCount; struct { LUID Luid; DWORD Attributes; } Privileges[1]; } TOKEN_PRIVILEGES;
typedef struct _SSP { DWORD dwServiceType; DWORD dwCurrentState; DWORD dwProcessId; } SERVICE_STATUS_PROCESS;

#define GetProcessHeap() ((PVOID)0)
#define HeapAlloc(a,b,c) ((PVOID)0)
#define HeapFree(a,b,c) ((void)0)
#define CloseHandle(h) ((BOOL)0)
#define CreateFileW(...) ((HANDLE)-1)
#define GetFileSize(h,x) ((DWORD)0)
#define ReadFile(a,b,c,d,e) ((BOOL)0)
#define WriteFile(a,b,c,d,e) ((BOOL)0)
#define DeleteFileW(a) ((BOOL)0)
#define GetModuleHandleW(a) ((HMODULE)0)
#define GetProcAddress(a,b) ((PVOID)0)
#define OpenProcessToken(a,b,c) ((BOOL)0)
#define LookupPrivilegeValueW(a,b,c) ((BOOL)0)
#define AdjustTokenPrivileges(a,b,c,d,e,f) ((BOOL)0)
#define GetLastError() ((DWORD)0)
#define GetCurrentProcess() ((HANDLE)0)
#define GetCurrentProcessId() ((DWORD)0)
#define GetTickCount() ((DWORD)0)
#define OpenProcess(a,b,c) ((HANDLE)0)
#define OpenSCManagerW(a,b,c) ((SC_HANDLE)0)
#define OpenServiceW(a,b,c) ((SC_HANDLE)0)
#define QueryServiceStatusEx(a,b,c,d,e) ((BOOL)0)
#define StartServiceW(a,b,c) ((BOOL)0)
#define CloseServiceHandle(a) ((void)0)
#define RegOpenKeyExW(a,b,c,d,e) ((LSTATUS)5)
#define RegQueryInfoKeyW(a,b,c,d,e,f,g,h,i,j,k,l) ((LSTATUS)5)
#define RegCloseKey(a) ((LSTATUS)0)
#define RegConnectRegistryW(a,b,c) ((LSTATUS)5)
#define Sleep(x) ((void)0)
#define _wcsnicmp wcsncasecmp
#define _snwprintf swprintf
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define NTAPI
#define WINAPI
#endif

/* additions for service config/restore paths */
#define ERROR_SERVICE_DISABLED 1058
#define SERVICE_NO_CHANGE 0xFFFFFFFF
#define SERVICE_DEMAND_START 3
#define SERVICE_STOP 0x0001
#define SERVICE_STOPPED 1
typedef struct _QSCW { DWORD dwStartType; } QUERY_SERVICE_CONFIGW;
typedef struct _SSTAT { DWORD dwCurrentState; } SERVICE_STATUS;
#define QueryServiceConfigW(a,b,c,d) ((BOOL)0)
#define ChangeServiceConfigW(a,b,c,d,e,f,g,h,i,j,k) ((BOOL)0)
#define ControlService(a,b,c) ((BOOL)0)
#define GetSystemDirectoryW(a,b) (0)
#define WaitForSingleObject(a,b) (0)
#define CREATE_NO_WINDOW 0
typedef struct _SIW { DWORD cb; } STARTUPINFOW;
typedef struct _PIW { HANDLE hProcess, hThread; DWORD pid, tid; } PROCESS_INFORMATION;
#define CreateProcessW(a,b,c,d,e,f,g,h,i,j) ((BOOL)0)
#define QueryFullProcessImageNameW(a,b,c,d) ((BOOL)0)
#define MoveFileW(a,b) ((BOOL)0)
#define MOVEFILE_REPLACE_EXISTING 1
#define MoveFileExW(a,b,c) ((BOOL)0)
