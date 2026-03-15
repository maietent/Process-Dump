#include "StdAfx.h"
#include "simple.h"
#include <unordered_map>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define PD_SYSTEM_EXTENDED_HANDLE_INFORMATION 64
#define PD_STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

typedef struct _PD_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PD_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PPD_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _PD_SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PD_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} PD_SYSTEM_HANDLE_INFORMATION_EX, *PPD_SYSTEM_HANDLE_INFORMATION_EX;


DWORD process_find(string match_regex, DynArray<process_description*>* result)
{
	PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if( snapshot != INVALID_HANDLE_VALUE )
	{
		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				char* process_name = new char[wcslen(entry.szExeFile)+1];
				sprintf( process_name, "%S", entry.szExeFile );
			
				string name (process_name);
				try
				{
					regex reg (match_regex);
					if( regex_match( name, reg ) )
					{  
						// Record this as a matching process
						result->Add( new process_description( process_name, entry.th32ProcessID ) );
					}
				}
				catch( std::tr1::regex_error e )
				{
					fprintf( stderr, "ERROR: Invalid regex expression for matching process names." );
					return 0;
				}


			}
		}

		CloseHandle(snapshot);
	}
	return result->GetSize();
}

string ExePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA( NULL, buffer, MAX_PATH );
    string::size_type pos = string( buffer ).find_last_of( "\\/" );
    return string( buffer ).substr( 0, pos);
}

void PrintLastError(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process
    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 

	fwprintf(stderr,(LPCTSTR) lpDisplayBuf );

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

HANDLE hijack_process_handle(DWORD pid, DWORD desired_access, DWORD* source_pid, bool verbose)
{
	if (source_pid != NULL)
		*source_pid = 0;

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL)
		return NULL;

	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
		return NULL;

	ULONG buffer_size = 0x10000;
	ULONG return_length = 0;
	char* buffer = NULL;
	NTSTATUS status = 0;

	do
	{
		if (buffer != NULL)
			delete[] buffer;

		buffer = new char[buffer_size];
		status = NtQuerySystemInformation(PD_SYSTEM_EXTENDED_HANDLE_INFORMATION, buffer, buffer_size, &return_length);
		if (status == PD_STATUS_INFO_LENGTH_MISMATCH)
		{
			if (return_length > buffer_size)
				buffer_size = return_length + 0x1000;
			else
				buffer_size *= 2;
		}
	} while (status == PD_STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status) || buffer == NULL)
	{
		if (buffer != NULL)
			delete[] buffer;
		return NULL;
	}

	PPD_SYSTEM_HANDLE_INFORMATION_EX handle_info = (PPD_SYSTEM_HANDLE_INFORMATION_EX)buffer;
	DWORD current_pid = GetCurrentProcessId();
	unordered_map<DWORD, HANDLE> source_processes;
	HANDLE duplicated_handle = NULL;

	for (ULONG_PTR i = 0; i < handle_info->NumberOfHandles; i++)
	{
		PD_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = handle_info->Handles[i];
		DWORD owner_pid = (DWORD)entry.UniqueProcessId;

		if (owner_pid == 0 || owner_pid == current_pid)
			continue;

		if ((entry.GrantedAccess & desired_access) != desired_access)
			continue;

		HANDLE source_process = NULL;
		unordered_map<DWORD, HANDLE>::iterator existing = source_processes.find(owner_pid);
		if (existing == source_processes.end())
		{
			source_process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, owner_pid);
			source_processes[owner_pid] = source_process;
		}
		else
		{
			source_process = existing->second;
		}

		if (source_process == NULL)
			continue;

		HANDLE candidate_handle = NULL;
		if (!DuplicateHandle(source_process, (HANDLE)entry.HandleValue, GetCurrentProcess(), &candidate_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
			continue;

		if (GetProcessId(candidate_handle) == pid)
		{
			duplicated_handle = candidate_handle;
			if (source_pid != NULL)
				*source_pid = owner_pid;
			break;
		}

		CloseHandle(candidate_handle);
	}

	for (unordered_map<DWORD, HANDLE>::iterator it = source_processes.begin(); it != source_processes.end(); ++it)
	{
		if (it->second != NULL)
			CloseHandle(it->second);
	}

	delete[] buffer;

	if (duplicated_handle != NULL && verbose)
		printf("Hijacked a handle to PID 0x%x from PID 0x%x.\n", pid, (source_pid != NULL ? *source_pid : 0));

	return duplicated_handle;
}
