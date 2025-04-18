#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "beacon.h"

#define _NO_NTDLL_CRT_
#include "native.h"

#define INITIAL_ARRAY_SIZE 100
#define PATH_MAX_LENGTH 512

#define CAPI(func_name) __declspec(dllimport) __typeof(func_name) func_name;
CAPI(calloc)
CAPI(free)
CAPI(NtQueryInformationProcess)
CAPI(NtQuerySystemInformation)
CAPI(K32GetModuleFileNameExA)
CAPI(memset)
CAPI(realloc)
CAPI(strcmp)
CAPI(strcpy)
CAPI(strlen)

typedef struct {
    DWORD* pids; 
    char** names; 
    size_t count; 
    size_t capacity; 
} servicesArray;

void initializeServiceArray(servicesArray* array, size_t initialSize) {
    array->pids = (DWORD*)calloc(initialSize * sizeof(DWORD), sizeof(char));
    array->names = (char**)calloc(initialSize * sizeof(char*), sizeof(char));
    array->count = 0;
    array->capacity = initialSize;
}

void addServiceToArray(servicesArray* array, DWORD pid, const char* name) {
    if (array->count == array->capacity) {
        array->capacity *= 2;
        array->pids = (DWORD*)realloc(array->pids, array->capacity * sizeof(DWORD));
        array->names = (char**)realloc(array->names, array->capacity * sizeof(char*));
    }
    array->pids[array->count] = pid;
    array->names[array->count] = (char*)calloc(strlen(name) + 1, sizeof(char));
    strcpy(array->names[array->count], name);

    array->count++;
}

void freeServiceArray(servicesArray* array) {
    for (size_t i = 0; i < array->count; i++)
        free(array->names[i]);

    free(array->pids);
}

servicesArray serviceArray;
char* lpUnprotected = "Unprotected";
char* lpPPL = "PsProtected-Light";
char* lpPP = "PsProtected";

char* GetUserFromProcess(HANDLE hProcess)
{
    char* username = NULL;
    HANDLE hToken;
    
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
    {
        DWORD size = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &size);

        TOKEN_USER* tokenUser = (TOKEN_USER*)calloc(size, sizeof(char));
        if (tokenUser)
        {
            if (GetTokenInformation(hToken, TokenUser, tokenUser, size, &size))
            {

                CHAR name[256] = {0};
                CHAR domain[256] = {0};
                DWORD nameSize = sizeof(name) / sizeof(CHAR);
                DWORD domainSize = sizeof(domain) / sizeof(CHAR);
                SID_NAME_USE sidType;
                
                if (LookupAccountSid(NULL, tokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidType))
                {
                    DWORD dwBufLen = nameSize + domainSize + 2;
                    username = calloc(dwBufLen, sizeof(char));
                    if (username)
                        sprintf_s(username, dwBufLen, "%s\\%s", domain, name);
                } 
            }

            free(tokenUser);
        }

        CloseHandle(hToken);
    }

    return username;
}

void enumerateServices(servicesArray* serviceArray) {
    SC_HANDLE hSCManager;
    LPBYTE lpBuffer = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwBufferSize = 0;

    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager failed. Error: %lu\n", GetLastError());
        return;
    }

    EnumServicesStatusExA(
        hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded,
        &dwServicesReturned, &dwResumeHandle, NULL);

    if (GetLastError() != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumServicesStatusEx failed. Error: %lu\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    dwBufferSize = dwBytesNeeded;
    lpBuffer = (LPBYTE)calloc(dwBufferSize, sizeof(char));
    if (!lpBuffer) {
        BeaconPrintf(CALLBACK_OUTPUT, "Memory allocation failed.\n");
        CloseServiceHandle(hSCManager);
        return;
    }
    if (!EnumServicesStatusExA(
            hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, lpBuffer, dwBufferSize,
            &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "EnumServicesStatusEx failed. Error: %lu\n", GetLastError());
        free(lpBuffer);
        CloseServiceHandle(hSCManager);
        return;
    }

    LPENUM_SERVICE_STATUS_PROCESSA pServices = (LPENUM_SERVICE_STATUS_PROCESSA)lpBuffer;

    for (DWORD i = 0; i < dwServicesReturned; i++)
        addServiceToArray(serviceArray, pServices[i].ServiceStatusProcess.dwProcessId, pServices[i].lpServiceName);

    free(lpBuffer);
    CloseServiceHandle(hSCManager);
}

void go (char* args, int length)
    
    initializeServiceArray(&serviceArray, INITIAL_ARRAY_SIZE);

    
    enumerateServices(&serviceArray);

    
    formatp buffer;
    BeaconFormatAlloc(&buffer, 40960);

    
    ULONG retLen = 0;
    NtQuerySystemInformation(SystemProcessInformation, 0, 0, &retLen);
    if (retLen == 0) 
    { 
        BeaconFormatPrintf(&buffer, "[-] NtQuerySystemInformation failed.\n");
        goto print;
    }

    
    const size_t bufLen = retLen;
    void *infoBuf = calloc(bufLen, sizeof(char));
    if (!infoBuf)
    {
        BeaconFormatPrintf(&buffer, "[-] calloc failed.\n");
        goto print;
    }

    BeaconFormatPrintf(&buffer, "%-7s %-30s %-20s %-30s %-10s %-30s %-100s\n", "PID", "Process Name", "Process Protection", "User", "Session", "Service", "Process Path");
    BeaconFormatPrintf(&buffer, "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");


    SYSTEM_PROCESS_INFORMATION *sys_info = (SYSTEM_PROCESS_INFORMATION *)infoBuf;
    if (NtQuerySystemInformation(SystemProcessInformation, sys_info, bufLen, &retLen) == STATUS_SUCCESS)
    {
        while (TRUE) 
        {
            PS_PROTECTION protection = {0, };
        
            DWORD pid = (DWORD)sys_info->UniqueProcessId;
            
            if (pid == 0)
            {
                sys_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sys_info + sys_info->NextEntryOffset);
                continue;
    
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc)
                char* procuser = GetUserFromProcess(hProc);

            
                CHAR filepath[MAX_PATH] = {0};
                char* servicename = NULL;
                if (GetModuleFileNameExA(hProc, NULL, (LPSTR)&filepath, MAX_PATH) == 0)
                {
                    memset(&filepath, 0, MAX_PATH);
                    sprintf_s((char*)&filepath, MAX_PATH, "%s", "[-] Error resolving image path");
                }
                else
                {
            
                    for (size_t i = 0; i < serviceArray.count; i++)
                    {
                        if (pid == serviceArray.pids[i])
                        {
                            servicename = serviceArray.names[i];
                            break;
                        }
                    }                    
                }

            
                NTSTATUS ntstatus = STATUS_SUCCESS;
                ntstatus = NtQueryInformationProcess(hProc, ProcessProtectionInformation, &protection, sizeof(protection), NULL);
                if (NT_SUCCESS(ntstatus))
                {
                    char* prot = NULL;
                    if (protection.Type == PsProtectedTypeNone)
                        prot = lpUnprotected;
                    else if (protection.Type == PsProtectedTypeProtectedLight)
                        prot = lpPPL;
                    else if (protection.Type == PsProtectedTypeProtected)
                        prot = lpPP;
                
                    BeaconFormatPrintf(&buffer, "%-7d %-30ls %-20s %-30s %-10d %-30s %-100s\n", pid, sys_info->ImageName.Buffer, prot, procuser == NULL ? "?" : procuser, sys_info->SessionId, servicename == NULL ? "N/A" : servicename, filepath);
                
                }
                else
                    BeaconFormatPrintf(&buffer, "%-7d %-30ls %-20s %-30s %-10d %-30s %-100s\n", pid, sys_info->ImageName.Buffer, "[-] NtQIP", procuser == NULL ? "?" : procuser, sys_info->SessionId, servicename == NULL ? "N/A" : servicename, filepath);

               
                CloseHandle(hProc);
                memset(&protection, 0, sizeof(protection));                
                if (procuser != NULL)
                {
                    memset(procuser, 0, strlen(procuser));
                    free(procuser);
                }
            }
            else
                BeaconFormatPrintf(&buffer, "%-7d %-30ls %-20s %-30s %-10d %-30s %-100s\n", pid, sys_info->ImageName.Buffer, "[-] OpenProcess", "N/A", sys_info->SessionId, "N/A", "N/A");
                
            if (!sys_info->NextEntryOffset)
                break;

            sys_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sys_info + sys_info->NextEntryOffset);
        }
    }
    else
        BeaconFormatPrintf(&buffer, "[-] NtQuerySystemInformation failed.\n");
    

    memset(infoBuf, 0, bufLen);
    free(infoBuf);

print:

    freeServiceArray(&serviceArray);

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));
    BeaconFormatFree(&buffer);
}