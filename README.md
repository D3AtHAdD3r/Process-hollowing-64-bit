# Process-hollowing-64-bit

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
