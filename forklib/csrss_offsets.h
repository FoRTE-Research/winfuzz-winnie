// This file was generated by a tool. Do not edit it manually!
// To regenerate it, please run gen_csrss_offsets.py

// This header is generated to target 64-bit Windows including SysWoW64

#pragma once

#ifdef _WIN64

// RVA of CsrServerApiRoutine up to RtlpEnvironLookupTable in System32\ntdll.exe
#define csrDataRva_x64 0x16cc08
// RtlpEnvironLookupTable = 0x16cd00
#define csrDataSize_x64 0xf8

#else

// WoW64 ntdll.dll
// RVA of _CsrServerApiRoutine up to _RtlpEnvironLookupTable in SysWOW64\ntdll.dll
#define csrDataRva_x86 0x126388
// RtlpEnvironLookupTable = 0x1263a0
#define csrDataSize_x86 0x18

// RVA of CsrServerApiRoutine up to RtlpEnvironLookupTable in System32\ntdll.exe
#define csrDataRva_wow64 0x16cc08
// RtlpEnvironLookupTable = 0x16cd00
#define csrDataSize_wow64 0xf8

#endif
