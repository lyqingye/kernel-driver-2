
#ifndef PE_DEF_HEAD
#define PE_DEF_HEAD

#if !defined (BYTE)
typedef unsigned char    BYTE;
typedef BYTE*			 PBYTE;
#endif
#if !defined (WORD)
typedef unsigned short   WORD;
typedef WORD*			 PWORD;
#endif
#if !defined (DWORD)
typedef unsigned long    DWORD;
typedef DWORD*			 PDWORD;
#endif
#if !defined (INT32)
typedef signed int       INT32;
typedef INT32*			 PINT32;
#endif
#if !defined (INT64)
typedef signed __int64	 INT64;
typedef INT64*			 PINT64;
#endif
#if !defined (LONG)
typedef long			 LONG;
typedef LONG*			 PLONG;
#endif
#if !defined (UINT)
typedef unsigned int	 UINT;
typedef UINT*			 PUINT;
#endif
#if !defined (UINT32)
typedef unsigned int	 UINT32;
typedef UINT32*			 PUINT32;
#endif
#if !defined (UINT64)
typedef unsigned __int64 UINT64;
typedef UINT64*			 PUINT64;
#endif

#pragma warning(disable:4201)

#pragma once

typedef struct _PE_IMAE_DOS_HEADER {       //DOS .EXE header                                    Î»ÖÃ  
	WORD e_magic;                       //Magic number;                                      0x00  
	WORD e_cblp;                        //Bytes on last page of file                           0x02  
	WORD e_cp;                          //Pages in file                                      0x04  
	WORD e_crlc;                        //Relocations                                        0x06  
	WORD e_cparhdr;                     //Size of header in paragraphs                       0x08  
	WORD e_minalloc;                    //Minimum extra paragraphs needed                    0x0A  
	WORD e_maxalloc;                    //Maximum extra paragraphs needed                    0x0C  
	WORD e_ss;                          //Initial (relative) SS value                        0x0E  
	WORD e_sp;                          //Initial SP value                                   0x10  
	WORD e_csum;                        //Checksum                                           0x12  
	WORD e_ip;                          //Initial IP value                                   0x14  
	WORD e_cs;                          //Initial (relative) CS value                        0x16  
	WORD e_lfarlc;                      //File address of relocation table                   0x18  
	WORD e_ovno;                        //Overlay number                                     0x1A  
	WORD e_res[4];                      //Reserved words                                     0x1C  
	WORD e_oemid;                       //OEM identifier (for e_oeminfo)                     0x24  
	WORD e_oeminfo;                     //OEM information; e_oemid specific                  0x26   
	WORD e_res2[10];                    //Reserved words                                     0x28  
	LONG e_lfanew;                      //File address of new exe header                     0x3C  
} PE_IMAGE_DOS_HEADER, *PPE_IMAGE_DOS_HEADER;

#define PE_IMAGE_SIZEOF_SHORT_NAME         8

typedef struct _PE_IMAGE_SECTION_HEADER {
	BYTE    Name[PE_IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} PE_IMAGE_SECTION_HEADER, *PPE_IMAGE_SECTION_HEADER;

typedef struct _PE_IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} PE_IMAGE_FILE_HEADER, *PPE_IMAGE_FILE_HEADER;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _PE_IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} PE_IMAGE_DATA_DIRECTORY, *PPE_IMAGE_DATA_DIRECTORY;

//
// Optional header format.
//

typedef struct _PE_IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	PE_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PE_IMAGE_OPTIONAL_HEADER32, *PPE_IMAGE_OPTIONAL_HEADER32;

typedef struct _PE_IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	INT64		ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	INT64		SizeOfStackReserve;
	INT64		SizeOfStackCommit;
	INT64		SizeOfHeapReserve;
	INT64		SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	PE_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PE_IMAGE_OPTIONAL_HEADER64, *PPE_IMAGE_OPTIONAL_HEADER64;

#define PE_IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define PE_IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

typedef struct _PE_IMAGE_NT_HEADERS64 {
	DWORD Signature;
	PE_IMAGE_FILE_HEADER FileHeader;
	PE_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} PE_IMAGE_NT_HEADERS64, *PPE_IMAGE_NT_HEADERS64;

typedef struct _PE_IMAGE_NT_HEADERS {
	DWORD Signature;
	PE_IMAGE_FILE_HEADER FileHeader;
	PE_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} PE_IMAGE_NT_HEADERS32, *PPE_IMAGE_NT_HEADERS32;

typedef struct _PE_IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} PE_IMAGE_EXPORT_DIRECTORY, *PPE_IMAGE_EXPORT_DIRECTORY;

typedef struct _PE_IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	};
	DWORD   TimeDateStamp;                  // 0 if not bound,
											// -1 if bound, and real date\time stamp
											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
											// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} PE_IMAGE_IMPORT_DESCRIPTOR,*PPE_IMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
typedef struct _PE_IMAGE_IMPORT_BY_NAME {
	WORD    Hint;
	char   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		UINT64 ForwarderString;  // PBYTE 
		UINT64 Function;         // PDWORD
		UINT64 Ordinal;
		UINT64 AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} PE_IMAGE_THUNK_DATA64,*PPE_IMAGE_THUNK_DATA64;

typedef struct _PE_IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;      // PBYTE 
		DWORD Function;             // PDWORD
		DWORD Ordinal;
		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} PE_IMAGE_THUNK_DATA32,*PPE_IMAGE_THUNK_DATA32;

typedef struct _PE_IMAGE_BASE_RELOCATION {
	DWORD   VirtualAddress;
	DWORD   SizeOfBlock;
	//  WORD    TypeOffset[1];
} PE_IMAGE_BASE_RELOCATION,*PPE_IMAGE_BASE_RELOCATION;

#define PE_RELOCA_RVA(data) ((data) & 0x0FFF)
#define PE_RELOCA_FLAG(data) (((data) & 0xF000) >> 12) 

#endif