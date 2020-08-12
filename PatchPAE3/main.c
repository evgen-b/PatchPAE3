#include <ph.h>
#include <imagehlp.h>
#include <time.h> //gmtime

#define ARG_OUTPUT 1
#define ARG_TYPE 2
#define ARG_HELP 3

#define TYPE_KERNEL 1
#define TYPE_LOADER 2
#define TYPE_HAL 3
#define TYPE_PAE 4
#define TYPE_SSE2NX 5
#define TYPE_HT 6
#define TYPE_SFC 7

typedef VOID (NTAPI *PPATCH_FUNCTION)(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    );

const PWSTR appver=L"0.0.0.48 beta-5";

PPH_STRING ArgInput;
PPH_STRING ArgOutput;
PPH_STRING ArgType;
PPH_STRING ArgHelpTopic;

ULONG ArgTypeInteger;

VOID Fail(
    __in PWSTR Message,
    __in ULONG Win32Result
    )
{
    if (Win32Result == 0)
        wprintf(L"%s\n", Message);
    else
        wprintf(L"%s: %s\n", Message, PhGetWin32Message(Win32Result)->Buffer);

    RtlExitUserProcess(STATUS_UNSUCCESSFUL);
}

ULONG GetBuildNumber(
    __in PWSTR FileName
    )
{
    ULONG buildNumber = 0;
    PVOID versionInfo;
    VS_FIXEDFILEINFO *rootBlock;
    ULONG rootBlockLength;

    versionInfo = PhGetFileVersionInfo(FileName);

    if (!versionInfo)
        return 0;

    if (VerQueryValue(versionInfo, L"\\", &rootBlock, &rootBlockLength) && rootBlockLength != 0)
        buildNumber = rootBlock->dwFileVersionLS >> 16;

    PhFree(versionInfo);

    return buildNumber;
}

VOID Patch(
    __in PPH_STRING FileName,
    __in PPATCH_FUNCTION Action
    )
{
    BOOLEAN success;
    PPH_ANSI_STRING ansiFileName;
    LOADED_IMAGE loadedImage;

    ansiFileName = PhCreateAnsiStringFromUnicodeEx(FileName->Buffer, FileName->Length);

    if (!MapAndLoad(ansiFileName->Buffer, NULL, &loadedImage, FALSE, FALSE))
        Fail(L"Unable to map and load image", GetLastError());

    success = FALSE;
    Action(&loadedImage, &success);
    // This will unload the image and fix the checksum.
    UnMapAndLoad(&loadedImage);

    PhDereferenceObject(ansiFileName);

    if (success)
        wprintf(L"Patched.\n");
    else
        Fail(L"Failed.", 0);
}

PUCHAR GetPEHdr(
    __in PLOADED_IMAGE LoadedImage
	)
{
    PUCHAR ptr = LoadedImage->MappedAddress;

	const USHORT e_magic=0x5a4d;
	const ULONG signature=0x4550;
	USHORT mz;
	ULONG pe;
	ULONG e_lfanew;

	mz=*(PUSHORT) ptr;
	//wprintf(L"mz: %x.\n", mz);
	if (mz != e_magic) return NULL;

	if (LoadedImage->SizeOfImage < 0x40) return NULL;
	e_lfanew=*(PULONG) (ptr+0x3c);
	//wprintf(L"offset: %d.\n", e_lfanew);

	if (LoadedImage->SizeOfImage < e_lfanew+0x18) return NULL; // signature+IMAGE_FILE_HEADER
	ptr=ptr+e_lfanew;
	pe=*(PULONG) ptr;
	//wprintf(L"pe: %x.\n", pe);
	if (pe != signature) return NULL;

	return ptr;

}

ULONG GetTimeDateStamp(
    __in PPH_STRING FileName
    )
{
    PPH_ANSI_STRING ansiFileName;
    LOADED_IMAGE loadedImage;
	PUCHAR pStamp;
	ULONG Stamp;
	
    ansiFileName = PhCreateAnsiStringFromUnicodeEx(FileName->Buffer, FileName->Length);

    if (!MapAndLoad(ansiFileName->Buffer, NULL, &loadedImage, FALSE, FALSE))
        Fail(L"Unable to map and load image", GetLastError());

	pStamp = GetPEHdr(&loadedImage);
	if (pStamp == NULL) return 0;
	Stamp = *(PULONG) (pStamp+8);

    UnMapAndLoad(&loadedImage);
    PhDereferenceObject(ansiFileName);

	return Stamp;
}

ULONG GetMachine(
    __in PPH_STRING FileName
    )
{
    PPH_ANSI_STRING ansiFileName;
    LOADED_IMAGE loadedImage;
	PUCHAR pMachine;
	ULONG Machine;
	
    ansiFileName = PhCreateAnsiStringFromUnicodeEx(FileName->Buffer, FileName->Length);

    if (!MapAndLoad(ansiFileName->Buffer, NULL, &loadedImage, FALSE, FALSE))
        Fail(L"Unable to map and load image", GetLastError());

	pMachine = GetPEHdr(&loadedImage);
	if (pMachine == NULL) return 0;
	Machine = *(PUSHORT) (pMachine+4);

    UnMapAndLoad(&loadedImage);
    PhDereferenceObject(ansiFileName);

	return Machine;
}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// KERNEL  _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

// ========================================
// ======================================== 2195 K-PARTS ==========
// ========================================

VOID PatchKernel2195Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
/*
8B5F64                 mov     ebx,[edi][064]
6A07                   push    7                    ; shl_7 = Datacenter (32 Gb)
8975F4                 mov     [ebp][-00C],esi
C7450800008000         mov     [ebp][8],00800000    ; 8*4k = 32 Gb
E8B979EBFF             call    Product_Suite_MASK
3C01                   cmp     al,1                 ; is Datacenter (7) edition?
7517                   jnz     test_Winnt           ; jump if no Datacenter --> NOP NOP
85DB                   test    ebx,ebx              ; with /3Gb switch in boot.ini you can use only 4*4k = 16 Gb
7507                   jnz     set_16Gb_with_3gb_switch
BE00008000             mov     esi,00800000         ; else set to max=32 Gb too
EB3B                   jmps    continue
set_16Gb_with_3gb_switch:
B800004000             mov     eax,00400000         ; 4*4k = 16 Gb
8BF0                   mov     esi,eax
894508                 mov     [ebp][8],eax
EB2F                   jmps    continue
test_WinNT:
813D********57006900   cmp     [00488E68],00690057  ; 0x00690057h means "Wi" in "WinNT" edition, not "ServerNT"
*/
{
    UCHAR target[] =
    {
// mov ebx,[edi][064]
0x8B, 0x5F, 0x64,
// push 7
0x6A, 0x07,
// mov [ebp][-00C],esi
0x89, 0x75, 0xF4,
// mov [ebp][8],0x00800000h
0xC7, 0x45, 0x08, 0x00, 0x00, 0x80, 0x00,
// call Product_Suite_MASK
0xE8, 0x00, 0x00, 0x00, 0x00,
// cmp al,1
0x3C, 0x01,
// jnz test_Winnt --> nop(2)
0x75, 0x17,
// test ebx,ebx
0x85, 0xDB,
// jnz set_16Gb_with_3gb_switch
0x75, 0x07,
// mov esi,0x00800000h
0xBE, 0x00, 0x00, 0x80, 0x00,
// jmps continue
0xEB //, 0x3B, ...
    };
    ULONG movOffset = 22;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 16 && j != 17 && j != 18 && j != 19) // ignore offset
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 0055FD40 -> nop(2)
            *(PUSHORT)&ptr[movOffset] = 0x013C;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel2195Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{//MmAddPhysicalMemoryEx
    UCHAR target[] =
    {
//push         7
0x6A, 0x07,
//call         0041679C ; ExVerifySuite
0xE8, 0xAE, 0x9D, 0xEB, 0xFF,
//cmp          al,1
0x3C, 0x01,
//jnz          0055C9F9 -> nop(2)
0x75, 0x07,
//mov          eax,00FFFFFF ; = (64 Gb - 4 Kb)
0xB8, 0xFF, 0xFF, 0xFF, 0x00,
//jmps         0055CA1A
0xEB
    };
    ULONG movOffset = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 4 && j != 5 && j != 6) // ignore offset
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz ... -> nop(2)
            *(PUSHORT)&ptr[movOffset] = 0x013C;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== K-2600 PARTS ==========
// ========================================

VOID PatchKernel2600Part1_v1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // cmp ebx,ecx
        0x3B, 0xFB,
        // jnc 0005754EC
        0x73, 0xD9,
        // push 7
        0x6A, 0x07,
        // call ExVerifySuite
        0xE8 //0x**, 0x**, 0x**, 0x**
        // cmp *l,1
        // 0x**, 0x01
        // jnz * 
        // 0x75, 0x07
        // ...
    };
    ULONG movOffset = 13;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 000575523 -> jz 000575523
            ptr[movOffset] = 0x74;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel2600Part1_v2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // cmp ebx,ecx
        0x3B, 0xD9,
        // jnc 0005754EC
        0x73, 0xDB,
        // push 7
        0x6A, 0x07,
        // call ExVerifySuite
        0xE8 //0x18, 0xC0, 0xEE, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz 000575523 
        // 0x75, 0x07
        // ...
    };
    ULONG movOffset = 13;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 000575523 -> jz 000575523
            ptr[movOffset] = 0x74;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel2600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // push 7
        0x6A, 0x07,
        // mov esi,eax
        0x8B, 0xF0,
        // mov [ebp][-4],ebx
        0x89, 0x5D, 0xFC,
        // mov [ebp][-8],edi
        0x89, 0x7D, 0xF8,
        // call ExVerifySuite
        0xE8 //0xE1, 0xFC, 0xE8, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz 0005D186E 
        // 0x75, 0x1B
        // ...
    };
    ULONG movOffset = 17;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 0005D186E -> jz 0005D186E
            ptr[movOffset] = 0x74;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 3790 SP0 K-PARTS ==========
// ========================================

VOID PatchKernel3790sp0_part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// evgen_b 3790 sp0
{
    UCHAR target[] =
    {
//mov          esi,[ebx][064]
0x8B, 0x73, 0x64,
//mov          edi,02000000 -> 10000000h
0xBF, 0x00, 0x00, 0x00, 0x02,
//push         7
0x6A, 0x07,
//mov          d,[ebp][-4],00100000 -> 10000000h
0xC7, 0x45, 0xFC, 0x00, 0x00, 0x10, 0x00,
//mov          [ebp][-8],edi
0x89, 0x7D, 0xF8,
//call         ExVerifySuite
0xE8, 0x37, 0xE6, 0xE7, 0xFF, //21-22-23-24
//cmp          al,1
0x3C, 0x01,
//jnz          005E5848 -> nop(2)
0x75, 0x09,
//test         esi,esi
0x85, 0xF6,
//jnz          005E586A -> nop(2)
0x75, 0x27,
//mov          [ebp][-4],edi
0x89, 0x7D, 0xFC,
//jmps        005E5889
0xEB
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j]
				&& j != 2 && j != 12 && j != 19 && j != 21 && j != 22 && j != 23 && j != 24 && j != 32 && j != 35) // ignore offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

			*(PULONG)&ptr[movOffset+ 4] = 0x10000000;
			*(PULONG)&ptr[movOffset+13] = 0x10000000;
			*(PUSHORT)&ptr[movOffset+27] = 0x9090;
			*(PUSHORT)&ptr[movOffset+31] = 0x9090;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790sp0_part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// evgen_b 3790 sp0
{
    UCHAR target[] =
    {//MmAddPhysicalMemoryEx
//push         7
0x6A, 0x07,
//call         ExVerifySuite
0xE8, 0x3B, 0x6B, 0xEE, 0xFF,
//cmp          al,1
0x3C, 0x01,
//jnz         .00057D342 -> nop
0x75, 0x07,
//mov          eax,02000000 ; * 4Kb page = 128 Gb enterprise
0xB8, 0x00, 0x00, 0x00, 0x02,
//jmps         0057D363
0xEB
    };
    ULONG movOffset = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j]
				&& j != 3 && j != 4 && j != 5 && j != 6 && j != 10) // ignore offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

			*(PUSHORT)&ptr[movOffset] = 0x9090;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 3790 SP1/SP2 K-PARTS ==========
// ========================================

VOID PatchKernel3790Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : BF 00 00 00 02 6A 0A C7 45 FC 00 00 10 00
	// Replacepattern : ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? 00 10
{
    UCHAR target[] =
    {
        // mov edi, 02.00.00.00 -> mov edi, 10.00.00.00
        0xBF, 0x00, 0x00, 0x00, 0x02,
        // push 0A
        0x6A, 0x0A,
        // mov [ebp][-4], 00.10.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x10, 0x00
        // mov [ebp][-8],edi
        // 0x89, 0x7D, 0xF8,
        // call ExVerifySuite
        // 0xE8, 0xCC, 0xD3, 0xE6, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz ...
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  3] = 0x00;
            ptr[movOffset +  4] = 0x10;
            ptr[movOffset + 12] = 0x00;
            ptr[movOffset + 13] = 0x10;
			//wprintf(L"part1\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko (pattern fix by evgen_b)
	// Searchpattern  : 75 09 C7 45 FC 00 00 08 00 EB 69 6A 07 E8
	// Replacepattern : ?? ?? ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ??
{
    UCHAR target[] =
    {
        // jnz 000612D97
        0x75, 0x09,
        // mov [ebp][-4], 00.08.00.00 -> mov [	ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x08, 0x00,
        // jmps 000612E00
        0xEB, 0x69,
        // push 07
        0x6A, 0x07,
        // call ExVerifySuite
        0xE8 // 0xB8, 0xD3, 0xE6, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz ...
    };
    ULONG movOffset = 7;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset]   = 0x00;
            ptr[movOffset+1] = 0x10;
			//wprintf(L"part2\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part3(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : C7 45 FC 00 00 00 01 74 33 B8 00 00 40 00
	// Replacepattern : ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? 00 10
{
    UCHAR target[] =
    {
        // mov [ebp][-4], 01.00.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x01,
        // jz 00612E00
        0x74, 0x33,
		// mov eax, 00.40.00.00 -> mov eax, 10.00.00.00
		0xB8, 0x00, 0x00, 0x40, 0x00
		// mov [ebp][-4],eax
		// 0x89, 0x45, 0xFC,
		// mov [ebp][-8],eax
		// 0x89, 0x45, 0xF8,
        // jmps 000612E00
        // 0xEB, 0x26
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  5] = 0x00;
            ptr[movOffset +  6] = 0x10;
            ptr[movOffset + 12] = 0x00;
            ptr[movOffset + 13] = 0x10;
			//wprintf(L"part3\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part4(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : C7 45 FC 00 00 10 00 74 10 C7 45 F8 00 00 40 00
	// Replacepattern : ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ?? ?? ?? 00 10
{
    UCHAR target[] =
    {
        // mov [ebp][-4], 00.10.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x10, 0x00,
        // jz 00612E00
        0x74, 0x10,
		// mov [ebp][-8], 00.40.00.00 -> mov [ebp][-8], 10.00.00.00
		0xC7, 0x45, 0xF8, 0x00, 0x00, 0x40, 0x00
		// jmps 00612E00
		// 0xEB, 0x07
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  5] = 0x00;
            ptr[movOffset +  6] = 0x10;
            ptr[movOffset + 14] = 0x00;
            ptr[movOffset + 15] = 0x10;
			//wprintf(L"part4\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part5(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : C7 45 F8 00 00 10 00 33 F6 83 C3 08 8B 03
	// Replacepattern : ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ?? ?? ??
{
    UCHAR target[] =
    {
        // mov [ebp][-8], 00.10.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xF8, 0x00, 0x00, 0x10, 0x00,
        // xor esi,esi
        0x33, 0xF6,
		// add ebx,8
		0x83, 0xC3, 0x08,
		// mov eax,[ebx]
		0x8B, 0x03
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  5] = 0x00;
            ptr[movOffset +  6] = 0x10;
			//wprintf(L"part5\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790sp1sp2_part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;
    BOOLEAN success3 = FALSE;
    BOOLEAN success4 = FALSE;
    BOOLEAN success5 = FALSE;

    PatchKernel3790Part1(LoadedImage, &success1);
    PatchKernel3790Part2(LoadedImage, &success2);
    PatchKernel3790Part3(LoadedImage, &success3);
    PatchKernel3790Part4(LoadedImage, &success4);
    PatchKernel3790Part5(LoadedImage, &success5);
    *Success = success1 && success2 && success3 && success4 && success5;
}

VOID PatchKernel3790sp1sp2_part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// evgen_b 3790.5580 sp1sp2: in original work by Oliver/Remko not implemented!
{
    UCHAR target[] =
    {//MmAddPhysicalMemoryEx
//push         00A
0x6A, 0x0A,
//call         ExVerifySuite
0xE8, 0x50, 0x7B, 0xED, 0xFF,
//cmp          al,1
0x3C, 0x01,
//jnz          005AA4B5
0x75, 0x07,
//mov          eax,00080000
0xB8, 0x00, 0x00, 0x08, 0x00,
//jmps         005AA4EE
0xEB
	};
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j]
				&& j != 3 && j != 4 && j != 5 && j != 6 && j != 10) // ignore offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

			*(PUSHORT)&ptr[movOffset+9] = 0x9090;
			*(PULONG)&ptr[movOffset+12] = 0x02000000;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 4093 K-PART ==========
// ========================================

VOID PatchKernel4000Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// evgen_b
{
    UCHAR target[] =
    {
// push 7 'DataCenter
0x6A, 0x07,
//call ExVerifySuite
0xE8, 0, 0, 0, 0,
//cmp al,1
0x3C, 0x01,
//jnz NotDataCenter ' -> nop
0x75, 0,
//mov eax,002000000 ' 128 Gb (4K pages)
0xB8, 0x00, 0x00, 0x00, 0x02,
//jmps continue
0xEB //, 0
    };
    ULONG movOffset = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j]
				&& j != 3 && j != 4 && j != 5 && j != 6
				&& j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz ... -> nop
            ptr[movOffset] = 0x90;
            ptr[movOffset+1] = 0x90;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel4000Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// evgen_b
{
    UCHAR target[] =
    {
//push 7 'DataCenter
0x6A, 0x07,
//call ExVerifySuite
0xE8, 0, 0, 0, 0,
//cmp al,1
0x3C, 0x01,
//jnz NotDataCenter ' -> nop
0x75, 0,
//test esi,esi ' boot.ini /3gb option?
0x85, 0xF6,
//jnz Mem16GbMax
0x75, 0,
//mov [ebp][-4],edi
0x89, 0x7D, 0xFC,
//jmps continue
0xEB //, 0 
    };
    ULONG movOffset = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j]
				&& j != 3 && j != 4 && j != 5 && j != 6
				&& j != 10
				&& j != 14) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz ... -> nop
            ptr[movOffset] = 0x90;
            ptr[movOffset+1] = 0x90;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 7600 K-PART ==========
// ========================================

VOID PatchKernel6000_7601(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did ZwQueryLicenseValue succeed?
        0x85, 0xc0,
        // jl short loc_75644b ; if it didn't go to the default case
        0x7c, 0x11,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_75644b ; if it's zero, go to the default case
        0x74, 0x0a,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // 0xa3, 0x2c, 0x76, 0x53, 0x00
        // jmp short loc_756455 ; go to the next bit
        // 0xeb, 0x0a
        // loc_75644b: mov ds:_MiTotalPagesAllowed, 0x80000
        // 0xc7, 0x05, 0x2c, 0x76, 0x53, 0x00, 0x00, 0x00, 0x08, 0x00
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 9200 K-PART ==========
// ========================================

VOID PatchKernel9200(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_914314 ; if it didn't go to the default case
        0x78, 0x4c,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_914314 ; if it's zero, go to the default case
        0x74, 0x45,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 6 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    //ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0 &&
                    ptr[k + 5] == 0x74
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 9600 K-PART ==========
// ========================================

VOID PatchKernel9600_10140(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    ) // up to windows 10 beta build ~10140
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_923593 ; if it didn't go to the default case
        0x78, 0x50,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_923593 ; if it's zero, go to the default case
        0x74, 0x49,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 6 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    //ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0 &&
                    ptr[k + 5] == 0x74
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 17763 K-PART ==========
// ========================================

VOID PatchKernel10240_16299(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// 10240 - win10 RTM (evgen_b)
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target1[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_009BCC3B ; if it didn't go to the default case
        0x78, 0x46,
        // mov esi, [ebp-4] ; get the returned memory limit
        0x8b, 0x75, 0xfc,
        // test esi, esi ; is it non-zero?
        0x85, 0xf6,
        // jz short loc_009BCC3B ; if it's zero, go to the default case
        0x74, 0x3f,
        // shl esi, 8 ; multiply by 256
        0xc1, 0xe6, 0x08
        // mov ds:_MiTotalPagesAllowed, esi ; store in MiTotalPagesAllowed
        // ...
    };

    UCHAR target2[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_009BCC32 ; if it didn't go to the default case
        0x78, 0x0d,
        // mov ecx, [ebp-4] ; get the returned memory limit
        0x8b, 0x4d, 0xfc,
        // test ecx, ecx ; is it non-zero?
        0x85, 0xc9,
        // jz short loc_009BCC32 ; if it's zero, go to the default case
        0x74, 0x06,
        // shl ecx, 8 ; multiply by 256
        0xc1, 0xe1, 0x08
        // mov ds:_MiTotalPagesAllowed, ecx ; store in MiTotalPagesAllowed
        // ...
    };

    ULONG movOffset1 = 4;
    ULONG movOffset2 = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, m, n;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target1); i++)
    {
        for (j = 0; j < sizeof(target1); j++)
        {
            if (ptr[j] != target1[j] && j != 3 && j != 6 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target1))
        {
            // Found it. Patch the code.

            // mov esi, [ebp+var_4] -> mov esi, 0x020000
            ptr[movOffset1] = 0xbe;
            *(PULONG)&ptr[movOffset1 + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset1 + 5] = 0x90;
            ptr[movOffset1 + 6] = 0x90;

            // Do the same thing to the next mov ecx, [ebp+var_4] 
            // occurence.
            for (m = 0; m < 100; m++)
            {
				for (n = 0; n < sizeof(target2); n++)
				{
					if (ptr[n] != target2[n] && n != 3 && n != 6 && n != 10) // ignore jump offsets
						break;
				}

				if (n == sizeof(target2))
                {
                    // mov ecx, [ebp+var_4] -> mov ecx, 0x020000
                    ptr[movOffset2] = 0xb9;
                    *(PULONG)&ptr[movOffset2 + 1] = 0x20000;
                    // nop out the jz
                    ptr[movOffset2 + 5] = 0x90;
                    ptr[movOffset2 + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
				ptr++;
            }

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 2195 K-MAIN ==========
// ========================================

VOID PatchKernel_1999_2195_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{//evgen_b
    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchKernel2195Part1(LoadedImage, &success1);
    PatchKernel2195Part2(LoadedImage, &success2);

    *Success = success1 && success2;

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchKernel2600Part1_v1(LoadedImage, &success1);
		if (!success1)
		{
			PatchKernel2600Part1_v2(LoadedImage, &success1);
		}
		PatchKernel2600Part2(LoadedImage, &success2);
		*Success = success1 && success2;
	}


}

// ========================================
// ======================================== 2600 K-MAIN ==========
// ========================================

VOID PatchKernel_2196_2600_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchKernel2600Part1_v1(LoadedImage, &success1);
	if (!success1)
	{
		PatchKernel2600Part1_v2(LoadedImage, &success1);
	}
    PatchKernel2600Part2(LoadedImage, &success2);
    *Success = success1 && success2;

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchKernel2195Part1(LoadedImage, &success1);
		PatchKernel2195Part2(LoadedImage, &success2);

		*Success = success1 && success2;
	}

	if (!(*Success))
	{
		PatchKernel3790sp0_part1(LoadedImage, &success1);
		if (success1)
    		{
			PatchKernel3790sp0_part2(LoadedImage, &success2);
			*Success = success2;
			return;
			}
		PatchKernel3790sp1sp2_part1(LoadedImage, &success1);
		if (success1)
    		{
			PatchKernel3790sp1sp2_part2(LoadedImage, &success2);
			*Success = success2;
			return;
			}
	}


}

// ========================================
// ======================================== 3790 K-MAIN ==========
// ========================================

VOID PatchKernel_2601_3790_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchKernel3790sp1sp2_part1(LoadedImage, &success1);
	if (success1)
    	{
        PatchKernel3790sp1sp2_part2(LoadedImage, &success2);
	    *Success = success2;
		return;
        }

	PatchKernel3790sp0_part1(LoadedImage, &success1);
	if (success1)
    	{
        PatchKernel3790sp0_part2(LoadedImage, &success2);
	    *Success = success2;
		return;
        }

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchKernel2600Part1_v1(LoadedImage, &success1);
		if (!success1)
		{
			PatchKernel2600Part1_v2(LoadedImage, &success1);
		}
		PatchKernel2600Part2(LoadedImage, &success2);
		*Success = success1 && success2;
	}

	if (!(*Success))
	{
		PatchKernel4000Part1(LoadedImage, &success1);
		PatchKernel4000Part2(LoadedImage, &success2);
		*Success = success1 && success2;
	}

}

// ========================================
// ======================================== 4093 K-MAIN ==========
// ========================================

VOID PatchKernel_3791_5999_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchKernel4000Part1(LoadedImage, &success1);
    PatchKernel4000Part2(LoadedImage, &success2);
    *Success = success1 && success2;

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchKernel3790sp1sp2_part1(LoadedImage, &success1);
		if (success1)
    		{
			PatchKernel3790sp1sp2_part2(LoadedImage, &success2);
			*Success = success2;
			return;
			}

		PatchKernel3790sp0_part1(LoadedImage, &success1);
		if (success1)
    		{
			PatchKernel3790sp0_part2(LoadedImage, &success2);
			*Success = success2;
			return;
			}
	}

	if (!(*Success))
	{
	    PatchKernel6000_7601(LoadedImage, &success1);
	    *Success = success1;
	}

}

// ========================================
// ======================================== 7600 K-MAIN ==========
// ========================================

VOID PatchKernel_6000_8399_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;

    PatchKernel6000_7601(LoadedImage, &success1);
	if (!success1)
    	{
		// merge with new kernel win8 pre-beta: 7850, 7955,8102,8250,...
        PatchKernel9200(LoadedImage, &success1);
        }
    *Success = success1;

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		BOOLEAN success2 = FALSE;
		PatchKernel4000Part1(LoadedImage, &success1);
		PatchKernel4000Part2(LoadedImage, &success2);
		*Success = success1 && success2;
	}

}

// ========================================
// ======================================== 9200 K-MAIN ==========
// ========================================

VOID PatchKernel_8400_9200_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;

    PatchKernel9200(LoadedImage, &success1);
    *Success = success1;

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchKernel6000_7601(LoadedImage, &success1);
	    *Success = success1;
	}

	if (!(*Success))
	{
		PatchKernel9600_10140(LoadedImage, &success1);
		*Success = success1;
	}

}

// ========================================
// ======================================== 9600 K-MAIN ==========
// ========================================

VOID PatchKernel_9201_9600_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;

    PatchKernel9600_10140(LoadedImage, &success1);
    *Success = success1;

    // if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchKernel9200(LoadedImage, &success1);
		*Success = success1;
	}

	if (!(*Success))
	{
	    PatchKernel10240_16299(LoadedImage, &success1);
		*Success = success1;
	}

}

// ========================================
// ======================================== 17763 K-MAIN ==========
// ========================================

VOID PatchKernel_9601_17623_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;

    PatchKernel10240_16299(LoadedImage, &success1);
	if (!success1)
    	{
        PatchKernel9600_10140(LoadedImage, &success1);
        }
    *Success = success1;

    // if fail, try to apply nearest patch: for previous and next file version

	// nothing

}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// LOADER  _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

// ========================================
// ======================================== 6000 L-PART ==========
// ========================================

VOID PatchLoader6000_SPx(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
/*
wj32: BlImgLoadPEImageEx

There is a function called ImgpValidateImageHash. We are 
going to patch BlImgLoadPEImageEx so that it doesn't care 
what the result of the function is.

sub esi, [ebx+4]
0x2b, 0x73, 0x04,
push eax
0x50,
add esi, [ebp+var_18]
0x03, 0x75, 0xe8,
lea eax, [ebp+Source1]
0x8d, 0x45, 0x8c,
push eax
0x50,
push esi
0x56,
mov eax, ebx
0x8b, 0xc3
call _ImgpValidateImageHash@16
0xe8, 0x59, 0x0b, 0x00, 0x00
mov ecx, eax ; copy return status into ecx
test ecx, ecx ; did ImgpValidateImageHash succeed?
mov [ebp+arg_0], ecx ; store the NT status into a variable
jge short loc_42109f ; if the function succeeded, go there

Found it. Patch the code.
mov ecx, eax -> mov [ebp+arg_0], 0
0x8b, 0xc8 -> 0xc7, 0x45, 0x08, 0x00, 0x00, 0x00, 0x00
jge short loc_42109f -> jmp short loc_42109f
0x85, 0xc9 -> 0xeb, 0xc9
*/
{
// winload from Vista SP0 very different... universal template for SP0...SP2 (evgen_b):
// E8 ** ** ** **     call ImgpValidateImageHash(...)
// 8B C8              mov  ecx,eax -> 31C9 xor ecx,ecx
// ** **              test ecx,ecx / cmp ecx,ebx
// 89 4D 08           mov [ebp][8],ecx
// 7D **              jge @+26/jge @+27 -> EB** jmps _bypass
// 8B 45 24           mov eax,[ebp][024]
// ** **              test eax,eax / cmp eax,ebx
// 74 03              jz @+3
    UCHAR target[] =
    {
        // call ImgpValidateImageHash(...)
        0xE8, 0x00, 0x00, 0x00, 0x00,
        // mov  ecx,eax -> 31C9 xor ecx,ecx
        0x8B, 0xC8,
        // test ecx,ecx / cmp ecx,ebx
        0x00, 0x00,
        // mov [ebp][8],ecx
        0x89, 0x4D, 0x08,
        // jge @+26/jge @+27 -> EB** jmps _bypass
        0x7D, 0x00,
        // mov eax,[ebp][024]
        0x8B, 0x45, 0x24,
        // test eax,eax / cmp eax,ebx
        0x00, 0x00,
        // jz @+3
        0x74, 0x03
        // ...
    };
    ULONG movOffset = 5;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 1 && j != 2 && j != 3 && j != 4 && j != 7 && j != 8 && j != 13 && j != 17 && j != 18) // ignore **
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov  ecx,eax -> xor ecx,ecx
            ptr[movOffset    ] = 0x31;
            ptr[movOffset + 1] = 0xC9;
	        // jge _bypass -> jmps _bypass
            ptr[movOffset + 7] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 7600 SP0 L-PART ==========
// ========================================

VOID PatchLoader7600_SP0(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch BlImgLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax, [ebp+Source1]
		//0x8d, 0x85, **, **, 0xff, 0xff
        0x8d, 0x85, 0x94, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_12c]
		//0xff, 0xb5, **, **, 0xff, 0xff
        0xff, 0xb5, 0xd4, 0xfe, 0xff, 0xff,
        // mov eax, [ebp+var_24]
		//0x8b, 0x45, **
        0x8b, 0x45, 0xdc,
        // push [ebp+var_18]
		//0xff, 0x75, **
        0xff, 0x75, 0xe8,
        // call _ImgpValidateImageHash@24
        0xe8 //, 0x63, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428ee5 ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 3 && j != 4 && j != 10 && j != 11 && j != 16 && j != 19) // ignore **

                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428ee5 -> jmp short loc_428ee5
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 7000 beta L-PART ==========
// ========================================

VOID PatchLoader7000_beta(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax,[ebp][-174]
		//0x8d, 0x85, **, **, 0xff, 0xff
        0x8d, 0x85, 0x8c, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push d,[ebp][-134]
		//0xff, 0xb5, **, **, 0xff, 0xff
        0xff, 0xb5, 0xcc, 0xfe, 0xff, 0xff,
        // mov eax,[ebp][-038]
		//0x8b, 0x45, **
        0x8b, 0x45, 0xc8,
        // push d,[ebp][-01C]
		//0xff, 0x75, **
        0xff, 0x75, 0xe4,
		//push d,[esi][00C]
		//FF, 0x76, **
		0xFF, 0x76, 0x0C,
        // call _ImgpValidateImageHash
        0xe8 //, 0x51, 0x05, 0x00, 0x00,
        // cmp eax,edi
        // 3B C7
        // mov [ebp][-8],eax
        // 89 45 F8
        // jge 00428216; if the function succeeded, go there -> jmp 00428216
        // 7D 28

			// Note that we don't need to update var [ebp][-8] as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

    };
    ULONG jgeOffset = 33;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 3 && j != 4 && j != 10 && j != 11 && j != 16 && j != 19 && j != 22) // ignore **

                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jge short ... -> jmp short ...
            // 0x7d, 0x28 -> 0xeb, 0x28
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 6801 beta L-PART ==========
// ========================================

VOID PatchLoader6801_beta(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
// Vista winload very different... (evgen_b):
// E8 ** ** ** **     call ImgpValidateImageHash(...)
// 8B D0                mov edx,eax -> ??? xor edx,edx ([ebp][-528] - temp var, no need to patch)
// ** **       3B D7 cmp edx,edi
// 89 95 ** ** FF FF mov [ebp][-528],edx
// 7D **                  jge @+3a -> EB** jmps _bypass
// 8B 85 ** ** FF FF mov eax,[ebp][-588]
// ** **      3B C7 cmp eax,edi
// 74 03              jz @+3
    UCHAR target[] =
    {
        // call ImgpValidateImageHash(...)
        0xE8, 0x00, 0x00, 0x00, 0x00,
        // mov edx,eax
        0x8B, 0xD0,
        // 3B D7 cmp edx,edi
        0x00, 0x00,
        // 89 95 ** ** FF FF mov [ebp][-528],edx
        0x89, 0x95, 0x00, 0x00, 0xFF, 0xFF,
        //  jge @+3a -> EB** jmps _bypass
        0x7D, 0x00,
        // 8B 85 ** ** FF FF mov eax,[ebp][-588]
        0x8B, 0x85, 0x00, 0x00, 0xFF, 0xFF,
        // 3B C7 cmp eax,edi
        0x00, 0x00,
        // jz @+3
        0x74, 0x03
        // ...
    };
    ULONG movOffset = 15;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 1 && j != 2 && j != 3 && j != 4 && j != 7 && j != 8 && j != 11 && j != 12 && j != 16 && j != 19 && j != 20 && j != 23 && j != 24) // ignore **
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

	        // jge _bypass -> jmps _bypass
            ptr[movOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 7601 SP1 L-PART ==========
// ========================================

VOID PatchLoader7601_noKB(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax, [ebp+Source1]
        0x8d, 0x85, 0x94, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_12c]
        0xff, 0xb5, 0xd4, 0xfe, 0xff, 0xff,
        // mov eax, [ebp+var_24]
        0x8b, 0x45, 0xdc,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // call _ImgpValidateImageHash@24
        0xe8 //, 0x63, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428f57 ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			//2018-04-01 fix1:
            if (ptr[j] != target[j] && j != 3 && j != 4 && j != 10 && j != 11 && j != 16 && j != 19)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428f57 -> jmp short loc_428f57
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 7601 PRE-SP2 L-PART ==========
// ========================================

VOID PatchLoader7601_KB3033929(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// fix for KB3033929 (evgen_b)
{
	// ImgpLoadPEImage

	// There is a function called ImgpValidateImageHash. We are 
	// going to patch ImgpLoadPEImage so that it doesn't care 
	// what the result of the function is.

	UCHAR target[] =
	{
		// push d,[ebp][-014]
		0xFF, 0x75, 0xEC,
		// lea eax,[ebp][-00000017C] ; [ebp+Source1]
		0x8D, 0x85, 0x84, 0xFE, 0xFF, 0xFF,
		// push eax
		0x50,
		// push d,[ebp][-028]
		0xFF, 0x75, 0xD8,
		// mov eax,[ebp][8]
		0x8B, 0x45, 0x08,
		// push d,[eax][00C]
		0xFF, 0x70, 0x0C,
		// lea eax,[ebp][-064]
		0x8D, 0x45, 0x9C,
		// call _ImgpValidateImageHash@24
		0xE8 //, 5F, 05, 00, 00
		// mov [ebp][-8],eax ; copy return status into var_8
		// 0x89, 0x45, 0xf8
		// test eax, eax ; did ImgpValidateImageHash succeed?
		// 0x85, 0xc0
		// jge short 000428EDE ; if the function succeeded, go there
		// 0x7d, 0x2e -> EB, 2E
	};
	ULONG jgeOffset = 32;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			//2018-04-01 fix2:
			if (ptr[j] != target[j] && j != 2 && j != 5 && j != 6 && j != 12 && j != 15 && j != 18 && j != 21)
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.
			// Note that we don't need to update var_8 as it is 
			// a temporary status variable which will be overwritten 
			// very shortly.

			// jge short 000428EDE -> jmp short 000428EDE
			// 0x7d, 0x2e -> 0xeb, 0x2e
			ptr[jgeOffset] = 0xeb;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

// ========================================
// ======================================== 8250 L-PART ==========
// ========================================

VOID PatchLoader8250Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{//evgen_b:
// ImgpLoadPEImage
    UCHAR target[] =
    {
//push         d,[ebp][030]
0xFF, 0x75, 0x30,
//mov          edi,[ebp][8]
0x8B, 0x7D, 0x08,
//
0x50,
//lea          eax,[ebp][-1C4]
0x8D, 0x85, 0x3C, 0xFE, 0xFF, 0xFF,
//push         eax
0x50,
//push         esi
0x56,
//push         d,[ebp][-024]
0xFF, 0x75, 0xDC,
//mov          esi,[ebp][-00C]
0x8B, 0x75, 0xF4,
//push         d,[edi][00C]
0xFF, 0x77, 0x0C,
//mov          eax,esi
0x8B, 0xC6,
//call        00431B31 ; ImgpValidateImageHash
0xE8 //, 0x15, 0x06, 0x00, 0x00,
//mov          ebx,eax
//0x8B, 0xD8,
//test         ebx,ebx
//0x85, 0xDB,
//jns         0043154E ...  -> jmp short
//0x79, 0x2C
    };
    ULONG jnsOffset = 35;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 2 && j != 5 && j != 9 && j != 10 && j != 17 && j != 20 && j != 23)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short ... -> jmp short ...
            // 0x79, xx -> 0xEB, xx
            ptr[jnsOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchLoader8250Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{//evgen_b:
// BlImgLoadImageWithProgressEx
    UCHAR target[] =
    {
//lea          edx,[ebp][-068]
//8D 55 98
//lea          ecx,[ebp][-140]
//8D 8D C0 FE FF FF
//call        0047DAE3
//E8 60 D2 04 00
//push         0
0x6A, 0x00,
//push         2
0x6A, 0x02,
//lea          eax,[ebp][-068]
0x8D, 0x45, 0x98,
//push         eax
0x50,
//push         d,[ebp][-140]
0xFF, 0xB5, 0xC0, 0xFE, 0xFF, 0xFF,
//xor          eax,eax
0x33, 0xC0,
//push         0
0x6A, 0x00,
//push         d,[ebp][010]
0xFF, 0x75, 0x10,
//call        00431B31 ; ImgpValidateImageHash
0xE8 //, 0x94, 0x12, 0x00, 0x00,
//mov          edi,eax
//0x8B, 0xF8,
//test         edi,edi
//0x85, 0xFF,
//jns         004308B5 -> jmp short ...
//0x79, 0x12
    };
    ULONG jnsOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 6 && j != 10 && j != 11 && j != 20)
                break;
        }

        if (j == sizeof(target))
        {
            // jns short ... -> jmp short ...
            // 0x79, xx -> 0xEB, xx
            ptr[jnsOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 8400 L-PART ==========
// ========================================

VOID PatchLoader8400Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage
    UCHAR target[] =
    {
//push         eax
0x50,
//push         d,[ebp][-018]
0xFF, 0x75, 0xE8,
//lea          eax,[ebp][-00000013C]
0x8D, 0x85, 0xC4, 0xFE, 0xFF, 0xFF,
//push         eax
0x50,
//push         ecx
0x51,
//push         d,[esi][00C]
0xFF, 0x76, 0x0C,
//lea          eax,[ebp][-06C]
0x8D, 0x45, 0x94,
//call         ImgpValidateImageHash
0xE8 //,0,0,0,0
// 8B D8 mov          ebx,eax
// 85 DB test         ebx,ebx
// 79 2A jns          ...  -> jmp short (0xEB, 0x2A)
    };
    ULONG jnsOffset = 27;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 6 && j != 7 && j != 14 && j != 17)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short ... -> jmp short ...
            // 0x79, xx -> 0xEB, xx
            ptr[jnsOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchLoader8400Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgressEx
    UCHAR target[] =
    {
//push         0
0x6A, 0x00,
//push         d,[ebp][-00C]
0xFF, 0x75, 0xF4,
//lea          eax,[ebp][-070]
0x8D, 0x45, 0x90,
//push         eax
0x50,
//push         d,[ebp][-000000148]
0xFF, 0xB5, 0xB8, 0xFE, 0xFF, 0xFF,
//xor          eax,eax
0x33, 0xC0,
//push         d,[ebp][010]
0xFF, 0x75, 0x10,
//call         ImgpValidateImageHash
0xE8 //, 0,0,0,0
//8B F8 mov          edi,eax
//85 FF test         edi,edi
//79 1A jns          ...  -> jmp short (0xEB, 0x1A)
    };
    ULONG jnsOffset = 29;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 4 && j != 7 && j != 11 && j != 12 && j != 19)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short ... -> jmp short ...
            // 0x79, xx -> 0xEB, xx
            ptr[jnsOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 9200 L-PART ==========
// ========================================

VOID PatchLoader9200Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // push eax
        0x50,
        // push [ebp+var_14]
        0xff, 0x75, 0xec,
        // lea eax, [ebp+var_13c]
        0x8d, 0x85, 0xc4, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push ecx
        0x51,
        // push dword ptr [esi+0ch]
        0xff, 0x76, 0x0c,
        // lea eax, [ebp+var_74]
        0x8d, 0x45, 0x8c,
        // call _ImgpValidateImageHash@24
        0xe8 //, 0x4f, 0x06, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_43411d ; if the function succeeded, go there
        // 0x79, 0x2c
    };
    ULONG jnsOffset = 27;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 6 && j != 7 && j != 14 && j != 17)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short loc_43411d -> jmp short loc_43411d
            // 0x79, 0x2c -> 0xeb, 0x2c
            ptr[jnsOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9200Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgressEx

    UCHAR target[] =
    {
        // push 0
        0x6a, 0x00,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // lea eax, [ebp+var_78]
        0x8d, 0x45, 0x88,
        // push eax
        0x50,
        // push [ebp+var_150]
        0xff, 0xb5, 0xb0, 0xfe, 0xff, 0xff,
        // xor eax, eax
        0x33, 0xc0,
        // push [ebp+arg_8]
        0xff, 0x75, 0x10,
        // call _ImgpValidateImageHash@24
        0xe8 //, 0xe6, 0x13, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_433374 ; if the function succeeded, go there
        // 0x79, 0x1a
    };
    ULONG movOffset = 25;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 4 && j != 7 && j != 11 && j != 12 && j != 19)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov ebx, eax -> xor ebx, ebx
            // 0x8b, 0xd8 -> 0x33, 0xdb
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xdb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 7850 L-PART ==========
// ========================================

VOID PatchLoader7850(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{//evgen_b:
	UCHAR target[] =
	{
//build 7850:
//or eax,2
0x83, 0xC8, 0x02,
//mov esi,[ebp][8]
0x8B, 0x75, 0x08,
//push eax
0x50,
//lea eax,[ebp][-1B4]
0x8D, 0x85, 0x4C, 0xFE, 0xFF, 0xFF,
//push eax
0x50,
//push d,[ebp][-174]
0xFF, 0xB5, 0x8C, 0xFE, 0xFF, 0xFF,
//mov eax,[ebp][-8]
0x8B, 0x45, 0xF8,
//push d,[ebp][-020]
0xFF, 0x75, 0xE0,
//push d,[esi][0C]
0xFF, 0x76, 0x0C,
//call 042D132 ; ImgpValidateImageHash
0xE8 //, 0xE4, 0x05, 0x00, 0x00,
//mov ebx,eax
//0x8B, 0xD8,
//test ebx,ebx
//0x85, 0xDB,
//jns 0042CB80 -> EB, 2C jmp...
//0x79, 0x2C,
//mov eax,[ebp][020]
//0x8B, 0x45, 0x20,
//test eax,eax
//0x85, 0xC0
	};
	ULONG jgeOffset = 38;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 5 && j != 9 && j != 10 && j != 16 && j != 17 && j != 22 && j != 25 && j != 28)
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.
			// Note that we don't need to update var_8 as it is 
			// a temporary status variable which will be overwritten 
			// very shortly.

			//jns ... -> EB, 2C jmp...
			ptr[jgeOffset] = 0xeb;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

// ========================================
// ======================================== 9755 L-PART ==========
// ========================================

VOID PatchLoader7955(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{//evgen_b:
	UCHAR target[] =
	{
//build 7955:
//push         d,[ebp][030]
0xFF, 0x75, 0x30,
//mov          esi,[ebp][8]
0x8B, 0x75, 0x08,
//push         eax
0x50,
//lea          eax,[ebp][-0000001AC]
0x8D, 0x85, 0x54, 0xFE, 0xFF, 0xFF,
//push         eax
0x50,
//push         edx
0x52,
//push         d,[ebp][-024]
0xFF, 0x75, 0xDC,
//mov          eax,edi
0x8B, 0xC7,
//push         d,[esi][00C]
0xFF, 0x76, 0x0C,
//call        .00042DE21 ; ImgpValidateImageHash
0xE8 //, 0x44, 0x06, 0x00, 0x00,
//mov          ebx,eax
//0x8B, 0xD8,
//test         ebx,ebx
//0x85, 0xDB,
//jns         .00042D80B -> EB, 28 jmp...
//0x79, 0x28
	};
	ULONG jgeOffset = 32;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 2 && j != 5 && j != 9 && j != 10 && j != 17 && j != 22 && j != 25 && j != 28)
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.
			// Note that we don't need to update var_8 as it is 
			// a temporary status variable which will be overwritten 
			// very shortly.

			//jns ... -> EB, 2C jmp...
			ptr[jgeOffset] = 0xeb;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

// ========================================
// ======================================== 8100 L-PART ==========
// ========================================

VOID PatchLoader8100(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{//evgen_b:
	UCHAR target[] =
	{

//build 8102:
//push         d,[ebp][030]
0xFF, 0x75, 0x30,
//mov          esi,[ebp][8]
0x8B, 0x75, 0x08,
//push         eax
0x50,
//lea          eax,[ebp][-0000001AC]
0x8D, 0x85, 0x54, 0xFE, 0xFF, 0xFF,
//push         eax
0x50,
//mov          eax,[ebp][-8]
0x8B, 0x45, 0xF8,
//push         ecx
0x51,
//push         d,[ebp][-020]
0xFF, 0x75, 0xE0,
//push         d,[esi][00C]
0xFF, 0x76, 0x0C,
//call        .000430738 ; ImgpValidateImageHash
0xE8 //, 0x00, 0x06, 0x00, 0x00,
//mov          ebx,eax
//0x8B, 0xD8,
//test         ebx,ebx
//0x85, 0xDB,
//jns         .00043016A ; -> jmp...
//0x79, 0x2C
	};
	ULONG jgeOffset = 33;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 2 && j != 5 && j != 9 && j != 10 && j != 16 && j != 20 && j != 23)
				break;
		}

		if (j == sizeof(target))
		{
			//jns ... -> EB, 2C jmp...
			ptr[jgeOffset] = 0xeb;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

// ========================================
// ======================================== 9600 L-PART ==========
// ========================================

VOID PatchLoader9600Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // push eax
        0x50,
        // push [ebp+var_78]
        0xff, 0x75, 0x88,
        // lea eax, [ebp+var_148]
        0x8d, 0x85, 0xb8, 0xfe, 0xff, 0xff,
        // push [ebp+var_14]
        0xff, 0x75, 0xec,
        // push eax
        0x50,
        // mov eax, [ebp+var_30]
        0x8b, 0x45, 0xd0, // 9431: 8B 45 CC
        // push ecx
        0x51,
        // mov ecx, [eax+0ch]
        0x8b, 0x48, 0x0c,
        // call _ImgpValidateImageHash@32
        0xe8 //, 0x3a, 0x08, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_434bc2 ; if the function succeeded, go there
        // 0x79, 0x2d
    };
    ULONG jnsOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 6 && j != 7 && j != 12 && j != 16 && j != 20)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short loc_434bc2 -> jmp short loc_434bc2
            // 0x79, 0x2d -> 0xeb, 0x2d
            ptr[jnsOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgress2

    UCHAR target[] =
    {
        // push 0
        0x6a, 0x00,
        // push 0
        0x6a, 0x00,
        // push [ebp+var_30]
        0xff, 0x75, 0xd0,
        // xor edx, edx
        0x33, 0xd2,
        // push [ebp+var_20]
        0xff, 0x75, 0xe0,
        // push eax
        0x50,
        // push [ebp+var_164]
        0xff, 0xb5, 0x9c, 0xfe, 0xff, 0xff,
        // call _ImgpValidateImageHash@32
        0xe8 //, 0x35, 0x17, 0x00, 0x00
        // mov esi, eax
        // 0x8b, 0xf0
        // test esi, esi ; did ImgpValidateImageHash succeed?
        // 0x85, 0xf6
        // jns short loc_433cec ; if the function succeeded, go there
        // 0x79, 0x52
    };
    ULONG movOffset = 24;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 6 && j != 11 && j != 15 && j != 16)
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov esi, eax -> xor esi, esi
            // 0x8b, 0xf0 -> 0x33, 0xf6
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xf6;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 9800 L-PART ==========
// ========================================

VOID PatchLoader9800Part1(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 9841, win 10--
{
	UCHAR target[] =
	{
//xor          ecx,ecx
0x33, 0xC9,
//push         ecx
0x51,
//push         ecx
0x51,
//push         d,[ebp][-34]
0xFF, 0x75, 0xCC,
//push         d,[ebp][-28]
0xFF, 0x75, 0xD8,
//push         eax
0x50,
//push         d,[ebp][-0000016C]
0xFF, 0xB5, 0x94, 0xFE, 0xFF, 0xFF,
//push         ecx
0x51,
//push         d,[ebp][-0C]
0xFF, 0x75, 0xF4,
//mov          ecx,[ebp][8]
0x8B, 0x4D, 0x08,
//call         ImgpValidateImageHash
0xE8 //, 0,0,0,0
//8B F0 mov          esi,eax -> xor esi,esi *** 0x33, 0xF6
//85 F6 test         esi,esi
//79 52 jns          ...
	};
	ULONG movOffset = 29;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 6 && j != 9 && j != 13 && j != 14 && j != 20 && j != 23) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

            // mov esi, eax -> xor esi,esi
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xF6;

			*Success = TRUE;
			break;
		}

		ptr++;
	}
}

VOID PatchLoader9800Part2(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 9841
{
	UCHAR target[] =
	{
//push         eax
0x50,
//push         d,[ebp][-78]
0xFF, 0x75, 0x88,
//lea          eax,[ebp][-00000148]
0x8D, 0x85, 0xB8, 0xFE, 0xFF, 0xFF,
//push         d,[ebp][-14]
0xFF, 0x75, 0xEC,
//push         eax
0x50,
//push         ecx
0x51,
//lea          eax,[ebp][-000000D4]
0x8D, 0x85, 0x2C, 0xFF, 0xFF, 0xFF,
//push         eax
0x50,
//mov          eax,[ebp][-2C]
0x8B, 0x45, 0xD4,
//push         d,[ebp][24]
0xFF, 0x75, 0x24,
//mov          ecx,[eax][0C]
0x8B, 0x48, 0x0C,
//call         ImgpValidateImageHash
0xE8 //0,0,0,0
//8B D8 mov          ebx,eax -> xor ebx,ebx *** 0x31, 0xDB
//85 DB test         ebx,ebx
//79 2D jns          ...
	};
	ULONG movOffset = 36;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 3 && j != 6 && j != 7 && j != 12 && j != 17 && j != 18 && j != 24 && j != 27 && j != 30) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

			// mov ebx,eax -> xor ebx,ebx
			// 0x8B, 0xD8 -> 0x31, 0xDB
			ptr[movOffset] = 0x31;
			ptr[movOffset + 1] = 0xDB;

			*Success = TRUE;
			break;
		}

		ptr++;
	}
}

// ========================================
// ======================================== 10240 L-PART ==========
// ========================================

VOID PatchLoader10240Part1(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 10240 - win10 RTM
{
	// BlImgLoadImageWithProgress2
	UCHAR target[] =
	{
        //xor ecx,ecx
        0x33, 0xC9,
        //push ecx
        0x51,
        //push ecx
        0x51,
        //push ecx
        0x51,
        //push d,[ebp][-034]
		//FF, 75, **
        0xFF, 0x75, 0xCC,
        //push d,[ebp][-028] *** 14366 FF 75 D4 push d,[ebp][-02C]
		//FF, 75, **
        0xFF, 0x75, 0xD8,
        //push eax
        0x50,
        //push d,[ebp][-16C] **
		//FF, B5, **, **, FF, FF,
        0xFF, 0xB5, 0x94, 0xFE, 0xFF, 0xFF,
        //push ecx
        0x51,
        //push d,[ebp][-00C]
        0xFF, 0x75, 0xF4,
        //mov ecx,[ebp][8]
        0x8B, 0x4D, 0x08,
        //call ImgpValidateImageHash
        0xE8 //, 0x__, 0x__, 0x__, 0x__,
        //mov esi,eax -> xor esi,esi *** 0x33, 0xF6
        //0x8B, 0xF0,
        //test esi,esi ; did ImgpValidateImageHash succeed?
        //0x85, 0xF6,
        //jns valid_OK
        //0x79, 0x__,
	};
	ULONG movOffset = 30;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 7 && j != 10 && j != 14 && j != 15 && j != 21 && j != 24) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

            // mov esi, eax -> xor esi,esi
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xF6;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader10240Part1_v17623(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 17623 - win10 RS4 RC
{
	// BlImgLoadImageWithProgress2
	UCHAR target[] =
	{
        //xor ecx,ecx
        0x33, 0xC9,
        //push ecx
        0x51,
        //push ecx
        0x51,
        //push ecx
        0x51,
        //push         d,[ebp][-030]
		//FF, 75, **
        0xFF, 0x75, 0xD0,
        //push         d,[ebp][-02C]
		//FF, 75, **
        0xFF, 0x75, 0xD4,
        //push eax
        0x50,
        //push         d,[ebp][-12C]
		//FF, B5, **, **, FF, FF,
        0xFF, 0xB5, 0xD4, 0xFE, 0xFF, 0xFF,
        //push ecx
        0x51,
		// ========== 17623 ==========
        //mov ecx,[ebp][8]
		//8B, 4D, **
        0x8B, 0x4D, 0x08,
		//push         edi
		0x57,
        //call ImgpValidateImageHash
        0xE8 //, 0x__, 0x__, 0x__, 0x__,
        //mov esi,eax -> xor esi,esi *** 0x33, 0xF6
        //0x8B, 0xF0,
        //test esi,esi ; did ImgpValidateImageHash succeed?
        //0x85, 0xF6,
        //jns valid_OK
        //0x79, 0x__,
	};
	ULONG movOffset = 28;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 7 && j != 10 && j != 14 && j != 15 && j != 21) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

            // mov esi, eax -> xor esi,esi
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xF6;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader10240Part1_v17713(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 17713 - win10 RS5 IP
{
	// BlImgLoadImageWithProgress2
	UCHAR target[] =
	{
//xor ecx,ecx
0x33, 0xC9,
//push ecx
0x51,
//push ecx
0x51,
//push ecx
0x51,
//push d,[esp][040]
0xFF, 0x74, 0x24, 0x40,
//push d,[esp][040]
0xFF, 0x74, 0x24, 0x40,
//push eax
0x50,
//push d,[esp][068]
0xFF, 0x74, 0x24, 0x68,
//push ecx
0x51,
//mov ecx,[ebp][010]
0x8B, 0x4D, 0x10,
//push edi
0x57,
//call ImgpValidateImageHash
0xE8 //, 0x__, 0x__, 0x00, 0x00,
//mov esi,eax -> 33 F6 xor esi,esi
//0x8B, 0xF0,
//test esi,esi
//0x85, 0xF6,
//jns valid_OK
//0x79, 0x__
	};
	ULONG movOffset = 28;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 8 && j != 12 && j != 17 && j != 21) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

            // mov esi, eax -> xor esi,esi
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xF6;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}


VOID PatchLoader10240Part1_v18277(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 18277 - win10 pre-RS6
{
	// BlImgLoadImageWithProgress2
	UCHAR target[] =
	{
//xor          ecx,ecx
0x33, 0xC9,
//push         ecx
0x51,
//push         ecx
0x51,
//push         ecx
0x51,
//push         d,[esp][048]
0xFF, 0x74, 0x24, 0x48,
//push         d,[esp][044]
0xFF, 0x74, 0x24, 0x44,
//push         eax
0x50,
//push         d,[esp][070]
0xFF, 0x74, 0x24, 0x70,
//push         ecx
0x51,
//push         d,[esp][034]
0xFF, 0x74, 0x24, 0x34,
//mov          ecx,[ebp][010]
0x8B, 0x4D, 0x10,
//call 10063754 ImgpValidateImageHash
0xE8 //, 0x72, 0x2C, 0x00, 0x00,
//mov          esi,eax -> 31 F6 xor esi,esi // 33 F6 xor esi,esi
//0x8B, 0xF0,
//test         esi,esi
//0x85, 0xF6,
//jns         .010060B3B valid_OK
//0x79, 0x53,
//mov          ecx,[ebp][010]
//0x8B, 0x4D, 0x10,
//mov          edx,esi
//0x8B, 0xD6
	};
	ULONG movOffset = 31;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 8 && j != 12 && j != 17 && j != 22) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

            // mov esi, eax -> xor esi,esi
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xF6;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

//////////////////// loader_part_2 ////////////////////



VOID PatchLoader10240Part2_v10586(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 10240 - win10 RTM (evgen_b)
{
/* 10011
50                             push         eax
FF B5 ** ** FF FF              push         d,[ebp][-00000090]
8D 85 ** ** FF FF              lea          eax,[ebp][-00000178]
FF 75 **                       push         d,[ebp][-10]
50                             push         eax
51                             push         ecx
8D 85 ** ** FF FF              lea          eax,[ebp][-000000BC]
50                             push         eax
8B 45 **                       mov          eax,[ebp][-34]
56                             push         esi
8B 48 **                       mov          ecx,[eax][0C]
E8 ** ** ** **                 call         00437975
8B D8                          mov          ebx,eax
85 DB                          test         ebx,ebx
0F 88 ** ** ** **              js           00436F23
*/
	// ImgpLoadPEImage
	UCHAR target[] =
	{
		// push eax
		0x50,
		// push d,[ebp][-090]
		0xFF, 0xB5, 0x70, 0xFF, 0xFF, 0xFF,
		// lea eax,[ebp][-178] *** 10580: 8D 85 80 FE FF FF - lea eax,[ebp][-180]
		0x8D, 0x85, 0x88, 0xFE, 0xFF, 0xFF,
		// push d,[ebp][-010]
		0xFF, 0x75, 0xF0,
		// push eax
		0x50,
		// push ecx
		0x51,
		// lea eax,[ebp][-0BC]
		0x8D, 0x85, 0x44, 0xFF, 0xFF, 0xFF,
		// push eax
		0x50,
		// mov eax,[ebp][-030] *** 10011: 8B 45 CC mov eax,[ebp][-034]
		0x8B, 0x45, 0xd0,
		// push esi
		0x56,
		// mov ecx,[eax][00C]
		0x8B, 0x48, 0x0C,
		// call _ImgpValidateImageHash@32
		0xE8 //, 0x__, 0x__, 0x__, 0x__
		// mov ebx,eax -> xor ebx,ebx *** 0x31, 0xDB
		// 0x8B, 0xD8
		// test ebx,ebx ; did ImgpValidateImageHash succeed?
		// 0x85, 0xDB
		// js Fail
		// 0x0F, 0x__, 0x__, 0x__, 0x__, 0x__
	};
	ULONG movOffset = 37;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 3 && j != 4 && j != 9 && j != 10 && j != 15 && j != 20 && j != 21 && j != 27 && j != 31
                                    && j != 33 && j != 34 && j != 35 && j != 36) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

			// mov ebx,eax -> xor ebx,ebx
			// 0x8B, 0xD8 -> 0x31, 0xDB
			ptr[movOffset] = 0x31;
			ptr[movOffset + 1] = 0xDB;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader10240Part2_v14366(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 14366 - win10 IP (evgen_b)
{
	// ImgpLoadPEImage
	UCHAR target[] =
	{
		// push eax
		0x50,
		// push d,[ebp][-07C]
		0xFF, 0x75, 0x84,
		// lea eax,[ebp][-170] **
		0x8D, 0x85, 0x90, 0xFE, 0xFF, 0xFF,
		// push d,[ebp][-010]
		0xFF, 0x75, 0xF0,
		// push eax
		0x50,
		// push ecx
		0x51,
		// lea eax,[ebp][-0C0]
		0x8D, 0x85, 0x40, 0xFF, 0xFF, 0xFF,
		// push eax
		0x50,
		// mov eax,[ebp][-018]
		0x8B, 0x45, 0xE8,
		// push esi
		0x56,
		// mov ecx,[eax][00C]
		0x8B, 0x48, 0x0C,
		// call ImgpValidateImageHash
		0xE8 //, 0x__, 0x__, 0x__, 0x__
		// mov ebx,eax -> xor ebx,ebx *** 0x31, 0xDB
		// 0x8B, 0xD8
		// cmp ebx,0C000022D ; some quantum mechanics
		// 81 FB 2D 02 00 C0
		// jnz l_43A375
		// 75 5B
		// l_43A375:
		// test ebx, ebx ; did ImgpValidateImageHash succeed?
		// jns Validation_OK
	};
	ULONG movOffset = 34;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 3 && j != 6 && j != 7 && j != 12 && j != 17 && j != 18 && j != 24 && j != 28) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

			// mov ebx,eax -> xor ebx,ebx
			ptr[movOffset] = 0x31;
			ptr[movOffset + 1] = 0xDB;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader10240Part2_v15063(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 15063 - win10 RS2 IP (evgen_b)
{
	// ImgpLoadPEImage
	UCHAR target[] =
	{
		// push eax
		0x50,
		// push d,[ebp][-070]
		0xFF, 0x75, 0x90,
		// lea eax,[ebp][-00000016C] **
		0x8D, 0x85, 0x94, 0xFE, 0xFF, 0xFF,
		// push edi
		0x57,
		// push eax
		0x50,
		// push ecx
		0x51,
		// lea eax,[ebp][-0000000B8]
		0x8D, 0x85, 0x48, 0xFF, 0xFF, 0xFF,
		// push eax
		0x50,
		// mov eax,[ebp][-034]
		0x8B, 0x45, 0xCC,
		// push d,[ebp][-8]
		0xFF, 0x75, 0xF8,
		// mov ecx,[eax][00C]
		0x8B, 0x48, 0x0C,
		// call ImgpValidateImageHash
        0xE8, 0,0,0,0,
		// mov ebx,eax -> xor ebx,ebx *** 0x31, 0xDB
		0x8B, 0xD8
        // mov [ebp][024],ebx
        // 89 5D 24
		// cmp ebx,0C000022D ; some quantum mechanics
		// 81 FB 2D 02 00 C0
		// jnz l_43CA96
		// 75 39
	};
	ULONG movOffset = 34;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 3 && j != 6 && j != 15 && j != 22 && j != 25 && j != 28 && j != 30 && j != 31 && j != 32 && j != 33) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

			// mov ebx,eax -> xor ebx,ebx
			ptr[movOffset] = 0x31;
			ptr[movOffset + 1] = 0xDB;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader15048Part2(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 15048 fuck!
{
	// ImgpLoadPEImage
	UCHAR target[] =
	{
//push         eax
0x50,
//push         d,[ebp][-78]
0xFF, 0x75, 0x88,
//lea          eax,[ebp][-16C]
0x8D, 0x85, 0x94, 0xFE, 0xFF, 0xFF,
//mov          edx,edi
0x8B, 0xD7,
//push         d,[ebp][-18]
0xFF, 0x75, 0xE8,
//push         eax
0x50,
//push         ecx
0x51,
//lea          eax,[ebp][-B8]
0x8D, 0x85, 0x48, 0xFF, 0xFF, 0xFF,
//push         eax
0x50,
//push         esi
0x56,
//mov          esi,[ebp][-38]
0x8B, 0x75, 0xC8,
//mov          ecx,[esi][0C]
0x8B, 0x4E, 0x0C,
//call        .00043D9AC
0xE8, 0,0,0,0,
//mov          ebx,eax -> xor ebx,ebx *** 0x31, 0xDB
0x8B, 0xD8
//cmp          ebx,C000022D
//0x81, 0xFB, 0x2D, 0x02, 0x00, 0xC0
//jnz          0043CAAE
//0x0F, 0x85, ...
	};
	ULONG movOffset = 36;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j] && j != 3 && j != 6 && j != 7 && j != 14 && j != 19 && j != 20
                    && j != 27 && j != 30 && j != 32 && j != 33 && j != 34 && j != 35) // ignore **
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

			// mov ebx,eax -> xor ebx,ebx
			ptr[movOffset] = 0x31;
			ptr[movOffset + 1] = 0xDB;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

// ========================================
// ======================================== 6000 L-MAIN ==========
// ========================================

VOID PatchLoader_6000_6002_main(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{
	BOOLEAN success = FALSE;

	// call smart template for SP0...SP2 patch (evgen_b)
	PatchLoader6000_SPx(LoadedImage, &success);
	*Success = success;

	// if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		//template for 6801 beta (evgen_b)
		PatchLoader6801_beta(LoadedImage, &success);
		if (!success)
		{
			//template for 7000/7022/7048 beta (evgen_b)
			PatchLoader7000_beta(LoadedImage, &success);
		}
			if (!success)
			{
				// template for SP0
				PatchLoader7600_SP0(LoadedImage, &success);
			}
	}
	*Success = success;

}

// ========================================
// ======================================== 7600 L-MAIN ==========
// ========================================

VOID PatchLoader_6003_7600_main(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{
	BOOLEAN success = FALSE;

	// template for SP0
	PatchLoader7600_SP0(LoadedImage, &success);
	if (!success)
	{
		//template for 7000/7022/7048 beta (evgen_b)
		PatchLoader7000_beta(LoadedImage, &success);
		if (!success)
		{
			//template for 6801 beta (evgen_b)
			PatchLoader6801_beta(LoadedImage, &success);
		}
			if (!success)
			{
				//may be try patch very old loader like vista sp2:
				// windows 7 and vista loader merge here
				PatchLoader6000_SPx(LoadedImage, &success);
			}
	}
	*Success = success;

	// if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchLoader7601_noKB(LoadedImage, &success);
		if (!success)
		{
			PatchLoader7601_KB3033929(LoadedImage, &success);
		}
		*Success = success;
	}
}

// ========================================
// ======================================== 7601 L-MAIN ==========
// ========================================

VOID PatchLoader_7601_main(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{
	// first, call normal patch, and if it fail, call fixed for KB3033929 patch (evgen_b)

	BOOLEAN success = FALSE;

	PatchLoader7601_noKB(LoadedImage, &success);
	if (!success)
	{
		PatchLoader7601_KB3033929(LoadedImage, &success);
	}
	*Success = success;

	// if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchLoader7600_SP0(LoadedImage, &success);
		if (!success)
		{
			//template for 7000/7022/7048 beta (evgen_b)
			PatchLoader7000_beta(LoadedImage, &success);
		}
		*Success = success;
	}

	if (!(*Success))
	{
		PatchLoader7850(LoadedImage, &success);
		if (!success)
		{
			PatchLoader7955(LoadedImage, &success);
			if (!success)
			{
				PatchLoader8100(LoadedImage, &success);
			}
		}
		*Success = success;
	}

}

// ========================================
// ======================================== 9200 L-MAIN ==========
// ========================================

VOID PatchLoader_7602_9200_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

	PatchLoader9200Part1(LoadedImage, &success1);
	if (!success1)
	{
		PatchLoader8400Part1(LoadedImage, &success1);
		if (!success1)
		{
			PatchLoader8250Part1(LoadedImage, &success1);
		}
	}

	PatchLoader9200Part2(LoadedImage, &success2);
	if (!success2)
	{
		PatchLoader8400Part2(LoadedImage, &success2);
		if (!success2)
		{
			PatchLoader8250Part2(LoadedImage, &success2);
		}
	}
	
    *Success = success1 && success2;

	//old loaders without part-2 like Windows 7
	if (!(*Success))
	{
		PatchLoader7850(LoadedImage, &success1);
		if (!success1)
		{
			PatchLoader7955(LoadedImage, &success1);
			if (!success1)
			{
				PatchLoader8100(LoadedImage, &success1);
			}
		}
		*Success = success1;
	}

	// if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchLoader7601_KB3033929(LoadedImage, &success1);
		if (!success1)
		{
			PatchLoader7601_noKB(LoadedImage, &success1);
		}
		*Success = success1;
	}

	if (!(*Success))
	{
		PatchLoader9600Part1(LoadedImage, &success1);
		PatchLoader9600Part2(LoadedImage, &success2);
		*Success = success1 && success2;
	}

}

// ========================================
// ======================================== 9600 L-MAIN ==========
// ========================================

VOID PatchLoader_9201_9600_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchLoader9600Part1(LoadedImage, &success1);
    PatchLoader9600Part2(LoadedImage, &success2);
    *Success = success1 && success2;

	// if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchLoader9200Part1(LoadedImage, &success1);
		if (!success1)
		{
			PatchLoader8400Part1(LoadedImage, &success1);
			if (!success1)
			{
				PatchLoader8250Part1(LoadedImage, &success1);
			}
		}

		PatchLoader9200Part2(LoadedImage, &success2);
		if (!success2)
		{
			PatchLoader8400Part2(LoadedImage, &success2);
			if (!success2)
			{
				PatchLoader8250Part2(LoadedImage, &success2);
			}
		}
	
    *Success = success1 && success2;
	}
}

// ========================================
// ======================================== 17763 L-MAIN ==========
// ========================================

VOID PatchLoader_9601_17623_main(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 10240 - win10 RTM
{
	// ImgpLoadPEImage and BlImgLoadImageWithProgressEx

	// There is a function called ImgpValidateImageHash. We are 
	// going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
	// so that they don't care what the result of the function is.

	BOOLEAN success1 = FALSE;
	BOOLEAN success2 = FALSE;

    PatchLoader9800Part1(LoadedImage, &success1);
	if (success1)
	{
        PatchLoader9800Part2(LoadedImage, &success2);
        *Success = success2;
        return;
    }

	PatchLoader10240Part1(LoadedImage, &success1);
	if (!success1)
	{
		PatchLoader10240Part1_v17623(LoadedImage, &success1);
    	if (!success1)
    	{
    		PatchLoader10240Part1_v17713(LoadedImage, &success1);
    		if (!success1)
    		{
				PatchLoader10240Part1_v18277(LoadedImage, &success1);
			}

    	}
	}
	
	PatchLoader10240Part2_v10586(LoadedImage, &success2);
	if (!success2)
	{
		PatchLoader10240Part2_v14366(LoadedImage, &success2);
    	if (!success2)
    	{
    		PatchLoader10240Part2_v15063(LoadedImage, &success2);
        	if (!success2)
        	{
        		PatchLoader15048Part2(LoadedImage, &success2);
        	}
    	}
	}
	//wprintf(L"exit1: %u; exit2: %u\n", success1, success2);
	*Success = success1 && success2;

	// if fail, try to apply nearest patch: for previous and next file version

	if (!(*Success))
	{
		PatchLoader9600Part1(LoadedImage, &success1);
		PatchLoader9600Part2(LoadedImage, &success2);
		*Success = success1 && success2;
	}

}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// HAL     _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

// ========================================
// ======================================== 2600 H-PART ==========
// ========================================

VOID PatchHAL2600Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // mov cl,[edi][5]
        0x8A, 0x4F, 0x05,
        // test cl,cl
        0x84, 0xC9,
        // push ebx
        0x53,
        // jz 08002782C
        0x74, 0x17,
        // cmp b,[0800232B8],0
        0x80, 0x3D // 0xB8, 0x32, 0x02, 0x80, 0x00
        // ...
    };
    ULONG movOffset = 6;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jz 08002782C -> jmps 08002782C
            ptr[movOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchHAL2600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // push 1
        0x6A, 0x01,
        // push 010                       --> push 030
        0x6A, 0x10,                    // --> 6A 30
        // push 001000000                 --> push -1
        0x68, 0x00, 0x00, 0x00, 0x01,  // --> 68 FF FF FF FF
        // push ebx
        0x53
        // mov d,[0800232C4],000000040    --> mov d,[0800232C4],000004000
        // 0xC7, 0x05, 0xC4, 0x32, 0x02, 0x80, 0x40, 0x00, 0x00, 0x00 -- > C7 05 C4 32 02 80 00 40 00 00
        // mov esi,00010000               --> mov esi,00030000
        // 0xBE, 0x00, 0x00, 0x01, 0x00   --> BE 00 00 03 00
        // call 08002D68E
        // 0xE8, 0x70, 0xF9, 0xFF, 0xFF
        // ...
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset+03] = 0x30;
            *(PULONG)&ptr[movOffset+05] = 0xFFFFFFFF;
            ptr[movOffset+16] = 0x00;
            ptr[movOffset+17] = 0x40;
            ptr[movOffset+23] = 0x03;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 2600 H-MAIN ==========
// ========================================

VOID PatchHAL_2600_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchHAL2600Part1(LoadedImage, &success1);
    PatchHAL2600Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// B_PAE   _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

// ========================================
// ======================================== 8400 BP-PART ==========
// ========================================

VOID PatchBypassPAE8400(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target[] =
    {
//lea          eax,[ebp][-014]
0x8D, 0x45, 0,
//push         eax
0x50,
//push         edi
0x57,
//push         esi
0x56,
//call        BlArchCpuId
0xE8, 0,0,0,0,
//test         b,[ebp][-8],040
0xF6, 0x45, 0, 0x40,
//jz          ...
0x74, 0, // --> nop(2)
//push         7
0x6A, 0x07
    };
    ULONG movOffset = 15;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 2 && j != 7 && j != 8 && j != 9 && j != 10 && j != 13 && j != 16) // ignore **
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            *(PUSHORT)&ptr[movOffset] = 0x9090;
            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 9200 BP-PART ==========
// ========================================

VOID PatchBypassPAE9200(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target[] =
    {
//lea          eax,[esp][010]
0x8D, 0x44, 0x24, 0,
//push         eax
0x50,
//push         edi
0x57,
//push         esi
0x56,
//call        BlArchCpuId
0xE8, 0,0,0,0,
//test         b,[esp][01C],040
0xF6, 0x44, 0x24, 0, 0x40,
//jz          ...
0x0F, 0x84, 0,0,0,0, // --> nop(6)
//push         8
0x6A, 0x08
    };
    ULONG movOffset = 17;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 3 && j != 8 && j != 9 && j != 10 && j != 11 && j != 15 && j != 19 && j != 20 && j != 21 && j != 22) // ignore **
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            *(PUSHORT)&ptr[movOffset] = 0x9090;
            *(PULONG)&ptr[movOffset+2] = 0x90909090;
            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 9600 BP-PART ==========
// ========================================

VOID PatchBypassPAE9600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target[] =
    { //like 9200, but push esi<->push edi
//lea          eax,[esp][018]
0x8D, 0x44, 0x24, 0,
//push         eax
0x50,
//push         esi
0x56,
//push         edi
0x57,
//call        BlArchCpuId
0xE8, 0,0,0,0,
//test         b,[esp][01C],040
0xF6, 0x44, 0x24, 0, 0x40,
//jz          ...
0x0F, 0x84, 0,0,0,0, //x,x,x,x --> nop(6)
//push         8
0x6A, 0x08
    };
    ULONG movOffset = 17;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 3 && j != 8 && j != 9 && j != 10 && j != 11 && j != 15 && j != 19  && j != 20  && j != 21  && j != 22 ) // ignore **
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            *(PUSHORT)&ptr[movOffset] = 0x9090;
            *(PULONG)&ptr[movOffset+2] = 0x90909090;
            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 15063 BP-PART ==========
// ========================================

VOID PatchBypassPAE15063(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{// like 9200, but push 8 -> mov [esp]...
    UCHAR target[] =
    {
//lea          eax,[esp][010]
0x8D, 0x44, 0x24, 0,
//push         eax
0x50,
//push         edi
0x57,
//push         esi
0x56,
//call        BlArchCpuId
0xE8, 0,0,0,0,
//test         b,[esp][01C],040
0xF6, 0x44, 0x24, 0, 0x40,
//jz          ...
0x0F, 0x84, 0,0,0,0, // --> nop(6)
//89742414 mov          [esp][014],esi (15063)
//897C2448 mov          [esp][048],edi (16226)
0x89
    };
    ULONG movOffset = 17;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 3 && j != 8 && j != 9 && j != 10 && j != 11 && j != 15 && j != 19 && j != 20 && j != 21 && j != 22) // ignore **
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            *(PUSHORT)&ptr[movOffset] = 0x9090;
            *(PULONG)&ptr[movOffset+2] = 0x90909090;
            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 17623 BP-PART ==========
// ========================================

VOID PatchBypassPAE17623(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target[] =
    {
//lea          eax,[esp][018]
0x8D, 0x44, 0x24, 0,
//push         eax
0x50,
//push         edi
0x57,
// ======= 17623 =======
//6A 01 push 1
0x6A, 0x01,
//call        BlArchCpuId
0xE8, 0,0,0,0,
//test         b,[esp][024],040
0xF6, 0x44, 0x24, 0, 0x40,
//jz          ...
0x0F, 0x84, 0,0,0,0, // --> nop(6)
//33 D2 xor edx,edx
//33 C0 xor eax,eax - ver.17063 
0x33
    };
    ULONG movOffset = 18;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 3 && j != 9 && j != 10 && j != 11 && j != 12 && j != 16 && j != 20 && j != 21 && j != 22 && j != 23) // ignore **
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            *(PUSHORT)&ptr[movOffset] = 0x9090;
            *(PULONG)&ptr[movOffset+2] = 0x90909090;
            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// B_SSE2_NX _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

/*
Kernel Feature Bits
KF_V86_VIS                      0x00000001
KF_RDTSC                        0x00000002
KF_CR4                          0x00000004
KF_CMOV                         0x00000008
KF_GLOBAL_PAGE                  0x00000010
KF_LARGE_PAGE                   0x00000020
KF_MTRR                         0x00000040
KF_CMPXCHG8B                    0x00000080
KF_MMX                          0x00000100
KF_WORKING_PTE                  0x00000200
KF_PAT                          0x00000400
KF_FXSR                         0x00000800
KF_FAST_SYSCALL                 0x00001000
KF_XMMI                         0x00002000
KF_3DNOW                        0x00004000
KF_AMDK6MTRR                    0x00008000
KF_XMMI64                       0x00010000
KF_DTS                          0x00020000
KF_BRANCH                       0x00020000 // from ksamd64.inc
KF_SSE3                         0x00080000
KF_CMPXCHG16B                   0x00100000
KF_XSTATE                       0x00800000 // from ks386.inc, ksamd64.inc
KF_NX_BIT                       0x20000000
KF_NX_DISABLED                  0x40000000
KF_NX_ENABLED                   0x80000000

KF_XSAVEOPT_BIT                 15
KF_XSTATE_BIT                   23
KF_RDWRFSGSBASE_BIT             28
*/

// ========================================
// ======================================== 8400 BSN-PART ==========
// ========================================

VOID PatchBypassSSE2NX8400(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target1[] =
    {
//mov          edx,200138B6
0xBA, 0xB6, 0x38, 0x01, 0x20,
//and          eax,edx
0x23, 0xC2,
//cmp          eax,edx
0x3B, 0xC2,
//jnz         ...
0x0F, 0x85 //x,x,x,x --> nop(6)
    };
    UCHAR target2[] =
    {
//mov          edx,200138B6
0xBA, 0xB6, 0x38, 0x01, 0x20,
//and          ecx,edx
0x23, 0xCA,
//cmp          ecx,edx
0x3B, 0xCA,
//jnz         ...
0x0F, 0x85 //x,x,x,x --> nop(6)
    };
    ULONG movOffset1 = 9;
    ULONG movOffset2 = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target1); i++)
    {
        for (j = 0; j < sizeof(target1); j++)
        {
			if (ptr[j] != target1[j])
				break;
        }//j~1

        if (j == sizeof(target1))
        {
            // Found it (1)
            for (k = 1; k < 1000; k++)
            {
                for (j = 0; j < sizeof(target2); j++)
                {
        			if (ptr[k+j] != target2[j])
        				break;
                }//j~2
                if (j == sizeof(target2))
                    {
                    // Found it (2)

                    *(PUSHORT)&ptr[movOffset1] = 0x9090;
                    *(PULONG)&ptr[movOffset1+2] = 0x90909090;
        
                    *(PUSHORT)&ptr[k+movOffset2] = 0x9090;
                    *(PULONG)&ptr[k+movOffset2+2] = 0x90909090;

                    *Success = TRUE;
                    break;

                    }//target2

            }//k++
        }//target1

        ptr++;

    }//i++
}

// ========================================
// ======================================== 9841 BSN-PART ==========
// ========================================

VOID PatchBypassSSE2NX9841(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target1[] =
    {
//mov          ecx,200138B6
0xB9, 0xB6, 0x38, 0x01, 0x20,
//and          eax,ecx
0x23, 0xC1,
//cmp          eax,ecx
0x3B, 0xC1,
//jnz         ...
0x0F, 0x85 //x,x,x,x --> nop(6)
    };
    UCHAR target2[] =
    {
//mov          ecx,200138B6
0xB9, 0xB6, 0x38, 0x01, 0x20,
//and          esi,ecx
0x23, 0xF1,
//cmp          esi,ecx
0x3B, 0xF1,
//jnz         ...
0x0F, 0x85 //x,x,x,x --> nop(6)
    };
    ULONG movOffset1 = 9;
    ULONG movOffset2 = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target1); i++)
    {
        for (j = 0; j < sizeof(target1); j++)
        {
			if (ptr[j] != target1[j])
				break;
        }//j~1

        if (j == sizeof(target1))
        {
            // Found it (1)
            for (k = 1; k < 1000; k++)
            {
                for (j = 0; j < sizeof(target2); j++)
                {
        			if (ptr[k+j] != target2[j])
        				break;
                }//j~2
                if (j == sizeof(target2))
                    {
                    // Found it (2)

                    *(PUSHORT)&ptr[movOffset1] = 0x9090;
                    *(PULONG)&ptr[movOffset1+2] = 0x90909090;
        
                    *(PUSHORT)&ptr[k+movOffset2] = 0x9090;
                    *(PULONG)&ptr[k+movOffset2+2] = 0x90909090;

                    *Success = TRUE;
                    break;

                    }//target2

            }//k++
        }//target1

        ptr++;

    }//i++
}


// ========================================
// ======================================== 10122 BSN-PART ==========
// ========================================

VOID PatchBypassSSE2NX10122(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    ) // FUCK!
{
    UCHAR target1[] =
    {
//mov          ecx,200138B6
0xB9, 0xB6, 0x38, 0x01, 0x20,
//and          esi,ecx
0x23, 0xF1,
//cmp          esi,ecx
0x3B, 0xF1,
//jnz         ...
0x75 //x --> nop(2)
    };
    UCHAR target2[] =
    {
//mov          ecx,200138B6
0xB9, 0xB6, 0x38, 0x01, 0x20,
//and          eax,ecx
0x23, 0xC1,
//cmp          eax,ecx
0x3B, 0xC1,
//jnz         ...
0x0F, 0x85 //x,x,x,x --> nop(6)
    };
    ULONG movOffset1 = 9;
    ULONG movOffset2 = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target1); i++)
    {
        for (j = 0; j < sizeof(target1); j++)
        {
			if (ptr[j] != target1[j])
				break;
        }//j~1

        if (j == sizeof(target1))
        {
            // Found it (1)
            for (k = 1; k < 1000; k++)
            {
                for (j = 0; j < sizeof(target2); j++)
                {
        			if (ptr[k+j] != target2[j])
        				break;
                }//j~2
                if (j == sizeof(target2))
                    {
                    // Found it (2)

                    *(PUSHORT)&ptr[movOffset1] = 0x9090; //jmp short
        
                    *(PUSHORT)&ptr[k+movOffset2] = 0x9090;
                    *(PULONG)&ptr[k+movOffset2+2] = 0x90909090; //jmp long

                    *Success = TRUE;
                    break;

                    }//target2

            }//k++
        }//target1

        ptr++;

    }//i++
}

// ========================================
// ======================================== 10586 BSN-PART ==========
// ========================================

VOID PatchBypassSSE2NX10586(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target1[] =
    {
//mov          ecx,20013CB6
0xB9, 0xB6, 0x3C, 0x01, 0x20,
//and          eax,ecx
0x23, 0xC1,
//cmp          eax,ecx
0x3B, 0xC1,
//jnz         ...
0x0F, 0x85 //x,x,x,x --> nop(6)
    };
//  UCHAR target2[] same as target1
    ULONG movOffset1 = 9;
    ULONG movOffset2 = 9;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target1); i++)
    {
        for (j = 0; j < sizeof(target1); j++)
        {
			if (ptr[j] != target1[j])
				break;
        }//j~1

        if (j == sizeof(target1))
        {
            // Found it (1)
            for (k = 1; k < 1000; k++)
            {
                for (j = 0; j < sizeof(target1); j++)
                {
        			if (ptr[k+j] != target1[j])
        				break;
                }//j~2
                if (j == sizeof(target1))
                    {
                    // Found it (2)

                    *(PUSHORT)&ptr[movOffset1] = 0x9090;
                    *(PULONG)&ptr[movOffset1+2] = 0x90909090;
        
                    *(PUSHORT)&ptr[k+movOffset2] = 0x9090;
                    *(PULONG)&ptr[k+movOffset2+2] = 0x90909090;

                    *Success = TRUE;
                    break;

                    }//target2

            }//k++
        }//target1

        ptr++;

    }//i++
}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// B_HT    _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

// ========================================
// ======================================== 8400 BH-PART ==========
// ========================================

VOID PatchBypassHT8400(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    UCHAR target[] =
    {
//jz           L1 ; --> jz bypass (L1+0x10)
0x74, 0x0E,
//mov          cx,001A0
0x66, 0xB9, 0xA0, 0x01,
//add          [eax],al
0x00, 0x00,
//rdmsr
0x0F, 0x32,
//and          dx,0FB
0x66, 0x83, 0xE2, 0xFB,
//wrmsr
0x0F, 0x30,
//L1: mov      cx,00080
0x66, 0xB9, 0x80, 0x00,
//add          al,al
0x00, 0xC0,
//rdmsr
0x0F, 0x32,
//or           ax,00800
0x66, 0x0D, 0x00, 0x08,
//add          [eax],al
0x00, 0x00,
//wrmsr
0x0F, 0x30,
//xor          bp,bp ; (<--bypass<--)
0x66, 0x33, 0xED
    };
    ULONG movOffset = 1;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j])
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Increase jz distance by 0x10 to prevent EFER.NXE from being set
			ptr[movOffset] += 0x10;
            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

//=============================================================================

VOID PatchBypassPAE_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
	// !!! ONLY FOR WINDOWS 8.1 ... 10BETA BUILD10130 !!!

    BOOLEAN success1 = FALSE;
    PatchBypassPAE8400(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassPAE9200(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassPAE9600(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassPAE15063(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassPAE17623(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

	*Success = FALSE;
}

VOID PatchBypassSSE2NX_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;
    PatchBypassSSE2NX8400(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassSSE2NX9841(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassSSE2NX10122(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    PatchBypassSSE2NX10586(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    *Success = FALSE;
}

VOID PatchBypassHT_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;
    PatchBypassHT8400(LoadedImage, &success1);
    if (success1) {*Success = TRUE; return;}

    *Success = FALSE;
}

// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// B_SFC   _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

// ========================================
// ======================================== 2195 BSFC-PART ==========
// ========================================

VOID PatchBypassSFC2195_part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    UCHAR target[] =
    {

0xE9, 0x00, 0x00, 0x00, 0x00,
//jmp ** ** ** **
0xA1, 0x00, 0x00, 0x00, 0x00,
//mov eax,[_adr_]
0x83, 0xF8, 0x9D,
//cmp eax,09D
0x75, 0x00,
//jnz ** ** ** **
0x8B, 0xC6,
//mov eax,esi --> nop(2)
0xA3, 0x00, 0x00, 0x00, 0x00,
//mov [_adr_],eax
0x3B, 0xC3
//cmp eax,ebx

    };
    ULONG movOffset = 15;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 1 && j != 2 && j != 3 && j != 4 && j != 6 && j != 7 && j != 8 && j != 9
				&& j != 14 && j != 18 && j != 19 && j != 20 && j != 21) // ignore **
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            *(PUSHORT)&ptr[movOffset] = 0x9090;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 2195 BSFC-PART ==========
// ========================================

VOID PatchBypassSFC2195_part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
	wchar_t target[]=L"SFCDisable";
	wchar_t wpatch[]=L"SFCSetting";
    ULONG Offset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

	//wprintf(L"\nsizeof(target)=%d s=%s\n", sizeof(target), target); // some unicode mindfuker:
	//for (j = 0; j < sizeof(target); j++) wprintf(L"\nj=%d char=%x char=%c", j, ((UCHAR *)target)[j], ((UCHAR *)target)[j]);

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != ((UCHAR *)target)[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Replace string:
			memcpy(&ptr[Offset], &wpatch, sizeof(target));

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 2600 BSFC-PART ==========
// ========================================

VOID PatchBypassSFC2600_part1_v1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    UCHAR target[] =
    {

	// win XP sp2 sp3
0xA1, 0, 0, 0, 0,
//mov eax,[_adr_]
0x83, 0xF8, 0x9D,
//cmp eax,09D
0x75, 0,
//jnz __OK        ---> jmps __OK (EB xx)
0x33, 0xC0,
//xor eax,eax
0x40,
//inc eax
0xA3 //, 0, 0, 0, 0
//mov [_adr_],eax

    };
    ULONG movOffset = 8;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 1 && j != 2 && j != 3 && j != 4 && j != 9) // ignore offsets
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 2600 BSFC-PART ==========
// ========================================

VOID PatchBypassSFC2600_part1_v2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    UCHAR target[] =
    {

	// win XP sp0 sp1 server 2003r2 sp1
0xA1, 0, 0, 0, 0,
//mov eax,[_adr_]
0x83, 0xF8, 0x9D,
//cmp eax,09D
0x75, 0,
//jnz __OK        ---> jmps __OK (EB xx)
0x8B, 0xC6,
//mov eax,esi
0xA3 //, 0, 0, 0, 0
//mov [_adr_],eax

    };
    ULONG movOffset = 8;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
			if (ptr[j] != target[j] && j != 1 && j != 2 && j != 3 && j != 4 && j != 9) // ignore offsets
				break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

// ========================================
// ======================================== 2195 BSFC-PART ==========
// ========================================

VOID PatchSFC_2195_main(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchBypassSFC2195_part1(LoadedImage, &success1);
	if (!success1)
	{
		PatchBypassSFC2600_part1_v1(LoadedImage, &success1);
		if (!success1)
		{
			PatchBypassSFC2600_part1_v2(LoadedImage, &success1);
		}
	}

    PatchBypassSFC2195_part2(LoadedImage, &success2);

    *Success = success1 && success2;
}


// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// END     _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
// _/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/

VOID HelpType_Common()
{
	wprintf(
	L"* print user guide for patch \"4 Gb 32-bit memory limit\":\n"
	L"    PatchPAE3.EXE -help unlock_pae\n"
	L"* print user guide for patch \"bypass Windows 8 CPU feature checks\":\n"
	L"    PatchPAE3.EXE -help bypass_cpuid\n"
	L"* print user guide for patch \"bypass Windows SFC/WFP\":\n"
	L"    PatchPAE3.EXE -help bypass_wfp\n\n"
	);
}

VOID HelpType_EnablePAE()
{
	wprintf(
	L"This patch allows you to use more than 3-4GB of RAM on an x86 Windows system.\n\n"

	L"[For Windows Vista/2008/7/8/8.1/10:]\n"
	L"1.  Open an elevated Command Prompt window.\n\n"

    L"2.  cd C:\\Windows\\system32\n"
    L"    Make sure the current directory is in fact system32.\n\n"

	L"[For Windows 8/8.1/10 only:]\n"
	L"3.  C:\\WherePatchPaeIs\\PatchPAE3.exe -type kernel -o ntknew.exe ntoskrnl.exe\n"
	L"    This will patch the kernel to enable a maximum of 128GB of RAM.\n"
	L"[For Windows Vista/7/2008 only:]\n"
	L"3.  C:\\WherePatchPaeIs\\PatchPAE3.exe -type kernel -o ntkpanew.exe ntkrnlpa.exe\n"
	L"    This will patch the kernel to enable a maximum of 128GB of RAM.\n\n"

	L"4.  C:\\WherePatchPaeIs\\PatchPAE3.exe -type loader -o winldnew.exe winload.exe\n"
	L"    This will patch the loader to disable signature verification.\n\n"

	L"5.  bcdedit /copy {current} /d \"Windows (PAE Patched)\"\n"
	L"    This will create a new boot entry. A message should appear:\n"
	L"    The entry was successfully copied to {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.\n\n"

	L"[For Windows 8/8.1/10 only:]\n"
	L"6.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} kernel ntknew.exe\n"
	L"    This will set our boot entry to load our patched kernel.\n"
	L"[For Windows Vista/7/2008 only:]\n"
	L"6.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} kernel ntkpanew.exe\n"
	L"    This will set our boot entry to load our patched kernel.\n\n"

	L"7.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} path \\Windows\\system32\\winldnew.exe\n"
	L"    This will set our loader to be our patched loader.\n\n"

	L"8.  bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} nointegritychecks 1\n"
	L"    This will disable verification of the loader.\n"
	L"    This example not support for UEFI!\n\n"

	L"9.  bcdedit /set {bootmgr} default {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\n"
	L"    This will set our boot entry to be the default.\n\n"

	L"10. bcdedit /set {bootmgr} timeout 3\n"
	L"    This will set the timeout to be shorter.\n"
	L"    Note: you can change this timeout to whatever you like.\n\n"

	L"[For Windows 8/8.1/10 Only:]\n"
	L"11. bcdedit /set {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} bootmenupolicy legacy\n"
	L"    This will set our boot menu to classic text mode before loading drivers.\n"
	L"    Some stupid 32-bit drivers cannot work with more then 4 GB.\n\n"

	L"12. Restart the computer and enjoy.\n\n"

	L"To remove the patch:\n"
	L"    * Run msconfig, click Boot, highlight the\n"
	L"      entry named \"Windows (PAE Patched)\", and click Delete.\n"
	L"    * Delete the files ntknew.exe (or ntkpanew.exe) and\n"
	L"      winldnew.exe from C:\\Windows\\system32.\n\n"

	L"[For Windows XP/2003/Longhorn 4093:]\n"
	L"1.  Open Command Prompt window as Administrator.\n\n"

    L"2.  cd C:\\Windows\\system32\n"
    L"    Make sure the current directory is in fact system32.\n\n"

	L"3.  C:\\WherePatchPaeIs\\PatchPAE3.exe -type kernel -o ntxpnew.exe ntkrnlpa.exe\n"
	L"    This will patch the kernel to enable a maximum of 128GB of RAM.\n\n"
		
	L"[For Windows XP Only, no need for 2003/2000/Longhorn 4093:]\n"
	L"4.  C:\\WherePatchPaeIs\\PatchPAE3.exe -type hal -o halnew.dll hal.dll\n"
	L"    This will patch the hardware abstraction layer to\n"
	L"    enable a maximum of 128GB of RAM.\n\n"
		
	L"5.  attrib -R -A -S -H c:\\boot.ini\n"
	L"    You must change attributes for c:\\boot.ini to modify it.\n"
	L"    Then open c:\\boot.ini in text editor:\n"
	L"    notepad c:\\boot.ini\n\n"
		
	L"[For Windows XP only:]\n"
	L"6.  Add the line like this to section [operating systems] in c:\\boot.ini:\n"
	L"    multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS=\"Windows XP (PAE Patched)\" /kernel=ntkrnlpa.exe /hal=halnew.dll /fastdetect /pae /noexecute=optin.\n"
	L"    where \"multi(_)disk(_)rdisk(_)partition(_)\\WINDOWS\" you will copy from\n"
	L"    existing item in c:\\boot.ini\n"
	L"[For Windows 2003/Longhorn 4093 only:]\n"
	L"6.  Add the line like this to section [operating systems] in c:\\boot.ini:\n"
	L"    multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS=\"Server 2003 (PAE Patched)\" /kernel=ntkrnlpa.exe /fastdetect /pae /noexecute=optin.\n"
	L"    where \"multi(_)disk(_)rdisk(_)partition(_)\\WINDOWS\" you will copy from\n"
	L"    existing item in c:\\boot.ini\n\n"

	L"7.  Then save changes in c:\\boot.ini.\n"
	L"    You no need to patch the HAL in Server 2003/2000/Longhorn 4093.\n"
	L"    You no need to patch the loader in XP/2003/2000/Longhorn 4093.\n\n"
		
	L"8.  attrib +R +A +S +H c:\\boot.ini\n"
	L"    Set attributes for c:\\boot.ini to system/hidden.\n\n"
		
	L"9.  Restart the computer and enjoy.\n"
	L"    Some stupid 32-bit XP drivers cannot work with more then 4 GB.\n"
	L"    You may replace it from Server 2003.\n\n"

	L"[For Windows 2000/2003SP0:]\n"
	L"    PatchPAE cannot run in Windows 2000/2003SP0 now, but you may copy ntkrnlpa.exe\n"
	L"    from Win2k/Win2k3 to newer version of Windows like XP or 7 and patch it here.\n"
	L"    All actions for 2000 kernel are exactly same as for 2003 (step 3).\n"
	L"    Finally, copy patched kernel into Windows 2000 back and add new\n"
	L"    item in Win2k boot.ini like 2003 (step 5-8).\n\n"
		
	L"To remove the patch from XP/2003/2000/Longhorn 4093:\n"
	L"    * Delete line with \"Windows XP (PAE Patched)\" in\n"
	L"      section [operating systems] in c:\\boot.ini\n"
	L"    * Delete the files ntxpnew.exe and halnew.dll from C:\\Windows\\system32.\n\n"

	L"If You boot from UEFI, You must patch winload.efi instead winload.exe and\n"
	L"disable \"Secure Boot\" Option in UEFI.\n"

    L"\nhttp://www.geoffchappell.com/notes/windows/license/memory.htm"
    L"\nhttp://wj32.org/wp/2013/10/25/pae-patch-updated-for-windows-8-1/"
    L"\nhttp://iknowu.duckdns.org/files/public/Windows_XP_SP3_Remove_PAE_Limit/Windows_XP_Remove_PAE_Limit.htm"
    L"\nhttp://www.remkoweijnen.nl/blog/2011/03/27/windows-2003-server-standard-memory-patch/"
    L"\nhttps://geektimes.ru/post/202406/"
    L"\nhttp://www.overclock.net/t/77229/windows-xp-ram-limit/20"
    L"\nhttps://thxlp.wordpress.com/2008/08/03/%%E8%%80%%81%%E7%%94%%9F%%E5%%B8%%B8%%E8%%B0%%88-windows%%E5%%92%%8C4g%%E4%%BB%%A5%%E4%%B8%%8A%%E7%%89%%A9%%E7%%90%%86%%E5%%86%%85%%E5%%AD%%98/"
    L"\nhttp://rutracker.org/forum/viewtopic.php?t=4694409\n"
	);
}
VOID HelpType_BypassCPUID()
{
	wprintf(
	L"W8CPUFeaturePatch can be used to bypass the checks for the availability of the following\n"
	L"CPU features in Windows 8: PAE, NX, SSE2, CMPXCHG16B\n\n"

	L"1.  If your CPU doesn't support SSE2, NX or both (missing PAE support implies\n"
	L"    missing NX support) run patch with:\n"
	L"    PatchPAE3.EXE -type bypass_sse2nx -o ntknew.exe ntoskrnl.exe\n\n"
	L"    This will patch the kernel to disable CPUID NX- and SSE2-bit check.\n\n"

	L"2.  To enable support for more than one logical CPU core after patching NX,\n"
	L"    fix hyper-threading in hal.dll and fix hyper-threading in halmacpi.dll:\n"
	L"    PatchPAE3.EXE -type bypass_ht -o halnew.dll hal.dll\n"
	L"    PatchPAE3.EXE -type bypass_ht -o halmanew.dll halmacpi.dll\n\n"

	L"3.  If your CPU doesn't support PAE, fix winload.exe with patch:\n"
	L"    PatchPAE3.EXE -type bypass_pae -o winld1.exe winload.exe\n\n"
	L"    This will patch the loader to disable CPUID PAE-bit check.\n\n"

	L"4.  To get rid of the digital signature warning on boot after applying one of\n"
	L"    the patches above, remove winload patchguard:\n"
	L"    PatchPAE3.EXE -type loader -o winld2.exe winld1.exe\n\n"
	L"    This will patch the loader to disable signature verification.\n\n"

	L"5.  Update files (ntoskrnl.exe, hal.dll, halmacpi.dll, winload.exe) in\n"
	L"    install.wim resource file, then create ISO image.\n\n"

	L"6.  You have to run bcdedit.exe /set {default} NoIntegrityChecks Yes , if you patched winload.exe.\n\n"

	L"7.  Use dism.exe to work with install.wim\n\n"

	L"8.  Use takeown.exe and icacls.exe to replace original files\n\n"

	L"Notes:\n\n"

	L"* The patch does not make Windows 8 compatible to your CPU since it only bypasses the compatibility checks.\n"
	L"  This means that if Windows 8 tries to use one of the features, your computer will probably crash.\n"
	L"  For example, if you applied the CMPXCHG16B patch, a 0x0000001E (KMODE_EXCEPTION_NOT_HANDLED) BSOD with\n"
	L"  error code 0xFFFFFFFFC000001D (STATUS_ILLEGAL_INSTRUCTION) could occur if a CMPXCHG16B instruction is\n"
	L"  attempted to be executed. The only relatively safe patches are the NX and the hal/halmacpi patch.\n\n"

	L"* The patch does not make Windows 8 emulate PAE/DEP/NX since it only bypasses the compatibility checks.\n"
	L"  Windows 8 and old betas of Windows 10 (build < ~10130) can emulate NX/DEP, newer versions can't.\n"
	L"  Windows 7 and older no need this patch because emulation PAE/NX/DEP not locked.\n\n"

	L"* The tool cannot predict how the feature checks will be implemented in future file versions of the\n"
	L"  files to be patched, which means that there is a risk that future file versions cannot be patched\n\n"

	L"* For the reasons above, don't use these patches on your main OS! (disable updates)\n\n"

	L"* If Windows is stuck at the spinning dots on boot, you have to disable hyper-threading\n"
	L"  or to patch hal.dll and halmacpi.dll\n\n"

	L"http://forums.mydigitallife.info/threads/46840-Windows-8-CPU-Feature-Patch-(Bypass-Windows-8-CPU-feature-checks)\n"
	L"http://forums.mydigitallife.info/threads/37517-Q-Win-8-bypass-PAE-NX-SSE2-check\n\n"

	);
}

VOID HelpType_BypassWFP()
{
	wprintf(
	L"Disable SFC/WFP 2000 SP2+/2003/XP.\n\n"
	L"The Windows File Protection feature in Microsoft Windows prevents programs\n"
	L"from replacing critical Windows system files. After patch you may have to\n"
	L"turn the feature on or off in certain configurations. You can enable or\n"
	L"disable Windows File Protection in Microsoft Windows with a registry edit.\n\n"

	L"1a  For Windos 2000 SP2 and newer (no need to patch SP0/SP1):\n"
	L"    PatchPAE3.EXE -type bypass_wfp -o sfcnew.dll sfc.dll\n"
	L"    This will add disable SFC/WPF feature in 2000 system.\n\n"
	L"1b  For Windos XP/2003 patch:\n"
	L"    PatchPAE3.EXE -type bypass_wfp -o sfc_osnew.dll sfc_os.dll\n"
	L"    This will add disable SFC/WPF feature in 2003/XP system.\n\n"

	L"2.  Add the registry key:\n"
	L"    reg.exe ADD \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v SFCSetting /t REG_DWORD /d 0xFFFFFF9D /f\n"
	L"    This command deactivates SFC/WPF.\n\n"
	L"    Patched version sfc.dll/sfc_os.dll uses the key SFCSetting instead\n"
	L"    SFCDisable, because some M$ programs reset original-named key to 0.\n\n"

	L"5.  Update files sfc*.dll in distributive or run Windows\n"
	L"    in Safe Mode to replace files on live OS.\n\n"

	L"http://forum.oszone.net/post-378004.html#post378004\n"
	L"https://msfn.org/board/topic/110834-disable-xp-sfcwfp-works-with-sp3/\n\n"

	);
}


BOOLEAN CommandLineCallback(
    __in_opt PPH_COMMAND_LINE_OPTION Option,
    __in_opt PPH_STRING Value,
    __in_opt PVOID Context
    )
{
    if (Option)
    {
        switch (Option->Id)
        {
        case ARG_OUTPUT:
            PhSwapReference(&ArgOutput, Value);
            break;
        case ARG_TYPE:
            PhSwapReference(&ArgType, Value);
            break;
        case ARG_HELP:
            PhSwapReference(&ArgHelpTopic, Value);
            break;
		}
    }
    else
    {
        if (!ArgInput)
            PhSwapReference(&ArgInput, Value);
    }

    return TRUE;
}

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            // Handle error...
        }
    }
    return bIsWow64;
}

UINT GetFileVersion (TCHAR *pszFilePath, UINT *major, UINT *minor, UINT *revision, UINT *build)
{
    DWORD               dwSize              = 0;
    BYTE                *pbVersionInfo      = NULL;
    VS_FIXEDFILEINFO    *pFileInfo          = NULL;
    UINT                puLenFileInfo       = 0;

	//UINT major, minor, revision, build;

    // Get the version information for the file requested
    dwSize = GetFileVersionInfoSize( pszFilePath, NULL );
    if ( dwSize == 0 )
    {
        //printf( "Error in GetFileVersionInfoSize: %d\n", GetLastError() );
        return 1;
    }

    pbVersionInfo = (BYTE *) malloc(dwSize);
    if ( !pbVersionInfo )
    {
        //printf( "Error in memory allocate: %d\n", GetLastError() );
        return 2;
    }

    if ( !GetFileVersionInfo( pszFilePath, 0, dwSize, pbVersionInfo ) )
    {
        //printf( "Error in GetFileVersionInfo: %d\n", GetLastError() );
        free (pbVersionInfo);
        return 3;
    }

    if ( !VerQueryValue( pbVersionInfo, TEXT("\\"), (LPVOID*) &pFileInfo, &puLenFileInfo ) )
    {
        //printf( "Error in VerQueryValue: %d\n", GetLastError() );
        free (pbVersionInfo);
        return 4;
    }

// + dwProductVersionLS, dwProductVersionMS

	if(IsWow64())
{
        // 64 bit build
        *major =     (pFileInfo->dwFileVersionMS >> 16) & 0xffff;
        *minor =     (pFileInfo->dwFileVersionMS >>  0) & 0xffff;
        *revision =  (pFileInfo->dwFileVersionLS >> 16) & 0xffff;
        *build =     (pFileInfo->dwFileVersionLS >>  0) & 0xffff;
} 
else
{
        // 32 bit build
        *major =     HIWORD(pFileInfo->dwFileVersionMS);
        *minor =     LOWORD(pFileInfo->dwFileVersionMS);
        *revision =  HIWORD(pFileInfo->dwFileVersionLS);
        *build =     LOWORD(pFileInfo->dwFileVersionLS);
}


    //printf( "File Version: %d.%d.%d.%d\n", major, minor, revision, build);
    free (pbVersionInfo);

	return 0;
}

UINT UnpackTimeDateStamp(ULONG vTimeDateStamp, UINT *tm_year, UINT *tm_mon, UINT *tm_mday, UINT *tm_hour, UINT *tm_min, UINT *tm_sec)
{
	time_t rawtime;
	struct tm *info;

	*tm_year = *tm_mon = *tm_mday = *tm_hour = *tm_min = *tm_sec = 0;

	if(!vTimeDateStamp)
	{
		//printf("TimeDateStamp: Empty\r\n");
		return 1;
	}

	rawtime = (time_t) vTimeDateStamp;
	info = gmtime(&rawtime);

	*tm_year = info->tm_year + 1900;
	*tm_mon  = info->tm_mon + 1;
	*tm_mday = info->tm_mday;
	*tm_hour = info->tm_hour;
	*tm_min  = info->tm_min;
	*tm_sec  = info->tm_sec;

    //printf( "File Build: %d.%d.%d %d:%d:%d\n", *tm_year, *tm_mon, *tm_mday, *tm_hour, *tm_min, *tm_sec);
	//printf("stamp: %s\n", asctime(gmtime(&rawtime)));

	return 0;
}

int __cdecl main(int argc, char *argv[])
{
    static PH_COMMAND_LINE_OPTION options[] =
    {
        { ARG_HELP, L"help", MandatoryArgumentType },
        { ARG_OUTPUT, L"o", MandatoryArgumentType },
        { ARG_TYPE, L"type", MandatoryArgumentType }
    };

    PH_STRINGREF commandLine;
    ULONG stamp, machine;
	PWSTR strMachine;
	UINT major,  minor, revision, build;
	UINT tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec;

    if (!NT_SUCCESS(PhInitializePhLibEx(0, 0, 0)))
        return 1;

    PhUnicodeStringToStringRef(&NtCurrentPeb()->ProcessParameters->CommandLine, &commandLine);
    PhParseCommandLine(&commandLine, options, sizeof(options) / sizeof(PH_COMMAND_LINE_OPTION), PH_COMMAND_LINE_IGNORE_FIRST_PART, CommandLineCallback, NULL);

	wprintf(
	L"\nPatchPAE by wj32:\n - support for Windows Vista SP1/SP2, 7, 7 SP1, 8, 8.1\n - Server 2008 SP2\n"
	L"evgen_b MOD:\n"
	L" - added support for Vista SP0, 7 SP1 with KB3033929+,\n"
	L" - Windows XP SP2/SP3,\n"
	L" - Windows 10 (10240/10586/14393/15063/16299/17134/17763)\n"
	L" - Server 2003 SP0/SP1/SP2/SP2R2, Server 2008 SP1\n"
	L" - Server/Windows 2000 SP4 and 2000 SP4 with KernelEx by blackwingcat\n"
	L" - Windows Longhorn (4093 stable)\n"
	L" - Support many Windows betas:\n"
	L"     6801,7000,7022,7048,7057,7068,7077,7100,7127,7137,7201,7231,7260,7264,\n"
	L"     7850,7955,8102,8250,8400,9431,9841,9926,10049,10074,10122,10130,10147,\n"
	L"     10159,10166,14316,14352,14366,14393,14901,14915,15048,16257,16281,16226,\n"
	L"     16353,17063,17123,17623,17713,18277\n"
	L" - added Bypass Windows 8 CPU feature checks Patch by Jan1\n\n"
	L"Visual C++ 2010 Redistributable required.\n");
	wprintf(L"Version: %s\n\n", appver);

    if (argc < 3)
    {
		HelpType_Common();	
		return 2;
    }

	    if (argc == 3 && ArgHelpTopic)
    {
        if (PhEqualString2(ArgHelpTopic, L"unlock_pae", TRUE))
			HelpType_EnablePAE();
        else if (PhEqualString2(ArgHelpTopic, L"bypass_cpuid", TRUE))
			HelpType_BypassCPUID();
        else if (PhEqualString2(ArgHelpTopic, L"bypass_wfp", TRUE))
			HelpType_BypassWFP();
        else
			HelpType_Common();	
		return 2;
    }

    ArgTypeInteger = TYPE_KERNEL;

    if (ArgType)
    {
        if (PhEqualString2(ArgType, L"kernel", TRUE))
            ArgTypeInteger = TYPE_KERNEL;
        else if (PhEqualString2(ArgType, L"loader", TRUE))
            ArgTypeInteger = TYPE_LOADER;
        else if (PhEqualString2(ArgType, L"hal", TRUE))
            ArgTypeInteger = TYPE_HAL;
        else if (PhEqualString2(ArgType, L"bypass_pae", TRUE))
            ArgTypeInteger = TYPE_PAE;
        else if (PhEqualString2(ArgType, L"bypass_sse2nx", TRUE))
            ArgTypeInteger = TYPE_SSE2NX;
        else if (PhEqualString2(ArgType, L"bypass_ht", TRUE))
            ArgTypeInteger = TYPE_HT;
        else if (PhEqualString2(ArgType, L"bypass_wfp", TRUE))
            ArgTypeInteger = TYPE_SFC;
        else
            Fail(L"Wrong type. Must be \"kernel\", \"hal\" or \"loader\" for enable PAE.\n"
                L"Must be  \"bypass_pae\", \"bypass_sse2nx\" or \"bypass_ht\" for bypass cpuid PAE/NX/SSE2/HT check.\n"
                L"Must be  \"bypass_wfp\" for bypass SFC/WFP check.\n", 0);
    }

    if (PhIsNullOrEmptyString(ArgInput))
        Fail(L"Input file not specified!", 0);
    if (PhIsNullOrEmptyString(ArgOutput))
        Fail(L"Output file not specified!", 0);

    if (!CopyFile(ArgInput->Buffer, ArgOutput->Buffer, FALSE))
        Fail(L"Unable to copy file", GetLastError());

	stamp=GetTimeDateStamp(ArgOutput);
	//wprintf(L"TimeDateStamp: %x\n", stamp);

	machine=GetMachine(ArgOutput);
	//wprintf(L"Machine: %x\n", machine);

	switch (machine)
	{
		case 0x014c:
			strMachine=L"i386";
			break;
		case 0x8664:
			strMachine=L"AMD64";
			break;
		case 0x01C0:
			strMachine=L"ARM32";
			break;
		case 0xAA64:
			strMachine=L"ARM64";
			break;
		case 0x0200:
			strMachine=L"IA64";
			break;
		default:
			strMachine=L"other";
	}


	stamp=GetTimeDateStamp(ArgOutput);

    if (GetFileVersion (ArgOutput->Buffer, &major,  &minor, &revision, &build))
	{
        // в билде Windows 7 6801 beta - отсутствуют ресурсы, версию читать неоткуда.

		// FOR EXAMPLE:
		if		(stamp < 0x4549ACB4)
			//4549ACB4h  -> 02/11/2006  11:30:44 -> before vista sp0
			revision = 4000;
		else if (stamp < 0x4A5BBF2E)
			//4A5BBF2Eh  -> 14/07/2009  02:11:42  -> before windows 7 sp0
			revision = 6800;
		else if (stamp < 0x5010AE11)
			//5010AE11h  -> 26/07/2012  05:40:17  -> before windows 8.0
			revision = 9000;
		else if (stamp < 0x53088924)
			//53088924h  -> 22/02/2014  14:25:24  - before windows 8.1 ???
			revision = 9500;
		else
			revision = 13000;

		wprintf(L"Unable to get build number of the input file.\n"
				L"Assume revision:          %u\n", revision);
	}
	else
	{
		wprintf (L"Input File Version:       %d.%d.%d.%d\n", major, minor, revision, build);
	}
	UnpackTimeDateStamp (stamp, &tm_year, &tm_mon, &tm_mday, &tm_hour, &tm_min, &tm_sec);
	wprintf (L"Input File TimeDateStamp: %04d.%02d.%02d %02d:%02d:%02d (%8X)\n", tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, stamp);

	wprintf (L"Input File MachineID:     %s (%X)\n", strMachine, machine);

	if (ArgTypeInteger == TYPE_KERNEL)
    {
        if (revision <= 2195)
			// win 2k
            Patch(ArgOutput, PatchKernel_1999_2195_main);
        else if (revision <= 2600)
			// win xp
            Patch(ArgOutput, PatchKernel_2196_2600_main);
		else if (revision <= 3790)
			// server 2003
			Patch(ArgOutput, PatchKernel_2601_3790_main);
        else if (revision < 6000) //~4000-4100
			// Longhorn (ntkrnlpa.exe/halaacpi.dll) 4074 HAL supports PAE like
			// 2003 and no need to patch, but it crashes. MP too.
            Patch(ArgOutput, PatchKernel_3791_5999_main);
        else if (revision < 8400)
			// vista, server 2008, 7
            Patch(ArgOutput, PatchKernel_6000_8399_main);
        else if (revision <= 9200)
			// win 8
            Patch(ArgOutput, PatchKernel_8400_9200_main);
        else if (revision <= 9600)
			// win 8.1
            Patch(ArgOutput, PatchKernel_9201_9600_main);
		else if (revision > 9600)
			// win 10 RTM 10240-10586-14393-15063-16299-17134-17763
			Patch(ArgOutput, PatchKernel_9601_17623_main);
		else
            Fail(L"Unsupported kernel version.", 0);
    }
	else if (ArgTypeInteger == TYPE_HAL)
	{
        if (revision == 2600)
			// XP only
			Patch(ArgOutput, PatchHAL_2600_main);
		else
            Fail(L"Unsupported HAL version.", 0);
	}
	else if (ArgTypeInteger == TYPE_LOADER)
    {
        if (revision <= 6002)
			// win Vista
            Patch(ArgOutput, PatchLoader_6000_6002_main);
        else if (revision <= 7600)
			// win 7 w/o SP
            Patch(ArgOutput, PatchLoader_6003_7600_main);
        else if (revision == 7601)
			// win 7 SP1
            Patch(ArgOutput, PatchLoader_7601_main);
        else if (revision <= 9200)
			// win 8
            Patch(ArgOutput, PatchLoader_7602_9200_main);
        else if (revision <= 9600)
			// win 8.1
            Patch(ArgOutput, PatchLoader_9201_9600_main);
		else if (revision > 9600)
			// win 10 RTM 10240-10586, win 10 IP 14366, ...
			Patch(ArgOutput, PatchLoader_9601_17623_main);
		else
            Fail(L"Unsupported loader version.", 0);
    }
	else if (ArgTypeInteger == TYPE_PAE)
    {
		if (revision >= 8400)
			Patch(ArgOutput, PatchBypassPAE_main);
		else
            Fail(L"Unsupported loader version.", 0);
    }
	else if (ArgTypeInteger == TYPE_SSE2NX)
    {
		if (revision >= 8400)
			Patch(ArgOutput, PatchBypassSSE2NX_main);
		else
            Fail(L"Unsupported kernel version.", 0);
    }
	else if (ArgTypeInteger == TYPE_SFC)
	{
        if (revision >= 2195)
			// 2k/XP/2003
			Patch(ArgOutput, PatchSFC_2195_main);
		else
            Fail(L"Unsupported dll version.", 0);
	}
	else
    { //TYPE_HT
		if (revision >= 8400)
			Patch(ArgOutput, PatchBypassHT_main);
		else
            Fail(L"Unsupported HAL version.", 0);
    }

    return 0;
}

/*
== Compiling ==
To compile PatchPAE3, you need to get Process Hacker from processhacker.sourceforge.net and build it.
The directory structure should look like this:
 * ...\ProcessHacker2\lib\...
 * ...\ProcessHacker2\phlib\...
 * ...\PatchPAE3\PatchPAE3.sln
*/
