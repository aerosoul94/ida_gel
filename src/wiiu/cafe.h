
#ifndef CAFE_H
#define CAFE_H

#define ELF_IDENT_OS_CAFE       0xCA
#define ELF_IDENT_ABI_CAFE_RPL  0xFE

#define ELF_FILETYPE_CAFE_RPL   0xfe01

#define ELF_SECTIONFLAGEX_CAFE_RPL_COMPZ	0x08000000

#define ELF_SECTIONTYPE_CAFE_RPL_EXPORTS	0x80000001
#define ELF_SECTIONTYPE_CAFE_RPL_IMPORTS	0x80000002
#define ELF_SECTIONTYPE_CAFE_RPL_CRCS     0x80000003
#define ELF_SECTIONTYPE_CAFE_RPL_FILEINFO 0x80000004

typedef struct _CAFE_RPL_FILE_INFO_3_0
{
  Elf32_Word mVersion; /* CAFE_RPL_FILE_INFO_VERSION */
  Elf32_Word mRegBytes_Text;
  Elf32_Word mRegBytes_TextAlign;
  Elf32_Word mRegBytes_Data;
  Elf32_Word mRegBytes_DataAlign;
  Elf32_Word mRegBytes_Read;
  Elf32_Word mRegBytes_ReadAlign;
  Elf32_Word mRegBytes_Temp;
  Elf32_Word mTrampAdj;
  Elf32_Word mSDABase;
  Elf32_Word mSDA2Base;
  Elf32_Word mSizeCoreStacks;
  Elf32_Word mSrcFileNameOffset; /* from start of FILE_INFO */
  Elf32_Word mReserved[3];
} CAFE_RPL_FILE_INFO_3_0;

typedef struct _CAFE_RPL_FILE_INFO_4_1
{
  Elf32_Word mVersion;
  Elf32_Word mRegBytes_Text;
  Elf32_Word mRegBytes_TexAlign;
  Elf32_Word mRegBytes_Data;
  Elf32_Word mRegBytes_DataAlign;
  Elf32_Word mRegBytes_LoaderInfo;
  Elf32_Word mRegBytes_LoaderInfoAlign;
  Elf32_Word mRegBytes_Temp;
  Elf32_Word mTrampAdj;
  Elf32_Word mSDABase;
  Elf32_Word mSDA2Base;
  Elf32_Word mSizeCoreStacks;
  Elf32_Word mSrcFileNameOffset;
  Elf32_Word mFlags;
  Elf32_Word mSysHeapBytes;
  Elf32_Word mTagsOffset;
} CAFE_RPL_FILE_INFO_4_1;

typedef struct _CAFE_RPL_FILE_INFO_4_2
{
  Elf32_Word mVersion;
  Elf32_Word mRegBytes_Text;
  Elf32_Word mRegBytes_TextAlign;
  Elf32_Word mRegBytes_Data;
  Elf32_Word mRegBytes_DataAlign;
  Elf32_Word mRegBytes_LoaderInfo;
  Elf32_Word mRegBytes_LoaderInfoAlign;
  Elf32_Word mRegBytes_Temp;
  Elf32_Word mTrampAdj;
  Elf32_Word mSDABase;
  Elf32_Word mSDA2Base;
  Elf32_Word mSizeCoreStacks;
  Elf32_Word mSrcFileNameOffset;
  Elf32_Word mFlags;
  Elf32_Word mSysHeapBytes;
  Elf32_Word mTagsOffset;
  Elf32_Word mRPLMinSDKVersion;
  Elf32_Word mCompressionLevel;
  Elf32_Word mTrampAddition;
  Elf32_Word mFileInfoPad;
  Elf32_Word mSDKVersion;
  Elf32_Word mSDKRevision;
  Elf32_Word mTLSModuleIndex;
  Elf32_Half mTLSAlignShift;
  Elf32_Half mRuntimeFileInfoSize;
} CAFE_RPL_FILE_INFO_4_2;

#endif /* CAFE_H */