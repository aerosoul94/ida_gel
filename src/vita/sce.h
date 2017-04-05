#pragma once

#include "elf.h"

#define ET_SCE_EXEC     	  0xfe00
#define ET_SCE_RELEXEC  	  0xfe04		/* PRX */

#define ET_SCE_ARMRELEXEC   0xffa5

#define SHT_SCE_ARMRELA   0x700000a4

#define PT_SCE_RELA		  0x60000000

#define PT_SCE_COMMENT  0x6fffff00
#define PT_SCE_VERSION	0x6fffff01

#define PT_SCE_ARMRELA  0x700000A4
#define PT_SCE_SEGSYM   0x700000A8

#define SYS_MODULE_NAME_LEN	    27
#define SYS_MODULE_MAX_SEGMENTS	4

#define SYS_LIB_AUTO_EXPORT	  (0x0001)
#define SYS_LIB_WEAK_EXPORT	  (0x0002)
#define SYS_LIB_NOLINK_EXPORT	(0x0004)
#define SYS_LIB_WEAK_IMPORT	  (0x0008)

/* MODULE INFO */

typedef struct _scemoduleinfo_common {
  unsigned short modattribute;
  unsigned char modversion[2];
  char modname[SYS_MODULE_NAME_LEN];
  char terminal;
} sceModuleInfo_common;

typedef struct _scemoduleinfo_prx2arm {
  sceModuleInfo_common c; 
  Elf32_Addr resreve; 
  Elf32_Addr ent_top; 
  Elf32_Addr ent_end; 
  Elf32_Addr stub_top;
  Elf32_Addr stub_end;
  Elf32_Word dbg_fingerprint;
  Elf32_Addr tls_top;
  Elf32_Addr tls_filesz;
  Elf32_Addr tls_memsz; 
  Elf32_Addr start_entry;
  Elf32_Addr stop_entry; 
  Elf32_Addr arm_exidx_top;
  Elf32_Addr arm_exidx_end;
  Elf32_Addr arm_extab_top;
  Elf32_Addr arm_extab_end;
} sceModuleInfo_prx2arm;

/* IMPORTS */

typedef struct _scelibstub_common {
  unsigned char structsize;
  unsigned char reserved1[1];
  unsigned short version;
  unsigned short attribute;
  unsigned short nfunc;
  unsigned short nvar;
  unsigned short ntlsvar;
  unsigned char reserved2[4];
} sceKernelLibraryStubTable_common;

typedef sceKernelLibraryStubTable_common
        sceKernelLibraryStubTable_prx2_common;

typedef struct _scelibstub_prx2arm {
  sceKernelLibraryStubTable_prx2_common c;
  Elf32_Word libname_nid;
  Elf32_Addr libname;
  Elf32_Word sce_sdk_version;
  Elf32_Addr func_nidtable;
  Elf32_Addr func_table;
  Elf32_Addr var_nidtable; 
  Elf32_Addr var_table; 
  Elf32_Addr tls_nidtable; 
  Elf32_Addr tls_table;
} sceKernelLibraryStubTable_prx2arm;

/* EXPORTS */

typedef struct _scelibent_common {
  unsigned char structsize;
  unsigned char auxattribute;
  short unsigned int version;
  short unsigned int attribute;
  short unsigned int nfunc;
  short unsigned int nvar;
  short unsigned int ntlsvar;
  unsigned char hashinfo;
  unsigned char hashinfotls;
  unsigned char reserved2[1];
  unsigned char nidaltsets;
} sceKernelLibraryEntryTable_common;

typedef sceKernelLibraryEntryTable_common
        sceKernelLibraryEntryTable_prx2_common;

typedef struct _scelibent_prx2arm {
  sceKernelLibraryEntryTable_prx2_common c;
  Elf32_Word libname_nid;
  Elf32_Addr libname; 
  Elf32_Addr nidtable;
  Elf32_Addr addtable;
} sceKernelLibraryEntryTable_prx2arm;
