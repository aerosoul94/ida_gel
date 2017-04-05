#pragma once

#include "elf.h"

#define ELFOSABI_CELLOSLV2            102     /* CellOS Lv2 */ /* sce local */

#define ET_SCE_PPURELEXEC	  0xffa4

#define SHT_SCE_PPURELA	  0x700000a4

#define PT_PROC_PARAM		  0x60000001
#define PT_PROC_PRX     	0x60000002

#define PT_SCE_COMMENT  0x6fffff00
#define PT_SCE_VERSION	0x6fffff01

#define PT_SCE_PPURELA	0x700000a4
#define PT_SCE_SEGSYM   0x700000a8

#define PF_SPU_X  (0x00100000) /* SPU executable defined, but unused.*/
#define PF_SPU_W  (0x00200000) /* SPU writable  */
#define PF_SPU_R  (0x00400000) /* SPU readable  */
#define PF_RSX_X  (0x01000000) /* RSX executable defined, but unused. */
#define PF_RSX_W  (0x02000000) /* RSX writable */
#define PF_RSX_R  (0x04000000) /* RSX readable */

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

typedef struct _scemoduleinfo_ppu32 {
  sceModuleInfo_common c;
  Elf32_Addr gp_value;
  Elf32_Addr ent_top;
  Elf32_Addr ent_end;
  Elf32_Addr stub_top;
  Elf32_Addr stub_end;
} sceModuleInfo_ppu32;

typedef struct _scemoduleinfo_ppu64 {
  sceModuleInfo_common c;
  Elf64_Addr gp_value;
  Elf64_Addr ent_top; 
  Elf64_Addr ent_end; 
  Elf64_Addr stub_top;
  Elf64_Addr stub_end;
} sceModuleInfo_ppu64;


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
        sceKernelLibraryStubTable_ppu_common;

typedef struct _scelibstub_ppu32 {
  sceKernelLibraryStubTable_ppu_common c;
  Elf32_Addr libname;
  Elf32_Addr func_nidtable;
  Elf32_Addr func_table;
  Elf32_Addr var_nidtable;
  Elf32_Addr var_table;
  Elf32_Addr tls_nidtable;
  Elf32_Addr tls_table;
} sceKernelLibraryStubTable_ppu32;

typedef struct _scelibstub_ppu64 {
  sceKernelLibraryStubTable_ppu_common c;
  Elf64_Addr libname;
  Elf64_Addr func_nidtable;
  Elf64_Addr func_table;
  Elf64_Addr var_nidtable;
  Elf64_Addr var_table;
  Elf64_Addr tls_nidtable;
  Elf64_Addr tls_table;
} sceKernelLibraryStubTable_ppu64;

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
        sceKernelLibraryEntryTable_ppu_common;

typedef struct _scelibent_ppu32 {
  sceKernelLibraryEntryTable_ppu_common c;
  Elf32_Addr libname;
  Elf32_Addr nidtable;
  Elf32_Addr addtable;
} sceKernelLibraryEntryTable_ppu32;

typedef struct _scelibent_ppu64 {
  sceKernelLibraryEntryTable_ppu_common c;
  Elf64_Addr libname;
  Elf64_Addr nidtable;
  Elf64_Addr addtable;
} sceKernelLibraryEntryTable_ppu64;

/* PROCESS PARAM */

#define SYS_PROCESS_PARAM_MAGIC			0x13bcc5f6

typedef struct {
  unsigned int size;
  unsigned int magic;
  unsigned int version;
  unsigned int sdk_version;
  int primary_prio;
  unsigned int primary_stacksize;
  unsigned int malloc_pagesize;
  unsigned int ppc_seg;
  unsigned int crash_dump_param_addr;
} sys_process_param_t;

/* PROCESS PRX */

#define SYS_PROCESS_PRX_MAGIC			0x1b434cec
#define SYS_PROCESS_PRX_VERSION         4           /* latest */

typedef struct sys_process_prx_info_t {
  unsigned int size;
  unsigned int magic;
  unsigned int version;
  unsigned int sdk_version;
  unsigned int libent_start;
  unsigned int libent_end;
  unsigned int libstub_start;
  unsigned int libstub_end;
  unsigned char major_version;
  unsigned char minor_version;
  unsigned char reserved[6];
} sys_process_prx_info_t;
