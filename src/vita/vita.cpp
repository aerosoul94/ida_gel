#include "../elf_common/elf_reader.hpp"
#include "psp2_loader.hpp"
#include "sce.h"

#include <idaldr.h>
#include <memory>

static int idaapi
 accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  if (n > 0)
    return 0;

  elf_reader<elf32> elf(li);

  if (elf.verifyHeader() && 
      elf.machine() == EM_ARM) {
    const char *type;

    if (elf.type() == ET_SCE_EXEC)
      type = "Executable";
    else if (elf.type() == ET_SCE_RELEXEC)
      type = "Relocatable Executable";
    else
      return 0;

    set_processor_type("ARM", SETPROC_ALL);

    qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "Playstation Vita %s", type);

    return ACCEPT_FIRST | 1;
  }

  return 0;
}

static void idaapi
 load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
  elf_reader<elf32> elf(li); elf.read();
  psp2_loader ldr(&elf, "vita.txt"); ldr.apply();
}

#ifdef _WIN32
__declspec(dllexport)
#endif
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,
  accept_file,
  load_file,
  NULL,
  NULL,
  NULL
};