#include <fstream>

#include "../elf_common/elf_reader.h"
#include "psp2_loader.h"
#include "sce.h"

#include <idaldr.h>
#include <memory>

static int idaapi
 accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename)
{
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

    *processor = "arm";

    fileformatname->sprnt("Playstation Vita %s", type);

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
  nullptr,
  nullptr,
  nullptr
};