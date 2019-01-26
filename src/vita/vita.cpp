#include "psp2_loader.h"

static int idaapi
 accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename) {
  elf_reader<elf32> elf(li);

  if (elf.verifyHeader() && elf.machine() == EM_ARM) {
    const char *type = "Unknown";
    switch (elf.type()) {
      case ET_SCE_RELEXEC:
        type = "Relocatable PRX";
        break;
      case ET_SCE_EXEC:
        type = "Executable";
        break;
    }

    fileformatname->sprnt("PS Vita for ARM (%s)", type);

    return 1;
  }

  return 0;
}

void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
  elf_reader<elf32> elf(li);
  elf.read();
  psp2_loader ldr(&elf, "vita.txt");

  set_processor_type("ARM", SETPROC_LOADER);

  inf.baseaddr = 0;
  inf.specsegs = 4;

  set_imagebase(elf.entry());

  ldr.apply();
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