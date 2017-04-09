#include "cafe_loader.h"
#include "cafe.h"
#include "tinfl.c"

cafe_loader::cafe_loader(elf_reader<elf32> *elf) 
  : m_elf(elf)
{
  m_externStart = 0xffffffff;
  m_externEnd   = 0;
}

void cafe_loader::apply() {
  applySegments();
  swapSymbols();
  applyRelocations();
  processImports();
  processExports();
  applySymbols();
}

void cafe_loader::applySegments() {
  auto &sections = m_elf->getSections();

  // decompress all sections
  // TODO: only decompress once and when needed
  for (auto &section : sections) {
    if (section.sh_flags & ELF_SECTIONFLAGEX_CAFE_RPL_COMPZ) {
      const char *data = section.data();

      uint32 deflatedLen = *(uint32 *)data;

      swap(deflatedLen);

      unsigned char *deflatedData = new unsigned char[deflatedLen];

      deflatedLen = tinfl_decompress_mem_to_mem(
                              deflatedData,
                              deflatedLen,
                              data + 4,
                              section.sh_size - 4,
                              TINFL_FLAG_PARSE_ZLIB_HEADER
                              );

      section.setData((const char *)deflatedData, deflatedLen);
    }
  }

  const char *stringTable = m_elf->getSectionStringTable()->data();

  size_t index = 0;
  for (auto section : m_elf->getSections()) {
    if (section.sh_flags & SHF_ALLOC) {
      if (section.sh_type == SHT_NULL)
        continue;

      uchar perm = SEGPERM_READ;
      char *sclass;
      
      if (section.sh_flags & SHF_WRITE)
        perm |= SEGPERM_WRITE;
      if (section.sh_flags & SHF_EXECINSTR)
        perm |= SEGPERM_EXEC;
      
      if (section.sh_flags & SHF_EXECINSTR &&
          section.sh_type != ELF_SECTIONTYPE_CAFE_RPL_IMPORTS &&
          section.sh_type != ELF_SECTIONTYPE_CAFE_RPL_EXPORTS)
        sclass = CLASS_CODE;
      else if (section.sh_type == SHT_NOBITS)
        sclass = CLASS_BSS;
      else
        sclass = CLASS_DATA;
      
      const char *data = section.data();

      const char *name = NULL;
      if (section.sh_name != NULL)
        name = &stringTable[section.sh_name];

      applySegment(index, 
                   data, 
                   section.sh_addr, 
                   section.getSize(),
                   name,
                   sclass,
                   perm,
                   m_elf->getAlignment(section.sh_addralign),
                   section.sh_type == SHT_NOBITS ? false : true);

      ++index;
    }
  }
}

void cafe_loader::applySegment(uint32 sel,
                               const char *data,
                               uint32 addr,
                               uint32 size,
                               const char *name,
                               const char *sclass,
                               uchar perm,
                               uchar align,
                               bool load) {
  segment_t seg;
  seg.startEA = addr;
  seg.endEA = addr + size;
  seg.color = DEFCOLOR;
  seg.sel = sel;
  seg.bitness = 1;
  seg.orgbase = sel;
  seg.comb = scPub;
  seg.perm = perm;
  seg.flags = SFL_LOADER;
  seg.align = align;

  set_selector(sel, 0);

  if (name == NULL)
    name = "";

  add_segm_ex(&seg, name, sclass, NULL);

  if (load == true)
    mem2base(data, addr, addr + size, BADADDR);
}

void cafe_loader::applyRelocations() {
  auto &sections = m_elf->getSections();

  for (auto &section : sections) {
    if (section.sh_type == SHT_RELA) {
      auto symsec = m_elf->getSymbolsSection();
      auto symbols = m_elf->getSymbols();
      auto stringTable = m_elf->getSections()[symsec->sh_link].data();

      auto nrela = section.getSize() / sizeof(Elf32_Rela);
      auto relocations = reinterpret_cast<Elf32_Rela *>(section.data());

      for (size_t i = 0; i < nrela; ++i) {
        auto &rela = relocations[i];
          
        swap(rela.r_info);
        swap(rela.r_offset);
        swap(rela.r_addend);

        uint32 type = ELF32_R_TYPE(rela.r_info);
        uint32 sym  = ELF32_R_SYM (rela.r_info);

        // r_offset = address of relocation
        // r_addend = offset past symbol
        // r_sym    = address used as value to patch

        if (type == R_PPC_NONE)
          continue;

        uint32 addr = symbols[sym].st_value + rela.r_addend;

        switch (type) {
        // TODO: support RPL relocation
        // since RPL relocation is not yet supported we do 
        // not need to patch anything.
        // as far as I've seen they're already set anyway
/*      case R_PPC_ADDR32:
          patch_long(rela.r_offset, addr);
          break;
        case R_PPC_ADDR16_LO:
          patch_word(rela.r_offset, addr);
          break;
        case R_PPC_ADDR16_HI:
          patch_word(rela.r_offset, addr >> 16);
          break;
        case R_PPC_ADDR16_HA:
          patch_word(rela.r_offset, (addr + 0x8000) >> 16);
          break;              */
        case R_PPC_REL24: {
            if (symbols[sym].st_value & 0xc0000000 &&
              ELF32_ST_TYPE(symbols[sym].st_info) == STT_FUNC) {
              auto inst = get_original_long(rela.r_offset);
              auto addr = rela.r_offset + (inst & 0x3fffffc);

              if (m_externStart > addr)
                m_externStart = addr;
              if (m_externEnd < addr)
                m_externEnd = addr + 8;

              import temp = { 
                              addr, 
                              symbols[sym].st_value, 
                              &stringTable[symbols[sym].st_name] 
                            };

              m_imports.push_back(temp);
            }
          }
          break;
        }
      }
    }
  }
}

void cafe_loader::processImports() {
  if (m_externStart != 0xffffffff && m_externEnd != 0) {
    segment_t ext;
    ext.startEA = m_externStart;
    ext.endEA = m_externEnd;
    ext.sel = 255;
    ext.bitness = 1;
    ext.color = DEFCOLOR;
    ext.orgbase = 255;
    ext.comb = scPub;
    ext.perm = SEGPERM_READ | SEGPERM_EXEC;
    ext.flags = SFL_LOADER;
    ext.align = saRelQword;

    set_selector(255, 0);
    add_segm_ex(&ext, ".extern", "XTRN", NULL);
  }

  for (auto &import : m_imports) {
    char name[256];
    do_name_anyway(import.addr, import.name);

    char lib[32];
    get_segm_name(import.orig, lib, 32);

    netnode impnode;
    impnode.create();

    if (demangle_name(name, 256, import.name, NULL))
      impnode.supset(import.addr, name);
    else
      impnode.supset(import.addr, import.name);

    import_module(lib + 9, NULL, impnode, NULL, "wiiu");
  }
}

void cafe_loader::processExports() {
  segment_t *seg;
  uint32 start = 0;
  uint32 numExports;

  if ((seg = get_segm_by_name(".fexports")) != NULL) {
    start = seg->startEA;
    numExports = get_long(start);

    for (int i = 0; i < numExports + 1; ++i) {
      doDwrd((start + (i * 8)) + 0, 4);
      doDwrd((start + (i * 8)) + 4, 4);

      if (i == 0)
        continue;

      uint32 addr = get_long(start + (i * 8) + 0);
      uint32 name = get_long(start + (i * 8) + 4);

      auto_make_proc(addr);

      char exp[256];
      get_ascii_contents(start + name, 
          get_max_ascii_length(start + name, ASCSTR_C, true), 
              ASCSTR_C, exp, 256);

      add_entry(addr, addr, exp, true);
    }
  }

  if ((seg = get_segm_by_name(".dexports")) != NULL)
  {
    start = seg->startEA;
    numExports = get_long(start);

    for (int i = 0; i < numExports + 1; i++)
    {
      doDwrd((start + (i * 8)) + 0, 4);
      doDwrd((start + (i * 8)) + 4, 4);

      if (i == 0)
        continue;

      uint32 addr = get_long(start + (8 * i) + 0);
      uint32 name = get_long(start + (8 * i) + 4);

      char exp[256];
      get_ascii_contents(start + name, 
          get_max_ascii_length(start + name, ASCSTR_C, true), 
              ASCSTR_C, exp, 256);

      add_entry(addr, addr, exp, true);
    }
  }
}

void cafe_loader::swapSymbols() {
  msg("Swapping symbols...\n");

  // Since section based relocations depend on symbols 
  // we need to swap symbols before we get to relocations.
  auto section = m_elf->getSymbolsSection();
  auto symbols = m_elf->getSymbols();

  for (size_t i = 0; 
        i < section->getSize() / 
          section->sh_entsize; ++i) {
    auto symbol = &symbols[i];

    swap(symbol->st_name);
    swap(symbol->st_shndx);
    swap(symbol->st_size);
    swap(symbol->st_value);
  }
}

void cafe_loader::applySymbols() {
  msg("Applying symbols...");
  
  auto section = m_elf->getSymbolsSection();
  
  if (section == NULL)
    return;
  
  auto nsym = section->getSize() / section->sh_entsize;
  auto symbols = m_elf->getSymbols();

  const char *stringTable = m_elf->getSections()[section->sh_link].data();

  for (size_t i = 0; i < nsym; ++i) {
    auto &symbol = symbols[i];
      
    uint32 type = ELF32_ST_TYPE(symbol.st_info),
           bind = ELF32_ST_BIND(symbol.st_info);
    uint32 value = symbol.st_value;

    if (symbol.st_shndx > m_elf->getNumSections() ||
      !(m_elf->getSections()[symbol.st_shndx].sh_flags & SHF_ALLOC))
      continue;

    if (symbol.st_shndx == SHN_ABS)
      continue;

    // TODO: these are the same for all ELF's, maybe move to ELF reader
    switch (type) {
    case STT_OBJECT:
      do_name_anyway(value, &stringTable[symbol.st_name]);
      break;
    case STT_FILE:
      describe(value, true, "Source File: %s", &stringTable[symbol.st_name]);
      break;
    case STT_FUNC:
      do_name_anyway(value, &stringTable[symbol.st_name]);
      auto_make_proc(value);
      break;
    }
  }
}