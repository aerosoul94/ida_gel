#include <fstream>

#include "psp2_loader.h"
#include <struct.hpp>
#include <pro.h>
#include <string>

psp2_loader::psp2_loader(elf_reader<elf32> *elf, std::string databaseFile)
  : m_elf(elf)
{
  inf.demnames |= DEMNAM_GCC3;  // assume gcc3 names
  inf.af       |= AF_PROCPTR;   // Create function if data xref data->code32 exists
  //inf.af       |= AF_IMMOFF;    // Convert 32bit instruction operand to offset
  inf.af       |= AF_DREFOFF;   // Create offset if data xref to seg32 exists
  inf.af2      |= AF2_DOEH;

  char databasePath[QMAXPATH];

  if (!getsysfile(databasePath, QMAXFILE, databaseFile.c_str(), LDR_SUBDIR))
    loader_failure("Could not locate database file (%s).\n", databaseFile.c_str());

  m_database.open(databasePath);

  if (!m_database.is_open())
    loader_failure("Failed to open database file (%s).\n", databaseFile.c_str());

  unsigned int nid;
  std::string symbol;
  while (m_database >> std::hex >> nid >> symbol) { 
    m_nidset.insert(std::pair<unsigned int, std::string>(nid, symbol));
  }
}

void psp2_loader::apply() {
  declareStructures();

  applySegments();

  if ( isLoadingPrx() )
    applyRelocations();

  applyModuleInfo();
  applySymbols();
}

void psp2_loader::applySegments() {
  if ( m_elf->getNumSections() > 0 )
    applySectionHeaders();
  else if ( m_elf->getNumSegments() > 0 )
    applyProgramHeaders();
}

void psp2_loader::applySectionHeaders() {
  auto &sections = m_elf->getSections();
  const char *strTab = m_elf->getSectionStringTable()->data();

  size_t index = 0;
  for (const auto &section : sections) {
    if (!(section.sh_flags & SHF_ALLOC) ||  // is not allocatable
          section.sh_size == SHT_NULL ||        // has no data
          section.sh_type == SHT_NULL)      // skip unused entry
      continue;

    uchar perm = SEGPERM_READ;
    const char *sclass;

    if (section.sh_flags & SHF_WRITE)
      perm |= SEGPERM_WRITE;
    if (section.sh_flags & SHF_EXECINSTR)
      perm |= SEGPERM_EXEC;

    if (section.sh_flags & SHF_EXECINSTR)
      sclass = CLASS_CODE;
    else if (section.sh_type == SHT_NOBITS)
      sclass = CLASS_BSS;
    else
      sclass = CLASS_DATA;

    const char *name = "";
    if (section.sh_name != 0)
      name = &strTab[section.sh_name];

    applySegment( index, 
                  section.sh_offset, 
                  section.sh_addr, 
                  section.sh_size,
                  name, 
                  sclass, 
                  perm, 
                  m_elf->getAlignment(section.sh_addralign),
                  section.sh_type == SHT_NOBITS);

    ++index;
  }
}

void psp2_loader::applyProgramHeaders() {
  auto &segments = m_elf->getSegments();

  size_t index = 0;
  for (const auto &segment : segments) {
    if (segment.p_memsz == 0)
      continue;

    uchar perm = 0;
    const char *sclass;

    if (segment.p_flags & PF_W)     // if its writable
      sclass = CLASS_DATA;
    if ((segment.p_flags & PF_R) && // if its only readable
      !(segment.p_flags & PF_W) &&
      !(segment.p_flags & PF_X))
      sclass = CLASS_CONST;
    if (segment.p_flags & PF_X)     // if its executable
      sclass = CLASS_CODE;
      
    if (segment.p_filesz == 0 &&
        segment.p_memsz > 0)
      sclass = CLASS_BSS;

    if (segment.p_flags & PF_X)
      perm |= SEGPERM_EXEC;
    if (segment.p_flags & PF_W)
      perm |= SEGPERM_WRITE;
    if (segment.p_flags & PF_R)
      perm |= SEGPERM_READ;

    applySegment(index, 
                 segment.p_offset, 
                 segment.p_vaddr, 
                 segment.p_memsz,
                 NULL, 
                 sclass, 
                 perm, 
                 m_elf->getAlignment(segment.p_align),
                 segment.p_filesz == 0);

    ++index;
  }
}

void psp2_loader::applySegment(
    uint32 sel, 
    uint64 offset, 
    uint64 addr, 
    uint64 size,
    const char *name, 
    const char *sclass, 
    uchar perm, 
    uchar align, 
    bool load) {
        
  segment_t seg;
  seg.start_ea = addr;
  seg.end_ea = addr + size;
  seg.color = DEFCOLOR;
  seg.sel = sel;
  seg.bitness = 1;
  seg.orgbase = sel;
  seg.comb = scPub;
  seg.perm = perm;
  seg.flags = SFL_LOADER;
  seg.align = align;

  set_selector(sel, 0);

  if (name == nullptr)
    name = "";

  add_segm_ex(&seg, name, sclass, 0);

  if (load == true)
    file2base(m_elf->getReader(), offset, addr, addr + size, true);
}

void psp2_loader::applyRelocations() {
  auto &segments = m_elf->getSegments();

  msg("Searching for relocation segments...\n");
  for (auto &segment : segments) {
    if (segment.p_type != PT_SCE_RELA)
      continue;
    
    //msg("This segment offset: %08x\n", segment.p_offset);
    //msg("This segment filesz: %08x\n", segment.p_filesz);

    auto nwords = segment.p_filesz / sizeof(Elf32_Word);
    auto rel = reinterpret_cast<Elf32_Word *>(segment.data());

    //msg("Relocation segment at offset %08x\n", segment.p_offset); 

    // initialized in format 1 and 2
    uint32 g_addr = 0,
           g_offset = 0,
           g_patchseg = 0;

    // initiliazed in format 0, 1, 2, and 3
    uint32 g_saddr = 0,
           g_addend = 0,
           g_type = 0,
           g_type2 = 0;

    size_t index = 0;
    for (size_t pos = 0; pos < nwords; ++pos) {
      auto r_format = rel[pos] & 0xF;

      //msg("Relocation %i\n", index);
      //msg("r_format %i\n", r_format);

      switch (r_format) {
      case 0: {
        //msg("%08x %08x %08x\n", rel[pos], rel[pos+1], rel[pos+2]);
        auto r_symseg   = (rel[pos] >> 4)  & 0xF;  // index into phdrs
             g_type     = (rel[pos] >> 8)  & 0xFF; // relocation type
             g_patchseg = (rel[pos] >> 16) & 0xF;  // index into phdrs
             g_type2    = (rel[pos] >> 20) & 0x7F; // second relocation
        auto r_dist2    = (rel[pos] >> 27) & 0xF8; // distance from first offset
             g_addend   = (rel[pos+1]);           // addend
             g_offset   = (rel[pos+2]);           // first offset

        // save these
        g_addr = segments[g_patchseg].p_vaddr;
        g_saddr = segments[r_symseg].p_vaddr;

        /*msg("  r_symseg   %i [%08x]\n", r_symseg, segments[r_symseg].p_vaddr);
        msg("  r_type     %i\n", g_type);
        msg("  r_patchseg %i [%08x]\n", g_patchseg, segments[g_patchseg].p_vaddr);
        msg("  r_type2    %i\n", g_type2);
        msg("  r_dist2    %x\n", r_dist2);
        msg("  r_addend   %08x\n", g_addend);
        msg("  r_offset   %08x\n", g_offset);
               
        msg("  relocation info[1]\n");
        msg("    patch addr %08x\n", segments[g_patchseg].p_vaddr + g_offset);
        msg("    sym addr   %08x\n", segments[r_symseg].p_vaddr);
        msg("    + addend   %08x\n", g_addend);

        if (g_type2) {
          msg("  relocation info[2]\n");
          msg("    patch addr %08x\n", segments[g_patchseg].p_vaddr + r_dist2 + g_offset);
          msg("    sym addr   %08x\n", segments[r_symseg].p_vaddr);
          msg("    + addend   %08x\n", g_addend);
        }*/
        pos += 2; 

        applyRelocation(g_type,
                        g_addr + g_offset,
                        g_saddr,
                        g_addend);

        if (g_type2 != R_ARM_NONE) {
          applyRelocation(g_type2,
                          g_addr + g_offset + r_dist2,
                          g_saddr,
                          g_addend);
        }
        break;  // size = 12
        }
      case 1: {
        //msg("%08x %08x\n", rel[pos], rel[pos + 1]);
        auto r_symseg   = (rel[pos] >> 4)  & 0xF;  // index into phdrs
             g_type     = (rel[pos] >> 8)  & 0xFF; // relocation type
             g_patchseg = (rel[pos] >> 16) & 0xF;  // index into phdrs
             g_offset   = (rel[pos] >> 20) |      // offset
                         ((rel[pos+1] & 0x3FF) << 12);
             g_addend   = (rel[pos+1] >> 10);     // addend

        // save these
        g_addr = segments[g_patchseg].p_vaddr;
        g_saddr = segments[r_symseg].p_vaddr;

        /*msg("  r_symseg   %i [%08x]\n", r_symseg, segments[r_symseg].p_vaddr);
        msg("  r_type     %i\n", g_type);
        msg("  r_patchseg %i [%08x]\n", g_patchseg, segments[g_patchseg].p_vaddr);
        msg("  r_offset   %08x\n", g_offset);
        msg("  r_addend   %08x\n", g_addend);
        msg("  relocation info [1]\n");
        msg("    patch addr %08x\n", segments[g_patchseg].p_vaddr + g_offset);
        msg("    sym addr   %08x\n", segments[r_symseg].p_vaddr);
        msg("    + addend   %08x\n", g_addend);*/

        applyRelocation(g_type, 
                        g_addr + g_offset,
                        g_saddr,
                        g_addend);
        g_type2 = 0;

        pos += 1;
        break;  // size = 8
        }
      case 2: {
        //msg("%08x %08x\n", rel[pos], rel[pos + 1]);
        auto r_symseg = (rel[pos] >> 4) & 0xF;
             g_type   = (rel[pos] >> 8) & 0xFF;
        auto r_offset = (rel[pos] >> 16);
             g_addend = (rel[pos+1]);

        g_offset += r_offset;
        g_saddr = segments[r_symseg].p_vaddr;

        /*msg("  r_symseg   %i [%08x]\n", r_symseg, segments[r_symseg].p_vaddr);
        msg("  r_type     %i\n", g_type);
        msg("  r_offset   %08x\n", r_offset);
        msg("  r_addend   %08x\n", g_addend);
        msg("  relocation info [1]\n");
        msg("    patch addr %08x + %08x\n", g_addr, r_offset);
        msg("    sym addr    %08x\n", segments[r_symseg].p_vaddr);
        msg("    + addend    %08x\n", g_addend);*/

        applyRelocation(g_type,
                        g_addr + g_offset,
                        g_saddr,
                        g_addend);

        g_type2 = 0;

        pos += 1; 
        break;  // size = 8
        }
      case 3: { // for THUMB/ARM MOVW/MOVT pairs
        //msg("%08x %08x\n", rel[pos], rel[pos + 1]);
        auto r_symseg = (rel[pos] >> 4)  & 0xF;
        auto r_mode   = (rel[pos] >> 8)  & 1; // 1 = THUMB, 0 = ARM
        auto r_offset = (rel[pos] >> 9)  & 0x3FFFF;
        auto r_dist2  = (rel[pos] >> 27) & 0x1F;
             g_addend = (rel[pos+1]);
        // if r_mode rtype1 = R_ARM_THM_MOVW_ABS_NC  <- THUMB
        // else rtype1 = R_ARM_MOVW_ABS_NC <- ARM
        // if r_mode rtype2 = R_ARM_THM_MOVT_ABS <- THUMB
        // else rtype2 = R_ARM_MOVT_ABS <- ARM
        // offset = prevoffset + r_offset
        // offset2 = offset + r_offset2
        /*msg("  r_symseg   %i\n", r_symseg);
        msg("  r_mode     %i\n", r_mode);
        msg("  r_offset   %08x\n", r_offset);
        msg("  r_dist2    %08x\n", r_dist2);
        msg("  r_addend   %08x\n", g_addend);*/

        if (r_mode == 1)
          g_type = R_ARM_THM_MOVW_ABS_NC;
        else if (r_mode == 0)
          g_type = R_ARM_MOVW_ABS_NC;

        if (r_mode == 1)
          g_type2 = R_ARM_THM_MOVT_ABS;
        else if (r_mode == 0)
          g_type2 = R_ARM_MOVT_ABS;

        g_offset += r_offset;
        g_saddr = segments[r_symseg].p_vaddr;

        /*msg("  relocation info [1]\n");
        msg("    r_type     %i\n", g_type);
        msg("    patch addr %08x + %08x\n", g_addr, g_offset);
        msg("    sym addr   %08x\n", segments[r_symseg].p_vaddr);
        msg("    + addend   %08x\n", g_addend);

        msg("  relocation info [2]\n");
        msg("    r_type2    %i\n", g_type2);
        msg("    patch addr %08x + %08x + %08x\n", g_addr, g_offset, r_dist2);
        msg("    sym addr   %08x\n", segments[r_symseg].p_vaddr);
        msg("    + addend   %08x\n", g_addend);*/

        applyRelocation(g_type,
                        g_addr + g_offset,
                        g_saddr,
                        g_addend);

        applyRelocation(g_type2,
                        g_addr + g_offset + r_dist2,
                        g_saddr,
                        g_addend);

        pos += 1; 
        break;  // size = 8
        }
      case 4: {
        //msg("%08x\n", rel[pos]);
        auto r_offset = (rel[pos] >> 4)  & 0x7FFFFF;
        auto r_dist2  = (rel[pos] >> 27) & 0x1F;
        // offset = prevoffset + r_offset
        // offset2 = r_offset + 
        // uses previous rtype1 and rtype2
        /*msg("  r_offset  %08x\n", r_offset);
        msg("  r_dist2   %08x\n", r_dist2);*/

        g_offset += r_offset;

        /*msg("  relocation info [1]\n");
        msg("    r_type     %i\n", g_type);
        msg("    patch addr %08x + %08x\n", g_addr, g_offset);
        msg("    sym addr   %08x\n", g_saddr);
        msg("    + addend   %08x\n", g_addend);

        msg("  relocation info [2]\n");
        msg("    r_type2     %i\n", g_type2);
        msg("    patch addr %08x + %08x + %08x\n", g_addr, g_offset, r_dist2);
        msg("    sym addr   %08x\n", g_saddr);
        msg("    + addend   %08x\n", g_addend);*/

        applyRelocation(g_type,
                        g_addr + g_offset,
                        g_saddr,
                        g_addend);

        applyRelocation(g_type2,
                        g_addr + g_offset + r_dist2,
                        g_saddr,
                        g_addend);

        pos += 0; break;  // size = 4
        }
      case 5: {
        //msg("%08x\n", rel[pos]);
        auto r_dist_1 = (rel[pos] >> 4)  & 0x1FF;
        auto r_dist_2 = (rel[pos] >> 13) & 0x1F;
        auto r_dist_3 = (rel[pos] >> 18) & 0x1FF;
        auto r_dist_4 = (rel[pos] >> 27) & 0x1F;
        /*msg("r_dist_1    %08x\n", r_dist_2);
        msg("r_dist_2    %08x\n", r_dist_2);
        msg("r_dist_3    %08x\n", r_dist_3);
        msg("r_dist_4    %08x\n", r_dist_4);

        msg("  relocation info [1]\n");
        msg("    r_type     %i\n", g_type);
        msg("    patch addr %08x + %08x\n", g_addr, g_offset + r_dist_1);
        msg("    sym addr   %08x\n", g_saddr);
        msg("    + addend   %08x\n", g_addend);

        msg("  relocation info [2]\n");
        msg("    r_type2     %i\n", g_type2);
        msg("    patch addr %08x + %08x + %08x\n", g_addr, g_offset, r_dist_2);
        msg("    sym addr   %08x\n", g_saddr);
        msg("    + addend   %08x\n", g_addend);*/

        applyRelocation(g_type,
                        g_addr + g_offset + r_dist_1,
                        g_saddr,
                        g_addend);

        applyRelocation(g_type2,
                        g_addr + g_offset + r_dist_2,
                        g_saddr,
                        g_addend);

        g_offset += r_dist_1 + r_dist_3;

        /*msg("  relocation info [3]\n");
        msg("    r_type     %i\n", g_type);
        msg("    patch addr %08x + %08x\n", g_addr, g_offset + r_dist_3);
        msg("    sym addr   %08x\n", g_saddr);
        msg("    + addend   %08x\n", g_addend);

        msg("  relocation info [4]\n");
        msg("    r_type2     %i\n", g_type2);
        msg("    patch addr %08x + %08x + %08x\n", g_addr, g_offset, r_dist_4);
        msg("    sym addr   %08x\n", g_saddr);
        msg("    + addend   %08x\n", g_addend);*/

        applyRelocation(g_type,
                        g_addr + g_offset,
                        g_saddr,
                        g_addend);

        applyRelocation(g_type2,
                        g_addr + g_offset + r_dist_4,
                        g_saddr,
                        g_addend);
        pos += 0; break;  // size = 4
        }
      case 6: {
        //msg("%08x\n", rel[pos]);
        auto r_offset = (rel[pos] >> 4);
        //msg("  r_offset   %08x\n", r_offset);

        g_offset += r_offset;

        // assumes value is already stored
        auto orgval = get_original_dword(segments[g_patchseg].p_vaddr + g_offset);
        uint32 segbase = 0;
        for (auto seg : m_elf->getSegments()) {
          if (orgval >= seg.p_vaddr && 
              orgval <  seg.p_vaddr + seg.p_filesz) {
            segbase = seg.p_vaddr;
          }
        }

        auto r_addend = orgval - segbase;
             g_saddr  = segbase; //+ m_relocAddr;

        /*msg("  relocation info [1]\n");
        msg("    r_patchseg %i [%08x]\n", g_patchseg, segments[g_patchseg].p_vaddr);
        msg("    patch addr %08x + %08x\n", g_addr, g_offset);
        msg("    sym addr   %08x\n", g_saddr + r_addend);*/

        g_type2 = 0;
        g_type  = R_ARM_ABS32;

        applyRelocation(g_type,
                        g_addr + g_offset,
                        g_saddr,
                        r_addend);
        pos += 0; break;  // size = 4
        }
      case 7:   // 7 bit offsets
      case 8:   // 4 bit offsets
      case 9: { // 2 bit offsets
        //msg("%08x\n", rel[pos]);
        auto r_offsets = (rel[pos] >> 4);
        //msg("r_offsets   %08x\n", r_offsets);

        uint32 bitsize;
        uint32 mask;
        switch (r_format) {
          case 7: bitsize = 7; mask = 0x7F; break;
          case 8: bitsize = 4; mask = 0x0F; break;
          case 9: bitsize = 2; mask = 0x03; break;
        }

        do {
          auto offset = (r_offsets & mask) * sizeof(uint32);
          g_offset += offset;
          auto orgval = get_original_dword(segments[g_patchseg].p_vaddr + g_offset);

          uint32 segbase = 0;
          for (auto seg : m_elf->getSegments()) {
            if (orgval >= seg.p_vaddr && 
                orgval <  seg.p_vaddr + seg.p_filesz) {
              segbase = seg.p_vaddr;
            }
          }

          auto r_addend = orgval - segbase;
               g_saddr  = segbase;// + m_relocAddr;

          /*msg("  relocation info [1]\n");
          msg("    offset %08x\n", offset);
          msg("    r_patchseg %i [%08x]\n", g_patchseg, segments[g_patchseg].p_vaddr);
          msg("    patch addr %08x + %08x\n", g_addr, g_offset);
          msg("    sym addr   %08x\n", g_saddr);
          msg("    + addend   %08x\n", r_addend);*/

          //doDwrd(g_addr + g_offset, 4);

          g_type2 = 0;
          g_type  = R_ARM_ABS32;

          applyRelocation(g_type,
                          g_addr + g_offset,
                          g_saddr,
                          r_addend);

        } while (r_offsets >>= bitsize);

        pos += 0; break;
        }
      default:
        msg("Invalid r_format %i at offset %lx!n", r_format, pos * 4);
        break;
      }

      ++index;
    }
  }
}

void psp2_loader::applyRelocation(uint32 type, uint32 addr, uint32 symval, uint32 addend) {
  switch (type) {
  case R_ARM_NONE:
  case R_ARM_V4BX:
    break;
  case R_ARM_ABS32:
  case R_ARM_TARGET1:
    patch_dword(addr, symval + addend);
    break;
  case R_ARM_REL32:
  case R_ARM_TARGET2:
    patch_dword(addr, symval - addr + addend);
    break;
  default:
    msg("Unsupported relocation type (%i)!\n", type);
  }
}

void psp2_loader::applyModuleInfo() {
  auto firstSegment = m_elf->getSegments()[0].p_vaddr;
  auto modInfoAddr = m_elf->entry() + firstSegment;

  tid_t tid = get_struc_id("_scemoduleinfo");
  create_struct(modInfoAddr, sizeof(_scemoduleinfo_prx2arm), tid);

  auto entTop = get_dword(modInfoAddr + offsetof(_scemoduleinfo_prx2arm, ent_top));
  auto entEnd = get_dword(modInfoAddr + offsetof(_scemoduleinfo_prx2arm, ent_end));
  loadExports( firstSegment + entTop, firstSegment + entEnd );

  auto stubTop = get_dword(modInfoAddr + offsetof(_scemoduleinfo_prx2arm, stub_top));
  auto stubEnd = get_dword(modInfoAddr + offsetof(_scemoduleinfo_prx2arm, stub_end));
  loadImports( firstSegment + stubTop, firstSegment + stubEnd );
}

void psp2_loader::loadExports(uint32 entTop, uint32 entEnd) {
  uchar structsize;

  for (ea_t ea = entTop; ea < entEnd; ea += structsize) {
    structsize = get_byte(ea);

    auto nfunc   = get_word(ea + offsetof(_scelibent_common, nfunc));
    auto nvar    = get_word(ea + offsetof(_scelibent_common, nvar));
    auto ntlsvar = get_word(ea + offsetof(_scelibent_common, ntlsvar));

    auto count = nfunc + nvar + ntlsvar;

    if (structsize == sizeof(_scelibent_prx2arm)) {
      create_struct(ea, sizeof(_scelibent_prx2arm), get_struc_id("_scelibent"));

      auto nidtable = get_dword(ea + offsetof(_scelibent_prx2arm, nidtable));
      auto addtable = get_dword(ea + offsetof(_scelibent_prx2arm, addtable));

      if (nidtable != 0 && addtable != 0) {
        for (size_t i = 0; i < count; i++) {
          auto nidoffset = nidtable + (i * 4);
          auto addoffset = addtable + (i * 4);

          auto nid = get_dword(nidoffset);
          auto add = get_dword(addoffset);

          auto resolvedNid = getNameFromDatabase(nid);
          if (resolvedNid) {
            set_cmt(nidoffset, resolvedNid, false);
            if (add & 1)
              add -= 1;
            force_name(add, resolvedNid);
          }

          if (i < nfunc)
            auto_make_proc(add);

          create_dword(nidoffset, 4);
          create_dword(addoffset, 4);
        }
      }
    } else {
      msg("Unknown export structure at %08x\n", ea);
    }
  }
}

void psp2_loader::loadImports(uint32 stubTop, uint32 stubEnd) {
  uchar structsize;

  for (ea_t ea = stubTop; ea < stubEnd; ea += structsize) {
    structsize = get_byte(ea);

    auto nfunc   = get_word(ea + offsetof(_scelibstub_common, nfunc));
    auto nvar    = get_word(ea + offsetof(_scelibstub_common, nvar));
    auto ntlsvar = get_word(ea + offsetof(_scelibstub_common, ntlsvar));

    if (structsize == sizeof(_scelibstub_prx2arm)) {
      create_struct(ea, sizeof(_scelibstub_prx2arm), get_struc_id("_scelibstub"));

      auto funcnidtable = get_dword(ea + offsetof(_scelibstub_prx2arm, func_nidtable));
      auto functable    = get_dword(ea + offsetof(_scelibstub_prx2arm, func_table));
      auto varnidtable  = get_dword(ea + offsetof(_scelibstub_prx2arm, var_nidtable));
      auto vartable     = get_dword(ea + offsetof(_scelibstub_prx2arm, var_table));
      auto tlsnidtable  = get_dword(ea + offsetof(_scelibstub_prx2arm, tls_nidtable));
      auto tlstable     = get_dword(ea + offsetof(_scelibstub_prx2arm, tls_table));

      if (funcnidtable != 0 && functable != 0) {
        for (size_t i = 0; i < nfunc; ++i) {
          auto nidoffset  = funcnidtable + (i * 4);
          auto funcoffset = functable + (i * 4);

          auto nid  = get_dword(nidoffset);
          auto func = get_dword(funcoffset);

          auto resolvedNid = getNameFromDatabase(nid);
          if (resolvedNid) {
            set_cmt(nidoffset, resolvedNid, false);
            if (func & 1)
              func -= 1;
            force_name(func, resolvedNid);
          }

          create_dword(nidoffset, 4);
          create_dword(funcoffset, 4);

          if (add_func(func, BADADDR)) {
            get_func(func)->flags |= FUNC_LIB;
          }
        }
      }

      if (varnidtable != 0 && vartable != 0) {
        for (size_t i = 0; i < nvar; ++i) {
          auto nidoffset = varnidtable + (i * 4);
          auto varoffset = vartable + (i * 4);

          auto nid = get_dword(nidoffset);
          auto var = get_dword(varoffset);

          create_dword(nidoffset, 4);
          create_dword(varoffset, 4);
        }
      }

      if (tlsnidtable != 0 && tlstable != 0) {
        for (size_t i = 0; i < nvar; ++i) {
          auto nidoffset = tlsnidtable + (i * 4);
          auto tlsoffset = tlstable + (i * 4);

          auto nid = get_dword(nidoffset);
          auto tls = get_dword(tlsoffset);

          create_dword(nidoffset, 4);
          create_dword(tlsoffset, 4);
        }
      }
    } else if (structsize == 0x24) {
      create_byte(ea+0, 1);  // structsize
      create_byte(ea+1, 1);  // auxattribute
      create_word(ea+2, 2);  // version
      create_word(ea+4, 2);  // attribute
      create_word(ea+6, 2);  // nfunc
      create_word(ea+8, 2);  // nvar
      create_word(ea+10, 2); // reserved?
      create_dword(ea+12, 4); // libname_nid
      create_dword(ea+16, 4); // libname
      create_dword(ea+20, 4); // funcnidtable
      create_dword(ea+24, 4); // functable
      create_dword(ea+28, 4); // varnidtable
      create_dword(ea+32, 4); // vartable

      auto funcnidtable = get_dword(ea + 0x14);
      auto functable    = get_dword(ea + 0x18);
      auto varnidtable  = get_dword(ea + 0x1C);
      auto vartable     = get_dword(ea + 0x20);

      if (funcnidtable != 0 && functable != 0) {
        for (size_t i = 0; i < nfunc; ++i) {
          auto nidoffset = funcnidtable + (i * 4);
          auto funcoffset = functable + (i * 4);

          auto nid = get_dword(nidoffset);
          auto func = get_dword(funcoffset);

          auto resolvedNid = getNameFromDatabase(nid);
          if (resolvedNid) {
            set_cmt(nidoffset, resolvedNid, false);
            if (func & 1)
              func -= 1;
            force_name(func, resolvedNid);
          }

          create_dword(nidoffset, 4);
          create_dword(funcoffset, 4);

          if (add_func(func, BADADDR)) {
            get_func(func)->flags |= FUNC_LIB;
          }
        }
      }

      if (varnidtable != 0 && vartable != 0) {
        for (size_t i = 0; i < nvar; ++i) {
          auto nidoffset = varnidtable + (i * 4);
          auto varoffset = vartable + (i * 4);

          auto nid = get_dword(nidoffset);
          auto var = get_dword(varoffset);

          create_dword(nidoffset, 4);
          create_dword(varoffset, 4);
        }
      }

    } else {
      msg("Unknown import structure at %08x\n", ea);
    }
  }
}

const char *psp2_loader::getNameFromDatabase(unsigned int nid) {
  auto value = m_nidset.find(nid);
  if (value != m_nidset.end())
    return value->second.c_str();
  return nullptr;
}

void psp2_loader::applySymbols() {
  msg("Applying symbols...\n");

  auto section = m_elf->getSymbolsSection();

  if (section == NULL)
    return;

  auto nsym = m_elf->getNumSymbols();
  auto symbols = m_elf->getSymbols();

  const char *stringTable = m_elf->getSections().at(section->sh_link).data();

  for (size_t i = 0; i < nsym; ++i) {
    auto &symbol = symbols[i];

    auto type = ELF64_ST_TYPE(symbol.st_info),
         bind = ELF64_ST_BIND(symbol.st_info);
    auto value = symbol.st_value;

    if (symbol.st_shndx > m_elf->getNumSections() ||
      !(m_elf->getSections()[symbol.st_shndx].sh_flags & SHF_ALLOC))
      continue;

    if (symbol.st_shndx == SHN_ABS)
      continue;

    if (isLoadingPrx())
      value += m_elf->getSections()[symbol.st_shndx].sh_addr;

    switch (type) {
    case STT_OBJECT:
      force_name(value, &stringTable[symbol.st_name]);
      break;
    case STT_FILE:
      add_extra_line(value, true, "Source File: %s", &stringTable[symbol.st_name]);
      break;
    case STT_FUNC:
      force_name(value, &stringTable[symbol.st_name]);
      auto_make_proc(value);
      break;
    default:
      break;
    }
  }
}

void psp2_loader::declareStructures() {
  struc_t *sptr;

  tid_t modInfoCommon = add_struc(-1, "_scemoduleinfo_common");
  sptr = get_struc(modInfoCommon);
  if (sptr != NULL) {
    add_struc_member(sptr, "modattribute", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "modversion", BADADDR, byte_flag(), NULL, 2);
    add_struc_member(sptr, "modname", BADADDR, byte_flag(), NULL, SYS_MODULE_NAME_LEN);
    add_struc_member(sptr, "terminal", BADADDR, byte_flag(), NULL, 1);

    sptr = get_struc(add_struc(-1, "_scemoduleinfo"));
    if (sptr != NULL) {
      opinfo_t mt = {};
      mt.tid = modInfoCommon;
      add_struc_member(sptr, "c", BADADDR, stru_flag(), &mt, get_struc_size(mt.tid));

      add_struc_member(sptr, "resreve", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "ent_top", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "ent_end", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "stub_top", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "stub_end", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "dbg_fingerprint", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "tls_top", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "tls_filesz", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "tls_memsz", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "start_entry", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "stop_entry", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "arm_exidx_top", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "arm_exidx_end", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "arm_extab_top", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "arm_extab_end", BADADDR, dword_flag(), NULL, 4);
    }
  }

  tid_t libStubCommon = add_struc(-1, "_scelibstub_common");
  sptr = get_struc(libStubCommon);
  if (sptr != NULL) {
    add_struc_member(sptr, "structsize", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "reserved1", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "version", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "attribute", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "nfunc", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "nvar", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "ntlsvar", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "reserved2", BADADDR, byte_flag(), NULL, 4);

    sptr = get_struc(add_struc(-1, "_scelibstub"));
    if (sptr != NULL) {
      opinfo_t mt = {};
      mt.tid = libStubCommon;
      add_struc_member(sptr, "c", BADADDR, stru_flag(), &mt, get_struc_size(mt.tid));

      add_struc_member(sptr, "libname_nid", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "libname", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "sce_sdk_version", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "func_nidtable", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "func_table", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "var_nidtable", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "var_table", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "tls_nidtable", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "tls_table", BADADDR, dword_flag(), NULL, 4);
    }
  }

  tid_t libEntCommon = add_struc(-1, "_scelibent_common");
  sptr = get_struc(libEntCommon);
  if (sptr != NULL) {
    add_struc_member(sptr, "structsize", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "reserved1", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "version", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "attribute", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "nfunc", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "nvar", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "ntlsvar", BADADDR, word_flag(), NULL, 2);
    add_struc_member(sptr, "hashinfo", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "hashinfotls", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "reserved2", BADADDR, byte_flag(), NULL, 1);
    add_struc_member(sptr, "nidaltsets", BADADDR, byte_flag(), NULL, 1);

    sptr = get_struc(add_struc(-1, "_scelibent"));
    if (sptr != NULL) {
      opinfo_t mt = {};
      mt.tid = libEntCommon;
      add_struc_member(sptr, "c", BADADDR, stru_flag(), &mt, get_struc_size(mt.tid));

      add_struc_member(sptr, "libname_nid", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "libname", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "nidtable", BADADDR, dword_flag(), NULL, 4);
      add_struc_member(sptr, "addtable", BADADDR, dword_flag(), NULL, 4);
    }
  }
}
