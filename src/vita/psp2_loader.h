#pragma once

#include "elf_reader.h"
#include "sce.h"

#include <fstream>
#include <array>
#include <map>

class psp2_loader
{
  elf_reader<elf32> *m_elf;
  uint64 m_relocAddr;

  std::ifstream m_database;
  std::map<uint32, std::string> m_nidset;

public:
  psp2_loader(elf_reader<elf32> *elf, std::string databaseFile);

  void apply();

  bool isLoadingPrx() const
    { return m_elf->type() == ET_SCE_RELEXEC; }

  bool isLoadingExec() const
    { return m_elf->type() == ET_EXEC; }

private:
  void declareStructures();

  void applySegments();
  void applySectionHeaders();
  void applyProgramHeaders();
  void applySegment(
        uint32 sel,  uint64 offset, 
        uint64 addr, uint64 size,
        const char *name, const char *sclass, 
        uchar perm, uchar align, 
        bool load = true
    );

  void applyRelocations();
  void applyRelocation(uint32 type, uint32 addr, uint32 addend, uint32 value);

  void applyModuleInfo();
  void loadExports(uint32 entTop, uint32 entEnd);
  void loadImports(uint32 stubTop, uint32 stubEnd);

  const char *getNameFromDatabase(unsigned int nid);

  void applySymbols();
};

