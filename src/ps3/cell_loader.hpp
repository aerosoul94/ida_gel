#pragma once

#include "elf_reader.hpp"
#include "tinyxml.h"
#include "sce.h"
#include <string>

class cell_loader {
  elf_reader<elf64> *m_elf;   ///< Handle for this loader's ELF reader.
  TiXmlDocument m_database;   ///< Handle for this loader's NID xml database.
  uint64 m_relocAddr; // Base relocaton address for PRX's.
  uint64 m_gpValue;   // TOC value
  bool m_hasSegSym;   // has seg sym, but the real meaning
                      // is if its a 0.85 PRX since its the only
                      // way I know how to check
  
public:
  cell_loader(elf_reader<elf64> *elf, uint64 relocAddr, std::string databasePath);
  
  void apply();
  
  bool isLoadingExec() const
    { return m_elf->type() == ET_EXEC; }

  bool isLoadingPrx() const
    { return m_elf->type() == ET_SCE_PPURELEXEC; }
  
private:
  void applySegments();
  void applySegment(uint32 sel, 
                    uint64 offset, 
                    uint64 addr, 
                    uint64 size, 
                    const char *name, 
                    const char *sclass, 
                    uchar perm, 
                    uchar align, 
                    bool load = true);

  void applySectionHeaders();
  void applyProgramHeaders();
  
  void applyRelocations();
  void applySectionRelocations();
  void applySegmentRelocations();
  void applyRelocation(uint32 type, uint32 addr, uint32 saddr);
  
  void declareStructures();

  void applyModuleInfo();
  void loadExports(uint32 entTop, uint32 entEnd);
  void loadImports(uint32 stubTop, uint32 stubEnd);
  
  const char *getNameFromDatabase(const char *group, unsigned int nid);

  void applyProcessInfo();
  
  void swapSymbols();
  void applySymbols();
};