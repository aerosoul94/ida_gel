#pragma once

#include "elf_reader.hpp"
#include "cafe.h"

class cafe_loader {
  elf_reader<elf32> *m_elf;
  uint32 m_relocAddr;

  uint32 m_externStart;
  uint32 m_externEnd;

  struct import {
    uint32 addr;
    uint32 orig;
    const char *name;
  };

  std::vector<import> m_imports;
  
public:
  cafe_loader(elf_reader<elf32> *elf);
  
  void apply();
  
private:
  void applySegments();
  void applySegment(uint32 sel,
                    const char *data,
                    uint32 addr,
                    uint32 size,
                    const char *name,
                    const char *sclass,
                    uchar perm,
                    uchar align,
                    bool load);

  void applyRelocations();

  void processImports();
  void processExports();

  void swapSymbols();
  void applySymbols();
};