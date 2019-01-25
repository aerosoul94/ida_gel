
/**
 * A very basic template based ELF reader. It is very common for OS's
 * to implement their own ELF ABI. Section and segment headers are most 
 * commonly kept standard.
 *
 * Assumes that:
 * - Elf_Ehdr is standard.
 * - Elf_Shdr is standard.
 * - Elf_Phdr is standard.
 * - Only one SYMTAB section according to ELF ABI.
 * - This system is little endian.  If there is a problem with this,
 *   please let the author know.
 *
 * What it stores info for:
 * - Elf_Ehdr as read from file.
 * - vector of Elf_Shdr abstracted as Section.
 * - vector of Elf_Phdr abstracted as Segment.
 * - index of symbol section.
 * - index of dynamic segment. <- TODO
 * - index of section header string table section.
 *
 * Important facts about this reader:
 * - Elf_Ehdr, Elf_Shdr, and Elf_Phdr is swapped if ELFDATA2MSB is set.
 *   This is to facilitate faster header/section/segment handling without 
 *   the user needing to swap them.
 * - Section/segment data is not modified by this reader.
 * - Any section/segment data must be swapped by the user.
 * - Data is only loaded when requested. (see Segment/Section data())
**/

#pragma once

#include "elf.h"

#include <idaldr.h> // TODO: do not depend on this
#include <vector>

static void printhex(const unsigned char *data, size_t size)
{
  msg("00000000 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
  for (size_t i = 0; i < size; i += 16)
  {
    msg("%08zx ", i);
    msg("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
      data[i + 0], data[i + 1], data[i + 2], data[i + 3], data[i + 4],
      data[i + 5], data[i + 6], data[i + 7], data[i + 8], data[i + 9],
      data[i + 10], data[i + 11], data[i + 12], data[i + 13], data[i + 14],
      data[i + 15]);
  }
}

template <typename T> 
void swap(T &buf) {
  unsigned char &pbuf = reinterpret_cast<unsigned char &>(buf);
  std::reverse(&pbuf, &pbuf + sizeof(T));
}

class elf32 {
public:
  typedef Elf32_Ehdr Ehdr;
  typedef Elf32_Shdr Shdr;
  typedef Elf32_Phdr Phdr;
  typedef Elf32_Sym  Sym;
  typedef Elf32_Word Word;
  typedef Elf32_Addr Addr;
};

class elf64 {
public:
  typedef Elf64_Ehdr Ehdr;
  typedef Elf64_Shdr Shdr;
  typedef Elf64_Phdr Phdr;
  typedef Elf64_Sym  Sym;
  typedef Elf64_Word Word;
  typedef Elf64_Addr Addr;
};

template <class Elf>
class Segment
  : public Elf::Phdr {
  linput_t *m_reader;
  std::vector<char> m_data;

public:
  Segment() {}

  Segment(linput_t *li) 
    : m_reader(li)
  {
  }

  char *data() 
  {
    if (m_data.empty()) 
    {
      m_data.resize(this->p_filesz);
      qlseek(m_reader, this->p_offset);
      qlread(m_reader, (void *)m_data.data(), this->p_filesz);
    }

    return m_data.data();
  }

  void setData(const char *data, size_t length) 
  {
    m_data.assign(data, data + length);
  }

  void setReader(linput_t *li) 
  {
    this->m_reader = li;
  }
};

template <class Elf> 
class Section
  : public Elf::Shdr {
  linput_t *m_reader;
  std::vector<char> m_data;

public:
  Section() {}

  char *data() 
  {
    if (m_data.empty()) {
      m_data.resize(this->sh_size);
      if (qlseek(m_reader, this->sh_offset) != this->sh_offset)
        msg("Failed to seek to data.\n");
      if (qlread(m_reader, (void *)m_data.data(), this->sh_size) == -1)
        msg("Failed to read data.\n");
    }

    return m_data.data();
  }

  void setData(const char *data, size_t length)
  {
    m_data.assign(data, data + length);
  }

  void setReader(linput_t *li)
  {
    this->m_reader = li;
  }

  uint32 getNumEntries() const
  {
    if (this->sh_entsize != 0)
      return this->sh_size / this->sh_entsize;
    return 0;
  }

  uint32 getSize() const
  {
    return m_data.size();
  }
};

template <
          class Elf               // Elf type
          /*TODO: class reader*/  // reader interface
          /*TODO: class logger*/  // log file interface
          >
class elf_reader {
  typename Elf::Ehdr m_header;
  std::vector< Segment<Elf> > m_segments;
  std::vector< Section<Elf> > m_sections;
  Section<Elf> *m_symbolTableSection;
  Section<Elf> *m_sectionStringTable;

  linput_t *m_reader;

public:
  elf_reader(linput_t *li)
    : m_reader(li) 
  {
    m_symbolTableSection = NULL;
    m_sectionStringTable = NULL;
  }

  void read() {
    this->readHeader();
    this->readSegments();
    this->readSections();
  }

  void print() {
    this->printHeader();
    this->printSegment();
    this->printSections();
    this->printSymbols();
  }

  bool verifyHeader() {
    readHeader();

    if (m_header.e_ident[EI_MAG0] == ELFMAG0 &&
        m_header.e_ident[EI_MAG1] == ELFMAG1 &&
        m_header.e_ident[EI_MAG2] == ELFMAG2 &&
        m_header.e_ident[EI_MAG3] == ELFMAG3) {
      return true;
    }

    return false;
  }

  linput_t *getReader() const 
      { return m_reader; }

  uchar osabi() const 
      { return m_header.e_ident[EI_OSABI]; }

  uchar bitsize() const
      { return m_header.e_ident[EI_CLASS]; }

  uchar endian() const
      { return m_header.e_ident[EI_DATA]; }

  typename Elf::Word type() const 
      { return m_header.e_type; }

  typename Elf::Word machine() const
      { return m_header.e_machine; }

  typename Elf::Addr entry() const 
      { return m_header.e_entry; }

  typename Elf::Word flags() const
      { return m_header.e_flags; }

  uint32_t getNumSegments() const 
      { return m_segments.size(); }

  uint32_t getNumSections() const 
      { return m_sections.size(); }

  std::vector< Segment<Elf> > &getSegments()
      { return m_segments; }

  std::vector< Section<Elf> > &getSections()
      { return m_sections; }

  Section<Elf> *getSectionStringTable() const 
      { return m_sectionStringTable; }

  Section<Elf> *getSymbolsSection() const
      { return m_symbolTableSection; }

  uint32_t getNumSymbols() const
      { return m_symbolTableSection->getNumEntries(); }

  typename Elf::Sym *getSymbols() const
      { return (typename Elf::Sym *)m_symbolTableSection->data(); }

  Section<Elf> *getSectionByName(const char *name) 
  {
    const char *strTab = m_sectionStringTable->data();
    for (auto &section : m_sections) {
      if (strcmp(&strTab[section.sh_name], name) == 0)
        return &section;
    }
    return NULL;
  }

  uchar getAlignment(typename Elf::Word align) 
  {
    switch (align) {
      case 0x1:     return saRelByte;
      case 0x2:     return saRelWord;
      case 0x4:     return saRelDble;
      case 0x8:     return saRelQword;
      case 0x40:    return saRel64Bytes;
      case 0x80:    return saRel128Bytes;
      case 0x100:   return saRelPage;
      case 0x200:   return saRel512Bytes;
      case 0x400:   return saRel2048Bytes;
      case 0x1000:  return saRel4K;
      default:      return saRelDble;
    }
  }

private:
  void readHeader() {
    //msg("Reading header.\n");

    qlseek(m_reader, 0);
    qlread(m_reader, &m_header, sizeof(m_header));

    if (m_header.e_ident[EI_DATA] == ELFDATA2MSB) {
      swap(m_header.e_type);
      swap(m_header.e_machine);
      swap(m_header.e_version);
      swap(m_header.e_entry);
      swap(m_header.e_phoff);
      swap(m_header.e_shoff);
      swap(m_header.e_flags);
      swap(m_header.e_ehsize);
      swap(m_header.e_phentsize);
      swap(m_header.e_phnum);
      swap(m_header.e_shentsize);
      swap(m_header.e_shnum);
      swap(m_header.e_shstrndx);
    }

    //this->printHeader();
  }

  void readSegments() {
    if (m_header.e_phnum > 0) {
      //msg("Reading segments.\n");
      m_segments.resize(m_header.e_phnum);

      qlseek(m_reader, m_header.e_phoff);

      for (auto &segment : m_segments) {
        qlread(m_reader, (typename Elf::Phdr *)&segment, m_header.e_phentsize);

        if (m_header.e_ident[EI_DATA] == ELFDATA2MSB) {
          swap(segment.p_type);
          swap(segment.p_flags);
          swap(segment.p_offset);
          swap(segment.p_vaddr);
          swap(segment.p_paddr);
          swap(segment.p_filesz);
          swap(segment.p_memsz);
          swap(segment.p_align);
        }

        segment.setReader(m_reader);
      }

      //this->printSegments();
    }
  }

  void readSections() {
    if (m_header.e_shnum > 0) {
      //msg("Reading sections...\n");

      m_sections.resize(m_header.e_shnum);

      size_t index = 0;
      for (auto &section : m_sections) {
        qlseek(m_reader, m_header.e_shoff + index * m_header.e_shentsize);
        qlread(m_reader, (typename Elf::Shdr *)&section, m_header.e_shentsize);

        if (m_header.e_ident[EI_DATA] == ELFDATA2MSB) {
          swap(section.sh_name);
          swap(section.sh_type);
          swap(section.sh_flags);
          swap(section.sh_addr);
          swap(section.sh_offset);
          swap(section.sh_size);
          swap(section.sh_link);
          swap(section.sh_info);
          swap(section.sh_addralign);
          swap(section.sh_entsize);
        }

        section.setReader(m_reader);

        // only one symbol table per ELF
        if (section.sh_type == SHT_SYMTAB)
          m_symbolTableSection = &section;

        ++index;
      }

      if (m_header.e_shstrndx != SHN_UNDEF &&
          m_sections[m_header.e_shstrndx].sh_type == SHT_STRTAB)
        m_sectionStringTable = &m_sections[m_header.e_shstrndx];

      //this->printSections();
    }
   }

   void printHeader() {
    msg("Elf Header:\n");
    msg("  e_ident  ");
    for (int i = 0; i < EI_NIDENT; i++)
      msg(" %02x", m_header.e_ident[i]);
    msg("\n");
    msg("  e_type      %04x\n", m_header.e_type);
    msg("  e_machine   %04x\n", m_header.e_machine);
    msg("  e_version   %08x\n", m_header.e_version);
    msg("  e_entry     %08x\n", m_header.e_entry);
    msg("  e_phoff     %08x\n", m_header.e_phoff);
    msg("  e_shoff     %08x\n", m_header.e_shoff);
    msg("  e_flags     %08x\n", m_header.e_flags);
    msg("  e_ehsize    %d\n", m_header.e_ehsize);
    msg("  e_phentsize %d\n", m_header.e_phentsize);
    msg("  e_phnum     %d\n", m_header.e_phnum);
    msg("  e_shentsize %d\n", m_header.e_shentsize);
    msg("  e_shnum     %d\n", m_header.e_shnum);
    msg("  e_shstrndx  %d\n", m_header.e_shstrndx);
   }

   void printSegments() {
    size_t index = 0;
    for (auto &segment : m_segments) {
      msg("Program Header #%d\n", index);
      msg("  p_type   %08x\n", segment.p_type);
      msg("  p_offset %08x\n", segment.p_offset);
      msg("  p_vaddr  %08x\n", segment.p_vaddr);
      msg("  p_paddr  %08x\n", segment.p_paddr);
      msg("  p_filesz %08x\n", segment.p_filesz);
      msg("  p_memsz  %08x\n", segment.p_memsz);
      msg("  p_flags  %08x\n", segment.p_flags);
      msg("  p_align  %08x\n", segment.p_align);
      ++index;
    }
   }

   void printSections() {
    size_t index = 0;
    for (auto &section : m_sections) {
      msg("Section Header #%d\n", index);
      msg("  sh_name      %08x\n", section.sh_name);
      msg("  sh_type      %08x\n", section.sh_type);
      msg("  sh_addr      %08x\n", section.sh_addr);
      msg("  sh_offset    %08x\n", section.sh_offset);
      msg("  sh_size      %08x\n", section.sh_size);
      msg("  sh_link      %08x\n", section.sh_link);
      msg("  sh_info      %08x\n", section.sh_info);
      msg("  sh_addralign %08x\n", section.sh_addralign);
      msg("  sh_entsize   %08x\n", section.sh_entsize);
      ++index;
    }
   }
};