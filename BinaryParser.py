from pefile import PE
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import describe_e_type
from miasm.core.interval import interval
import os
import re


class Section:
    def __init__(self, name, address, size):
        self.name = name
        self.address = address
        self.size = size


class ImportFunction:
    def __init__(self, name, address, library=None):
        self.name = name
        self.address = address
        self.libary = library


class ExporFunction:
    def __init__(self, name, address):
        self.name = name
        self.address = address


class PEInfo:
    def __init__(self, path):
        self.path = path
        self.type = 'PE'
        self.parser = PE(path, fast_load=True)
        self.parser.parse_data_directories()
        self.imageBase = self.parser.OPTIONAL_HEADER.ImageBase
        self.entryPoint = self.parser.OPTIONAL_HEADER.AddressOfEntryPoint
        self.sections = []
        self.stringAddrs = []
        self.strings = self.strings()
        for section in self.parser.sections:
            s = Section(section.Name.decode().replace('\x00', ''), section.VirtualAddress + self.imageBase,
                        section.Misc_VirtualSize)
            self.sections.append(s)
        self.imports = []
        for entry in self.parser.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                importFunc = ImportFunction(imp.name, imp.address, entry.dll)
                self.imports.append(importFunc)
        self.exports = []
        if hasattr(self.parser, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.parser.DIRECTORY_ENTRY_EXPORT.symbols:
                exportFunc = ExporFunction(self.imageBase + exp.address, exp.name)
                self.exports.append(exportFunc)
        self.findStrings()

    def getOffsetAtAddress(self, address):
        for section in self.parser.sections:
            if section.contains_rva(address):
                return section.get_offset_from_rva(address)
        return None

    @property
    def codeRange(self):
        for section in self.parser.sections:
            if '.text' in section.Name.decode():
                return interval([(
                    section.VirtualAddress + self.imageBase,
                    section.VirtualAddress + self.imageBase + section.Misc_VirtualSize)])

    @property
    def dataRange(self):
        dataRanges = []
        for section in self.parser.sections:
            if 'data' in section.Name.decode():
                dataRanges.append((section.VirtualAddress + self.imageBase,
                                   section.VirtualAddress + self.imageBase + section.Misc_VirtualSize))
        return dataRanges

    def inDataSection(self, address):
        for start, end in self.dataRange:
            if start <= address and address < end:
                return True
        else:
            return False

    def getData(self, start, size):
        f = open(self.path, 'rb')
        f.seek(start)
        data = f.read(size)
        f.close()
        return data

    def findStrings(self):
        strings = {}
        for section in self.parser.sections:
            if 'data' in section.Name.decode():
                start = section.PointerToRawData
                size = section.SizeOfRawData
                address = self.imageBase + section.VirtualAddress
                data = self.getData(start, size)
                indexs = re.finditer(b"([a-zA-Z0-9` \n~!@#$%^&*()-_=+|';\":.,?><*-]{2,})", data)
                for index in indexs:
                    strings[address + index.start(0)] = str(data[index.start(0):index.end(0)])[2:-1]
        return strings

    def strings(self):
        strings = []
        for address, string in self.findStrings().items():
            strings.append((hex(address), string))
        for section in self.parser.sections:
            if 'data' not in section.name:
                start = section.PointerToRawData
                size = section.SizeOfRawData
                vAddress = self.imageBase + section.VirtualAddress
                data = self.getData(start, size)
                indexs = re.finditer(b"([a-zA-Z0-9` \n~!@#$%^&*()-_=+|';\":.,?><*-]{2,})", data)
                for index in indexs:
                    address = hex(vAddress + index.start(0))
                    string = str(data[index.start(0):index.end(0)])[2:-1]
                    strings.append((address, string))
                    self.stringAddrs.append(vAddress + index.start(0))
        return strings

    def info(self):
        text = 'File name: <b>' + os.path.basename(self.path) + '</b><br/>'
        text += 'Type: <b>' + self.type + '</b><br/>'
        text += 'Imagebase: <b>' + hex(self.imageBase) + '</b><br/>'
        text += 'Entrypoint: <b>' + hex(self.entryPoint) +'</b>'
        return text

class ELFInfo:
    def __init__(self, path):
        self.path = path
        self.parser = ELFFile(open(path, 'rb'))
        self.type = 'ELF'
        self.sections = []
        self.stringAddrs = []
        self.strings = self.strings()
        self.imageBase = 0
        self.entryPoint = 0
        for section in self.parser.iter_sections():
            if '.text' in section.name:
                self.entryPoint = section.header.sh_addr
        if describe_e_type(self.parser.header.e_type).split()[0] != 'DYN':
            for seg in self.iter_segments_by_type('PT_LOAD'):
                addr = seg.header.p_vaddr
                if addr != 0:
                    if addr < self.imageBase or self.imageBase == 0:
                        self.imageBase = addr

        for section in self.parser.iter_sections():
            if section.name:
                s = Section(section.name, section.header.sh_addr, section.header.sh_size)
                self.sections.append(s)
        self.symbols = {}
        self.imports = []
        self.exports = []
        self.populateSymbols()
        self.populateIEFunctions()
        self.findStrings()

    def populateSymbols(self):
        for section in self.parser.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    value = symbol.entry.st_value
                    if not value:
                        continue
                    self.symbols[symbol.name] = value
            if isinstance(section, RelocationSection):
                if section.header.sh_link != 'SHN_UNDEF':
                    symbols = self.parser.get_section(section.header.sh_link)
                    for rel in section.iter_relocations():
                        sym_idx = rel.entry.r_info_sym
                        if sym_idx:
                            symbol = symbols.get_symbol(sym_idx)
                            if symbol and symbol.name:
                                self.symbols[symbol.name] = rel.entry.r_offset

    def populateIEFunctions(self):
        for section in self.parser.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym.entry.st_info['type'] == 'STT_FUNC':
                        if sym.entry.st_shndx == 'SHN_UNDEF':
                            if sym.name in self.symbols:
                                importFunc = ImportFunction(sym.name, self.symbols[sym.name])
                                self.imports.append(importFunc)
                        else:
                            if sym.name in self.symbols:
                                exportFunc = ExporFunction(sym.name, self.symbols[sym.name])
                                self.exports.append(exportFunc)

    @property
    def codeRange(self):
        start = 0
        end = 0
        for section in self.parser.iter_sections():
            if section.name == '.init':
                start = section.header.sh_addr
            if section.name == '.fini':
                end = section.header.sh_addr + section.header.sh_size
        return interval([(start, end)])

    @property
    def dataRange(self):
        dataRanges = interval()
        for section in self.parser.iter_sections():
            if 'data' in section.name:
                start = section.header.sh_addr
                end = start + section.header.sh_size
                dataRanges += interval([(start, end)])
        return dataRanges

    def getOffsetAtAddress(self, address):
        return address - self.imageBase

    def iter_segments_by_type(self, t):
        for seg in self.parser.iter_segments():
            if t == seg.header.p_type or t in str(seg.header.p_type):
                yield seg

    def getData(self, offset, size):
        file = open(self.parser.stream.name, 'rb')
        file.seek(offset)
        data = file.read(size)
        file.close()
        return data

    def findStrings(self):
        strings = {}
        for section in self.parser.iter_sections():
            if 'data' in section.name:
                data = self.getData(section.header.sh_offset, section.header.sh_size)
                indexs = re.finditer(b"([a-zA-Z0-9` \n~!@#$%^&*()-_=+|';\":.,?><*-]{2,})", data)
                for index in indexs:
                    strings[section.header.sh_addr + index.start(0)] = str(data[index.start(0):index.end(0)])[2:-1]
        return strings

    def strings(self):
        strings = []
        for address, string in self.findStrings().items():
            strings.append((hex(address), string))
        for section in self.parser.iter_sections():
            if 'data' not in section.name:
                data = self.getData(section.header.sh_offset, section.header.sh_size)
                indexs = re.finditer(b"([a-zA-Z0-9` \n~!@#$%^&*()-_=+|';\":.,?><*-]{2,})", data)
                for index in indexs:
                    address = hex(section.header.sh_addr + index.start(0))
                    string = str(data[index.start(0):index.end(0)])[2:-1]
                    strings.append((address, string))
                    self.stringAddrs.append(section.header.sh_addr)
        return strings


    def inDataSection(self, address):
        for start, end in self.dataRange:
            if start <= address and address < end:
                return True
        else:
            return False

    def info(self):
        text = 'File name: <b>' + os.path.basename(self.path) + '</b><br/>'
        text += 'Type: <b>' + self.type + '</b><br/>'
        text += 'Imagebase: <b>' + hex(self.imageBase) + '</b><br/>'
        text += 'Entrypoint: <b>' + hex(self.entryPoint) +'</b>'
        return text