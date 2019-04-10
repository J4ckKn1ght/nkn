import json

import r2pipe
from miasm.analysis.binary import Container, ContainerELF, ContainerPE
from miasm.analysis.machine import Machine
from miasm.analysis.sandbox import Sandbox_Linux_x86_32, Sandbox_Linux_x86_64, Sandbox_Win_x86_32, Sandbox_Win_x86_64
from miasm.core.interval import interval
from miasm.expression.expression import ExprInt, ExprLoc, ExprMem, ExprId, ExprOp

import Utils
from BinaryParser import PEInfo, ELFInfo
from RadareParser import Function

def detect_func_name(cur_bloc, loc_db, *args, **kwargs):
    for line in cur_bloc.lines:
        for i in range(len(line.args)):
            arg = line.args[i]
            if isinstance(arg, ExprMem):
                ptr = arg.ptr
                if isinstance(ptr, ExprOp):
                    if isinstance(ptr.args[0], ExprId) and ('IP' in str(ptr.args[0])) and isinstance(ptr.args[1],
                                                                                                     ExprInt):
                        ip = line.offset + line.l
                        offset = ptr.args[1].arg
                        loc_key = loc_db.get_offset_location(ip + offset)
                        if loc_key is not None:
                            line.args[i] = ExprLoc(loc_key, arg.size)
                            names = loc_db.get_location_names(cur_bloc.loc_key)
                            if len(names) == 0:
                                new_name = list(loc_db.get_location_names(loc_key))
                                if len(new_name) != 0:
                                    new_name = '_' + new_name[0].decode()
                                    try:
                                        loc_db.add_location_name(cur_bloc.loc_key, new_name)
                                    except:
                                        pass
                elif isinstance(ptr, ExprInt) and line.name == 'JMP':
                    offset = ptr.arg
                    loc_key = loc_db.get_offset_location(offset)
                    if loc_key is not None:
                        line.args[i] = ExprLoc(loc_key, arg.size)
                        names = loc_db.get_location_names(cur_bloc.loc_key)
                        if len(names) == 0:
                            new_name = list(loc_db.get_location_names(loc_key))
                            if len(new_name) != 0:
                                new_name = '_' + new_name[0].decode()
                                try:
                                    loc_db.add_location_name(cur_bloc.loc_key, new_name)
                                except:
                                    pass


class BinaryAnalysis:
    path = None
    container = None
    machine = None
    sb = None
    rawData = None
    iraType = None
    disasmEngine = None
    binaryInfo = None
    radare = None
    funcs = []
    blocks = []
    dataType = {}
    dataXrefs = {}
    doneAddress = set()
    doneInterval = interval()
    data = []
    locDB = None
    strings = {}

    @staticmethod
    def init(binary):
        BinaryAnalysis.clear()
        BinaryAnalysis.path = binary
        BinaryAnalysis.rawData = list(open(binary, 'rb').read())
        BinaryAnalysis.container = Container.from_stream(open(binary, 'rb'))
        BinaryAnalysis.locDB = BinaryAnalysis.container.loc_db
        BinaryAnalysis.machine = Machine(BinaryAnalysis.container.arch)
        BinaryAnalysis.iraType = BinaryAnalysis.machine.ira
        if isinstance(BinaryAnalysis.container, ContainerPE):
            BinaryAnalysis.binaryInfo = PEInfo(binary)
        elif isinstance(BinaryAnalysis.container, ContainerELF):
            BinaryAnalysis.binaryInfo = ELFInfo(binary)
        if BinaryAnalysis.binaryInfo.type == 'PE':
            if BinaryAnalysis.container.arch == 'x86_32':
                parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
                options = parser.parse_args()
                BinaryAnalysis.sb = Sandbox_Win_x86_32(BinaryAnalysis.path, options, globals())
            elif BinaryAnalysis.container.arch == 'x86_64':
                parser = Sandbox_Win_x86_64.parser(description="PE sandboxer")
                options = parser.parse_args()
                BinaryAnalysis.sb = Sandbox_Win_x86_64(BinaryAnalysis.path, options, globals())
        elif BinaryAnalysis.binaryInfo.type == 'ELF':
            if BinaryAnalysis.container.arch == 'x86_32':
                parser = Sandbox_Linux_x86_32.parser(description="PE sandboxer")
                options = parser.parse_args()
                BinaryAnalysis.sb = Sandbox_Linux_x86_32(BinaryAnalysis.path, options, globals())
            elif BinaryAnalysis.container.arch == 'x86_64':
                parser = Sandbox_Linux_x86_64.parser(description="PE sandboxer")
                options = parser.parse_args()
                BinaryAnalysis.sb = Sandbox_Linux_x86_64(BinaryAnalysis.path, options, globals())
        BinaryAnalysis.disasmEngine = BinaryAnalysis.machine.dis_engine(BinaryAnalysis.container.bin_stream,
                                                                        loc_db=BinaryAnalysis.container.loc_db)
        BinaryAnalysis.disasmEngine.dis_block_callback = detect_func_name
        BinaryAnalysis.strings = BinaryAnalysis.binaryInfo.findStrings()
        BinaryAnalysis.radare = r2pipe.open(binary)
        BinaryAnalysis.radare.cmd('aaa;')
        BinaryAnalysis.detectFunctions()
        BinaryAnalysis.disassembly()
        for start, end in (BinaryAnalysis.binaryInfo.codeRange - BinaryAnalysis.doneInterval):
            BinaryAnalysis.data.append((start - 1, end))
        for start, end in BinaryAnalysis.binaryInfo.dataRange:
            BinaryAnalysis.data.append((start, end - 1))

    @staticmethod
    def detectFunctions():
        funcsJson = BinaryAnalysis.radare.cmd('aflj;')
        funcsParses = json.loads(funcsJson)
        Utils.runMultiThread(funcsParses, BinaryAnalysis.parseFunc)

    @staticmethod
    def disassembly():
        Utils.runMultiThread(BinaryAnalysis.funcs, BinaryAnalysis.disasmFunc)
        BinaryAnalysis.blocks = sorted(BinaryAnalysis.blocks, key=lambda x: x[0].lines[0].offset)

    @staticmethod
    def disasmFunc(func, lock):
        lock.acquire()
        func.cfg = BinaryAnalysis.disasmEngine.dis_multiblock(func.address)
        lockey = BinaryAnalysis.locDB.get_offset_location(func.address)
        name = BinaryAnalysis.locDB.pretty_str(lockey)
        if not 'loc_' in name:
            func.name = name
        delBlocks = []
        for block in func.cfg.blocks:
            address = block.lines[0].offset
            if address < func.minBound or address >= func.maxBound:
                delBlocks.append(block)
        for block in delBlocks:
            func.cfg.del_block(block)
        for block in func.cfg.blocks:
            if len(block.lines) > 0:
                if block.lines[0].offset not in BinaryAnalysis.doneAddress:
                    BinaryAnalysis.blocks.append((block, func))
                    BinaryAnalysis.doneAddress.add(block.lines[0].offset)
                for line in block.lines:
                    BinaryAnalysis.doneInterval += interval([(line.offset, line.offset + line.l)])
                    for arg in line.args:
                        if isinstance(arg, ExprInt):
                            if arg.arg in func.dataRefs and BinaryAnalysis.binaryInfo.inDataSection(arg.arg):
                                num = int(arg.arg)
                                BinaryAnalysis.dataType[num] = Utils.typeBySize[arg.size]
                                if num in BinaryAnalysis.dataXrefs:
                                    BinaryAnalysis.dataXrefs[num].append(line.offset)
                                else:
                                    BinaryAnalysis.dataXrefs[num] = [line.offset]
        for address, string in BinaryAnalysis.strings.items():
            BinaryAnalysis.dataType[address] = 'string'

        lock.release()
        locKey = BinaryAnalysis.locDB.get_offset_location(func.address)
        names = BinaryAnalysis.locDB.get_location_names(locKey)
        if len(names) == 0:
            if not BinaryAnalysis.locDB.get_name_location(func.name):
                BinaryAnalysis.locDB.add_location_name(locKey, func.name)
            else:
                BinaryAnalysis.locDB.add_location_name(locKey, '_' + func.name)

    @staticmethod
    def parseFunc(funcJson, lock):
        func = Function(funcJson)
        BinaryAnalysis.funcs.append(func)

    @staticmethod
    def clear():
        BinaryAnalysis.path = None
        BinaryAnalysis.container = None
        BinaryAnalysis.machine = None
        BinaryAnalysis.rawData = None
        BinaryAnalysis.iraType = None
        BinaryAnalysis.disasmEngine = None
        BinaryAnalysis.binaryInfo = None
        BinaryAnalysis.radare = None
        BinaryAnalysis.funcs = []
        BinaryAnalysis.blocks = []
        BinaryAnalysis.dataType = {}
        BinaryAnalysis.dataXrefs = {}
        BinaryAnalysis.doneAddress = set()
        BinaryAnalysis.doneInterval = interval()
        BinaryAnalysis.data = []
        BinaryAnalysis.locDB = None
        BinaryAnalysis.strings = {}