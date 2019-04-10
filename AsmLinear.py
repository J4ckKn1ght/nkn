from functools import partial
import sys
from io import StringIO

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import QApplication, QAbstractItemView, QDialog, QHBoxLayout, QMenu, QAction, QInputDialog, \
    QMessageBox
from future.utils import viewitems
from miasm.analysis.data_flow import DiGraphDefUse, ReachingDefinitions, AssignblkNode
from miasm.analysis.depgraph import DependencyGraph
from miasm.core.utils import Disasm_Exception
from miasm.expression.expression import Expr, ExprId, ExprInt
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE

from Analysis import BinaryAnalysis
from CommonView import AsmLineWithOpcode, LocLine, DataLine, AsmLineNoOpcode
from CommonView import CommonListView
from Utils import sizeByType


class AsmLinear(CommonListView):
    addCFG = pyqtSignal(object)
    addIRLinear = pyqtSignal(object)
    gotoHexView = pyqtSignal(int, int)
    log = pyqtSignal(str)
    changedData = pyqtSignal(int, object)

    def __init__(self):
        super(AsmLinear, self).__init__()
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.initModel()
        self.hookCode = {}
        self.emulateView = None
        self.fillNopAct = QAction("Fill nop", self)
        self.fillNopAct.triggered.connect(self.fillNop)
        self.replaceAsmAct = QAction("Replace with new asm", self)
        self.replaceAsmAct.triggered.connect(self.replaceAsm)
        self.showXrefsAct = QAction("Show Xrefs")
        self.showXrefsAct.triggered.connect(self.showXrefs)
        self.taintAct = QAction("Taint", self)
        self.findDepAct = QAction("Find dependency", self)
        self.toHexView = QAction("Follow hex view", self)
        self.addHookAct = QAction("Add hook code", self)
        self.addHookAct.triggered.connect(self.addHook)
        self.emulateAct = QAction("Emulate code", self)
        self.emulateAct.triggered.connect(self.emulateCode)

    def initModel(self):
        codePoint = 0
        dataPoint = 0
        code = BinaryAnalysis.blocks[codePoint]
        data = BinaryAnalysis.data[dataPoint]
        while codePoint < len(BinaryAnalysis.blocks) or dataPoint < len(BinaryAnalysis.data):
            if codePoint < len(BinaryAnalysis.blocks) and (
                    (code[0].lines[0].offset < data[0]) or (dataPoint == len(BinaryAnalysis.data))):
                pres = code[1].cfg.predecessors(code[0].loc_key)
                if len(pres) == 1:
                    preBlock = code[1].cfg.loc_key_to_block(pres[0])
                    if preBlock.lines[-1].name != 'CALL':
                        item = LocLine(code[0].loc_key)
                        address = code[0].lines[0].offset
                        if address in code[1].codeXRefs:
                            item.xrefs = code[1].codeXRefs[address]
                        self.model.appendRow(item)
                else:
                    item = LocLine(code[0].loc_key)
                    address = code[0].lines[0].offset
                    if address in code[1].codeXRefs:
                        item.xrefs = code[1].codeXRefs[address]
                    self.model.appendRow(item)
                for line in code[0].lines:
                    item = AsmLineWithOpcode(line, code[0], code[1])
                    self.addressMap[item.address] = item
                    self.model.appendRow(item)
                codePoint += 1
                if codePoint < len(BinaryAnalysis.blocks):
                    code = BinaryAnalysis.blocks[codePoint]
            elif dataPoint < len(BinaryAnalysis.data):
                i, end = data
                if i == 0x400840:
                    pass
                while i <= end:
                    if i in BinaryAnalysis.dataType:
                        typeData = BinaryAnalysis.dataType[i]
                        if i in BinaryAnalysis.dataXrefs:
                            xrefs = BinaryAnalysis.dataXrefs[i]
                        else:
                            xrefs = None
                        if typeData == 'string':
                            data = BinaryAnalysis.strings[i]
                        else:
                            data = BinaryAnalysis.container.bin_stream.getbytes(i, sizeByType[typeData])
                    else:
                        xrefs = None
                        typeData = 'byte'
                        data = BinaryAnalysis.container.bin_stream.getbytes(i, 1)
                    if typeData == 'string':
                        item = DataLine(i, data.replace('\n', ''), typeData)
                    else:
                        item = DataLine(i, data, typeData)
                    item.xrefs = xrefs
                    self.addressMap[i] = item
                    self.model.appendRow(item)
                    i += len(data)
                dataPoint += 1
                if dataPoint < len(BinaryAnalysis.data):
                    data = BinaryAnalysis.data[dataPoint]

    def mouseDoubleClickEvent(self, event) -> None:
        index = self.selectedIndexes()[0]
        item = self.getItemFormIndex(index)
        if item.ref is not None:
            self.focusAddress(item.ref)
        elif isinstance(item, AsmLineWithOpcode):
            arg = item.args[self.lastClickIndex]
            if isinstance(arg, ExprInt):
                if arg.arg in self.addressMap:
                    self.focusAddress(arg.arg)
        self.lockRelease = True

    def contextMenuEvent(self, event) -> None:
        menu = QMenu(self)
        index = self.indexAt(event.pos())
        item = self.getItemFormIndex(index)
        self.getClickedIndex(item)
        arg = None
        if isinstance(item, AsmLineWithOpcode):
            arg = item.args[self.lastClickIndex]
        if isinstance(item, AsmLineWithOpcode):
            menu.addAction(self.fillNopAct)
            menu.addAction(self.replaceAsmAct)
            menu.addAction(self.addHookAct)
            menu.addAction(self.emulateAct)
            if arg is not None and isinstance(arg, Expr):
                menu.addAction(self.taintAct)
                self.taintAct.triggered.connect(partial(self.taintAnalysis, item))
            if arg is not None and isinstance(arg, ExprId):
                menu.addAction(self.findDepAct)
                self.findDepAct.triggered.connect(partial(self.findDep, item))
        if len(item.xrefs) > 0:
            menu.addAction(self.showXrefsAct)
        if not isinstance(item, LocLine):
            menu.addAction(self.toHexView)
            self.toHexView.triggered.connect(partial(self.toHex, item))
        menu.exec_(event.globalPos())

    def fillNop(self):
        indexs = self.selectedIndexes()
        row = indexs[0].row()
        fIndex = None
        block = None
        func = None
        lenBytes = 0
        fIndexBlock = -1
        for index in indexs:
            if fIndex is None:
                fIndex = index
            line = self.getItemFormIndex(fIndex)
            if block is None:
                block = line.block
                func = line.func
                startAddress = line.instr.offset
            lenBytes += line.instr.l
            if line.instr in block.lines:
                if fIndexBlock == -1:
                    fIndexBlock = block.lines.index(line.instr)
                block.lines.remove(line.instr)
                func.changed = True
            self.model.removeRow(row)
        for i in range(lenBytes):
            nopInstr = BinaryAnalysis.machine.mn.dis(b'\x90', BinaryAnalysis.disasmEngine.attrib)
            nopInstr.offset = startAddress + i
            block.lines.insert(fIndexBlock + i, nopInstr)
            instrView = AsmLineWithOpcode(nopInstr, block, func)
            self.addressMap[startAddress + i] = instrView
            self.model.insertRow(row, instrView)
            row += 1
        self.changedData.emit(BinaryAnalysis.binaryInfo.getOffsetAtAddress(startAddress), b'\x90' * lenBytes)
        self.focusItem(fIndex)

    def replaceAsm(self):
        indexes = self.selectedIndexes()
        totalBytes = 0
        lastIndex = 0
        fLine = self.getItemFormIndex(indexes[0])
        block = fLine.block
        func = fLine.func
        startAddress = fLine.instr.offset
        fIndexBlock = block.lines.index(fLine.instr)
        for index in indexes:
            line = self.getItemFormIndex(index)
            totalBytes += line.instr.l
            if lastIndex < index.row():
                lastIndex = index.row()
        tmp = lastIndex + 1
        totalNop = 0
        line = self.model.item(tmp, 0)
        while isinstance(line, AsmLineWithOpcode):
            if b'\x90' == line.instr.b:
                totalNop += 1
            else:
                break
            tmp += 1
            line = self.model.item(tmp, 0)
        text, okPressed = QInputDialog.getMultiLineText(self, "Assemble", "Assembly Code")
        if okPressed:
            asmCode = text.split('\n')
            listInstrs = []
            totalNewInstr = 0
            is_valid = True
            for code in asmCode:
                if len(code) > 0:
                    try:
                        instr = BinaryAnalysis.machine.mn.fromstring(code.upper().replace('0X', '0x'),
                                                                     BinaryAnalysis.locDB,
                                                                     BinaryAnalysis.disasmEngine.attrib)
                        instr.b = BinaryAnalysis.machine.mn.asm(instr)[0]
                        instr.l = len(instr.b)
                        totalNewInstr += len(instr.b)
                        listInstrs.append(instr)
                    except Disasm_Exception:
                        is_valid = False
            if is_valid:
                if (totalNewInstr <= totalBytes) or (totalNewInstr <= totalBytes + totalNop):
                    row = None
                    fIndex = None
                    for index in indexes:
                        if row is None:
                            row = index.row()
                            fIndex = index
                            address = self.getItemFormIndex(index).instr.offset
                        self.model.removeRow(row)
                        del block.lines[fIndexBlock]
                        func.changed = True
                    if totalNewInstr > totalBytes:
                        for i in range(totalBytes + totalNop - totalNewInstr):
                            self.model.removeRow(row)
                            del block.lines[fIndexBlock]
                    dataChange = b''
                    for i in range(len(listInstrs)):
                        instr = listInstrs[i]
                        instr.offset = address
                        dataChange += instr.b
                        block.lines.insert(fIndexBlock + i, instr)
                        instrView = AsmLineWithOpcode(instr, block, func)
                        self.addressMap[address] = instrView
                        address += len(instr.b)
                        self.model.insertRow(row, instrView)
                        row += 1
                    remain_nop = totalBytes - totalNewInstr
                    for i in range(remain_nop):
                        nopInstr = BinaryAnalysis.machine.mn.dis(b'\x90', BinaryAnalysis.disasmEngine.attrib)
                        nopInstr.offset = address + i
                        instrView = AsmLineWithOpcode(nopInstr, block, func)
                        block.lines.insert(fIndexBlock + len(listInstrs) + i, nopInstr)
                        self.addressMap[address + i] = instrView
                        self.model.insertRow(row, instrView)
                        dataChange += b'\x90'
                        row += 1
                    self.focusItem(fIndex)
                    self.changedData.emit(BinaryAnalysis.binaryInfo.getOffsetAtAddress(startAddress), dataChange)
                else:
                    QMessageBox.warning(self, "Assemble", "Can't assemble. New assembly code longer than older")
            else:
                QMessageBox.warning(self, "Assemble", "Invalid assembly code")

    def showXrefs(self):
        indexes = self.selectedIndexes()
        if len(indexes) == 1:
            index = indexes[0]
            item = self.getItemFormIndex(index)
            if item.xrefs:
                items = []
                for address in item.xrefs:
                    if address in self.addressMap:
                        items.append(self.addressMap[address])
                xrefsDialog = XrefsView(items, self)
                xrefsDialog.gotoAddress.connect(self.focusAddress)
                xrefsDialog.show()

    def taintAnalysis(self, item):
        func = item.func
        if func.ircfg is None:
            func.ira = BinaryAnalysis.iraType(func.cfg.loc_db)
            func.ircfg = func.ira.new_ircfg_from_asmcfg(func.cfg)
            func.defUse = DiGraphDefUse(ReachingDefinitions(func.ircfg))
        current_block = func.ircfg.get_block(item.block.loc_key)
        index = 0
        dstArg = None
        for index, assignblk in enumerate(current_block):
            if assignblk.instr.offset == item.address:
                for dst, src in assignblk.items():
                    dstArg = dst
                break
        queue = [AssignblkNode(item.block.loc_key, index, dstArg)]
        currentPoint = 0
        endPoint = 0
        while currentPoint <= endPoint:
            node = queue[currentPoint]
            currentPoint += 1
            assign = func.ircfg.blocks[node.label][node.index]
            self.focusAddress(assign.instr.offset, False)
            for node2 in func.defUse.successors(node):
                endPoint += 1
                queue.append(node2)

    def findDep(self, item):
        arg = item.args[self.lastClickIndex]
        address = item.address + item.instr.l
        func = item.func
        if func.ircfg is None:
            func.ira = BinaryAnalysis.iraType(func.cfg.loc_db)
            func.ircfg = func.ira.new_ircfg_from_asmcfg(func.cfg)
            func.defUse = DiGraphDefUse(ReachingDefinitions(func.ircfg))
        indexReg = eval('BinaryAnalysis.machine.mn.regs.regs' + str(arg.size).zfill(2) + '_expr').index(arg)
        arg = eval('BinaryAnalysis.machine.mn.regs.regs' + str(BinaryAnalysis.disasmEngine.attrib).zfill(2) + '_expr')[
            indexReg]
        elements = set()
        elements.add(arg)
        depgraph = DependencyGraph(func.ircfg, implicit=False, apply_simp=True, follow_call=False, follow_mem=True)
        currentLockey = next(iter(func.ircfg.getby_offset(address)))
        assignblkIndex = 0
        currentBlock = func.ircfg.get_block(currentLockey)
        for assignblkIndex, assignblk in enumerate(currentBlock):
            if assignblk.instr.offset == address:
                break
        outputLog = ''
        for solNum, sol in enumerate(depgraph.get(currentBlock.loc_key, elements, assignblkIndex, set())):
            results = sol.emul(func.ira, ctx={})
            outputLog += 'Solution %d:\n' % solNum
            for k, v in viewitems(results):
                outputLog += str(k) + ' = ' + str(v) + '\n'
            path = ' -> '.join(BinaryAnalysis.locDB.pretty_str(h) for h in sol.history[::-1])
            outputLog += path + '\n\n'
        self.log.emit(outputLog)

    def hook(self, jitter):
        address = jitter.pc
        if address in self.hookCode:
            hookCode = self.hookCode[address]
            oldStdout = sys.stdout
            redirectStdout = StringIO()
            sys.stdout = redirectStdout
            try:
                exec(hookCode)
            except Exception as e:
                self.log.emit(str(e))
            sys.stdout = oldStdout
            self.log.emit(redirectStdout.getvalue())
        return True

    def code_sentinelle(self, jitter):
        jitter.run = False
        jitter.pc = 0
        return True

    def emulateCode(self):
        indexes = self.selectedIndexes()
        if len(indexes) > 0:
            item = self.getItemFormIndex(indexes[0])
            if isinstance(item, AsmLineWithOpcode):
                stackSize = 0x1000000
                stackBase = 0x1230000
                jitter = BinaryAnalysis.machine.jitter('llvm')
                jitter.vm.add_memory_page(BinaryAnalysis.binaryInfo.imageBase, PAGE_READ | PAGE_WRITE, bytes(BinaryAnalysis.rawData))
                jitter.vm.add_memory_page(stackBase, PAGE_READ | PAGE_WRITE, bytes([0] * stackSize))
                jitter.cpu.RSP = stackBase + stackSize
                jitter.jit.log_mn = True
                jitter.jit.log_regs = True
                if jitter.attrib == 64:
                    jitter.push_uint64_t(0x1337beef)
                    jitter.cpu.RBP = jitter.cpu.RSP
                elif jitter.attrib == 32:
                    jitter.push_uint32_t(0x1337beef)
                    jitter.cpu.EBP = jitter.cpu.ESP
                jitter.add_breakpoint(0x1337beef, self.code_sentinelle)
                for address in self.hookCode:
                    jitter.add_breakpoint(address, self.hook)
                jitter.init_run(item.address)
                jitter.continue_run()

    def addHook(self):
        indexes = self.selectedIndexes()
        if len(indexes) > 0:
            item = self.getItemFormIndex(indexes[0])
            if isinstance(item, AsmLineWithOpcode):
                code = ''
                if item.address in self.hookCode:
                    code = self.hookCode[item.address]
                code, ok = QInputDialog.getMultiLineText(self, 'Insert Hook', '', code)
                if ok:
                    self.hookCode[item.address] = code

    def writeLog(self, logData):
        if self.emulateView is not None:
            if logData == "Emulate Finished":
                self.emulateView.close()
        self.log.emit(logData)

    def toHex(self, item):
        offset = BinaryAnalysis.binaryInfo.getOffsetAtAddress(item.address)
        if isinstance(item, AsmLineWithOpcode):
            lenData = item.instr.l
        else:
            lenData = len(item.data)
        self.gotoHexView.emit(offset, lenData)

    def keyPressEvent(self, event):
        pass

    def keyReleaseEvent(self, event) -> None:
        modifier = QApplication.keyboardModifiers()
        if event.key() == Qt.Key_Space:
            index = self.selectedIndexes()[0]
            line = self.getItemFormIndex(index)
            if isinstance(line, AsmLineWithOpcode):
                if modifier == Qt.ControlModifier:
                    self.addIRLinear.emit(line.func)
                else:
                    self.addCFG.emit(line)
        super(AsmLinear, self).keyReleaseEvent(event)


class XrefsView(QDialog):
    gotoAddress = pyqtSignal(int)

    def __init__(self, items, parent):
        super(XrefsView, self).__init__(parent)
        self.listInstrs = CommonListView()
        for item in items:
            self.listInstrs.model.appendRow(AsmLineNoOpcode(item.instr, item.block, item.func))
        self.listInstrs.dblAddress.connect(self.finish)
        self.layout = QHBoxLayout(self)
        self.layout.addWidget(self.listInstrs)
        self.widthView = 0
        for i in range(self.listInstrs.model.rowCount()):
            item = self.listInstrs.getItem(i)
            _, end = item.componentRanges[-1]
            if self.widthView < end * self.fontMetrics().averageCharWidth():
                self.widthView = end * self.fontMetrics().averageCharWidth()
        self.widthView += self.fontMetrics().averageCharWidth() * 10
        screenHight = QApplication.desktop().height()
        height = self.listInstrs.sizeHintForRow(0) * (
                self.listInstrs.model.rowCount() + 4) + 2 * self.listInstrs.frameWidth()
        if height > screenHight:
            height = screenHight - 100
        self.setMinimumWidth(self.widthView)
        self.setMinimumHeight(height)

    def finish(self, address):
        self.gotoAddress.emit(address)
        self.close()
