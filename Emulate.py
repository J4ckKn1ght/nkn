import sys
from io import StringIO

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QApplication, QSizePolicy, QDialog, QVBoxLayout, QPushButton, QInputDialog
from miasm.expression.expression import ExprMem

from Analysis import BinaryAnalysis
from CommonView import CommonListView, AsmLineWithOpcode, LocLine


class ListInstructions(CommonListView):
    result = pyqtSignal(str)

    def __init__(self, items):
        super(ListInstructions, self).__init__()
        self.hookCodeMap = {}
        self.startAddress = None
        self.endAddress = None
        self.allMem = []
        self.infoHook = ''
        for item in items:
            if isinstance(item, AsmLineWithOpcode):
                newItem = AsmLineWithOpcode(item.instr, item.block, item.func)
                for arg in item.instr.args:
                    if isinstance(arg, ExprMem):
                        self.allMem.append((arg, item.instr.arg2str(arg, loc_db=BinaryAnalysis.locDB)))
                if self.startAddress is None:
                    self.startAddress = item.address
                self.endAddress = item.address + item.instr.l
                self.hookCodeMap[item.address] = ''
            else:
                newItem = LocLine(item.lockey, None)
            self.model.appendRow(newItem)
        self.widthView = 0
        for i in range(self.model.rowCount()):
            item = self.getItem(i)
            _, end = item.componentRanges[-1]
            if self.widthView < end * self.fontMetrics().averageCharWidth():
                self.widthView = end * self.fontMetrics().averageCharWidth()
        self.widthView += self.fontMetrics().averageCharWidth() * 10

    def mouseDoubleClickEvent(self, event):
        index = self.selectedIndexes()[0]
        line = self.model.item(index.row(), 0)
        hookCode = self.hookCodeMap[line.address]
        code, ok = QInputDialog.getMultiLineText(self, 'Insert Hook', '', hookCode)
        if ok:
            self.hookCodeMap[line.address] = code
        super(ListInstructions, self).mouseDoubleClickEvent(event)

    def hook(self, jitter):
        address = jitter.pc
        if address == self.endAddress:
            jitter.run = False
            return True
        if address in self.hookCodeMap:
            hookCode = self.hookCodeMap[address]
            oldStdout = sys.stdout
            redirectStdout = StringIO()
            sys.stdout = redirectStdout
            try:
                exec(hookCode)
            except Exception as e:
                self.result.emit(str(e))
            sys.stdout = oldStdout
            self.infoHook += redirectStdout.getvalue()
        return True

    def code_sentinelle(self, jitter):
        jitter.run = False
        jitter.pc = 0
        return True

    def startEmulate(self):
        self.infoHook = ''
        sb = BinaryAnalysis.sb
        sb.jitter.jit.log_mn = True
        sb.jitter.jit.log_regs = True
        if sb.jitter.attrib == 64:
            sb.jitter.push_uint64_t(0x1337beef)
            sb.jitter.cpu.RBP = sb.jitter.cpu.RSP
        elif sb.jitter.attrib == 32:
            sb.jitter.push_uint32_t(0x1337beef)
            sb.jitter.cpu.EBP = sb.jitter.cpu.ESP
        sb.jitter.add_breakpoint(0x1337beef, self.code_sentinelle)
        self.hookCodeMap[self.startAddress] = 'print("RSP = " + hex(jitter.cpu.RSP))'
        for address, hookCode in self.hookCodeMap.items():
            if len(hookCode.strip()) != 0:
                sb.jitter.add_breakpoint(address, self.hook)
        sb.jitter.add_breakpoint(self.endAddress, self.hook)
        # try:
        #     sb.run(self.startAddress)
        # except:
        #     self.result.emit("Emulate failed. Memory address is not valid")
        sb.run(self.startAddress)
        out = ''
        allRegs = eval(
            'BinaryAnalysis.machine.mn.regs.regs' + str(BinaryAnalysis.disasmEngine.attrib).zfill(2) + '_str')
        for reg in allRegs:
            value = eval('sb.jitter.cpu.' + reg)
            out += reg + ' = ' + hex(value) + '\n'
        for mem, memStr in self.allMem:
            out += memStr + ' = ' + str(sb.jitter.eval_expr(mem)) + '\n'
        self.result.emit(out)
        self.result.emit(self.infoHook)
        self.result.emit("Emulate Finished")


class EmulateView(QDialog):
    def __init__(self, instrs, parent=None):
        super(EmulateView, self).__init__(parent)
        self.setWindowTitle("Emulate Code")
        self.instrs = instrs
        self.layout = QVBoxLayout(self)
        self.listInstrs = ListInstructions(self.instrs)
        self.emulateBtn = QPushButton("Emulate")
        self.emulateBtn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.emulateBtn.clicked.connect(self.listInstrs.startEmulate)
        self.layout.addWidget(self.listInstrs, 9)
        self.layout.addWidget(self.emulateBtn, 1)
        screenHight = QApplication.desktop().height()
        height = self.listInstrs.sizeHintForRow(1) * (
                self.listInstrs.model.rowCount() + 4) + 2 * self.listInstrs.frameWidth() + self.emulateBtn.sizeHint().height()
        if height > screenHight:
            height = screenHight - 100
        self.setMinimumWidth(self.listInstrs.widthView)
        self.setMinimumHeight(height)
