from functools import partial

from PyQt5.QtCore import Qt
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QMenu, QAction, QApplication
from grandalf.graphs import Vertex, Edge, Graph
from grandalf.layouts import SugiyamaLayout
from grandalf.routing import route_with_lines
from miasm.analysis.data_flow import DiGraphDefUse, ReachingDefinitions, AssignblkNode
from miasm.analysis.depgraph import DependencyGraph
from future.utils import viewitems

from Analysis import BinaryAnalysis
from CFG import CFG, BasicBlock, BasicEdge
from CommonView import AsmLineNoOpcode, LocLine
from miasm.expression.expression import ExprId, Expr


class AsmBlockView(BasicBlock):
    gotoAddress = pyqtSignal(int)

    def __init__(self, startLockey, endLockey, blocks, func):
        super(AsmBlockView, self).__init__()
        nameLine = LocLine(startLockey, func)
        self.model.appendRow(nameLine)
        self.lockey = startLockey
        self.endLockey = endLockey
        for block in blocks:
            for line in block.lines:
                detectBlock = None
                for block in func.cfg.blocks:
                    if detectBlock is None:
                        for line2 in block.lines:
                            if line == line2:
                                detectBlock = block
                                break
                asmLine = AsmLineNoOpcode(line, detectBlock, func)
                self.model.appendRow(asmLine)
        self.setSize()
        self.w = self.width()
        self.h = self.height()
        self.toHexAct = QAction("Follow hex view", self)

    def mouseDoubleClickEvent(self, event):
        x = event.pos().x()
        indexes = self.selectedIndexes()
        if len(indexes) == 1:
            index = indexes[0]
            line = self.getItemFormIndex(index)
            if isinstance(line, LocLine):
                return
            self.gotoAddress.emit(line.ref)


class AsmCFGView(CFG):
    gotoAsmLinear = pyqtSignal(int)
    gotoHexView = pyqtSignal(int, int)
    gotoIRCFG = pyqtSignal(object)

    def __init__(self, func):
        super(AsmCFGView, self).__init__()
        self.func = func
        self.initView()
        self.toHexAct = QAction("Follow hex view", self)
        self.taintAct = QAction("Taint Analysis")
        self.findDepAct = QAction("Find dependency")

    def initView(self):
        cfg = self.func.cfg
        vertexs = {}
        done = set()
        for block in cfg.blocks:
            if block in done:
                continue
            done.add(block)
            startLockey = block.loc_key
            endLockey = block.loc_key
            blocks = [block]
            while (block.lines[-1].name == 'CALL') and (len(cfg.predecessors(block.get_next())) == 1):
                nextLockey = block.get_next()
                if block.loc_key in cfg.successors(nextLockey):
                    break
                block = cfg.loc_key_to_block(nextLockey)
                blocks.append(block)
                endLockey = block.loc_key
                done.add(block)
            vertex = Vertex(startLockey)
            vertexs[startLockey] = vertex
            vertex.view = AsmBlockView(startLockey, endLockey, blocks, self.func)
        edges = []
        for src in vertexs.values():
            successLocKeys = cfg.successors(src.view.endLockey)
            for key in successLocKeys:
                vSrc = vertexs[src.view.lockey]
                vDst = vertexs[key]
                edge = Edge(vSrc, vDst)
                edge.view = BasicEdge(vDst)
                edges.append(edge)
                vSrc.view.outBlocks.append(vDst.view)
                vDst.view.inBlocks.append(vSrc.view)
        self.graph = Graph(vertexs.values(), edges)
        sugLayout = SugiyamaLayout(self.graph.C[0])
        sugLayout.route_edge = route_with_lines
        sugLayout.init_all()
        sugLayout.draw()
        for v in vertexs.values():
            self.addBlock(v.view, v.view.xy[0] - (v.view.w / 2), v.view.xy[1] - (v.view.h / 2))
            v.view.gotoAddress.connect(self.selectAddress)
        for e in edges:
            srcView = e.v[0].view
            srcBlock = e.v[0].data
            dstBlock = e.v[1].data
            if len(srcView.outBlocks) == 1:
                color = Qt.darkBlue
            elif dstBlock == cfg.successors(srcBlock)[0]:
                color = Qt.darkRed
            else:
                color = Qt.darkGreen
            edge_view = e.view
            edge_view.color = color
            self.scene.addItem(edge_view)

    def keyReleaseEvent(self, event) -> None:
        modifier = QApplication.keyboardModifiers()
        if event.key() == Qt.Key_Space:
            if modifier != Qt.ControlModifier:
                if self.clickedBlock is not None:
                    line = self.clickedBlock.getLineSelected()
                    self.gotoAsmLinear.emit(line.address)
                else:
                    self.gotoAsmLinear.emit(self.lastAddress)
            else:
                self.gotoIRCFG.emit(self.func)
        super(AsmCFGView, self).keyReleaseEvent(event)

    def contextMenuEvent(self, event) -> None:
        menu = QMenu(self)
        line = self.clickedBlock.getLineSelected()
        self.clickedBlock.getClickedIndex(line)

        arg = None
        if isinstance(line, AsmLineNoOpcode):
            arg = line.args[self.clickedBlock.lastClickIndex]
        if isinstance(line, AsmLineNoOpcode):
            menu.addAction(self.toHexAct)
            self.toHexAct.triggered.connect(partial(self.toHexView, line))
            if arg is not None and isinstance(arg, Expr):
                menu.addAction(self.taintAct)
                self.taintAct.triggered.connect(partial(self.taintAnalysis, line))
            if arg is not None and isinstance(arg, ExprId):
                menu.addAction(self.findDepAct)
                self.findDepAct.triggered.connect(partial(self.findDep, line))
        menu.exec_(event.globalPos())

    def toHexView(self, line):
        offset = BinaryAnalysis.binaryInfo.getOffsetAtAddress(line.address)
        lenData = line.instr.l
        self.gotoHexView.emit(offset, lenData)

    def highlightText(self, clickedBlock, text, index):
        for block in self.mapItems:
            if block != clickedBlock:
                if index > 0:
                    start = 1
                else:
                    start = 0
                block.highlighRelation(text, start)

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
            self.selectAddress(assign.instr.offset, False, False)
            for node2 in func.defUse.successors(node):
                endPoint += 1
                queue.append(node2)

    def findDep(self, item):
        arg = item.args[self.clickedBlock.lastClickIndex]
        address = item.address + item.instr.l
        func = item.func
        if func.ircfg is None:
            func.ira = BinaryAnalysis.iraType(func.cfg.loc_db)
            func.ircfg = func.ira.new_ircfg_from_asmcfg(func.cfg)
            func.defUse = DiGraphDefUse(ReachingDefinitions(func.ircfg))
        indexReg = eval('BinaryAnalysis.machine.mn.regs.regs' + str(arg.size).zfill(2) + '_expr').index(arg)
        arg = eval('BinaryAnalysis.machine.mn.regs.regs' + str(BinaryAnalysis.disasmEngine.attrib).zfill(2) + '_expr')[indexReg]
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
