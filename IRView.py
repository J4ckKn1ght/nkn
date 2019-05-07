from functools import partial

from PyQt5.QtCore import Qt, QItemSelectionModel
from PyQt5.QtGui import QStandardItem
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QComboBox, QAction, QMenu
from grandalf.graphs import Vertex, Edge, Graph
from grandalf.layouts import SugiyamaLayout
from grandalf.routing import route_with_lines
from miasm.analysis.data_flow import AssignblkNode
from miasm.expression.expression import ExprLoc, Expr

from CFG import CFG, BasicBlock, BasicEdge
from CommonView import CommonListView, IRLine, LocLine, QAbstractItemView


class IRLinearView(CommonListView):
    def __init__(self, ira, ircfg, defUse, pretty=True):
        super(IRLinearView, self).__init__()
        self.ira = ira
        self.ircfg = ircfg
        self.defUse = defUse
        self.pretty = pretty
        self.mapLocs = {}
        self.forwardTaintAct = QAction("Forward taint", self)
        self.backwardTaintAct = QAction("Backward taint", self)
        self.initView()

    def initView(self):
        for lockey, block in self.ircfg.blocks.items():
            nameLine = LocLine(lockey, self.ircfg)
            self.mapLocs[lockey] = nameLine
            self.model.appendRow(nameLine)
            index = 0
            for assignblk in block.assignblks:
                for dst, src in assignblk.items():
                    self.model.appendRow(IRLine(dst, src, block, index, self.pretty))
                index += 1
            spaceItem = QStandardItem()
            spaceItem.setFlags(Qt.NoItemFlags)
            self.model.appendRow(QStandardItem())

    def mouseDoubleClickEvent(self, event) -> None:
        index = self.indexAt(event.pos())
        item = self.getItemFormIndex(index)
        if isinstance(item, IRLine):
            arg = item.args[self.lastClickIndex]
            if isinstance(arg, ExprLoc):
                self.focusLoc(arg.loc_key)

    def focusLoc(self, loc):
        self.clearAllEffect()
        item = self.mapLocs[loc]
        index = self.model.indexFromItem(item)
        self.selectionModel().select(index, QItemSelectionModel.Select)
        self.scrollTo(index, QAbstractItemView.PositionAtCenter)

    def contextMenuEvent(self, event) -> None:
        menu = QMenu(self)
        index = self.indexAt(event.pos())
        item = self.getItemFormIndex(index)
        self.getClickedIndex(item, False)
        if isinstance(item, IRLine):
            arg = item.args[self.lastClickIndex]
            if isinstance(arg, Expr):
                menu.addAction(self.forwardTaintAct)
                menu.addAction(self.backwardTaintAct)
                self.forwardTaintAct.triggered.connect(partial(self.forwardTaint, item))
                self.backwardTaintAct.triggered.connect(partial(self.backwardTaint, item))
            menu.exec_(event.globalPos())

    def forwardTaint(self, item):
        queue = [AssignblkNode(item.block.loc_key, item.index, item.dst)]
        currentPoint = 0
        endPoint = 1
        while currentPoint < endPoint:
            node = queue[currentPoint]
            self.selectLine(node.label, node.index, node.var)
            currentPoint += 1
            for node2 in self.defUse.successors(node):
                queue.append(node2)
                endPoint += 1

    def findAssign(self, arg):
        for i in range(self.model.rowCount()):
            line = self.model.item(i, 0)
            if isinstance(line, IRLine):
                if line.dst == arg:
                    return line

    def backwardTaint(self, item):
        arg = item.args[self.lastClickIndex]
        line = self.findAssign(arg)
        self.selectionModel().select(self.model.indexFromItem(line), QItemSelectionModel.Select)
        queue = [AssignblkNode(line.block.loc_key, line.index, line.dst)]
        currentPoint = 0
        endPoint = 1
        while currentPoint < endPoint:
            node = queue[currentPoint]
            if currentPoint != 0:
                self.selectLine(node.label, node.index, node.var)
            currentPoint += 1
            for node2 in self.defUse.predecessors(node):
                queue.append(node2)
                endPoint += 1

    def selectLine(self, lockey, index, var):
        expr = self.ircfg.blocks[lockey][index][var]
        i = 0
        while i < self.model.rowCount():
            item = self.model.item(i, 0)
            if isinstance(item, LocLine):
                if item.lockey == lockey:
                    i += 1
                    item = self.model.item(i, 0)
                    while item.src != expr:
                        i += 1
                        item = self.model.item(i, 0)
                    self.selectionModel().select(self.model.index(i, 0), QItemSelectionModel.Select)
                    return
            i += 1


class IRWidget(QWidget):
    def __init__(self, ira, viewType):
        super(IRWidget, self).__init__()
        layout = QVBoxLayout(self)
        self.ira = ira
        self.viewType = viewType
        self.optimizeCB = QComboBox(self)
        self.optimizeCB.addItem('Raw')
        self.optimizeCB.addItem("Normal Simplify")
        self.optimizeCB.addItem("SSA Form")
        self.optimizeCB.addItem("Maxium Simplify")
        self.optimizeCB.currentIndexChanged.connect(self.changeOptimizeMode)
        self.currentIRCFG = self.ira.getRawIRCFG()
        self.currentIRA = self.ira.getRawIRA()
        self.currentDefUse = self.ira.getRawDefUse()
        if viewType == 0:
            self.mainWidget = IRLinearView(self.currentIRA, self.currentIRCFG, self.currentDefUse)
        else:
            self.mainWidget = IRCFGView(self.currentIRA, self.currentIRCFG, self.currentDefUse)
        layout.addWidget(self.optimizeCB, 1)
        layout.addWidget(self.mainWidget, 9)

    def changeOptimizeMode(self, index):
        if index == 0:
            self.currentIRA = self.ira.getRawIRA()
            self.currentIRCFG = self.ira.getRawIRCFG()
            self.currentDefUse = self.ira.getRawDefUse()
        elif index == 1:
            self.currentIRA = self.ira.getNormalIRA()
            self.currentIRCFG = self.ira.getNormalIRCFG()
            self.currentDefUse = self.ira.getNormalDefUse()
        elif index == 2:
            self.currentIRA = self.ira.getSSAIRA()
            self.currentIRCFG = self.ira.getSSAIRCFG()
            self.currentDefUse = self.ira.getSSADefUse()
        else:
            self.currentIRA = self.ira.getMaxIRA()
            self.currentIRCFG = self.ira.getMaxIRCFG()
            self.currentDefUse = self.ira.getMaxDefUse()
        layout = self.layout()
        layout.removeWidget(self.mainWidget)
        if self.viewType == 0:
            self.mainWidget = IRLinearView(self.currentIRA, self.currentIRCFG, self.currentDefUse)
        else:
            self.mainWidget = IRCFGView(self.currentIRA, self.currentIRCFG, self.currentDefUse)
        layout.addWidget(self.mainWidget, 9)

    def keyPressEvent(self, event) -> None:
        pass

    def keyReleaseEvent(self, event) -> None:
        if event.key() == Qt.Key_Space:
            layout = self.layout()
            layout.removeWidget(self.mainWidget)
            self.changeViewType()
            layout.addWidget(self.mainWidget, 9)

    def changeViewType(self):
        if self.viewType == 0:
            self.mainWidget = IRCFGView(self.currentIRA, self.currentIRCFG, self.currentDefUse)
            self.viewType = 1
        else:
            self.mainWidget = IRLinearView(self.currentIRA, self.currentIRCFG, self.currentDefUse)
            self.viewType = 0


class IRBlockView(BasicBlock):
    def __init__(self, lockey, block, pretty=True):
        super(IRBlockView, self).__init__()
        self.block = block
        self.lockey = lockey
        self.pretty = pretty
        nameLine = LocLine(lockey, None, pretty=self.pretty)
        self.model.appendRow(nameLine)
        index = 0
        for assignblk in block.assignblks:
            for dst, src in assignblk.items():
                self.model.appendRow(IRLine(dst, src, block, index, self.pretty))
            index += 1
        self.setSize()
        self.w = self.width()
        self.h = self.height()


class IRCFGView(CFG):
    def __init__(self, ira, ircfg, defUse):
        super(IRCFGView, self).__init__()
        self.ira = ira
        self.ircfg = ircfg
        self.defUse = defUse
        self.forwardTaintAct = QAction("Forward taint", self)
        self.backwardTaintAct = QAction("Backward taint", self)
        self.initView()

    def initView(self):
        vertexs = {}
        for lockey, block in self.ircfg.blocks.items():
            vertexs[lockey] = Vertex(block)
            vertexs[lockey].view = IRBlockView(lockey, block)
        edges = []
        for src in vertexs:
            successLocKeys = self.ircfg.successors(src)
            for key in successLocKeys:
                if key in vertexs:
                    vSrc = vertexs[src]
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
        for e in edges:
            srcView = e.v[0].view
            srcBlock = e.v[0].data
            dstBlock = e.v[1].data
            if len(srcView.outBlocks) == 1:
                color = Qt.darkBlue
            elif dstBlock.loc_key == self.ircfg.successors(srcBlock.loc_key)[0]:
                color = Qt.darkRed
            else:
                color = Qt.darkGreen
            edge_view = e.view
            edge_view.color = color
            self.scene.addItem(edge_view)

    def mouseDoubleClickEvent(self, event) -> None:
        block = self.clickedBlock
        line = block.getLineSelected()
        index = block.lastClickIndex
        arg = line.args[index]
        if isinstance(arg, ExprLoc):
            self.focusLoc(arg.loc_key)

    def highlightText(self, clickedBlock, text, index):
        for block in self.mapItems:
            if block != clickedBlock:
                block.highlighRelation(text, 0)

    def contextMenuEvent(self, event) -> None:
        menu = QMenu(self)
        block = self.clickedBlock
        item = block.getLineSelected()
        block.getClickedIndex(item, False)
        if isinstance(item, IRLine):
            arg = item.args[block.lastClickIndex]
            if isinstance(arg, Expr):
                menu.addAction(self.forwardTaintAct)
                menu.addAction(self.backwardTaintAct)
                self.forwardTaintAct.triggered.connect(partial(self.forwardTaint, item))
                self.backwardTaintAct.triggered.connect(partial(self.backwardTaint, item))
            menu.exec_(event.globalPos())

    def forwardTaint(self, item):
        queue = [AssignblkNode(item.block.loc_key, item.index, item.dst)]
        currentPoint = 0
        endPoint = 1
        while currentPoint < endPoint:
            node = queue[currentPoint]
            self.selectLine(node.label, node.index, node.var)
            currentPoint += 1
            for node2 in self.defUse.successors(node):
                queue.append(node2)
                endPoint += 1

    def findAssign(self, arg):
        for i in range(self.model.rowCount()):
            line = self.model.item(i, 0)
            if isinstance(line, IRLine):
                if line.dst == arg:
                    return line

    def backwardTaint(self, item):
        arg = item.args[self.lastClickIndex]
        line = self.findAssign(arg)
        self.selectionModel().select(self.model.indexFromItem(line), QItemSelectionModel.Select)
        queue = [AssignblkNode(line.block.loc_key, line.index, line.dst)]
        currentPoint = 0
        endPoint = 1
        while currentPoint < endPoint:
            node = queue[currentPoint]
            if currentPoint != 0:
                self.selectLine(node.label, node.index, node.var)
            currentPoint += 1
            for node2 in self.defUse.predecessors(node):
                queue.append(node2)
                endPoint += 1

    def selectLine(self, lockey, index, var):
        expr = self.ircfg.blocks[lockey][index][var]
        i = 0
        for block in self.mapItems:
            while i < block.model.rowCount():
                item = block.model.item(i, 0)
                if isinstance(item, LocLine):
                    if item.lockey == lockey:
                        i += 1
                        item = block.model.item(i, 0)
                        while item.src != expr:
                            i += 1
                            item = block.model.item(i, 0)
                        block.selectionModel().select(block.model.index(i, 0), QItemSelectionModel.Select)
                        return
                i += 1


class IRCFGRecover(CFG):
    def __init__(self, ircfg):
        super(IRCFGRecover, self).__init__()
        self.ircfg = ircfg
        self.initView()

    def initView(self):
        vertexs = {}
        for lockey, block in self.ircfg.blocks.items():
            vertexs[lockey] = Vertex(block)
            vertexs[lockey].view = IRBlockView(lockey, block, False)
        edges = []
        for src in vertexs:
            successLocKeys = self.ircfg.successors(src)
            for key in successLocKeys:
                if key in vertexs:
                    vSrc = vertexs[src]
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
        for e in edges:
            srcView = e.v[0].view
            srcBlock = e.v[0].data
            dstBlock = e.v[1].data
            if len(srcView.outBlocks) == 1:
                color = Qt.darkBlue
            elif dstBlock.loc_key == self.ircfg.successors(srcBlock.loc_key)[0]:
                color = Qt.darkRed
            else:
                color = Qt.darkGreen
            edge_view = e.view
            edge_view.color = color
            self.scene.addItem(edge_view)

    def mouseDoubleClickEvent(self, event) -> None:
        block = self.clickedBlock
        line = block.getLineSelected()
        index = block.lastClickIndex
        arg = line.args[index]
        if isinstance(arg, ExprLoc):
            self.focusLoc(arg.loc_key)

    def highlightText(self, clickedBlock, text, index):
        for block in self.mapItems:
            if block != clickedBlock:
                block.highlighRelation(text, 0)
