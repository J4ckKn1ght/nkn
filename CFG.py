from PyQt5.QtCore import Qt, QRectF, QPointF, QItemSelectionModel, pyqtSignal
from PyQt5.QtGui import QPainterPath, QPen, QBrush, QPolygonF, QCursor, QPainter
from PyQt5.QtWidgets import QAbstractItemView, QListView, QApplication, QGraphicsView, QGraphicsScene, QGraphicsItem, \
    QGraphicsPathItem
from math import radians, pi, cos, sin, pow, ceil

from CommonView import LocLine, CommonListView


class BasicBlock(CommonListView):
    highlightText = pyqtSignal(object, str, int)

    def __init__(self):
        super(BasicBlock, self).__init__()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setEditTriggers(QListView.NoEditTriggers)
        self.w = None
        self.h = None
        self.outBlocks = []
        self.inBlocks = []
        self.setStyleSheet('border: 2px solid;')
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setFocusPolicy(Qt.ClickFocus)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clearSelection()
            self.clearFocus()
            self.clearAllEffect()
        super(BasicBlock, self).mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        x = event.pos().x()
        selected_indexs = self.selectedIndexes()
        if len(selected_indexs) == 1:
            index = selected_indexs[0]
            line = self.model.item(index.row(), 0)
            width = self.fontMetrics().averageCharWidth()
            pos = ceil(x / width)
            index = line.getIndexByPos(pos)
            if index != -1:
                text = line.components[index].text
                if index > 0:
                    start = 1
                else:
                    start = 0
                self.highlighRelation(text, start)
                line.selectTextAt(index)
                self.highlightText.emit(self, text, index)
        super(BasicBlock, self).mouseReleaseEvent(event)

    def getLineSelected(self):
        index = self.selectedIndexes()[0]
        return self.getItemFormIndex(index)


class BasicEdge(QGraphicsItem):
    def __init__(self, dst):
        super(BasicEdge, self).__init__()
        self.points = []
        self.head = None
        self.color = Qt.black
        self.dst = dst
        self.setAcceptHoverEvents(True)

    def setpath(self, l):
        self.points = [QPointF(*p) for p in l]

    def boundingRect(self):
        br = self.getqgp().boundingRect()
        if self.head:
            br = br.united(self.head.boundingRect())
        return br

    def getqgp(self):
        qpp = QPainterPath(self.points[0])
        for p in self.points[1:]:
            qpp.lineTo(p)
        return QGraphicsPathItem(qpp)

    def shape(self):
        s = self.getqgp().shape()
        if self.head: s.addPolygon(self.head)
        return s

    def paint(self, painter, option, widget=None):
        qgp = self.getqgp()
        pen = QPen()
        pen.setWidth(2)
        pen.setColor(self.color)
        qgp.setPen(pen)
        qgp.setBrush(QBrush(Qt.NoBrush))
        qgp.paint(painter, option, widget)
        lastp = self.points[-1]
        angle = radians(qgp.path().angleAtPercent(1.))
        angle = angle + pi
        p = lastp + QPointF(cos(angle - pi / 6.) * 7, -sin(angle - pi / 6.) * 7)
        q = lastp + QPointF(cos(angle + pi / 6.) * 7, -sin(angle + pi / 6.) * 7)
        painter.setBrush(QBrush(self.color))
        self.head = QPolygonF([lastp, p, q])
        painter.drawPolygon(self.head)

    def hoverEnterEvent(self, event):
        QApplication.setOverrideCursor(QCursor(Qt.ArrowCursor))
        super(BasicEdge, self).hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        QApplication.restoreOverrideCursor()
        super(BasicEdge, self).hoverEnterEvent(event)

    def mouseDoubleClickEvent(self, event):
        scene = self.scene()
        graphicView = scene.parent()
        graphicView.clearAllFocus()
        dstView = self.dst.view
        dstView.selectionModel().select(dstView.model.index(0, 0), QItemSelectionModel.Select)
        dstBlock = graphicView.mapItems[self.dst.view]
        graphicView.centerOn(dstBlock)
        super(BasicEdge, self).mouseDoubleClickEvent(event)


class CFG(QGraphicsView):
    changeCFG = pyqtSignal(int)
    log = pyqtSignal(str)

    def __init__(self):
        super(CFG, self).__init__()
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setFocusPolicy(Qt.ClickFocus)
        self.mapItems = {}
        self.lastAddress = None
        self.clickedBlock = None

    def wheelEvent(self, event):
        modifiers = QApplication.keyboardModifiers()
        if modifiers == Qt.ControlModifier:
            self.scaleView(pow(2.0, event.angleDelta().y() / 500.0))
        else:
            super(CFG, self).wheelEvent(event)

    def scaleView(self, scaleFactor):
        factor = self.transform().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width()
        if factor < 0.07 or factor > 100:
            return
        self.scale(scaleFactor, scaleFactor)

    def mousePressEvent(self, event):
        self.clickedBlock = None
        x = self.mapToScene(event.pos()).x()
        y = self.mapToScene(event.pos()).y()
        for block in self.mapItems:
            if (block.x() <= x) and (x <= block.x() + block.width()) and (block.y() <= y) and (
                    y <= block.y() + block.height()):
                self.clickedBlock = block
                break
        if self.clickedBlock is not None:
            for block in self.mapItems:
                if block != self.clickedBlock:
                    block.clearSelection()
                    block.clearFocus()
                    block.clearAllEffect()
                else:
                    block.clearAllEffect()
        super(CFG, self).mousePressEvent(event)


    def clearAllFocus(self):
        for block in self.mapItems:
            block.clearSelection()
            block.clearFocus()
            block.clearAllEffect()

    def focusLoc(self, loc):
        for block in self.mapItems:
            block.clearSelection()
            block.clearFocus()
            block.clearAllEffect()
        for block, view in self.mapItems.items():
            if block.lockey == loc:
                block.selectionModel().select(block.model.index(0, 0), QItemSelectionModel.Select)
                self.centerOn(view)

    def addBlock(self, blockView, x, y):
        item = self.scene.addWidget(blockView)
        item.setPos(x, y)
        item.setFocusPolicy(Qt.ClickFocus)
        blockView.highlightText.connect(self.highlightText)
        self.mapItems[blockView] = item

    def selectAddress(self, address, focus=True, clearEffect=True):
        if clearEffect:
            self.clearAllFocus()
        self.lastAddress = address
        for block in self.mapItems:
            for i in range(block.model.rowCount()):
                line = block.model.item(i, 0)
                if not isinstance(line, LocLine):
                    if line.address == address:
                        block.selectionModel().select(block.model.index(i, 0), QItemSelectionModel.Select)
                        if focus:
                            self.centerOn(self.mapItems[block])
                        return

    def mouseDoubleClickEvent(self, event) -> None:
        if self.clickedBlock is not None:
            line = self.clickedBlock.getLineSelected()
            if not isinstance(line, LocLine):
                if line.ref:
                    self.changeCFG.emit(line.ref)
        super(CFG, self).mouseDoubleClickEvent(event)
