import string

from PyQt5.QtCore import Qt, QItemSelectionModel
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QTableView, QWidget, QHBoxLayout, QScrollBar, QHeaderView, \
    QAbstractItemView, QApplication, QMenu, QFileDialog

from Analysis import BinaryAnalysis

class Hex(QTableView):
    def __init__(self, data, scroll, parent):
        super(Hex, self).__init__(parent)
        self.data = data
        self.column = 16
        self.menu = QMenu(self)
        self.dumpAction = self.menu.addAction("Dump")
        self.model = QStandardItemModel(self)
        self.setVerticalScrollBar(scroll)
        self.verticalScrollBar().hide()
        self.horizontalScrollBar().hide()
        self.initModel()
        self.setShowGrid(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.horizontalHeader().setDefaultSectionSize(30)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(20)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setFixedWidth(30 * self.column + self.horizontalHeader().sectionSizeHint(0) + 45)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def initModel(self):
        header = ['%X' % i for i in range(16)]
        self.model.setHorizontalHeaderLabels(header)
        i = 0
        while i < len(self.data):
            row = []
            for c in range(self.column):
                row.append(QStandardItem('%02x' % self.data[i]))
                i += 1
                if i == len(self.data):
                    break
            self.model.appendRow(row)
        totalRow = self.model.rowCount()
        vHeader = ['%x' % (i) for i in range(totalRow)]
        self.model.setVerticalHeaderLabels(vHeader)
        self.setModel(self.model)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            modifiers = QApplication.keyboardModifiers()
            text = self.parent().text
            if modifiers != Qt.ControlModifier:
                text.clearSelection()
                text.clearFocus()
            index = self.indexAt(event.pos())
            row = index.row()
            column = index.column()
            cell = text.model.index(row, column)
            text.selectionModel().select(cell, QItemSelectionModel.Select)
        super(Hex, self).mousePressEvent(event)

    def mouseMoveEvent(self, event):
        text = self.parent().text
        text.clearSelection()
        text.clearFocus()
        for index in self.selectedIndexes():
            row = index.row()
            column = index.column()
            cell = text.model.index(row, column)
            text.selectionModel().select(cell, QItemSelectionModel.Select)
        super(Hex, self).mouseMoveEvent(event)

    def contextMenuEvent(self, event):
        if len(self.selectedIndexes()) > 0:
            action = self.menu.exec_(self.mapToGlobal(event.pos()))
            if action == self.dumpAction:
                data = []
                for index in self.selectedIndexes():
                    row = index.row()
                    column = index.column()
                    cell = self.model.index(row, column)
                    data.append(int(cell.data(), 16))
                fileName, _ = QFileDialog.getSaveFileName(self, "Save File")
                with open(fileName, 'wb') as f:
                    f.write(bytearray(data))


class Text(QTableView):
    def __init__(self, data, scroll, parent):
        super(Text, self).__init__(parent)
        self.data = data
        self.column = 16
        self.model = QStandardItemModel(self)
        self.setVerticalScrollBar(scroll)
        self.initModel()
        self.setShowGrid(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.horizontalHeader().setDefaultSectionSize(16)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(20)
        self.verticalHeader().hide()
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def initModel(self):
        header = ['%X' % i for i in range(16)]
        self.model.setHorizontalHeaderLabels(header)
        i = 0
        while i < len(self.data):
            row = []
            for c in range(self.column):
                if chr(self.data[i]) in string.printable:
                    s = chr(self.data[i]).strip()
                    row.append(QStandardItem(s))
                else:
                    row.append(QStandardItem('.'))
                i += 1
                if i == len(self.data):
                    break
            self.model.appendRow(row)
        self.setModel(self.model)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            modifiers = QApplication.keyboardModifiers()
            hex = self.parent().hex
            if modifiers != Qt.ControlModifier:
                hex.clearSelection()
                hex.clearFocus()
            index = self.indexAt(event.pos())
            row = index.row()
            column = index.column()
            cell = hex.model.index(row, column)
            hex.selectionModel().select(cell, QItemSelectionModel.Select)
        super(Text, self).mousePressEvent(event)

    def mouseMoveEvent(self, event):
        hex = self.parent().hex
        hex.clearSelection()
        hex.clearFocus()
        for index in self.selectedIndexes():
            row = index.row()
            column = index.column()
            cell = hex.model.index(row, column)
            hex.selectionModel().select(cell, QItemSelectionModel.Select)
        super(Text, self).mouseMoveEvent(event)


class HexView(QWidget):
    def __init__(self, data):
        super(HexView, self).__init__()
        self.layout = QHBoxLayout(self)
        self.scrollBar = QScrollBar(self)
        self.hex = Hex(data, self.scrollBar, self)
        self.text = Text(data, self.scrollBar, self)
        self.layout.addWidget(self.hex)
        self.layout.addWidget(self.scrollBar)
        self.layout.addWidget(self.text)

    def toOffset(self, offset, length=1):
        self.hex.clearSelection()
        self.hex.clearFocus()
        self.text.clearSelection()
        self.hex.clearFocus()
        fIndex = None
        for i in range(offset, offset + length):
            row = i / self.hex.column
            col = i % self.hex.column
            cell = self.hex.model.index(row, col)
            if fIndex is None:
                fIndex = cell
            self.hex.selectionModel().select(cell, QItemSelectionModel.Select)
            self.text.selectionModel().select(cell, QItemSelectionModel.Select)
        self.hex.scrollTo(fIndex, QAbstractItemView.PositionAtCenter)

    def changeData(self, offset, data):
        for i in range(offset, offset + len(data)):
            row = i / self.hex.column
            col = i % self.hex.column
            hexCell = self.hex.model.item(row, col)
            hexCell.setText('%x' % data[i - offset])
            textCell = self.text.model.item(row, col)
            if (32 <= data[i - offset]) and (data[i - offset] <= 127):
                textCell.setText(chr(data[i - offset]))
            else:
                textCell.setText('.')
            BinaryAnalysis.rawData[i] = data[i - offset]
