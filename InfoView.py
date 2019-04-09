from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QTableView, QHeaderView
from PyQt5.QtCore import pyqtSignal


class InfoView(QTableView):
    clicked = pyqtSignal(int)

    def __init__(self, header, data):
        super(InfoView, self).__init__()
        self.model = QStandardItemModel(self)
        for i in range(len(data)):
            rows = []
            for j in range(len(header)):
                item = QStandardItem(str(data[i][j]))
                rows.append(item)
            self.model.appendRow(rows)
        self.setModel(self.model)
        self.setShowGrid(False)
        self.setEditTriggers(QTableView.NoEditTriggers)
        self.setSelectionBehavior(QTableView.SelectRows)
        self.model.setHorizontalHeaderLabels(header)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().hide()
        self.setStyleSheet("QHeaderView::section:horizontal {margin-right: 80px;}")


class StringView(InfoView):
    def __init__(self, strings):
        super(StringView, self).__init__(['Address', 'String'], strings)

    def mouseDoubleClickEvent(self, event) -> None:
        index = self.currentIndex()
        cell = self.model.item(index.row(), 0)
        address = int(cell.text(), 16)
        self.clicked.emit(address)
        super(StringView, self).mouseDoubleClickEvent(event)
