from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QListView
from PyQt5.QtCore import pyqtSignal


class ListFuncs(QListView):
    gotoFunc = pyqtSignal(int)

    def __init__(self, funcs):
        super(ListFuncs, self).__init__()
        self.listFuncs = QStandardItemModel(self)
        self.funcs = funcs
        for func in funcs:
            item = QStandardItem(func.name)
            self.listFuncs.appendRow(item)
        self.setEditTriggers(QListView.NoEditTriggers)
        self.setModel(self.listFuncs)

    def mouseDoubleClickEvent(self, event):
        indexes = self.selectedIndexes()
        if indexes:
            row = indexes[0].row()
            self.gotoFunc.emit(self.funcs[row].address)