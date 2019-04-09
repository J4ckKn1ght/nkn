import os
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QMainWindow, QDesktopWidget, QWidget, QApplication, QStyleFactory, QVBoxLayout, QSplitter, \
    QTabWidget, QTextEdit, QAction, QFileDialog, QMessageBox, QSizePolicy

from Analysis import BinaryAnalysis
from AsmCFG import AsmCFGView
from AsmLinear import AsmLinear
from HexView import HexView
from InfoView import StringView, ImportView, ExportView
from ListFunctions import ListFuncs

STYLE = 'windowsvista'
ICON = 'imgs/nkn.png'
APPNAME = 'NKN'
FUNCTIONICON = 'imgs/function.png'


class Window(QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        screenShape = QDesktopWidget().screenGeometry()
        SCREEN_WIDTH = screenShape.width()
        SCREEN_HIGHT = screenShape.height()
        self.setWindowTitle(APPNAME)
        self.setWindowIcon(QIcon(ICON))
        self.setMinimumWidth(SCREEN_WIDTH // 3)
        self.setMinimumHeight(SCREEN_HIGHT // 3)
        self.statusBar = self.statusBar()
        self.mainMenu = self.menuBar()
        QApplication.setStyle(QStyleFactory.create(STYLE))
        self.iraChache = {}
        self.mainTab = None
        self.stringView = None
        self.asmLinear = None
        self.hexView = None
        self.initMenu()
        self.initToolBar()
        self.showMaximized()

    def initMenu(self):
        names = ['File', 'View', 'Tool']
        items = {
            'File': [
                ('Open', 'Ctrl+O', 'Open file', self.openFile),
                ('Save', 'Ctrl+S', 'Save file', self.saveFile),
                ('Save As', 'Ctrl+Shift+S', 'Save file as', self.saveFileAs),
                ('Quit', 'Ctrl+Q', 'Quit the program', self.closeApp),
            ],
            'View': [
                ('Linear Diassembly', 'Ctrl+L', 'Linear Dissembly View', self.openAsmLinearView),
                ('Asm Graph', 'Ctrl+G', 'Graph View', self.openAsmCFGView),
                ('IR Linear', 'Ctrl+G', 'IR Linear View', self.openIRLinearView),
                ('IR Graph', 'Ctrl+G', 'IR Graph View', self.openIRCFGView),
                ('Hex', 'Ctrl+H', 'Hex View', self.openHexView),
                ('String', 'Ctrl+L', 'String View', self.openStringView),
            ],
            'Tool': [
                ('Recovery Algorithm', 'Ctrl+R', "Recovery Algorithm", self.recoverAlgorithm)
            ]
        }
        for name in names:
            menu = self.mainMenu.addMenu('&' + name)
            for item, shortcut, status, func in items[name]:
                menu.addAction(self.createActionWithShortcut(item, shortcut, status, func))

    def initToolBar(self):
        names = ['File Utils', 'View']
        items = {
            'File Utils': [
                ('imgs/open.png', 'Open', 'Open file', self.openFile),
                ('imgs/save.png', 'Save', 'Save file', self.saveFile),
                ('imgs/saveas.png', 'Save as', 'Save file as', self.saveFileAs),
            ],
            'View': [
                ('imgs/hex.png', 'Hex', 'Hex View', self.openHexView),
                ('imgs/graph.png', 'Graph', 'Graph View', self.openAsmCFGView),
                ('imgs/linear.png', 'Linear Disassembly', 'Linear Disassembly View', self.openAsmLinearView),
            ],
        }
        for name in names:
            toolBar = self.addToolBar(name)
            for img, desc, status, func in items[name]:
                toolBar.addAction(self.createActionWithIcon(img, desc, status, func))

    def createActionWithShortcut(self, name, shortcut, status, func):
        """
        Tao action gan voi shortcut key. VD: createActionWithShortcut('Quit', 'Ctrl+Q', closeApp)
        :param name: ten action
        :param shortcut: phim shortcut gan voi action
        :param func: ham se chay khi bi click
        :return: QAction
        """
        action = QAction(name, self)
        action.setShortcut(shortcut)
        action.setStatusTip(status)
        action.triggered.connect(func)
        return action

    def createActionWithIcon(self, icon, description, status, func):
        """
        Tao action bieu tuong icon. VD: createActionWithIcon('ifa.png', 'Quit', closeApp)
        :param icon: ten file icon
        :param description: text hien thi khi de chuot vao
        :param func: ham se chay neu icon duoc click
        :return: QAction
        """
        action = QAction(QIcon(icon), description, self)
        action.setStatusTip(status)
        action.triggered.connect(func)
        return action

    # ==============================================================

    def closeApp(self):
        """
        Quit App
        :return:
        """
        sys.exit()

    def openFile(self):
        """"
        Open File, Load Function to ListFunction and Info
        :return:
        """
        try:
            f = open('cache', 'r')
            dir = f.read()
        except FileNotFoundError:
            dir = ''
        file, _ = QFileDialog.getOpenFileName(self, "Open File", dir,
                                              "All File (*);;Python File (*.elf);;PE File (*.exe",
                                              options=QFileDialog.DontUseNativeDialog)
        if file:
            dir = os.path.dirname(file)
            open('cache', 'w').write(dir)
            self.centralWidget = QWidget(self)
            self.setCentralWidget(self.centralWidget)
            QVBoxLayout(self.centralWidget)
            allLayout = self.centralWidget.layout()
            BinaryAnalysis.init(file)

            self.outputLog = QTextEdit()

            self.binInfo = QTextEdit()
            self.binInfo.setReadOnly(True)
            self.binInfo.setText(BinaryAnalysis.binaryInfo.info())

            self.listFunctions = ListFuncs(BinaryAnalysis.funcs)
            self.listFunctions.gotoFunc.connect(self.gotoAddress)

            leftTopBottomSplitter = QSplitter(Qt.Vertical)
            leftTopBottomSplitter.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
            leftTopBottomSplitter.addWidget(self.binInfo)
            leftTopBottomSplitter.addWidget(self.listFunctions)
            leftTopBottomSplitter.setStretchFactor(0, 1)
            leftTopBottomSplitter.setStretchFactor(1, 9)

            leftRightSplitter = QSplitter()

            self.mainTab = QTabWidget()
            self.mainTab.setTabsClosable(True)
            self.mainTab.tabCloseRequested.connect(self.closeTab)
            self.mainTab.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

            self.asmLinear = AsmLinear()
            self.mainTab.addTab(self.asmLinear, "Disassembly")
            self.asmLinear.focusAddress(BinaryAnalysis.binaryInfo.entryPoint)
            self.bindAsmLinear()

            self.hexView = HexView(BinaryAnalysis.rawData)
            self.mainTab.addTab(self.hexView, "Hex View")

            self.stringView = StringView(BinaryAnalysis.binaryInfo.strings)
            self.stringView.clicked.connect(self.gotoAddress)
            self.mainTab.addTab(self.stringView, "String List")

            self.importView = ImportView(BinaryAnalysis.binaryInfo.imports)
            self.importView.clicked.connect(self.gotoLibFunc)
            self.mainTab.addTab(self.importView, "Imports")

            self.exportView = ExportView(BinaryAnalysis.binaryInfo.exports)
            self.exportView.clicked.connect(self.gotoLibFunc)
            self.mainTab.addTab(self.exportView, "Exports")

            leftRightSplitter.addWidget(leftTopBottomSplitter)
            leftRightSplitter.addWidget(self.mainTab)
            leftRightSplitter.setStretchFactor(0, 2)
            leftRightSplitter.setStretchFactor(1, 8)
            topBottomSplitter = QSplitter(Qt.Vertical)
            topBottomSplitter.addWidget(leftRightSplitter)
            topBottomSplitter.addWidget(self.outputLog)
            topBottomSplitter.setStretchFactor(0, 8)
            topBottomSplitter.setStretchFactor(1, 2)
            allLayout.addWidget(topBottomSplitter)
            self.asmLinear.setFocus()

    def gotoLibFunc(self, name):
        for func in BinaryAnalysis.funcs:
            if func.name.endswith(name):
                self.gotoAsmLinear(func.address)
                break

    def bindAsmLinear(self):
        self.asmLinear.addCFG.connect(self.addAsmCFGView)
        self.asmLinear.gotoHexView.connect(self.gotoHexView)
        self.asmLinear.log.connect(self.outputLog.append)
        self.asmLinear.changedData.connect(self.changeData)
        self.asmLinear.addIRLinear.connect(self.addIRLinearView)

    def changeData(self, offset, data):
        index = self.mainTab.indexOf(self.hexView)
        if index == -1:
            self.hexView = HexView(BinaryAnalysis.rawData)
            self.addNewTab(self.hexView, "Hex View")
        self.hexView.changeData(offset, data)

    def addIRLinearView(self, func):
        from IRAnalysis import IRAnalysis
        from IRView import IRWidget
        if func in self.iraChache:
            if not func.changed:
                ira = self.iraChache[func]
            else:
                func.changed = False
                ira = IRAnalysis(func.address, func.cfg)
                self.iraChache[func] = ira
        else:
            ira = IRAnalysis(func.address, func.cfg)
            self.iraChache[func] = ira
        irLinearView = IRWidget(ira, 0)
        self.addNewTab(irLinearView, "IR Linear %s" % func.name)

    def addIRCFGView(self, func):
        from IRAnalysis import IRAnalysis
        from IRView import IRWidget
        if func in self.iraChache:
            if not func.changed:
                ira = self.iraChache[func]
            else:
                func.changed = False
                func.ircfg = None
                func.defUse = None
                func.ira = None
                ira = IRAnalysis(func.address, func.cfg)
                self.iraChache[func] = ira
        else:
            ira = IRAnalysis(func.address, func.cfg)
            self.iraChache[func] = ira
        irLinearView = IRWidget(ira, 2)
        self.addNewTab(irLinearView, "IR CFG %s" % func.name)

    def addAsmCFGView(self, line):
        for i in range(self.mainTab.count()):
            widget = self.mainTab.widget(i)
            if isinstance(widget, AsmCFGView):
                if line.func == widget.func:
                    if not line.func:
                        self.mainTab.setCurrentIndex(i)
                        return
                    else:
                        self.mainTab.removeTab(i)
                        line.func.changed = False
                        line.func.ircfg = None
                        line.func.ira = None
                        line.func.defUse = None
                        if line.func in self.iraChache:
                            del self.iraChache[line.func]
                        break
        asmCFGView = AsmCFGView(line.func)
        asmCFGView.gotoAsmLinear.connect(self.gotoAsmLinear)
        asmCFGView.changeCFG.connect(self.replaceAsmCFG)
        asmCFGView.gotoHexView.connect(self.gotoHexView)
        asmCFGView.gotoIRCFG.connect(self.addIRCFGView)
        asmCFGView.log.connect(self.outputLog.append)
        indexes = self.asmLinear.selectedIndexes()
        for index in indexes:
            item = self.asmLinear.getItemFormIndex(index)
            if hasattr(item, 'instr'):
                asmCFGView.selectAddress(item.instr.offset, False, False)
        asmCFGView.selectAddress(line.address, True, False)
        self.addNewTab(asmCFGView, "AsmCFG")

    def gotoAsmLinear(self, address):
        index = self.mainTab.indexOf(self.asmLinear)
        if index == -1:
            self.asmLinear = AsmLinear()
            self.bindAsmLinear()
            self.addNewTab(self.asmLinear, "Disassmbly")
        self.focusWidgetInTab(self.asmLinear)
        self.asmLinear.focusAddress(address)
        self.asmLinear.setFocus()

    def gotoHexView(self, offset, lenData):
        index = self.mainTab.indexOf(self.hexView)
        if index == -1:
            self.hexView = HexView(BinaryAnalysis.rawData)
            self.addNewTab(self.hexView, "Hex View")
        self.hexView.toOffset(offset, lenData)
        self.focusWidgetInTab(self.hexView)

    def addNewTab(self, widget, name):
        index = self.mainTab.currentIndex()
        self.mainTab.insertTab(index + 1, widget, name)
        self.mainTab.setCurrentIndex(index + 1)
        widget.setFocus()

    def gotoAddress(self, address):
        from IRView import IRWidget
        widget = self.getCurrentWidget()
        if isinstance(widget, AsmCFGView):
            self.replaceAsmCFG(address)
        elif isinstance(widget, IRWidget):
            for func in BinaryAnalysis.funcs:
                if func.address == address:
                    if widget.viewType == 0:
                        self.addIRLinearView(func)
                    else:
                        self.addIRCFGView(func)
                    self.mainTab.removeTab(self.mainTab.currentIndex() - 1)
                    break
        elif address in self.asmLinear.addressMap:
            linearIndex = self.mainTab.indexOf(self.asmLinear)
            self.mainTab.setCurrentIndex(linearIndex)
            self.asmLinear.focusAddress(address)
            self.asmLinear.setFocus()
        else:
            hexIndex = self.mainTab.indexOf(self.hexView)
            self.mainTab.setCurrentIndex(hexIndex)
            offset = BinaryAnalysis.binaryInfo.getOffsetAtAddress(address)
            self.hexView.toOffset(offset)
            self.hexView.setFocus()

    def replaceAsmCFG(self, address):
        newFunc = None
        index = self.mainTab.currentIndex()
        for func in BinaryAnalysis.funcs:
            if address == func.address:
                newFunc = func
                break
        if newFunc is not None:
            asmCFGView = AsmCFGView(newFunc)
            self.addNewTab(asmCFGView, "AsmCFG")
            asmCFGView.changeCFG.connect(self.replaceAsmCFG)
            self.mainTab.removeTab(index)
            asmCFGView.setFocus()

    def getCurrentWidget(self):
        return self.mainTab.currentWidget()

    def closeTab(self, index):
        self.mainTab.removeTab(index)
        self.mainTab.setCurrentIndex(index - 1)

    def focusWidgetInTab(self, widget):
        index = self.mainTab.indexOf(widget)
        self.mainTab.setCurrentIndex(index)
        widget.setFocus()

    def saveFile(self):
        if BinaryAnalysis.path is not None:
            button_pressed = QMessageBox.question(self, 'Save File', "Do you want to save?",
                                                  QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if button_pressed == QMessageBox.Yes:
                f = open(BinaryAnalysis.path, 'wb')
                f.write(bytearray(BinaryAnalysis.rawData))
                f.close()

    def saveFileAs(self):
        if BinaryAnalysis.path is not None:
            name, _ = QFileDialog.getSaveFileName(self, "Save File as")
            if name:
                f = open(name, 'wb')
                f.write(bytearray(BinaryAnalysis.rawData))
                f.close()

    def openAsmLinearView(self):
        if BinaryAnalysis.path is not None:
            self.gotoAsmLinear(BinaryAnalysis.binaryInfo.entryPoint)

    def openAsmCFGView(self):
        if BinaryAnalysis.path is not None:
            if self.mainTab.currentWidget() == self.asmLinear:
                indexes = self.asmLinear.selectedIndexes()
                if len(indexes) > 0:
                    line = self.asmLinear.getItemFormIndex(indexes[0])
                    self.addAsmCFGView(line)

    def openIRLinearView(self):
        if BinaryAnalysis.path is not None:
            if self.mainTab.currentWidget() == self.asmLinear:
                indexes = self.asmLinear.selectedIndexes()
                if len(indexes) > 0:
                    line = self.asmLinear.getItemFormIndex(indexes[0])
                    self.addIRLinearView(line.func)
            elif isinstance(self.mainTab.currentWidget(), AsmCFGView):
                self.addIRLinearView(self.mainTab.currentWidget().func)

    def openIRCFGView(self):
        if BinaryAnalysis.path is not None:
            if self.mainTab.currentWidget() == self.asmLinear:
                indexes = self.asmLinear.selectedIndexes()
                if len(indexes) > 0:
                    line = self.asmLinear.getItemFormIndex(indexes[0])
                    self.addIRCFGView(line.func)
            elif isinstance(self.mainTab.currentWidget(), AsmCFGView):
                self.addIRCFGView(self.mainTab.currentWidget().func)

    def openHexView(self):
        if self.hexView is not None:
            self.focusWidgetInTab(self.hexView)
        else:
            self.hexView = HexView(BinaryAnalysis.rawData)
            self.addNewTab(self.hexView, "Hex View")

    def openStringView(self):
        if self.stringView is not None:
            self.focusWidgetInTab(self.stringView)
        else:
            self.stringView = StringView(BinaryAnalysis.binaryInfo.strings)
            self.addNewTab(self.stringView, "Strings")

    def recoverAlgorithm(self):
        from IRAnalysis import IRAnalysis
        from IRView import IRCFGRecover, IRWidget
        widget = self.mainTab.currentWidget()
        func = None
        if isinstance(widget, AsmLinear):
            indexes = widget.selectedIndexes()
            if len(indexes) > 0:
                line = widget.getItemFormIndex(indexes[0])
                func = line.func
        elif isinstance(widget, AsmCFGView):
            func = widget.func
        elif isinstance(widget, IRWidget):
            address = widget.ira.address
            for f in BinaryAnalysis.funcs:
                if f.address == address:
                    func = f
                    break
        if func is not None:
            if func in self.iraChache:
                ira = self.iraChache[func]
            else:
                ira = IRAnalysis(func.address, func.cfg)
            newLocDB, newIRCFG = ira.recoverAlgorithm()
            recoverIRCFG = IRCFGRecover(newIRCFG)
            for block in recoverIRCFG.mapItems:
                line = block.model.item(0, 0)
                line.setText(newLocDB.pretty_str(line.lockey))
            self.addNewTab(recoverIRCFG, "Recovered IRCFG")