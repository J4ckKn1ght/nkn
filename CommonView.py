from PyQt5.QtCore import QItemSelectionModel, pyqtSignal
from PyQt5.QtGui import QStandardItem, QStandardItemModel, QTextDocument, QAbstractTextDocumentLayout, QPalette
from PyQt5.QtWidgets import QListView, QStyledItemDelegate, QStyleOptionViewItem, \
    QApplication, QStyle, \
    QAbstractItemView
from miasm.expression.expression import ExprInt, ExprId, ExprMem, ExprLoc

from Analysis import BinaryAnalysis
from Utils import *


class HTMLDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super(HTMLDelegate, self).__init__(parent)
        self.doc = QTextDocument(self)

    def paint(self, painter, option, index):
        painter.save()

        options = QStyleOptionViewItem(option)
        self.initStyleOption(options, index)

        self.doc.setHtml(options.text)
        options.text = ""

        style = QApplication.style() if options.widget is None \
            else options.widget.style()
        style.drawControl(QStyle.CE_ItemViewItem, options, painter)

        ctx = QAbstractTextDocumentLayout.PaintContext()

        if option.state & QStyle.State_Selected:
            ctx.palette.setColor(QPalette.Text, option.palette.color(
                QPalette.Active, QPalette.HighlightedText))

        textRect = style.subElementRect(QStyle.SE_ItemViewItemText, options)
        painter.translate(textRect.topLeft())
        self.doc.documentLayout().draw(painter, ctx)

        painter.restore()


class Component:
    def __init__(self, text, color, width):
        self.text = text
        self.color = color
        self.width = width
        self.normal = '<span style="color:{0}">{1}</span>{2}'.format(self.color, self.text,
                                                                     '&nbsp;' * (self.width - len(self.text)))
        self.select = '<span style="color:{0}">{1}</span>{2}'.format(selectedColor, self.text,
                                                                     '&nbsp;' * (self.width - len(self.text)))
        self.highlight = '<span style="color:{0}; background-color:{1};">{2}</span>{3}'.format(selectedColor,
                                                                                               highlightColor,
                                                                                               self.text,
                                                                                               '&nbsp;' * (
                                                                                                       self.width - len(
                                                                                                   self.text)))

    def highlightText(self, texts, isEqual):
        tmp = self.text
        for text in texts:
            if isEqual:
                if tmp == text:
                    tmp = tmp.replace(text, '<span style="background-color:{0}">{1}</span>').format(highlightColor,
                                                                                                    text)
            else:
                tmp = tmp.replace(text, '<span style="background-color:{0}">{1}</span>').format(highlightColor, text)
        return '<span style="color:{0}">{1}</span>{2}'.format(self.color, tmp,
                                                              '&nbsp;' * (self.width - len(self.text)))


class CommonItem(QStandardItem):
    def __init__(self):
        super(CommonItem, self).__init__()
        self.components = []
        self.componentRanges = []
        self.startArgIndex = 0
        self.normal = ''
        self.ref = None
        self.xrefs = []

    def highlight(self, texts, start=0):
        tmp = ''
        change = False
        isEqual = start < self.startArgIndex
        for i, component in enumerate(self.components):
            if i >= start:
                highlightText = component.highlightText(texts, isEqual)
                tmp += highlightText
                change |= (highlightText != component.normal)
            else:
                tmp += component.normal
        self.setText(tmp)
        return change

    def getIndexByPos(self, pos):
        for i in range(len(self.componentRanges)):
            start, end = self.componentRanges[i]
            if (start <= pos) and (pos <= end):
                return i
        return -1

    def selectTextAt(self, index):
        tmp = ''
        isEqual = index >= self.startArgIndex
        for i in range(len(self.components)):
            if i == index:
                tmp += self.components[i].select
            else:
                tmp += self.components[i].highlightText([self.components[index].text], isEqual)
        self.setText(tmp)

    def calculateRange(self):
        start = 0
        for i, component in enumerate(self.components):
            if i > 0:
                start += self.components[i - 1].width
            self.normal += component.normal
            end = start + len(component.text)
            self.componentRanges.append((start, end))
        self.setText(self.normal)


class LocLine(CommonItem):
    def __init__(self, lockey, func, pretty=True):
        self.address = BinaryAnalysis.locDB.get_location_offset(lockey)
        if pretty:
            name = BinaryAnalysis.locDB.pretty_str(lockey)
        else:
            name = str(lockey)
        super(LocLine, self).__init__()
        self.lockey = lockey
        self.func = func
        self.components.append(Component(name, locColor, len(name)))
        self.componentRanges.append((0, len(name)))
        self.normal = self.components[0].normal
        self.setText(self.normal)


class AsmLineWithOpcode(CommonItem):
    def __init__(self, line, block=None, func=None):
        super(AsmLineWithOpcode, self).__init__()
        self.instr = line
        self.block = block
        self.func = func
        self.address = line.offset
        self.startArgIndex = 3
        opcode = ' '.join('%02x' % c for c in line.b)
        self.components += [Component('0x%x' % line.offset, addressColor, 10),
                            Component(opcode, opcodeColor, 35),
                            Component(line.name, nameColor, 7)]
        self.args = [line.offset, opcode, line.name]
        for i, arg in enumerate(line.args):
            if i >= 1:
                self.components.append(Component(',', opColor, 2))
                self.args.append(',')
            self.args.append(arg)
            argStr = line.arg2str(arg, loc_db=BinaryAnalysis.locDB)
            width = len(argStr)
            if i == len(line.args) - 1:
                width += 15
            if isinstance(arg, ExprId):
                self.components.append(Component(argStr, idColor, width))
            elif isinstance(arg, ExprInt):
                self.components.append(Component(argStr, intColor, width))
            elif isinstance(arg, ExprMem):
                self.components.append(Component(argStr, memColor, width))
            elif isinstance(arg, ExprLoc):
                self.components.append(Component(argStr, locColor, width))
        self.comment = self.getComment()
        self.components.append(Component(self.comment, commentColor, len(self.comment)))
        self.calculateRange()
        if self.address in func.callRefs:
            self.ref = func.callRefs[self.address]

    def clone(self):
        return AsmLineWithOpcode(self.instr, self.func.cfg.loc_db, self.block, self.func)

    def getComment(self):
        for arg in self.instr.args:
            if isinstance(arg, ExprInt):
                num = int(arg.arg)
                if num in BinaryAnalysis.strings:
                    if len(BinaryAnalysis.strings[num]) > 15:
                        text = BinaryAnalysis.strings[num][:15].replace('\n', '') + '...'
                    else:
                        text = BinaryAnalysis.strings[num].replace('\n', '')
                    return text
                else:
                    lockey = BinaryAnalysis.locDB.get_offset_location(arg.arg)
                    if lockey:
                        return BinaryAnalysis.locDB.pretty_str(lockey)
                    else:
                        tmp = struct.pack('Q', int(arg.arg))
                        if all(((32 <= c) and (c <= 127)) or ((c == 0) and (tmp[0] != 0)) for c in tmp):
                            return tmp.decode()
        return ''


class AsmLineNoOpcode(CommonItem):
    def __init__(self, line, block=None, func=None):
        super(AsmLineNoOpcode, self).__init__()
        self.instr = line
        self.block = block
        self.func = func
        self.address = line.offset
        self.startArgIndex = 2
        self.components += [Component('0x%x' % line.offset, addressColor, 15), Component(line.name, nameColor, 7)]
        self.args = [line.offset, line.name]
        for i, arg in enumerate(line.args):
            if i >= 1:
                self.components.append(Component(',', opColor, 2))
                self.args.append(',')
            self.args.append(arg)
            argStr = line.arg2str(arg, loc_db=BinaryAnalysis.locDB)
            width = len(argStr)
            if i == len(line.args) - 1:
                width += 10
            if isinstance(arg, ExprId):
                self.components.append(Component(argStr, idColor, width))
            elif isinstance(arg, ExprInt):
                self.components.append(Component(argStr, intColor, width))
            elif isinstance(arg, ExprMem):
                self.components.append(Component(argStr, memColor, width))
            elif isinstance(arg, ExprLoc):
                self.components.append(Component(argStr, locColor, width))
        self.comment = self.getComment()
        self.components.append(Component(self.comment, commentColor, len(self.comment)))
        self.calculateRange()
        if self.address in func.callRefs:
            self.ref = func.callRefs[self.address]

    def clone(self):
        return AsmLineNoOpcode(self.instr, self.block, self.func)

    def getComment(self):
        for arg in self.instr.args:
            if isinstance(arg, ExprInt):
                num = int(arg.arg)
                if num in BinaryAnalysis.strings:
                    if len(BinaryAnalysis.strings[num]) > 15:
                        text = BinaryAnalysis.strings[num][:15].replace('\n', '') + '...'
                    else:
                        text = BinaryAnalysis.strings[num].replace('\n', '')
                    return text

                else:
                    lockey = BinaryAnalysis.locDB.get_offset_location(arg.arg)
                    if lockey:
                        return BinaryAnalysis.locDB.pretty_str(lockey)
                    else:
                        tmp = struct.pack('Q', int(arg.arg))
                        if all(((32 <= c) and (c <= 127)) or ((c == 0) and (tmp[0] != 0)) for c in tmp):
                            return tmp.decode()
        return ''


class CommonListView(QListView):
    dblAddress = pyqtSignal(int)

    def __init__(self):
        super(CommonListView, self).__init__()
        self.model = QStandardItemModel(self)
        self.setItemDelegate(HTMLDelegate(self))
        self.setModel(self.model)
        self.addressMap = {}
        self.resetList = []
        self.lockRelease = True
        self.clickedX = 0
        self.lastClickIndex = -1
        self.setEditTriggers(QListView.NoEditTriggers)
        self.setStyleSheet("QListView::item{margin-bottom: 5px; padding:0px}")

    def getItem(self, row):
        return self.model.item(row, 0)

    def getItemFormIndex(self, index):
        return self.model.item(index.row(), 0)

    def setSize(self):
        width_view = 0
        for i in range(self.model.rowCount()):
            item = self.getItem(i)
            _, end = item.componentRanges[-1]
            if width_view < end * self.fontMetrics().averageCharWidth():
                width_view = end * self.fontMetrics().averageCharWidth()
        self.setFixedWidth(width_view + self.fontMetrics().averageCharWidth() * 3)
        self.setFixedHeight(self.sizeHintForRow(1) * self.model.rowCount() + 2 * self.frameWidth() + 10)

    def highlighRelation(self, text, start, func=None):
        texts = [text]
        for regs in relate_registers:
            if text in regs:
                texts = regs
                break
        if (func is not None) and (func.address in self.addressMap):
            startItem = self.addressMap[func.address]
            index = self.model.indexFromItem(startItem)
            row = index.row()
            item = self.getItem(row)
            while hasattr(item, 'func') and item.func == func:
                if isinstance(item, LocLine):
                    change = item.highlight(texts, 0)
                else:
                    change = item.highlight(texts, start)
                if change:
                    self.resetList.append(item)
                row += 1
                item = self.getItem(row)
                if hasattr(item, 'address'):
                    if item.address > func.maxBound:
                        break
        else:
            for i in range(self.model.rowCount()):
                item = self.getItem(i)
                if item.isSelectable():
                    if isinstance(item, LocLine):
                        change = item.highlight(texts, 0)
                    else:
                        if hasattr(item, 'highlight'):
                            change = item.highlight(texts, start)
                    if change:
                        self.resetList.append(item)

    def mousePressEvent(self, event) -> None:
        self.lockRelease = False
        self.clickedX = event.pos().x()
        for item in self.resetList:
            if hasattr(item, 'normal'):
                item.setText(item.normal)
        self.resetList.clear()
        super(CommonListView, self).mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if not self.lockRelease:
            indexes = self.selectedIndexes()
            if len(indexes) == 1:
                index = self.selectedIndexes()[0]
                item = self.getItemFormIndex(index)
                self.getClickedIndex(item)
        super(CommonListView, self).mouseReleaseEvent(event)

    def getClickedIndex(self, item, highlight=True):
        import platform
        if platform.system() == 'Windows':
            widthChar = self.fontMetrics().averageCharWidth() + 4
            self.clickedX -= 5
        else:
            widthChar = self.fontMetrics().averageCharWidth()
        pos = self.clickedX // widthChar
        if hasattr(item, 'getIndexByPos'):
            index = item.getIndexByPos(pos)
            if index != -1:
                self.lastClickIndex = index
                if item.components[index].text != ',':
                    start = 0
                    if index > 1:
                        start = 2
                    if highlight:
                        func = None
                        if hasattr(item, 'func'):
                            func = item.func
                        self.highlighRelation(item.components[index].text, start, func)
                    item.selectTextAt(index)
                    self.resetList.append(item)

    def mouseDoubleClickEvent(self, event) -> None:
        self.lockRelease = True
        index = self.selectedIndexes()[0]
        item = self.getItemFormIndex(index)
        self.dblAddress.emit(item.address)

    def focusAddress(self, address, focus=True):
        if address in self.addressMap:
            if focus:
                self.clearAllEffect()
            item = self.addressMap[address]
            index = self.model.indexFromItem(item)
            self.selectionModel().select(index, QItemSelectionModel.Select)
            if focus:
                self.scrollTo(index, QAbstractItemView.PositionAtCenter)
            self.setFocus()

    def focusItem(self, index):
        self.clearAllEffect()
        self.selectionModel().select(index, QItemSelectionModel.Select)
        self.scrollTo(index, QAbstractItemView.PositionAtCenter)
        self.setFocus()

    def clearAllEffect(self):
        self.clearFocus()
        self.clearSelection()
        for item in self.resetList:
            if hasattr(item, 'normal'):
                try:
                    item.setText(item.normal)
                except:
                    pass
        self.resetList.clear()


class DataLine(CommonItem):
    def __init__(self, address, data, typeData):
        super(DataLine, self).__init__()
        self.data = data
        self.address = address
        self.typeData = typeData
        self.components += [Component('0x%x' % address, addressColor, 10), Component(typeData, typeColor, 10)]
        if typeData == 'string':
            self.components.append(Component(data, dataColor, len(data)))
        else:
            data_str = '0x%x' % formatData(data)
            self.components.append(Component(data_str, dataColor, len(data_str)))
        self.calculateRange()

    def clone(self):
        return DataLine(self.address, self.data, self.typeData)


class ListInstrsView(CommonListView):
    def __init__(self, lines, loc_db):
        super(ListInstrsView, self).__init__()
        for line in lines:
            item = AsmLineNoOpcode(line, loc_db)
            self.model.appendRow(item)
        self.setSize()


class IRLine(CommonItem):
    opList = ['=', '==', '*', '^', '&', '+', '-', ',', '?', '|']

    def __init__(self, dst, src, block, index, pretty=True):
        super(IRLine, self).__init__()
        self.dst = dst
        self.src = src
        self.block = block
        self.index = index
        self.pretty = pretty
        self.initModel()

    def initModel(self):
        from IRAnalysis import parseExpr
        parseDst = parseExpr(self.dst, [])
        parseSrc = parseExpr(self.src, [])
        self.args = parseDst + ['='] + parseSrc
        for i in range(len(self.args)):
            arg = self.args[i]
            if isinstance(arg, str):
                if arg in self.opList:
                    argStr = ' ' + arg + ' '
                else:
                    argStr = arg
                color = opColor
            elif isinstance(arg, ExprLoc):
                if self.pretty:
                    offset = BinaryAnalysis.locDB.get_location_offset(arg.loc_key)
                    argStr = BinaryAnalysis.locDB.pretty_str(arg.loc_key)
                    for lockey in BinaryAnalysis.locDB.loc_keys:
                        if BinaryAnalysis.locDB.get_location_offset(lockey) == offset:
                            name = list(BinaryAnalysis.locDB.get_location_names(lockey))
                            if len(name) > 0:
                                argStr = name[0].decode()
                                break
                else:
                    argStr = str(arg.loc_key)
                color = locColor
            elif isinstance(arg, ExprInt):
                argStr = str(arg)
                color = intColor
            elif isinstance(arg, ExprMem):
                argStr = str(arg)
                color = memColor
            elif isinstance(arg, ExprId):
                argStr = str(arg)
                color = idColor
            else:
                argStr = str(arg)
                color = idColor
            self.components.append(Component(argStr, color, len(argStr)))
        self.calculateRange()
