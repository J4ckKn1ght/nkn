from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
from MainWindow import Window
import sys

nkn = QApplication(sys.argv)
font = QFont("Free Mono", 11)
nkn.setFont(font)
mainWindow = Window()
mainWindow.showMaximized()
sys.exit(nkn.exec_())