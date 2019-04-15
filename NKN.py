from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
from MainWindow import Window
import sys
import platform

nkn = QApplication(sys.argv)
if platform.system() == 'Windows':
    font = QFont("Courier", 11)
else:
    font = QFont("Free Mono", 11)
nkn.setFont(font)
mainWindow = Window()
mainWindow.showMaximized()
sys.exit(nkn.exec_())