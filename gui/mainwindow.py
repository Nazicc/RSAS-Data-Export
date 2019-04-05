import os
import re
from PyQt5 import QtGui, QtWidgets
from gui.ui_mainwindow import *
from .threads import WorkThread

class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.input_Button.clicked.connect(self.input_Button_click)
        self.output_Button.clicked.connect(self.output_Button_click)
        self.start_Button.clicked.connect(self.start_Button_click)

    def input_Button_click(self):
        self.input_Button_cent = QtWidgets.QFileDialog.getExistingDirectory(Ｎone)
        self.input_lineEdit.setText(self.input_Button_cent)

    def output_Button_click(self):
        self.output_Button_cent = QtWidgets.QFileDialog.getExistingDirectory(Ｎone)
        self.output_lineEdit.setText(self.output_Button_cent)

    def start_Button_click(self):
        if self.input_lineEdit.text():
            self.input_Button_cent = self.input_lineEdit.text()
        else:
            try:
                self.input_Button_cent = self.input_Button_cent
            except Exception as e:
                QtWidgets.QMessageBox.information(None, "提示！", "要先设置文件夹！", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No ,  QtWidgets.QMessageBox.Yes )
                return e

        if self.output_lineEdit.text():
            self.output_Button_cent = self.output_lineEdit.text()
        else:
            try:
                self.output_Button_cent = self.output_Button_cent
            except Exception as e:
                QtWidgets.QMessageBox.information(None, "提示！", "要先设置文件夹！", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No ,  QtWidgets.QMessageBox.Yes )
                return e

        self.dirList = os.listdir(self.input_Button_cent)
        self.file_name_box = re.findall('.*?.zip',str(self.dirList))
        try:
            self.file_name_box[0]
        except Exception as e:
            QtWidgets.QMessageBox.information(None, "提示", "找不到原始报告，请查看使用说明！", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No ,  QtWidgets.QMessageBox.Yes )
            return e

        self.hight_status = self.hight_checkBox.isChecked()
        self.middle_status = self.middle_checkBox.isChecked()
        self.low_status = self.low_checkBox.isChecked()
        self.port_status = self.port_checkBox.isChecked()
        self.web_status = self.web_checkBox.isChecked()

        self.start_Button.setChecked(True)
        self.start_Button.setDisabled(True)
        self.work = WorkThread(self.input_Button_cent,self.output_Button_cent,self.hight_status,self.middle_status,self.low_status,self.port_status,self.web_status)
        self.work.log_return.connect(self.logger)
        self.work.start()

    def logger(self, msg):
        str_log='{}\n'.format(msg)
        self.log_textEdit.moveCursor(QtGui.QTextCursor.End)
        self.log_textEdit.insertPlainText(str_log)
        QtWidgets.QApplication.processEvents()
        if self.work.isRunning() == False:
            self.start_Button.setChecked(False)
            self.start_Button.setDisabled(False)