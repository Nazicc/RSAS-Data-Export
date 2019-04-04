import images_ico
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        setini = """:::::::::导出的人员信息:::::::::
检查单位=宝宝
检查人员=宝宝

:::::::::自定义导出数据 - 可删除、添加、调换位置:::::::::
1:6:检查单位|2:28:系统名称|3:8:主机名|4:16:IP地址|5:8:端口|6:8:协议|7:8:服务|8:45:漏洞名称|9:8:风险分类|10:8:风险等级|11:45:整改建议|12:45:漏洞描述|13:13:漏洞CVE编号|14:11:扫描起始时间|15:11:扫描结束时间|16:11:漏洞发现月份

:::::::::自定义标题颜色:::::::::
A-P:ff0000

:::::::::自定义漏洞等级 - 可删除，添加:::::::::
中|检测到目标NTP服务支持monlist命令
中|目标主机rpcinfo -p信息泄露
中|可通过finger服务猜测用户名列表
中|可通过finger服务获取用户信息
中|可通过rusers服务获取用户信息
高|目标主机showmount -e信息泄露"""
        try:
            with open('set.ini') as info_ini:
                ini = info_ini.readlines()[1:3]
                self.name_ini = ini[1].split('=')[1].strip()
                self.company_ini = ini[0].split('=')[1].strip()
        except Exception as e:
            with open('set.ini','a',encoding='gb18030') as set_ini:
                set_ini.write(setini)
                QtWidgets.QMessageBox.information(MainWindow, "提示！", "请修改同目录下的配置文件，重新打开软件！", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No ,  QtWidgets.QMessageBox.Yes )
                exit()

        title = 'RSAS漏洞数据导出工具1.8'
        font = QtGui.QFont()
        font.setFamily("宋体")
        font.setPointSize(10)
        MainWindow.setFont(font)
        #定义程序的标题
        MainWindow.setWindowTitle(title)
        #设定程序的最大分辨率，禁止最大化、拖动窗口
        MainWindow.setFixedSize(560, 310)
        #设置图标
        MainWindow.setWindowIcon(QtGui.QIcon(':/favicon.ico'))
        #获取显示器的分辨率
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        #获取程序的宽和高
        size = MainWindow.geometry()
        #实现在屏幕中间显示程序
        MainWindow.move((screen.width() - size.width())/2, (screen.height() - size.height())/2)

        #这是底部的状态栏
        MainWindow.status = MainWindow.statusBar()
        MainWindow.status.showMessage("检查单位：%s  检查人员：%s" % (self.company_ini,self.name_ini))

        #这是一个框架，用来固定按钮用的
        self.formLayoutWidget = QtWidgets.QWidget(MainWindow)
        self.formLayoutWidget.setGeometry(QtCore.QRect(10, 10, 451, 54))
        self.formLayoutWidget.setObjectName("formLayoutWidget")
        self.formLayout = QtWidgets.QFormLayout(self.formLayoutWidget)
        self.formLayout.setContentsMargins(0, 0, 0, 0)
        self.formLayout.setObjectName("formLayout")
        #文字：原始报告路径
        self.input_label = QtWidgets.QLabel(self.formLayoutWidget)
        self.input_label.setObjectName("input_label")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.input_label)
        #文字：输出报告路径
        self.output_label = QtWidgets.QLabel(self.formLayoutWidget)
        self.output_label.setObjectName("output_label")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.output_label)

        #原始报告路径后边的文本框
        self.input_lineEdit = QtWidgets.QLineEdit(self.formLayoutWidget)
        self.input_lineEdit.setObjectName("input_lineEdit")
        self.formLayout.addWidget(self.input_lineEdit)
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.input_lineEdit)

        #输出报告路径后边的文本框
        self.output_lineEdit = QtWidgets.QLineEdit(self.formLayoutWidget)
        self.output_lineEdit.setObjectName("output_lineEdit")
        self.formLayout.addWidget(self.output_lineEdit)
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.output_lineEdit)

        #框架的结束部分
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.formLayout.setItem(1, QtWidgets.QFormLayout.LabelRole, spacerItem)
        #这玩意就是打开路径按钮的框架
        self.start_verticalLayoutWidget = QtWidgets.QWidget(MainWindow)
        self.start_verticalLayoutWidget.setGeometry(QtCore.QRect(463, 2, 91, 71))
        self.start_verticalLayoutWidget.setObjectName("start_verticalLayoutWidget")
        self.start_verticalLayout = QtWidgets.QVBoxLayout(self.start_verticalLayoutWidget)
        self.start_verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.start_verticalLayout.setObjectName("start_verticalLayout")
        #这是原始报告路径后边的文本框后边的打开路径按钮
        self.input_Button = QtWidgets.QPushButton(self.start_verticalLayoutWidget)
        self.input_Button.setObjectName("input_Button")
        self.start_verticalLayout.addWidget(self.input_Button)

        #这是输出报告路径后边的文本框后边的打开路径按钮
        self.output_Button = QtWidgets.QPushButton(self.start_verticalLayoutWidget)
        self.output_Button.setObjectName("output_Button")
        self.start_verticalLayout.addWidget(self.output_Button)

        #这又是一个框架，固定用的
        self.horizontalLayoutWidget = QtWidgets.QWidget(MainWindow)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(10, 75, 451, 21))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        #文字：选择导出数据
        self.data_label = QtWidgets.QLabel(self.horizontalLayoutWidget)
        self.data_label.setObjectName("data_label")
        self.horizontalLayout.addWidget(self.data_label)
        #复选框：高危
        self.hight_checkBox = QtWidgets.QCheckBox(self.horizontalLayoutWidget)
        self.hight_checkBox.setObjectName("hight_checkBox")
        self.horizontalLayout.addWidget(self.hight_checkBox)
        #复选框：中危
        self.middle_checkBox = QtWidgets.QCheckBox(self.horizontalLayoutWidget)
        self.middle_checkBox.setObjectName("middle_checkBox")
        self.horizontalLayout.addWidget(self.middle_checkBox)
        #复选框：低危
        self.low_checkBox = QtWidgets.QCheckBox(self.horizontalLayoutWidget)
        self.low_checkBox.setObjectName("low_checkBox")
        self.horizontalLayout.addWidget(self.low_checkBox)
        #复选框：端口
        self.port_checkBox = QtWidgets.QCheckBox(self.horizontalLayoutWidget)
        self.port_checkBox.setObjectName("port_checkBox")
        self.horizontalLayout.addWidget(self.port_checkBox)
        #复选框：网站
        self.web_checkBox = QtWidgets.QCheckBox(self.horizontalLayoutWidget)
        self.web_checkBox.setObjectName("web_checkBox")
        self.horizontalLayout.addWidget(self.web_checkBox)
        #这又是一个框架
        self.end_verticalLayoutWidget = QtWidgets.QWidget(MainWindow)
        self.end_verticalLayoutWidget.setGeometry(QtCore.QRect(463, 69, 91, 31))
        self.end_verticalLayoutWidget.setObjectName("end_verticalLayoutWidget")
        self.end_verticalLayout = QtWidgets.QVBoxLayout(self.end_verticalLayoutWidget)
        self.end_verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.end_verticalLayout.setObjectName("end_verticalLayout")
        #按钮：开始导出
        self.start_Button = QtWidgets.QPushButton(self.end_verticalLayoutWidget)
        self.start_Button.setObjectName("start_Button")
        #框架结尾
        self.end_verticalLayout.addWidget(self.start_Button)
        #详细输出日志的文本框
        self.log_textEdit = QtWidgets.QTextEdit(MainWindow)
        self.log_textEdit.setGeometry(QtCore.QRect(5, 120, 550, 171))
        self.log_textEdit.setObjectName("log_textEdit")

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        self.input_label.setText(_translate("MainWindow", "原始报告路径："))
        self.output_label.setText(_translate("MainWindow", "输出报告路径："))
        self.input_Button.setText(_translate("MainWindow", "打开路径"))
        self.output_Button.setText(_translate("MainWindow", "打开路径"))
        self.data_label.setText(_translate("MainWindow", "选择导出数据："))
        self.hight_checkBox.setText(_translate("MainWindow", "高危"))
        self.middle_checkBox.setText(_translate("MainWindow", "中危"))
        self.low_checkBox.setText(_translate("MainWindow", "低危"))
        self.port_checkBox.setText(_translate("MainWindow", "端口"))
        self.web_checkBox.setText(_translate("MainWindow", "网站"))
        self.start_Button.setText(_translate("MainWindow", "开始导出"))
