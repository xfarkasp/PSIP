import sys
import threading

from PyQt5.QtCore import QTimer, pyqtSlot
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, \
    QPlainTextEdit, QSizePolicy, QLabel, QHBoxLayout

from Switch import Switch, send_synthetic_packet


class TableExample(QMainWindow):
    def __init__(self):
        super().__init__()
        self.output_text = QPlainTextEdit(self)

        # Create an instance of the logic class
        self.switch = Switch()

        # Connect the custom signal to a slot (method) in the GUI class
        self.switch.log_value_changed.connect(self.add_text)

        self.initUI()

        # self.switch.log_value = "asdasd"

        self.add_text("aaa")

        # Start a separate thread for sniffing packets
        sniff_thread = threading.Thread(target=self.switch.start_sniffing)
        sniff_thread.start()

        send_synthetic_packet("wi-fi")

    @pyqtSlot(str)
    def add_text(self, text):
        current_text = self.output_text.toPlainText()
        new_text = f'{text}\n'
        self.output_text.setPlainText(current_text + new_text)

    def initUI(self):
        table = QTableWidget(self)
        table.setRowCount(2)
        table.setColumnCount(2)

        # Set the table headers
        table.setVerticalHeaderLabels(['PORT 0', 'PORT 1'])
        table.setHorizontalHeaderLabels(['MAC Address', 'Timer'])
        table.setFixedSize(205, 80)  # Set your preferred width and height

        # port 0 data
        table.setItem(0, 0, QTableWidgetItem('00-B0-D0-63-C2-26'))
        table.setItem(0, 1, QTableWidgetItem('-'))

        # port 1 data
        table.setItem(1, 0, QTableWidgetItem('00-B0-D0-63-C2-26'))
        table.setItem(1, 1, QTableWidgetItem('-'))

        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Resize columns and rows to fit content
        table.resizeColumnsToContents()
        table.resizeRowsToContents()

        # Create a QPlainTextEdit for text output
        thread_id = threading.current_thread().ident
        self.output_text.setPlaceholderText(f"Thread ID: {thread_id}")

        print(f"Thread ID: {thread_id}")

        # Create a central widget and set the table and output_text as its layout
        central_widget = QWidget(self)
        central_layout = QHBoxLayout(central_widget)
        central_layout.addWidget(table)
        central_layout.addWidget(self.output_text)

        # Set stretch factor for the table in the layout
        central_layout.setStretchFactor(table, 1)


        # Set the central widget of the main window
        self.setCentralWidget(central_widget)

        self.setGeometry(100, 100, 400, 300)
        self.setWindowTitle('The Switcher')

def main():
    app = QApplication(sys.argv)
    ex = TableExample()

    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()