import sys
import threading

from PyQt5.QtCore import QTimer, pyqtSlot
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, \
    QPlainTextEdit, QSizePolicy, QLabel, QHBoxLayout, QHeaderView

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
        # Split the text into lines and keep the most recent ones
        lines = current_text.split('\n')[-100:]
        updated_text = '\n'.join(lines + [text])

        self.output_text.setPlainText(updated_text)

    def initUI(self):
        mac_table = QTableWidget(self)
        mac_table.setRowCount(2)
        mac_table.setColumnCount(2)

        # MAC table
        mac_table.setVerticalHeaderLabels(['PORT 0', 'PORT 1'])
        mac_table.setHorizontalHeaderLabels(['MAC Address', 'Timer'])
        # mac_table.setFixedSize(205, 80)  # Set your preferred width and height

        # port 0 data
        mac_table.setItem(0, 0, QTableWidgetItem('00-B0-D0-63-C2-26'))
        mac_table.setItem(0, 1, QTableWidgetItem('-'))

        # port 1 data
        mac_table.setItem(1, 0, QTableWidgetItem('00-B0-D0-63-C2-26'))
        mac_table.setItem(1, 1, QTableWidgetItem('-'))

        mac_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Resize columns and rows to fit content
        mac_table.resizeColumnsToContents()
        mac_table.resizeRowsToContents()

        stat_table = QTableWidget(self)
        stat_table.setRowCount(0)
        stat_table.setColumnCount(4)
        stat_table.setHorizontalHeaderLabels(['PORT0 INBOUND', 'PORT0 OUTBOUND', 'PORT1 INBOUND', 'PORT1 OUTBOUND'])

        # Resize columns and rows to fit content
        stat_table.resizeColumnsToContents()
        stat_table.resizeRowsToContents()


        # Create a QPlainTextEdit for text output
        thread_id = threading.current_thread().ident
        self.output_text.setPlaceholderText(f"Thread ID: {thread_id}")

        print(f"Thread ID: {thread_id}")

        # Create a central widget
        central_widget = QWidget(self)

        # Create a layout for the central widget
        central_layout = QHBoxLayout(central_widget)

        # Create a layout for the tables (stacked vertically)
        table_layout = QVBoxLayout()
        table_layout.addWidget(mac_table)
        table_layout.addWidget(stat_table)
        table_layout.setStretchFactor(stat_table, 1)

        # Add the table layout to the central layout
        central_layout.addLayout(table_layout)

        # Add the output text area to the central layout
        central_layout.addWidget(self.output_text)
        self.output_text.setReadOnly(True)

        # Set the central widget of the main window
        self.setCentralWidget(central_widget)

        # self.setGeometry(100, 100, 800, 600)  # Adjust the size accordingly
        self.setWindowTitle('The Switcher')

def main():
    app = QApplication(sys.argv)
    ex = TableExample()

    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()