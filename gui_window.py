import sys
import threading

from PyQt5.QtCore import QTimer, pyqtSlot
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, \
    QPlainTextEdit, QSizePolicy, QLabel, QHBoxLayout, QHeaderView, QPushButton

from Switch import Switch


class TableExample(QMainWindow):
    def __init__(self):
        super().__init__()
        self.output_text = QPlainTextEdit(self)
        self.timer_input_field = QPlainTextEdit(self)
        self.timer_update_button = QPushButton('Update', self)
        self.mac_table = QTableWidget(self)
        self.stat_table = QTableWidget(self)

        # self.timer_update_button.clicked.connect(
        #     lambda: self.switch)

        # Create an instance of the logic class
        self.switch = Switch()

        # Connect the custom signal to a slot (method) in the GUI class
        self.switch.log_value_changed.connect(self.add_text)
        self.switch.port0_changed.connect(self.update_port_0)
        self.switch.stat_value_changed.connect(self.update_stat)

        self.initUI()

        # start timer for decrementing timeout
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.timer_callback)
        self.start_timer()

        # Start a separate thread for sniffing packets
        sniff_thread = threading.Thread(target=self.switch.start_sniffing)
        sniff_thread.start()


    @pyqtSlot(str)
    def add_text(self, text):
        current_text = self.output_text.toPlainText()
        # Split the text into lines and keep the most recent ones
        lines = current_text.split('\n')[-100:]
        updated_text = '\n'.join(lines + [text])

        self.output_text.setPlainText(updated_text)

    @pyqtSlot(str)
    def update_port_0(self, text):
        self.mac_table.setItem(0, 0, QTableWidgetItem(text))

    @pyqtSlot(list)
    def update_stat(self, new_stats):
        index = 0
        for element in new_stats:
            self.stat_table.setItem(index, 0, QTableWidgetItem(str(element)))
            index += 1




    def start_timer(self):
        self.timer.start(1000)  # Timer interval in milliseconds (e.g., 1000 ms = 1 second)

    def stop_timer(self):
        self.timer.stop()

    def timer_callback(self):
        timer_value = self.switch.port0_timer
        if timer_value > 0 and len(self.switch.port0_address) != 0:
            timer_value -= 1
            self.switch.port0_timer = timer_value
            self.mac_table.setItem(0, 1, QTableWidgetItem(str(self.switch.port0_timer)))
            if timer_value == 0:
                print("time 0")
                self.switch.remove_device()


    def initUI(self):

        self.mac_table.setRowCount(2)
        self.mac_table.setColumnCount(2)

        # MAC table
        self.mac_table.setVerticalHeaderLabels(['wifi', 'PORT 1'])
        self.mac_table.setHorizontalHeaderLabels(['MAC Address', 'Timer'])
        # mac_table.setFixedSize(205, 80)  # Set your preferred width and height

        # port 0 data
        self.mac_table.setItem(0, 0, QTableWidgetItem('NONE'))
        self.mac_table.setItem(0, 1, QTableWidgetItem('-'))

        # port 1 data
        self.mac_table.setItem(1, 0, QTableWidgetItem('NONE'))
        self.mac_table.setItem(1, 1, QTableWidgetItem('-'))

        self.mac_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Resize columns and rows to fit content
        self.mac_table.resizeColumnsToContents()
        self.mac_table.resizeRowsToContents()


        self.stat_table.setRowCount(8)
        self.stat_table.setColumnCount(4)
        self.stat_table.setVerticalHeaderLabels(['Ethernet II', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'HTTP', 'TELNET'])
        self.stat_table.setHorizontalHeaderLabels(['PORT0 INBOUND', 'PORT0 OUTBOUND', 'PORT1 INBOUND', 'PORT1 OUTBOUND'])


        # Resize columns and rows to fit content
        self.stat_table.resizeColumnsToContents()
        self.stat_table.resizeRowsToContents()

        # Create a QPlainTextEdit for text output
        thread_id = threading.current_thread().ident
        self.output_text.setPlaceholderText(f"Thread ID: {thread_id}")

        # Create a central widget
        central_widget = QWidget(self)

        # Create a layout for the central widget
        central_layout = QHBoxLayout(central_widget)

        # Create a layout for the tables (stacked vertically)
        table_layout = QVBoxLayout()
        delay_update_layout = QHBoxLayout()
        mac_layout = QHBoxLayout()

        delay_update_layout.addWidget(self.timer_input_field)
        delay_update_layout.addWidget(self.timer_update_button)

        mac_layout.addWidget(self.mac_table)
        mac_layout.addLayout(delay_update_layout)

        table_layout.addLayout(mac_layout)
        table_layout.addWidget(self.stat_table)
        table_layout.setStretchFactor(self.stat_table, 1)

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