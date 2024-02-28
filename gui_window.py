import sys
import threading

from PyQt5.QtCore import QTimer, pyqtSlot, Qt
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, \
    QPlainTextEdit, QSizePolicy, QLabel, QHBoxLayout, QHeaderView, QPushButton, QComboBox, QScrollBar

from Switch import Switch


class Ui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.output_text = QPlainTextEdit(self)
        self.timer_input_field = QPlainTextEdit(self)
        self.timer_update_button = QPushButton('Start', self)
        self.mac_table = QTableWidget(self)
        self.stat_table = QTableWidget(self)
        # combo boxes for interface select
        self.port0_combo_box = QComboBox(self)
        self.port1_combo_box = QComboBox(self)

        self.port0_combo_box.currentIndexChanged.connect(lambda index: self.on_port0_combo_box_changed(index))
        self.port1_combo_box.currentIndexChanged.connect(lambda index: self.on_port1_combo_box_changed(index))

        self.timer_update_button.clicked.connect(lambda: self.on_timer_update_button_clicked())

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
        # self.mac_table.resizeColumnsToContents()

    @pyqtSlot(int, list)
    def update_stat(self, col_num, new_stats):
        index = 0
        for element in new_stats:
            self.stat_table.setItem(index, col_num, QTableWidgetItem(str(element)))
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

    def on_port0_combo_box_changed(self, index):
        selected_text = self.port0_combo_box.currentText()
        self.switch.port0_device = selected_text

    def on_port1_combo_box_changed(self, index):
        selected_text = self.port1_combo_box.currentText()
        self.switch.port1_device = selected_text

    def on_timer_update_button_clicked(self):
        # Start a separate thread for sniffing packets
        sniff_thread = threading.Thread(target=self.switch.start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()

        # sniff_thread2 = threading.Thread(target=self.switch.start_sniffing, args=(1,))
        # sniff_thread2.start()

    def initUI(self):
        # WIDGETS
        self.mac_table.setMaximumHeight(105)
        self.mac_table.setMaximumWidth(235)
        self.mac_table.setRowCount(2)
        self.mac_table.setColumnCount(2)

        self.mac_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.mac_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # MAC table
        self.mac_table.setVerticalHeaderLabels(['wifi', 'PORT 1'])
        self.mac_table.setHorizontalHeaderLabels(['MAC Address', 'Timer'])
        self.mac_table.setColumnWidth(1, 30)
        # mac_table.setFixedSize(205, 80)  # Set your preferred width and height

        # port 0 data
        self.mac_table.setItem(0, 0, QTableWidgetItem('NONE'))
        self.mac_table.setItem(0, 1, QTableWidgetItem('-'))

        # port 1 data
        self.mac_table.setItem(1, 0, QTableWidgetItem('NONE'))
        self.mac_table.setItem(1, 1, QTableWidgetItem('-'))

        self.stat_table.setRowCount(10)
        self.stat_table.setColumnCount(4)
        self.stat_table.setVerticalHeaderLabels(['Ethernet II', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS','TELNET', 'TOTAL'])
        self.stat_table.setHorizontalHeaderLabels(['PORT0 INBOUND', 'PORT0 OUTBOUND', 'PORT1 INBOUND', 'PORT1 OUTBOUND'])

        # Create a QPlainTextEdit for text output
        thread_id = threading.current_thread().ident
        self.output_text.setPlaceholderText(f"Thread ID: {thread_id}")

        interfaces = self.switch.get_active_interfaces()
        for iface in interfaces:
            self.port0_combo_box.addItem(str(iface))
            self.port1_combo_box.addItem(str(iface))

        # LAYOUTS
        central_widget = QWidget(self)

        # Create a layout for the central widget
        central_layout = QHBoxLayout(central_widget)

        # Create a layout for the tables (stacked vertically)
        table_layout = QVBoxLayout()
        delay_update_layout = QHBoxLayout()
        mac_layout = QHBoxLayout()
        port_select_layout = QVBoxLayout()

        self.timer_input_field.setMaximumHeight(30)
        self.timer_input_field.setMaximumWidth(100)
        delay_update_layout.addWidget(self.timer_input_field)
        delay_update_layout.addWidget(self.timer_update_button)

        port_select_layout.addWidget(self.port0_combo_box)
        port_select_layout.addWidget(self.port1_combo_box)
        port_select_layout.addLayout(delay_update_layout)

        mac_layout.addWidget(self.mac_table)
        mac_layout.addLayout(port_select_layout)

        table_layout.addLayout(mac_layout)
        table_layout.addWidget(self.stat_table)
        table_layout.setStretchFactor(self.stat_table, 1)

        # Add the table layout to the central layout
        central_layout.addLayout(table_layout)

        central_layout.addWidget(self.output_text)
        self.output_text.setReadOnly(True)

        # Set the central widget of the main window
        self.setCentralWidget(central_widget)

        self.setWindowTitle('The Switcher')

def main():
    app = QApplication(sys.argv)
    ex = Ui()

    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()