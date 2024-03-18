import sys
import threading

from PyQt5.QtCore import QTimer, pyqtSlot, Qt, QSize
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, \
    QPlainTextEdit, QSizePolicy, QLabel, QHBoxLayout, QHeaderView, QPushButton, QComboBox, QScrollBar, QListWidgetItem, \
    QListWidget

from Switch import Switch


class Ui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.output_text = QPlainTextEdit(self)
        self.timer_input_field = QPlainTextEdit(self)
        self.timer_update_button = QPushButton('Start', self)
        self.port1_widget = QListWidget()
        self.port2_widget = QListWidget()
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
        # old logic: self.switch.port0_changed.connect(self.update_port_0)
        self.switch.port_changed.connect(lambda: self.populate_lists())
        self.switch.stat_value_changed.connect(self.update_stat)

        self.initUI()

        # start timer for decrementing timeout
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.timer_callback)
        self.start_timer()

    def create_port_label(self, text):
        label = QLabel(text)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(QFont("Arial", 14, QFont.Bold))
        return label

    def add_separator(self, list_widget):
        separator_item = QListWidgetItem()
        separator_item.setFlags(separator_item.flags() & ~Qt.ItemIsSelectable)  # Disable selection
        separator_item.setSizeHint(QSize(1, 10))  # Set size
        separator_item.setBackground(QColor(0, 0, 0))  # Set background color
        list_widget.addItem(separator_item)

    @pyqtSlot()
    def populate_lists(self):
        # Clear existing items in the list widgets
        try:
            self.port1_widget.clear()
            self.port2_widget.clear()
            for port, mac_timer_dict in self.switch.mac_addresses.items():
                if port == "port1":
                    list_widget = self.port1_widget
                else:
                    list_widget = self.port2_widget

                # Add column identifiers
                list_widget.addItem("MAC\t\tTimer")
                self.add_separator(list_widget)

                for mac, timer in mac_timer_dict.items():
                    item = QListWidgetItem(f"{mac}\t{timer}")
                    list_widget.addItem(item)
        except Exception as e:
            print(f"Error occurred while adding MAC address: {e}")

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
        # timer_value = self.switch.port0_timer
        # if timer_value > 0 and len(self.switch.port0_address) != 0:
        #     timer_value -= 1
        #     self.switch.port0_timer = timer_value
        #     self.mac_table.setItem(0, 1, QTableWidgetItem(str(self.switch.port0_timer)))
        #     if timer_value == 0:
        #         print("time 0")
        #         self.switch.remove_device()

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
        layoutMac = QHBoxLayout()  # Horizontal layout
        # Create a QVBoxLayout for each port
        port1_layout = QVBoxLayout()
        port2_layout = QVBoxLayout()

        port1_layout.addWidget(self.create_port_label("Port 1"))  # Add port name label
        port1_layout.addWidget(self.port1_widget)

        port2_layout.addWidget(self.create_port_label("Port 2"))  # Add port name label
        port2_layout.addWidget(self.port2_widget)

        # Add the QVBoxLayouts to the main QHBoxLayout
        layoutMac.addLayout(port1_layout)
        layoutMac.addLayout(port2_layout)

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

        mac_layout.addLayout(layoutMac)
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

# import sys
# from PyQt5.QtCore import Qt, QSize
# from PyQt5.QtGui import QColor, QFont
# from PyQt5.QtWidgets import QApplication, QMainWindow, QHBoxLayout, QVBoxLayout, QWidget, QListWidget, QListWidgetItem, QLabel
#
# class MainWindow(QMainWindow):
#     def __init__(self):
#         super().__init__()
#
#         self.setWindowTitle("MAC Table")
#
#         self.central_widget = QWidget()
#         self.setCentralWidget(self.central_widget)
#
#
#         self.central_widget.setLayout(self.layoutMac)
#
#         self.layoutMac = QHBoxLayout()  # Horizontal layout
#         # Create a QVBoxLayout for each port
#         self.port1_layout = QVBoxLayout()
#         self.port2_layout = QVBoxLayout()
#
#         self.port1_widget = QListWidget()
#         self.port1_layout.addWidget(self.create_port_label("Port 1"))  # Add port name label
#         self.port1_layout.addWidget(self.port1_widget)
#
#         self.port2_widget = QListWidget()
#         self.port2_layout.addWidget(self.create_port_label("Port 2"))  # Add port name label
#         self.port2_layout.addWidget(self.port2_widget)
#
#         # Add the QVBoxLayouts to the main QHBoxLayout
#         self.layoutMac.addLayout(self.port1_layout)
#         self.layoutMac.addLayout(self.port2_layout)
#
#         self.populate_lists()
#
#     def create_port_label(self, text):
#         label = QLabel(text)
#         label.setAlignment(Qt.AlignCenter)
#         label.setFont(QFont("Arial", 14, QFont.Bold))
#         return label
#
#     def add_separator(self, list_widget):
#         separator_item = QListWidgetItem()
#         separator_item.setFlags(separator_item.flags() & ~Qt.ItemIsSelectable)  # Disable selection
#         separator_item.setSizeHint(QSize(1, 10))  # Set size
#         separator_item.setBackground(QColor(0, 0, 0))  # Set background color
#         list_widget.addItem(separator_item)
#
#     def populate_lists(self):
#         # Dummy data, you can replace this with your actual data
#         port_data = {
#             "Port 1": [("AA:BB:CC:DD:EE:FF", "00:00:20"), ("12:34:56:78:90:AB", "00:01:30")],
#             "Port 2": [("FF:EE:DD:CC:BB:AA", "00:02:45"), ("AB:90:78:56:34:12", "00:03:15")]
#         }
#
#         for port, macs in port_data.items():
#             if port == "Port 1":
#                 list_widget = self.port1_widget
#             else:
#                 list_widget = self.port2_widget
#
#             # Add column identifiers
#             list_widget.addItem("MAC\t\tTimer")
#             self.add_separator(list_widget)
#             for mac, timer in macs:
#                 item = QListWidgetItem(f"{mac}\t{timer}")
#                 list_widget.addItem(item)
#
# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     window = MainWindow()
#     window.setGeometry(100, 100, 600, 300)
#     window.show()
#     sys.exit(app.exec_())








