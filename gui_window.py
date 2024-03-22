import sys
import threading

from PyQt5.QtCore import QTimer, pyqtSlot, Qt, QSize
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, \
    QPlainTextEdit, QSizePolicy, QLabel, QHBoxLayout, QHeaderView, QPushButton, QComboBox, QScrollBar, QListWidgetItem, \
    QListWidget, QMessageBox

from Switch import Switch


class Ui(QMainWindow):
    def __init__(self):
        super().__init__()

        self.output_text = QPlainTextEdit(self)
        self.timer_input_field = QPlainTextEdit(self)

        self.timer_update_button = QPushButton('Set', self)
        self.start_sniffing = QPushButton('Start sniffing', self)
        self.stop_sniffing = QPushButton('Stop sniffing', self)
        self.clear_table = QPushButton('Clear table', self)
        self.clear_port1 = QPushButton('Clear port1', self)
        self.clear_port2 = QPushButton('Clear port2', self)
        self.clear_stats = QPushButton('Clear stats', self)

        self.port1_widget = QListWidget()
        self.port2_widget = QListWidget()
        self.stat_table = QTableWidget(self)
        # combo boxes for interface select
        self.port0_combo_box = QComboBox(self)
        self.port1_combo_box = QComboBox(self)

        self.port0_combo_box.setMaximumSize(220, 50)
        self.port1_combo_box.setMaximumSize(220, 50)

        self.port0_combo_box.currentIndexChanged.connect(lambda index: self.on_port0_combo_box_changed(index))
        self.port1_combo_box.currentIndexChanged.connect(lambda index: self.on_port1_combo_box_changed(index))

        self.timer_update_button.clicked.connect(lambda: self.on_timer_update_button_clicked())
        self.start_sniffing.clicked.connect(lambda: self.on_start_sniffing_button_clicked())

        self.stop_sniffing.clicked.connect(lambda: self.on_stop_sniffing_button_clicked())

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

        # self.pull_out_timer = QTimer(self)
        # self.pull_out_timer.timeout.connect(self.switch.pull_out_method)
        # self.start_pull_out_timer()

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
        try:

            self.populate_lists()

            for port, mac_timer_dict in self.switch.mac_addresses.items():
                macs_to_remove = []
                for mac, timer in mac_timer_dict.items():
                    self.switch.mac_addresses[port][mac] -= 1

                    if self.switch.mac_addresses[port][mac] <= 0:
                        macs_to_remove.append(mac)

                for mac in macs_to_remove:
                    self.switch.mac_addresses[port].pop(mac)

            self.switch.pull_out_method()


        except Exception as e:
            print(f"Error in timer_callback: {e}")

    def on_port0_combo_box_changed(self, index):
        selected_text = self.port0_combo_box.currentText()
        self.switch.port0_device = selected_text

    def on_port1_combo_box_changed(self, index):
        selected_text = self.port1_combo_box.currentText()
        self.switch.port1_device = selected_text

    def on_timer_update_button_clicked(self):
        try:
            text = self.timer_input_field.toPlainText()
            if text.isdigit():
                number = int(text)
                # save old timer
                old_timer_value = self.switch.packet_timeout
                # set the global timer value
                self.switch.packet_timeout = number
                # compare if old timer value was greater than new to remove outdated entries
                if old_timer_value > number:
                    for port, mac_timer_dict in self.switch.mac_addresses.items():
                        for mac, timer in mac_timer_dict.items():
                            if self.switch.mac_addresses[port][mac] >= self.switch.packet_timeout:
                                self.switch.mac_addresses[port][mac] = 0

            else:
                QMessageBox.warning(self, 'Non-Numeric Input', 'Please enter a numeric value.')
        except Exception as e:
            #QMessageBox.warning(self, 'ERROR: ', e)
            print(e)


    def on_start_sniffing_button_clicked(self):
        self.switch.sniffing_on = False
        sniff_thread = threading.Thread(target=self.switch.start_sniffing)
        sniff_thread.daemon = True
        sniff_thread.start()

    def on_stop_sniffing_button_clicked(self):
        # Create a lock
        sniffing_on_lock = threading.Lock()
        sniffing_on_lock.acquire()
        try:
            # Access/modify shared resource
            self.switch.sniffing_on = True
        finally:
            # Release the lock to allow other threads to acquire it
            sniffing_on_lock.release()

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
        self.stat_table.setVerticalHeaderLabels(
            ['Ethernet II', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'TELNET', 'TOTAL'])
        self.stat_table.setHorizontalHeaderLabels(
            ['PORT0 INBOUND', 'PORT0 OUTBOUND', 'PORT1 INBOUND', 'PORT1 OUTBOUND'])

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
        sniffing_layout = QHBoxLayout()
        clear_all_layout = QHBoxLayout()
        clear_ports_layout = QHBoxLayout()
        input_layout = QVBoxLayout()

        self.timer_input_field.setMaximumHeight(30)
        self.timer_input_field.setMaximumWidth(100)
        # combo boxes
        port_select_layout.addWidget(self.port0_combo_box)
        port_select_layout.addWidget(self.port1_combo_box)
        # sniffing buttons
        sniffing_layout.addWidget(self.start_sniffing)
        sniffing_layout.addWidget(self.stop_sniffing)
        # delay input and button
        delay_update_layout.addWidget(self.timer_input_field)
        delay_update_layout.addWidget(self.timer_update_button)
        # clear stats and mac table buttons
        clear_all_layout.addWidget(self.clear_table)
        clear_all_layout.addWidget(self.clear_stats)
        # clear specific port mac tables
        clear_ports_layout.addWidget(self.clear_port1)
        clear_ports_layout.addWidget(self.clear_port2)

        # create the input layout
        input_layout.addLayout(port_select_layout)
        input_layout.addLayout(sniffing_layout)
        input_layout.addLayout(delay_update_layout)
        input_layout.addLayout(clear_all_layout)
        input_layout.addLayout(clear_ports_layout)

        mac_layout.addLayout(layoutMac)
        mac_layout.addLayout(input_layout)

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
