from scapy.all import sniff
import time

from PyQt5.QtCore import QObject, pyqtSignal

BC_MAC = "FF:FF:FF:FF:FF:FF"
class Switch(QObject):
    # signals
    port0_changed = pyqtSignal(str)
    port1_changed = pyqtSignal(str)
    log_value_changed = pyqtSignal(str)

    def __init__(self):
        super().__init__()  # Call the superclass __init__ method
        self._packet_timeout = 30  # Timeout for MAC address entries in seconds
        self._port0_address = ""
        self._port1_address = ""

        self._port0_timer = self._packet_timeout
        self._port1_timer = self._packet_timeout

        self._log_value = ""

        self.connected_devices = {}  # Dictionary to store connected devices and their sockets
        self.mac_to_port = {'0': 'NONE', '1': 'NONE'}

        self.log_value = f""


    def start_sniffing(self):
        sniff(prn=self.packet_callback, store=0)

    @property
    def packet_timeout(self):
        return self._packet_timeout
    @property
    def port0_address(self):
        return self._port0_address

    @property
    def port1_address(self):
        return self._port1_address

    @property
    def log_value(self):
        return self._log_value

    @property
    def port0_timer(self):
        return self._port0_timer

    @packet_timeout.setter
    def packet_timeout(self, new_value):
        self._packet_timeout = new_value
        # self.packet_timeout_changed.emit(new_value)

    @port0_address.setter
    def port0_address(self, new_value):
        self._port0_address = new_value
        self.port0_changed.emit(new_value)

    @port1_address.setter
    def port1_address(self, new_value):
        self._port1_address = new_value
        self.port1_changed.emit(new_value)

    @log_value.setter
    def log_value(self, new_value):
        self._log_value = new_value
        self.log_value_changed.emit(new_value)

    @port0_timer.setter
    def port0_timer(self, new_value):
        print("ou yeah")
        self._port0_timer = new_value
        #self.log_value_changed.emit(new_value)


    def packet_callback(self, packet):
        if packet.haslayer("Ethernet"):
            src_mac = packet["Ethernet"].src
            dst_mac = packet["Ethernet"].dst
            type = packet["Ethernet"].fields["type"]
            interface = packet.sniffed_on
            #print(interface)
            # print(f"Received frame from {src_mac} to {dst_mac} type {type}")
            self.log_value = f"Received frame from {src_mac} to {dst_mac} type {type}"

            # Access packet information as needed
            # print(packet.summary())

            if interface == r"\Device\NPF_{3BFEC34C-48A4-453C-B8FC-A0260906CCB0}":
                self.port0_address = src_mac
                self.port0_timer = self._packet_timeout


    # def add_device(self, device_address, device_socket):
    #     self.connected_devices[device_address] = device_socket
    #     # Associate the MAC address with a switch port (assuming only two ports)
    #     if len(self.mac_to_port) < 2:
    #         self.mac_to_port[device_address] = len(self.mac_to_port)


    def remove_device(self):
        self.port0_address = ""


    def forward_packet(self, source_address, destination_address, packet):
        destination_device = self.connected_devices.get(destination_address)
       # if destination_address == BC_MAC:

        if destination_device:
            # print(f"Switch: Forwarding packet from {source_address} to {destination_address}")
            # destination_device.sendall(packet)
            # Update the timestamp for the MAC address associated with the outgoing port
            self.mac_to_port[source_address] = time.time()
