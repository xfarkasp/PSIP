from scapy.all import sniff, ARP, Ether
import psutil
import threading
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


        self.log_value = f"a"


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


    def packet_callback(self, packet):
        if packet.haslayer("Ethernet"):
            src_mac = packet["Ethernet"].src
            dst_mac = packet["Ethernet"].dst
            type = packet["Ethernet"].fields["type"]
            interface = packet.sniffed_on

            # print(f"Received frame from {src_mac} to {dst_mac} type {type}")
            self.log_value = f"Received frame from {src_mac} to {dst_mac} type {type}"

            # Access packet information as needed
            # print(packet.summary())

            if interface == r"\Device\NPF_{15D901A8-C9F4-45C6-B753-EFAC1E2A6113}":
                self.port0_address = src_mac


    def add_device(self, device_address, device_socket):
        self.connected_devices[device_address] = device_socket
        # Associate the MAC address with a switch port (assuming only two ports)
        if len(self.mac_to_port) < 2:
            self.mac_to_port[device_address] = len(self.mac_to_port)


    def remove_device(self, device_address):
        del self.connected_devices[device_address]
        if device_address in self.mac_to_port:
            del self.mac_to_port[device_address]


    def forward_packet(self, source_address, destination_address, packet):
        destination_device = self.connected_devices.get(destination_address)
       # if destination_address == BC_MAC:

        if destination_device:
            # print(f"Switch: Forwarding packet from {source_address} to {destination_address}")
            # destination_device.sendall(packet)
            # Update the timestamp for the MAC address associated with the outgoing port
            self.mac_to_port[source_address] = time.time()


    def check_timeout(self):
        while True:
            time.sleep(1)
            current_time = time.time()
            # Check for MAC addresses that have exceeded the timeout
            for mac_address, timestamp in list(self.mac_to_port.items()):
                if current_time - timestamp > self.packet_timeout:
                    print(f"Timeout for MAC address {mac_address}. Removing association.")
                    del self.mac_to_port[mac_address]
