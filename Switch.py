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
        self._port0_address = ""
        self._port1_address = ""
        self._log_value = ""

        self.connected_devices = {}  # Dictionary to store connected devices and their sockets
        self.mac_to_port = {'0': 'NONE', '1': 'NONE'}
        self.packet_timeout = 30  # Timeout for MAC address entries in seconds

        self.log_value = f"a"


    def start_sniffing(self):
        sniff(prn=self.packet_callback, store=0)


    @property
    def port0_address(self):
        return self._port0_address

    @property
    def port1_address(self):
        return self._port1_address

    @property
    def log_value(self):
        return self._log_value

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

    def determine_port(self, src_mac):
        if src_mac not in self.mac_to_port:
            # Assign a new port for the unknown MAC address
            port = len(self.mac_to_port) + 1
            self.mac_to_port[src_mac] = port
        return self.mac_to_port[src_mac]

    def get_interface_name(self, packet):
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address == packet[Ether].src:
                    print(interface)
                    return interface
        return "Unknown"

    def packet_callback(self, packet):
        if packet.haslayer("Ethernet"):
            src_mac = packet["Ethernet"].src
            dst_mac = packet["Ethernet"].dst
            type = packet["Ethernet"].fields["type"]

            # print(f"Received frame from {src_mac} to {dst_mac} type {type}")
            self.log_value = f"Received frame from {src_mac} to {dst_mac} type {type}"
            interface = self.get_interface_name(packet)
            print(f"Frame received on interface: {interface}")
            # Access packet information as needed
            # print(packet.summary())


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

def send_synthetic_packet(interface):
    available_interfaces = psutil.net_if_addrs().keys()
    print(f"Available interfaces: {', '.join(available_interfaces)}")

    # Check if the specified interface exists and is not a loopback interface
    if interface in available_interfaces and not psutil.net_if_stats()[interface].isup:
        mac_address = psutil.net_if_addrs()[interface][0].address
        # Rest of your code for sending synthetic packet...
        print(f"Sending synthetic packet on {interface} with MAC address: {mac_address}")
    else:
        print(f"Interface {interface} is not available or is a loopback interface.")