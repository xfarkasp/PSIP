import psutil
from scapy.all import sniff
import time

from PyQt5.QtCore import QObject, pyqtSignal
from scapy.arch import get_if_hwaddr
from scapy.interfaces import get_if_list
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import sendp

BC_MAC = "FF:FF:FF:FF:FF:FF"
class Switch(QObject):
    # signals
    port0_changed = pyqtSignal(str)
    port1_changed = pyqtSignal(str)
    log_value_changed = pyqtSignal(str)
    stat_value_changed = pyqtSignal(int, list)

    def __init__(self):
        super().__init__()  # Call the superclass __init__ method
        self._packet_timeout = 30  # Timeout for MAC address entries in seconds
        self._port0_address = ""
        self._port1_address = ""

        self._port0_device = ""
        self._port1_device = ""

        self._port0_timer = self._packet_timeout
        self._port1_timer = self._packet_timeout

        self._log_value = ""

        self._por0_stats_in = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por0_stats_out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por1_stats_in = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por1_stats_out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        self.last_packet_0 = None
        self.last_packet_1 = None


    def start_sniffing(self):

        sniff(iface=[self._port0_device, self._port1_device] ,prn=self.packet_callback, store=0)

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
    def port0_device(self):
        return self._port0_device

    @property
    def port1_device(self):
        return self._port1_device

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

    @port0_device.setter
    def port0_device(self, new_value):
        self._port0_device = new_value

    @port1_device.setter
    def port1_device(self, new_value):
        self._port1_device = new_value

    @log_value.setter
    def log_value(self, new_value):
        self._log_value = new_value
        self.log_value_changed.emit(new_value)

    @port0_timer.setter
    def port0_timer(self, new_value):
        self._port0_timer = new_value

    def stat_handler(self, col, packet):
        local_list = []
        flag = False
        if col == 0:
            local_list = self._por0_stats_in

        elif col == 1:
            local_list = self._por0_stats_out

        elif col == 2:
            local_list = self._por1_stats_in

        elif col == 3:
            local_list = self._por1_stats_out

        if Ether in packet:
            local_list[0] = local_list[0] + 1
            flag = True

        if ARP in packet:
            local_list[1] = local_list[1] + 1
            flag = True

        if IP in packet:
            local_list[2] = local_list[2] + 1
            flag = True

        if TCP in packet:
            local_list[3] = local_list[3] + 1
            flag = True

            if TCP in packet:
                if packet[TCP].dport in {80}:
                    local_list[6] += 1
                if packet[TCP].dport in {8080}:
                    local_list[7] += 1

        if UDP in packet:
            local_list[4] = local_list[4] + 1
            flag = True

        if ICMP in packet:
            local_list[5] = local_list[5] + 1
            flag = True

        if flag:
            local_list[9] = local_list[9] + 1
            self.stat_value_changed.emit(col, local_list)


    def packet_callback(self, packet):
        try:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            interface = packet.sniffed_on

            #print(interface)
            print(f"Received frame from {src_mac} to {dst_mac} type {type}")
            self.log_value = f"Received frame from {src_mac} to {dst_mac} type {type}"

            if interface == self.port0_device and packet.dst != self.port1_address and packet.src != self.port1_address:
                    self.port0_address = src_mac
                    self.port0_timer = self._packet_timeout
                    self.stat_handler(0, packet)

                    #if self.last_packet_1 != packet:
                    print("poslal som 0")
                    sendp(packet, iface=self._port1_device)
                    self.stat_handler(3, packet)
                    self.last_packet_0 = packet

            if interface == self.port1_device and packet.dst != self.port0_address and packet.src != self.port0_address:
                    self.port1_address = src_mac
                    #self.port1_timer = self._packet_timeout
                    self.stat_handler(2, packet)

                    #if self.last_packet_0 != packet:
                    print("poslal som 1")
                    sendp(packet, iface=self._port0_device)
                    self.stat_handler(1, packet)
                    self.last_packet_1 = packet
        except any:
            print("kokot pica u holica")


    def remove_device(self):
        self.port0_address = ""

    def get_active_interfaces(self):
        # active_interfaces = get_if_list()
        # return active_interfaces
        # Get the list of network interfaces
        interfaces = psutil.net_if_addrs()

        # Extract and print the interface names
        interface_names = list(interfaces.keys())
        return interface_names
