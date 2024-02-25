from scapy.all import sniff
import time

from PyQt5.QtCore import QObject, pyqtSignal
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
    stat_value_changed = pyqtSignal(list)

    def __init__(self):
        super().__init__()  # Call the superclass __init__ method
        self._packet_timeout = 30  # Timeout for MAC address entries in seconds
        self._port0_address = ""
        self._port1_address = ""

        self._port0_device = r"\Device\NPF_{3BFEC34C-48A4-453C-B8FC-A0260906CCB0}"
        self._port1_device = r"\Device\NPF_{BFFD7AA0-6595-4116-999B-8BEBFD162B98}"

        self._port0_timer = self._packet_timeout
        self._port1_timer = self._packet_timeout

        self._log_value = ""

        self._por0_stats_in = [0, 0, 0, 0, 0, 0, 0, 0]
        self._por0_stats_out = [0, 0, 0, 0, 0, 0, 0, 0]



    def start_sniffing(self, enum_int):
        callback_with_extra_arg = lambda packet: self.packet_callback(packet, enum_int)
        interface = ""
        if enum_int == 0:
            interface = self._port0_device
        if enum_int == 1:
            interface = self._port1_device
        sniff(prn=callback_with_extra_arg, store=0, iface=interface)

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
        self._port0_timer = new_value

    def packet_callback(self, packet, enum_int):
        desired_int = ""
        if enum_int == 0:
            desired_int = self._port0_device
        elif enum_int == 1:
            desired_int = self._port1_device

        if packet.haslayer("Ethernet"):
            src_mac = packet["Ethernet"].src
            dst_mac = packet["Ethernet"].dst
            type = packet["Ethernet"].fields["type"]
            interface = packet.sniffed_on
            #print(interface)
            # print(f"Received frame from {src_mac} to {dst_mac} type {type}")
            self.log_value = f"Received frame from {src_mac} to {dst_mac} type {type}"

            # Get a list of interface names
            interface_names = get_if_list()

            # for iface in interface_names:
            #     print(iface)
            if TCP in packet:
                packet[TCP].dport = 666
                #print(packet[TCP].dport)



            # Access packet information as needed
            # print(packet.summary())
            if enum_int == 0:
                sendp(packet, iface=r"\Device\NPF_{BFFD7AA0-6595-4116-999B-8BEBFD162B98}")
                if interface == desired_int:
                    self.port0_address = src_mac
                    self.port0_timer = self._packet_timeout
                    if Ether in packet:
                        self._por0_stats_in[0] = self._por0_stats_in[0] + 1
                        self.stat_value_changed.emit(self._por0_stats_in)

                    if ARP in packet:
                        self._por0_stats_in[1] = self._por0_stats_in[1] + 1
                        self.stat_value_changed.emit(self._por0_stats_in)

                    if IP in packet:
                        self._por0_stats_in[2] = self._por0_stats_in[2] + 1
                        self.stat_value_changed.emit(self._por0_stats_in)

                    if TCP in packet:
                        self._por0_stats_in[3] = self._por0_stats_in[3] + 1
                        self.stat_value_changed.emit(self._por0_stats_in)
                        if packet[TCP].dport in {80, 8080}:
                            self._por0_stats_in[6] += 1
                            self.stat_value_changed.emit(self._por0_stats_in)

                    if UDP in packet:
                        self._por0_stats_in[4] = self._por0_stats_in[4] + 1
                        self.stat_value_changed.emit(self._por0_stats_in)

                    if ICMP in packet:
                        self._por0_stats_in[5] = self._por0_stats_in[5] + 1
                        self.stat_value_changed.emit(self._por0_stats_in)
            if enum_int == 1:
                print("enum 1")
                if interface == desired_int:
                    print("aaaaaasdasdasd")
                    self._por0_stats_in[5] = self._por0_stats_in[5] + 1
                    self.stat_value_changed.emit(self._por0_stats_in)
                    if TCP in packet:
                        if packet[TCP].dport in {666}:
                            print("that is my boy")
                            self._por0_stats_in[6] += 1
                            self.stat_value_changed.emit(self._por0_stats_in)



    def remove_device(self):
        self.port0_address = ""


    def get_active_interfaces(self):
        active_interfaces = get_if_list()
        return active_interfaces

