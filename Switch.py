import threading

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
import netifaces

stop_sniffing_port_0_event = threading.Event()
stop_sniffing_port_1_event = threading.Event()

BC_MAC = "FF:FF:FF:FF:FF:FF"
class Switch(QObject):
    # signals
    port0_changed = pyqtSignal(str)
    port1_changed = pyqtSignal(str)

    port0_device_changed = pyqtSignal(str)
    port1_device_changed = pyqtSignal(str)

    log_value_changed = pyqtSignal(str)
    stat_value_changed = pyqtSignal(int, list)

    def __init__(self):
        super().__init__()  # Call the superclass __init__ method
        self._packet_timeout = 30  # Timeout for MAC address entries in seconds
        self._port0_address = ""
        self._port1_address = ""

        self._port0_device = r""
        self._port1_device = r""

        self._port0_timer = self._packet_timeout
        self._port1_timer = self._packet_timeout

        self._log_value = ""

        self._por0_stats_in = [0, 0, 0, 0, 0, 0, 0, 0]
        self._por0_stats_out = [0, 0, 0, 0, 0, 0, 0, 0]

    def should_stop_sniffer(self, packet):
        return stop_sniffing_port_0_event.is_set()

    def start_sniffing(self, enum_int):
        callback_with_extra_arg = lambda packet: self.packet_callback(packet, enum_int)
        interface = ""
        if enum_int == 0:
            interface = self._port0_device
        if enum_int == 1:
            interface = self._port1_device

        sniff(prn=callback_with_extra_arg, store=0, iface=interface, stop_filter=self.should_stop_sniffer)
        print("ended" + str(enum_int))
        stop_sniffing_port_0_event.clear()

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

    def packet_callback(self, packet, enum_int):
        thread_id = threading.current_thread().ident

        print(f"Thread ID: {thread_id}")
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

            # Access packet information as needed
            # print(packet.summary())
            if enum_int == 0:
                if TCP in packet:
                    packet[TCP].dport = 6789
                    sendp(packet, iface=self._port1_device)

                if interface == desired_int:
                    self.port0_address = src_mac
                    self.port0_timer = self._packet_timeout
                    if Ether in packet:
                        self._por0_stats_in[0] = self._por0_stats_in[0] + 1
                        self.stat_value_changed.emit(0, self._por0_stats_in)

                    if ARP in packet:
                        self._por0_stats_in[1] = self._por0_stats_in[1] + 1
                        self.stat_value_changed.emit(0, self._por0_stats_in)

                    if IP in packet:
                        self._por0_stats_in[2] = self._por0_stats_in[2] + 1
                        self.stat_value_changed.emit(0, self._por0_stats_in)

                    if TCP in packet:
                        self._por0_stats_in[3] = self._por0_stats_in[3] + 1
                        self.stat_value_changed.emit(0, self._por0_stats_in)
                        if packet[TCP].dport in {80, 8080}:
                            self._por0_stats_in[6] += 1
                            self.stat_value_changed.emit(0, self._por0_stats_in)

                    if UDP in packet:
                        self._por0_stats_in[4] = self._por0_stats_in[4] + 1
                        self.stat_value_changed.emit(0, self._por0_stats_in)

                    if ICMP in packet:
                        self._por0_stats_in[5] = self._por0_stats_in[5] + 1
                        self.stat_value_changed.emit(0, self._por0_stats_in)

            if enum_int == 1:
                print("enum 1")
                if interface == desired_int:
                    if TCP in packet:
                        if packet[TCP].dport in {6789}:
                            print("that is my boy")
                            self._por0_stats_out[3] += 1
                            self.stat_value_changed.emit(2, self._por0_stats_out)

        print(stop_sniffing_port_0_event.is_set())
        print(stop_sniffing_port_1_event.is_set())

        if enum_int == 0 and stop_sniffing_port_0_event.is_set():
            print("stopiiik1")
            #stop_sniffing_port_0_event.clear()
            return False

        if enum_int == 1 and stop_sniffing_port_1_event.is_set():
            print("stopiiik2")
            #stop_sniffing_port_1_event.clear()
            return False

    def remove_device(self):
        self.port0_address = ""


    def get_active_interfaces(self):
        interfaces = psutil.net_if_addrs()
        interface_names = list(interfaces.keys())
        return interface_names