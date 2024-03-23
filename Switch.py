import hashlib
import queue

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
    port_changed = pyqtSignal()
    port1_changed = pyqtSignal()
    log_value_changed = pyqtSignal(str)
    stat_value_changed = pyqtSignal(int, list)

    def __init__(self):
        super().__init__()  # Call the superclass __init__ method
        self.sniffing_on = True

        self._packet_timeout = 30  # Timeout for MAC address entries in seconds
        self._pull_out_timer_1 = 7
        self._pull_out_timer_2 = 7

        self.mac_addresses = {
            "port1": {},
            "port2": {}
        }

        self._log_value = ""

        self._por0_stats_in = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por0_stats_out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por1_stats_in = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por1_stats_out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        self.sent_frame_que = queue.Queue()

        self.unique_packet_hashes = set()

    def stop_sniffing(self, packet):
        return self.sniffing_on

    def start_sniffing(self):
        try:
            sniff(iface=[self._port0_device, self._port1_device], prn=self.packet_callback, store=0, stop_filter=self.stop_sniffing)

        except Exception as e:
            print("An error occurred during packet sniffing:", e)

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
        #self.port_changed.emit(new_value)

    @port1_address.setter
    def port1_address(self, new_value):
        self._port1_address = new_value
        #self.port_changed.emit(new_value)

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

    def add_mac_address(self, port, mac_address, timer_value):
        self.duplicity_check(mac_address, port)
        self.mac_addresses[port][mac_address] = timer_value
        #self.port_changed.emit()

    def duplicity_check(self, addr, port):
        # Check if the port is valid
        if port not in self.mac_addresses:
            #print(f"Port '{port}' is not valid.")
            return

        # Get the other port
        other_port = "port2" if port == "port1" else "port1"

        # Check if the MAC address exists on the other port
        if addr in self.mac_addresses[other_port]:
            # Remove the MAC address from the other port
            del self.mac_addresses[other_port][addr]
            #self.port_changed.emit()

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

    def get_port_on(self, dest_mac):
        if dest_mac != BC_MAC:
            for port, mac_dict in self.mac_addresses.items():
                for mac, _ in mac_dict.items():
                    if mac == dest_mac:
                        return port
        return 'BC'

    def packet_callback(self, packet):
        try:
            if self.is_interface_connected(self.port0_device) is True:
                self._pull_out_timer_1 = 7
            if self.is_interface_connected(self.port1_device) is True:
                self._pull_out_timer_2 = 7

            if Ether in packet:
                # Check if the packet was sent by your program (using the same interface)
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                if src_mac == dst_mac:
                    return
                interface = packet.sniffed_on
                if src_mac == get_if_hwaddr(interface):
                    #print("Packet sent by the program, skipping processing.")
                    return

                # Calculate hash from packet data
                packet_hash = hashlib.sha256(bytes(packet)).hexdigest()

                # Check if packet hash is already in the set
                if packet_hash not in self.unique_packet_hashes:
                    # Add hash to the set
                    self.unique_packet_hashes.add(packet_hash)

                    #print(f"Received frame from {src_mac} to {dst_mac}")
                    self.log_value = f"Received frame from {src_mac} to {dst_mac}"

                    if interface == self.port0_device:
                        self.add_mac_address('port1', src_mac, self._packet_timeout)
                        self.stat_handler(0, packet)
                        port_to_send = self.get_port_on(dst_mac)
                        print(port_to_send)
                        if port_to_send == 'port2' or port_to_send == 'BC':
                            sendp(packet, iface=self._port1_device)
                            #print("sent to port 2")
                            self.stat_handler(3, packet)

                    if interface == self.port1_device:
                        self.add_mac_address('port2', src_mac, self._packet_timeout)
                        self.stat_handler(2, packet)
                        port_to_send = self.get_port_on(dst_mac)
                        print(port_to_send)
                        if port_to_send == 'port1' or port_to_send == 'BC':
                            sendp(packet, iface=self._port0_device)
                            #print("sent to port 1")
                            self.stat_handler(1, packet)

                else:
                    #print("packet was already processed")
                    self.unique_packet_hashes.remove(packet_hash)

        except Exception as e:
            print(f"Error occurred while adding MAC address: {e}")


    def get_active_interfaces(self):
        # active_interfaces = get_if_list()
        # return active_interfaces
        # Get the list of network interfaces
        interfaces = psutil.net_if_addrs()

        # Extract and print the interface names
        interface_names = list(interfaces.keys())
        return interface_names

    def is_interface_connected(self, interface_name):
        try:
            # Get network interfaces information
            interfaces = psutil.net_if_stats()

            # Check if the interface exists and is up
            if interface_name in interfaces and interfaces[interface_name].isup:
                return True
            else:
                return False
        except Exception as e:
            print("Error:", e)
            return False

    def pull_out_method(self):
        if self.sniffing_on is not True:
            if self._pull_out_timer_1 >= 0:
                self._pull_out_timer_1 -= 1

            if self._pull_out_timer_2 >= 0:
                self._pull_out_timer_2 -= 1

            if self._pull_out_timer_1 == 0:
                #print(f"interface: {self.port0_device} disconnected")
                self.clear_mac('port1')
                #print(self.mac_addresses)

            if self._pull_out_timer_2 == 0:
                #print(f"interface: {self.port1_device} disconnected")
                self.clear_mac('port2')
                #print(self.mac_addresses)

    def clear_mac(self, port):
        if port == 'port1':
            self.mac_addresses['port1'] = {}
        elif port == 'port2':
            self.mac_addresses['port2'] = {}
        elif port == 'all':
            self.mac_addresses['port1'] = {}
            self.mac_addresses['port2'] = {}
    def clear_stats(self):
        self._por0_stats_in = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por0_stats_out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por1_stats_in = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._por1_stats_out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]