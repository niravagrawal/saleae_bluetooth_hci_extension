# This HLA supports Bluetooth HCI H4 packets parsing from low level ASYNC Serial Analyzer to prepare HCI packets and forward it to Ellisys HCI Injection interface to live monitor Bluetooth HCI transactions. 

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data.timing import SaleaeTime
import sys
import os
from socket import *
from datetime import *
import time

HCI_OVERVIEW_CHOICE1 = 'Primary'
HCI_OVERVIEW_CHOICE2 = 'Secondary'
HCI_OVERVIEW_CHOICE3 = 'Tertiary'

HCI_OVERVIEW_CHOICES = {
  HCI_OVERVIEW_CHOICE1,
  HCI_OVERVIEW_CHOICE2,
  HCI_OVERVIEW_CHOICE3
}

class Ellysis_Hci_Injection:
    _instance = None
    ellisys_sock = None
    udp_ip = "127.0.0.1"
    udp_port  = 24352
    timestamp_ns_prev = 0

    #def __new__(self, *args, **kwargs):
    #    if not self._instance:
    #        self._instance = super(Ellysis_Hci_Injection, self).__new__(self, *args, **kwargs)
    #    return self._instance

    def __init__(self, port):
        if port > 0:
            self.udp_port = port
        if self.ellisys_sock is None:
            print("started Ellysis_Hci_Injection class!", self.udp_port)
            self.ellisys_sock = socket(AF_INET, SOCK_DGRAM)

    def send_to_sock(self, packet):
        if self.ellisys_sock is not None:
            ADDRESS = (self.udp_ip, self.udp_port)
            self.ellisys_sock.sendto(packet, ADDRESS)
        
    def generate_packet_n_send(self, packet_type, data, timestamp, hci_inst):
        send_data = b''
        ## WriteServiceId
        # HciInjectionServiceId
        #print ("{} {}",packet_type, data)
        send_data += ((0x0002).to_bytes(length=2, byteorder='little', signed=False))
        # HciInjectionServiceVersion
        send_data += ((0x01).to_bytes(length=1, byteorder='little', signed=False))

        ## WriteDateTimeNs
        dt = timestamp.as_datetime()
        dt_day = datetime(dt.year, dt.month, dt.day)
        timestamp_ns = (dt.timestamp() - dt_day.timestamp()) * 1000000000
        #delta = float(timestamp_ns - self.timestamp_ns_prev)/1000000
        print(str(dt))
        self.timestamp_ns_prev = timestamp_ns

        send_data += ((0x02).to_bytes(length=1, byteorder='little', signed=False))
        send_data += ((dt.year).to_bytes(length=2, byteorder='little', signed=False))
        send_data += ((dt.month).to_bytes(length=1, byteorder='little', signed=False))
        send_data += ((dt.day).to_bytes(length=1, byteorder='little', signed=False))
        send_data += (int(timestamp_ns).to_bytes(length=6, byteorder='little', signed=False))

        ## Write HCI Primary/Secondary Instance
        # Bitrate
        send_data += ((0x83).to_bytes(length=1, byteorder='little', signed=False))
        send_data += (hci_inst).to_bytes(length=1, byteorder='little', signed=False)
        
        ## WriteBitrate
        # Bitrate
        send_data += ((0x80).to_bytes(length=1, byteorder='little', signed=False))
        send_data += (12000000).to_bytes(length=4, byteorder='little', signed=False)
        
        ## WriteHciData
        # HciPacketType
        send_data += ((0x81).to_bytes(length=1, byteorder='little', signed=False))
        send_data += ((packet_type).to_bytes(length=1, byteorder='little', signed=False))

        # HciPacketData
        send_data += ((0x82).to_bytes(length=1, byteorder='little', signed=False))
        send_data += (data)
        #print("[")
        #print(''.join( [ "%02X " % x for x in send_data ] ).strip())
        #print ("]")
        self.send_to_sock(send_data)    

class BT_HCI(HighLevelAnalyzer):
    _instance = None
    type = 0
    data = bytearray()
    buffer = bytearray()
    start_time_prev = None
    start_time_curr = None
    incoming = False
    detected = False
    hci_instance = 0
    ellysis_hci_inj_obj = None
    Ellisys_HCI_Injection_Overview = ChoicesSetting(choices= HCI_OVERVIEW_CHOICES )
    Ellisys_UDP_Port_Optional = NumberSetting(min_value = 24352, max_value = 24360)

    def __new__(self, *args, **kwargs):
        if not self._instance:
            self._instance = super(BT_HCI, self).__new__(self, *args, **kwargs)
        return self._instance
        
    def __init__(self):
        print("Settings:", self.Ellisys_HCI_Injection_Overview, int(self.Ellisys_UDP_Port_Optional))
        if HCI_OVERVIEW_CHOICE2 in self.Ellisys_HCI_Injection_Overview:
            self.hci_instance = 1
        elif HCI_OVERVIEW_CHOICE3 in self.Ellisys_HCI_Injection_Overview:
            self.hci_instance = 2
        else:
            self.hci_instance = 0
        #print("self.hci_instance:", self.hci_instance)
        self.ellysis_hci_inj_obj = Ellysis_Hci_Injection(port = int(self.Ellisys_UDP_Port_Optional))

    def get_capabilities(self):
        print("get_capabilities")

    def set_settings(self, settings):
        print("set_settings")

    def process_byte(self, byte, timestamp):
        if self.type == 0:
            if byte in [0x30, 0x31, 0x32, 0x33]:
                # Skip any eHCI low power packets
                return
            if not byte in [1,2,4,5]:
                print ("Invalid packet type %x, , incoming %u" % (byte, self.incoming))
                return
            self.type = byte
            if self.start_time_curr is not None:
                self.start_time_prev = self.start_time_curr
                delta = float(timestamp - self.start_time_prev)*1000
                #print("delta:", str(delta))
            self.start_time_curr = timestamp

            self.timestamp = timestamp
            self.data = bytearray()

            # auto-detect RX and TX lines
            if not self.detected:
                # - packet type == HCI Event   => Controller TX - Host RX
                # - packet type == HCI Command => Controller RX - Host TX
                if self.type == 0x04:
                    self.detected = True
                    self.incoming = True
                if self.type == 0x01:
                    self.detected = True
                    self.incoming = False
            return

        self.data.append(byte)

    def packet_complete(self):
        if self.type == 1:
            if len(self.data) < 3:
                return False
            plen = 3 + self.data[2]
            return len(self.data) >= plen
        if self.type == 2:
            if len(self.data) < 4:
                return False
            plen = 4 + (self.data[2] | (self.data[3] << 8))
            return len(self.data) >= plen
        if self.type == 4:
            if len(self.data) < 2:
                return False
            plen = 2 + self.data[1]
            return len(self.data) >= plen
        if self.type == 5:
            if len(self.data) < 4:
                return False
            plen = 4 + (self.data[2] | (self.data[3] << 8))
            return len(self.data) >= plen
        return False

    def byte_to_str(self):
        return ''.join( [ "%02X " % x for x in self.data ] ).strip()

    def packet_log_type_for_hci_type_and_incoming(self):
        packet_log_type = -1
        if self.type == 1:
            packet_log_type = 0x01
        elif self.type == 0x02:
            if self.incoming:
                packet_log_type = 0x82
            else:
                packet_log_type = 0x02
        elif self.type == 0x04:
            packet_log_type = 0x84
        elif self.type == 5:
            if self.incoming:
                packet_log_type = 0x85
            else:
                packet_log_type = 0x05
        else:
            print('packet type %x' % self.type)
        return packet_log_type
        
    def reset(self):
        self.type = 0
        
    def decode(self, data):
      for key in data.data:
        if key == "data":
          self.process_byte(int.from_bytes(data.data[key], 'little'), data.start_time)
          if self.packet_complete():
             packet_log_type = self.packet_log_type_for_hci_type_and_incoming()
             self.ellysis_hci_inj_obj.generate_packet_n_send(packet_log_type,self.data,self.timestamp, self.hci_instance)
             self.reset()
