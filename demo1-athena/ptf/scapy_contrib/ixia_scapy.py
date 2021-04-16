# scapy packet layer for IXIA floating instrumenttion fragment inside payload
# scapy.contrib.description = IXIA-INSTRUMENTATION-PACKETS
# scapy.contrib.status = loads

from scapy.packet import Packet,bind_layers
from scapy.fields import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

class IXIA_FIXED_INSTRUM(Packet): 
   name = "IXIA_FIXED_INSTRUM" 
   fields_desc =  [ XIntField("signature", 0x87736749), 
                    XIntField("pgid", 0), 
                    IntField("seqnum", 0), 
                    IntField("tstamp", 0)  ] 

# bind_layers(IP, IXIA_FIXED_INSTRUM)
# bind_layers(UDP, IXIA_FIXED_INSTRUM)
# bind_layers(TCP, IXIA_FIXED_INSTRUM)

class IXIA_FLOAT_INSTRUM(Packet): 
   name = "IXIA_FLOAT_INSTRUM" 
   fields_desc =  [ XIntField("signature1", 0x87736749), 
                    XIntField("signature2", 0x42871180), 
                    XIntField("signature3", 0x08711805), 
                    XIntField("pgid", 0), 
                    IntField("seqnum", 0), 
                    IntField("tstamp", 0)  ] 

bind_layers(IP, IXIA_FLOAT_INSTRUM)
bind_layers(UDP, IXIA_FLOAT_INSTRUM)
bind_layers(TCP, IXIA_FLOAT_INSTRUM)
