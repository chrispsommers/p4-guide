# scapy packet layer for IXIA instrumentation fragment inside payload
# scapy.contrib.description = IXIA-INSTRUMENTATION-PACKETS
# scapy.contrib.status = loads

from scapy.packet import Packet,bind_layers
from scapy.fields import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

IXIA_SIG1=0x87736749
IXIA_SIG2=0x42871180
IXIA_SIG3=0x08711805

class IXIA_FIXED_INSTRUM(Packet): 
   name = "IXIA_FIXED_INSTRUM" 
   fields_desc =  [ XIntField("signature", IXIA_SIG1), 
                    XIntField("pgid", 0), 
                    IntField("seqnum", 0), 
                    IntField("tstamp", 0)  ] 

class IXIA_FLOAT_INSTRUM(Packet): 
   name = "IXIA_FLOAT_INSTRUM" 
   fields_desc =  [ XIntField("signature1", IXIA_SIG1), 
                    XIntField("signature2", 0x42871180), 
                    XIntField("signature3", 0x08711805), 
                    XIntField("pgid", 0), 
                    IntField("seqnum", 0), 
                    IntField("tstamp", 0)  ] 


def guess_ixia_default_payload_class(self, payload):
    # Look for IXIA if no other layer found
   b = bytes(payload)
   if len(b) >= 4 and int.from_bytes(b[0:4],'big') == IXIA_SIG1:
      if len(b) >= 12 and int.from_bytes(b[4:8],'big') == IXIA_SIG2 and int.from_bytes(b[8:12],'big') == IXIA_SIG3:
         return IXIA_FLOAT_INSTRUM
      else:
         return IXIA_FIXED_INSTRUM
   else:
        return conf.raw_layer

Packet.default_payload_class = guess_ixia_default_payload_class


if __name__ == '__main__':
   """ Simple verificaiton of IXIA packet decode """
   p1=Ether()/IP()/TCP()/IXIA_FLOAT_INSTRUM()
   b=bytes(p1)
   p1a = Ether(b)
   p1a.show()

   p2=Ether()/IP()/UDP()/IXIA_FIXED_INSTRUM()
   b=bytes(p2)
   p2a = Ether(b)
   p2a.show()