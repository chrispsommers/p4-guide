import sys
import copy
import logging
import types
import time
import re

import ptf
import ptf.dataplane
import ptf.parse
import ptf.ptfutils
from ptf.testutils import *
from ptf.thriftutils import *
import ptf.packet as scapy
from ixia_scapy import *
# Some useful defines
IP_ETHERTYPE = 0x800
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11
MINSIZE = 0
# Default floating signature byes in groups of 4
SIGNATURE1=0x87736749
SIGNATURE2=0x42871180
SIGNATURE3=0x08711805
ETH_ONLY_ETHERTYPE=0xffff

def int_to_bytes(value, length):
    result = []

    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)
    result.reverse()
    return result

def i16_to_bytes(value):
    return int_to_bytes(value,2)
  
def i32_to_bytes(value):
    return int_to_bytes(value,4)

def Raw_i32(value):
    return Raw(bytes_to_string(i32_to_bytes(value)))

def Raw_i16(value):
    return Raw(bytes_to_string(i16_to_bytes(value)))


def pad(val=0,size=0):
    return ("".join([chr(val) for x in range(size)]))

def ip_make_tos(tos, ecn, dscp):
    if ecn is not None:
        tos = (tos & ~(0x3)) | ecn

    if dscp is not None:
        tos = (tos & ~(0xfc)) | (dscp << 2)

    return tos

def pkt_layers(p):
    # https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
    layers = []
    counter = 0
    while True:
        layer =p.getlayer(counter)
        if (layer != None):
            layers.append(layer.name)
        else:
            break
        counter += 1
    return layers

def pkt_layers_str(p):
    return ":".join(pkt_layers(p))
    
def verify_multiple_packets(test, port, pkts=[], pkt_lens=[], device_number=0, tmo=None, slack=0):

    """
    Checks for packets on a specific port, and compares them to a list of packets provided
    by the user. This is useful where the order of the packet arrival is unknown
    For e.g., if the ingress ports are different
    """


    rx_pkt_status = [False] * len(pkts)
    if tmo is None:
        tmo = ptf.ptfutils.default_negative_timeout
    rx_pkts = 0
    while rx_pkts < len(pkts):
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
                test,
                device_number=device_number,
                port_number=port,
                timeout=tmo)
        if not rcv_pkt:
            if slack:
                test.assertTrue((slack > (len(pkts) - rx_pkts)), "Timeout:Port[%d]:Got:[%d]:Allowed slack[%d]:Left[%d]\n" %(port, rx_pkts, slack, len(pkts)-rx_pkts))
                return
            else:
                print "No more packets but still expecting", len(pkts)-rx_pkts
                sys.stdout.flush()
                for i, a_pkt in enumerate(pkts):
                    #print rx_pkt_status[i]
                    #print format_packet(a_pkt)
                    if not rx_pkt_status[i]:
                        print format_packet(a_pkt)
                sys.stdout.flush()
                test.assertTrue(False, "Timeout:Port:[%d]:Got[%d]:Left[%d]\n" %(port,rx_pkts,len(pkts)-rx_pkts))
                return

        rx_pkts = rx_pkts + 1
        found = False
        for i, a_pkt in enumerate(pkts):
            if str(a_pkt) == str(rcv_pkt[:pkt_lens[i]]) and not rx_pkt_status[i]:
                rx_pkt_status[i] = True
                found = True
                break
        if not found:
            test.assertTrue(False, "RxPort:[%u]:Pkt#[%u]:Pkt:%s:Unmatched\n" %(port, rx_pkts, ":".join("{:02x}".format(ord(c)) for c in rcv_pkt[:pkt_lens[0]])))

########################### IXIA Packet Types ##############################################

pkt_types = {
    'ixeth':'ixia_eth_packet_fixed_instrum',
    'ixip':'ixia_ip_packet_fixed_instrum',
    'ixudp':'ixia_udp_packet_fixed_instrum',
    'ixtcp':'ixia_tcp_packet_fixed_instrum',

    'ixethf':'ixia_eth_packet_floating_instrum',
    'ixipf':'ixia_ip_packet_floating_instrum',
    'ixudpf':'ixia_udp_packet_floating_instrum',
    'ixtcpf':'ixia_tcp_packet_floating_instrum',
}

def map_test_packet_type(nickname):
    if nickname in pkt_types.keys():
        return pkt_types[nickname]
    else:
        print "ERROR - packet nickname '%s' unknown" % nickname
        print "KNOWN TYPES:", pkt_types
        return None

def make_test_packet(packet_type, pipe=None, app=None, **kwargs):
    # TODO - type per app[]
    return eval (packet_type)(**kwargs)

def ixia_tcp_packet_floating_instrum(
                        _sig1=SIGNATURE1,
                        _sig2=SIGNATURE2,
                        _sig3=SIGNATURE3,
                        _sig_offset=0,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
                        has_fake_ig_tstamp=False,
                        fake_ig_tstamp=0, 
                        pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='de:ad:be:ef:ba:be',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.193.194.195',
                        ip_dst='208.209.210.211',
                        ip_tos=0,
                        ip_ecn=None,
                        ip_dscp=None,
                        ip_ttl=64,
                        ip_id=0x0001,
                        ip_frag=0,
                        tcp_sport=1234,
                        tcp_dport=80,
                        tcp_flags="S",
                        ip_ihl=None,
                        ip_options=False,
                        with_tcp_chksum=True
                      ):
    """
    Return a simple dataplane TCP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param tcp_dport TCP destination port
    @param tcp_sport TCP source port
    @param tcp_flags TCP Control flags
    @param with_tcp_chksum Valid TCP checksum

    Generates a simple TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_tcp_chksum:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    else:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            tcp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, frag=ip_frag)/ \
                tcp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, frag=ip_frag, options=ip_options)/ \
                tcp_hdr
    instrum_frag = IXIA_FLOAT_INSTRUM(signature1=_sig1, signature2=_sig2, signature3=_sig3,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag
    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))

    return pkt

def ixia_udp_packet_floating_instrum(
                        _sig1=SIGNATURE1,
                        _sig2=SIGNATURE2,
                        _sig3=SIGNATURE3,
                        _sig_offset=0,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
                        has_fake_ig_tstamp=False,
                        fake_ig_tstamp=0, 
                        pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='de:ad:be:ef:ba:be',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.193.194.195',
                        ip_dst='208.209.210.211',
                        ip_tos=0,
                        ip_ecn=None,
                        ip_dscp=None,
                        ip_ttl=64,
                        udp_sport=1234,
                        udp_dport=80,
                        ip_ihl=None,
                        ip_options=False,
                        ip_flag=0,
                        ip_id=1,
                        with_udp_chksum=True,
                        udp_payload=None
                      ):
    """
    Return a simple dataplane UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_dport UDP destination port
    @param udp_sport UDP source port
    @param with_udp_chksum Valid UDP checksum
    @param udp_payload optional; added AFTER intrumentation


    Generates a simple UDP packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id)/ \
            udp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id, flags=ip_flag)/ \
                udp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, options=ip_options, id=ip_id, flags=ip_flag)/ \
                udp_hdr

    instrum_frag = IXIA_FLOAT_INSTRUM(signature1=_sig1, signature2=_sig2, signature3=_sig3,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag

    if udp_payload:
        pkt = pkt/udp_payload

    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))
    if len(pkt) > pktlen:
        print ("WARNING: Minimum packet type '%s' has len=%d; this exceeds requested pktlen=%d" %
         ("ixia_udp_packet_floating_instrum", len(pkt), pktlen))
    return pkt

def ixia_eth_packet_floating_instrum(
                    _sig1=SIGNATURE1,
                    _sig2=SIGNATURE2,
                    _sig3=SIGNATURE3,
                    _sig_offset=0,
                    _pgid=0,
                    _tstamp=0,
                    _seqnum=0,
                    has_fake_ig_tstamp=False,
                    fake_ig_tstamp=0, 
                    pktlen=60,
                    eth_dst='00:01:02:03:04:05',
                    eth_src='de:ad:be:ef:ba:be',
                    eth_type=ETH_ONLY_ETHERTYPE
                ):

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src, type=eth_type)

    instrum_frag = IXIA_FLOAT_INSTRUM(signature1=_sig1, signature2=_sig2, signature3=_sig3,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag

    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))

    return pkt

def ixia_ip_packet_floating_instrum(
                        _sig1=SIGNATURE1,
                        _sig2=SIGNATURE2,
                        _sig3=SIGNATURE3,
                        _sig_offset=0,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
                        has_fake_ig_tstamp=False,
                        fake_ig_tstamp=0, 
                        pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='de:ad:be:ef:ba:be',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.193.194.195',
                        ip_dst='208.209.210.211',
                        ip_tos=0,
                        ip_ecn=None,
                        ip_dscp=None,
                        ip_ttl=64,
                        ip_id=0x0001,
                        ip_ihl=None,
                        ip_options=False,
                        ip_proto=0
                     ):
    """
    Return a simple dataplane IP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID

    Generates a simple IP packet.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, proto=ip_proto)
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, proto=ip_proto)
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, proto=ip_proto, options=ip_options)

 
    instrum_frag = IXIA_FLOAT_INSTRUM(signature1=_sig1, signature2=_sig2, signature3=_sig3,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag

    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))

    return pkt

def ixia_tcp_packet_fixed_instrum(
                        _sig=SIGNATURE1,
                        _sig_offset=0,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
                        has_fake_ig_tstamp=False,
                        fake_ig_tstamp=0, 
                        pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='de:ad:be:ef:ba:be',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.193.194.195',
                        ip_dst='208.209.210.211',
                        ip_tos=0,
                        ip_ecn=None,
                        ip_dscp=None,
                        ip_ttl=64,
                        ip_id=0x0001,
                        ip_frag=0,
                        tcp_sport=1234,
                        tcp_dport=80,
                        tcp_flags="S",
                        ip_ihl=None,
                        ip_options=False,
                        with_tcp_chksum=True
                      ):
    """
    Return a simple dataplane TCP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param tcp_dport TCP destination port
    @param tcp_sport TCP source port
    @param tcp_flags TCP Control flags
    @param with_tcp_chksum Valid TCP checksum

    Generates a simple TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_tcp_chksum:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    else:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            tcp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, frag=ip_frag)/ \
                tcp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, frag=ip_frag, options=ip_options)/ \
                tcp_hdr
    instrum_frag = IXIA_FIXED_INSTRUM(signature=_sig,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag
    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))

    return pkt

def ixia_udp_packet_fixed_instrum(
                        _sig=SIGNATURE1,
                        _sig_offset=0,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
                        has_fake_ig_tstamp=False,
                        fake_ig_tstamp=0, 
                        pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='de:ad:be:ef:ba:be',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.193.194.195',
                        ip_dst='208.209.210.211',
                        ip_tos=0,
                        ip_ecn=None,
                        ip_dscp=None,
                        ip_ttl=64,
                        udp_sport=1234,
                        udp_dport=80,
                        ip_ihl=None,
                        ip_options=False,
                        ip_flag=0,
                        ip_id=1,
                        with_udp_chksum=True,
                        udp_payload=None
                      ):
    """
    Return a simple dataplane UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_dport UDP destination port
    @param udp_sport UDP source port
    @param with_udp_chksum Valid UDP checksum
    @param udp_payload optional; added AFTER intrumentation


    Generates a simple UDP packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id)/ \
            udp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id, flags=ip_flag)/ \
                udp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, options=ip_options, id=ip_id, flags=ip_flag)/ \
                udp_hdr

    instrum_frag = IXIA_FIXED_INSTRUM(signature=_sig,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag

    if udp_payload:
        pkt = pkt/udp_payload

    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))
    if len(pkt) > pktlen:
        print ("WARNING: Minimum packet type '%s' has len=%d; this exceeds requested pktlen=%d" %
         ("ixia_udp_packet_fixed_instrum", len(pkt), pktlen))
    return pkt

def ixia_eth_packet_fixed_instrum(
                    _sig=SIGNATURE1,
                    _sig_offset=0,
                    _pgid=0,
                    _tstamp=0,
                    _seqnum=0,
                    has_fake_ig_tstamp=False,
                    fake_ig_tstamp=0, 
                    pktlen=60,
                    eth_dst='00:01:02:03:04:05',
                    eth_src='de:ad:be:ef:ba:be',
                    eth_type=ETH_ONLY_ETHERTYPE
                ):

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src, type=eth_type)

    instrum_frag = IXIA_FIXED_INSTRUM(signature=_sig,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag

    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))

    return pkt

def ixia_ip_packet_fixed_instrum(
                        _sig=SIGNATURE1,
                        _sig_offset=0,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
                        has_fake_ig_tstamp=False,
                        fake_ig_tstamp=0, 
                        pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='de:ad:be:ef:ba:be',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.193.194.195',
                        ip_dst='208.209.210.211',
                        ip_tos=0,
                        ip_ecn=None,
                        ip_dscp=None,
                        ip_ttl=64,
                        ip_id=0x0001,
                        ip_ihl=None,
                        ip_options=False,
                        ip_proto=0
                     ):
    """
    Return a simple dataplane IP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID

    Generates a simple IP packet.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, proto=ip_proto)
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, proto=ip_proto)
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, proto=ip_proto, options=ip_options)

 
    instrum_frag = IXIA_FIXED_INSTRUM(signature=_sig,
                        pgid=_pgid, tstamp=_tstamp, seqnum=_seqnum)
    pkt = pkt / instrum_frag

    pkt = pkt/("".join([chr(x % 256) for x in xrange(pktlen - len(pkt))]))
    if len(pkt) > pktlen:
        print ("WARNING: Minimum packet type '%s' has len=%d; this exceeds requested pktlen=%d" %
         ("ixia_ip_packet_fixed_instrum", len(pkt), pktlen))

    return pkt

