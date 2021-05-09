import ptf.packet as scapy
from ixia_scapy import *
# Some useful defines
IP_ETHERTYPE = 0x800
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11
MINSIZE = 0
# Default floating signature bytes in groups of 4
SIGNATURE1=0x87736749
SIGNATURE2=0x42871180
SIGNATURE3=0x08711805
ETH_ONLY_ETHERTYPE=0xffff

def ip_make_tos(tos, ecn, dscp):
    if ecn is not None:
        tos = (tos & ~(0x3)) | ecn

    if dscp is not None:
        tos = (tos & ~(0xfc)) | (dscp << 2)

    return tos

def pkt_layers(p):
    # https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
    layers = []
    layer_num = 0
    while True:
        layer =p.getlayer(layer_num)
        if (layer != None):
            layers.append(layer.name)
        else:
            break
        layer_num += 1
    return layers

def pkt_layers_str(p):
    return ":".join(pkt_layers(p))

########################### IXIA Packet Types ##############################################

def fill_payload(pkt, pktlen, payload_pattern='zeroes'):
    if payload_pattern == 'increment':
        pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))
    elif payload_pattern == 'zeroes':
        pkt = pkt/("".join([chr(0) for x in range(pktlen - len(pkt))]))
    else:
        pkt = pkt/("".join([chr(0) for x in range(pktlen - len(pkt))]))
    return pkt

def ixia_tcp_packet_floating_instrum(
                        _sig1=SIGNATURE1,
                        _sig2=SIGNATURE2,
                        _sig3=SIGNATURE3,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
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
                        ip_id=0,
                        ip_frag=0,
                        tcp_sport=1234,
                        tcp_dport=80,
                        tcp_flags=0,
                        ip_ihl=None,
                        ip_options=False,
                        with_tcp_chksum=True,
                        tcp_window=8192,
                        payload_pattern='zeroes'
                      ):
    """
    Return a simple dataplane TCP packet with IXIA_FIXED_INSTRUM header following TCP 

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
    @param payload_pattern 'zeroes','increment'

    Generates a simple TCP packet. Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_tcp_chksum:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, window=tcp_window)
    else:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, window=tcp_window, chksum=0)

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
    fill_payload(pkt, pktlen, payload_pattern)
    return fill_payload(pkt, pktlen, payload_pattern)


def ixia_udp_packet_floating_instrum(
                        _sig1=SIGNATURE1,
                        _sig2=SIGNATURE2,
                        _sig3=SIGNATURE3,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
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
                        ip_id=0,
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

    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))
    if len(pkt) > pktlen:
        print ("WARNING: Minimum packet type '%s' has len=%d; this exceeds requested pktlen=%d" %
         ("ixia_udp_packet_floating_instrum", len(pkt), pktlen))
    return pkt

def ixia_eth_packet_floating_instrum(
                    _sig1=SIGNATURE1,
                    _sig2=SIGNATURE2,
                    _sig3=SIGNATURE3,
                    _pgid=0,
                    _tstamp=0,
                    _seqnum=0,
                    pktlen=100,
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

    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))

    return pkt

def ixia_ip_packet_floating_instrum(
                        _sig1=SIGNATURE1,
                        _sig2=SIGNATURE2,
                        _sig3=SIGNATURE3,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
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
                        ip_id=0,
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

    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))

    return pkt

def ixia_tcp_packet_fixed_instrum(
                        _sig=SIGNATURE1,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
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
                        ip_id=0,
                        ip_frag=0,
                        tcp_sport=1234,
                        tcp_dport=80,
                        tcp_flags=0,
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
    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))

    return pkt

def ixia_udp_packet_fixed_instrum(
                        _sig=SIGNATURE1,
                        _pgid=0,
                        _tstamp=0,
                        _seqnum=0,
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
                        ip_id=0,
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

    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))
    if len(pkt) > pktlen:
        print ("WARNING: Minimum packet type '%s' has len=%d; this exceeds requested pktlen=%d" %
         ("ixia_udp_packet_fixed_instrum", len(pkt), pktlen))
    return pkt

def ixia_eth_packet_fixed_instrum(
                    _sig=SIGNATURE1,
                    _pgid=0,
                    _tstamp=0,
                    _seqnum=0,
                    pktlen=100,
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

    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))

    return pkt

def ixia_ip_packet_fixed_instrum(
                        _sig=SIGNATURE1,
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
                        ip_id=0,
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

    pkt = pkt/("".join([chr(x % 256) for x in range(pktlen - len(pkt))]))
    if len(pkt) > pktlen:
        print ("WARNING: Minimum packet type '%s' has len=%d; this exceeds requested pktlen=%d" %
         ("ixia_ip_packet_fixed_instrum", len(pkt), pktlen))

    return pkt


def compare_pkts2(pkt1, pkt2,
                no_ip_chksum=False,
                no_tcp_chksum=False,
                no_payload=False,
                no_tstamp=False):
    """ Compare two packets, optionally skipping some parts
        return bool, string, masked pkt1, masked pkt2
        where bool = True if masked packets match,
        string = reason for mismatch,
        masked pkt1, masked pk2 = modified copies of input pkts as used for comparison
        after applying masking of selected fields per the "no_xx" flags 
    """

    # make copies, blank out fields per compare flags
    p1=pkt1.copy()
    p2=pkt2.copy()
    l='Ether'
    if pkt1.haslayer(l) or pkt2.haslayer(l):
        if not pkt1.haslayer(l):
            return False, "pkt1 missing %s layer" % l, p1, p2
        if not pkt2.haslayer(l):
            return False, "pkt2 missing %s layer" % l, p1, p2
    l='IP'
    if pkt1.haslayer(l) or pkt2.haslayer(l):
        if not pkt1.haslayer(l):
            return False, "pkt1 missing %s layer" % l, p1, p2
        if not pkt2.haslayer(l):
            return False, "pkt2 missing %s layer" % l, p1, p2

        if no_ip_chksum:
            p1[IP].chksum=0
            p2[IP].chksum=0

    l='TCP'
    if pkt1.haslayer(l) or pkt2.haslayer(l):
        if not pkt1.haslayer(l):
            return False, "pkt1 missing %s layer" % l, p1, p2
        if not pkt2.haslayer(l):
            return False, "pkt2 missing %s layer" % l, p1, p2

        if no_tcp_chksum:
            p1[TCP].chksum=0
            p2[TCP].chksum=0


    l='IXIA_FLOAT_INSTRUM'
    if pkt1.haslayer(l) or pkt2.haslayer(l):
        if not pkt1.haslayer(l):
            return False, "pkt1 missing %s layer" % l, p1, p2
        if not pkt2.haslayer(l):
            return False, "pkt2 missing %s layer" % l, p1, p2

        if no_tstamp:
            p1[IXIA_FLOAT_INSTRUM].tstamp=0
            p2[IXIA_FLOAT_INSTRUM].tstamp=0

    
    if len(pkt1) != len(pkt2):
        return False, 'unequal len: pkt1=%d,pkt2=%d' % (len(pkt1), len(pkt2)), p1, p2

    # Optionally remove raw/padding payloads
    if no_payload:
        if p1.haslayer(IXIA_FLOAT_INSTRUM):
            p1.getlayer(IXIA_FLOAT_INSTRUM).remove_payload()
        if p2.haslayer(IXIA_FLOAT_INSTRUM):
            p2.getlayer(IXIA_FLOAT_INSTRUM).remove_payload()

    
    if str(p1) != str(p2):
        print ("Layers: %s != %s " % (pkt_layers_str(p1), pkt_layers_str(p1)))
        return False, "Mismatched", p1,p2
    # else:
    #     print ("Matched %s layers: %s == %s" % (l, str(p1),str(p2)))

    return True, "", p1,p2
