#!/usr/bin/env python3

# Copyright 2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Andy Fingerhut, andy.fingerhut@gmail.com

# Modifications Copyright 2021 Keysight Technologies

import logging
import ptf
import os
import time
from ptf import config
import ptf.testutils as tu
import urllib3
from google.rpc import code_pb2

import base_test as bt

import snappi
import utils
import dpkt, sys

# Ixia packets
sys.path.append(os.path.join(os.path.dirname(__file__), '', 'scapy_contrib'))
from ixia_scapy import * 
from pktUtils import * 

logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

class Demo1TestBase(bt.P4RuntimeTest):
    def setUp(self):
        bt.P4RuntimeTest.setUp(self)

    #############################################################
    # Define a few small helper functions that help construct
    # parameters for the table_add() method.
    #############################################################

    def key_ipv4_da_lpm(self, ipv4_addr_string, prefix_len):
        return ('ipv4_da_lpm',
                [self.Lpm('hdr.ipv4.dstAddr',
                          bt.ipv4_to_int(ipv4_addr_string), prefix_len)])

    def act_set_l2ptr(self, l2ptr_int):
        return ('set_l2ptr', [('l2ptr', l2ptr_int)])

    def key_mac_da(self, l2ptr_int):
        return ('mac_da', [self.Exact('meta.fwd_metadata.l2ptr', l2ptr_int)])

    def act_set_bd_dmac_intf(self, bd_int, dmac_string, intf_int):
        return ('set_bd_dmac_intf',
                [('bd', bd_int),
                 ('dmac', bt.mac_to_int(dmac_string)),
                 ('intf', intf_int)])

    def key_send_frame(self, bd_int):
        return ('send_frame', [self.Exact('meta.fwd_metadata.out_bd', bd_int)])

    def act_rewrite_mac(self, smac_string):
        return ('rewrite_mac', [('smac', bt.mac_to_int(smac_string))])

class Demo1Test(Demo1TestBase):
    def setUp(self):
        bt.P4RuntimeTest.setUp(self)
        # This setUp method will be executed once for each test case.
        # It may be a little bit wasteful in time to load the compiled
        # P4 program for each test, but for only a few tests it is
        # still quick.  Suggestions welcome on good ways to load the
        # compiled P4 program only once, yet still allow someone to
        # select a subset of the test cases to be run from the `ptf`
        # command line.
        print ("\n\n***************\nLoading P4 Program...\n***************\n")
        success = bt.P4RuntimeTest.updateConfig(self)
        assert success


######################## snappi tests #########################

def print_pkts_side_by_side(p1,p2):
    exl=len(p1)
    bex=bytes(p1)
    rxl=len(p2)
    brx=bytes(p2)
    maxlen= rxl if rxl>exl else exl

    print ("Byte#\t Exp \t Eq?\t Rx\n")
    for i in range(maxlen):
        if i < exl and i < rxl:
            print ("[%d]\t %02x\t %s\t %02x" % (i, bex[i], "==" if brx[i]==bex[i] else "!=", brx[i]) )
        elif i < exl:
            print ("[%d]\t %02x\t %s\t %s" % (i, bex[i], "!=", "--") )
        else:
            print ("[%d]\t %s\t %s\t %02x" % (i, "--", "!=", brx[i]) )

class SnappiPtfUtils():
    """
    Convenience methods to simplify converting PTF tests to use snappi instead of scapy
    """

    def start_capture(api, cap_port_names):
        """ Start a capture which was already configured.
        api - snappi api handle
        cap_port_names - a [list] of ports to be captured
        """
        capture_state = api.capture_state()
        capture_state.state = 'start'
        capture_state.port_names = cap_port_names
        print('Starting capture on ports %s ...' % str(cap_port_names))
        res = api.set_capture_state(capture_state)
        if len(res.errors):
            print (str(res.errors))
        assert len(res.errors) == 0, str(res.errors)

    def start_traffic(api):
        """ Start traffic flow(s) whicih are already configured.
        api - snappi api handle
        """
        ts = api.transmit_state()
        ts.state = ts.START
        # Alternate semantics:
        # transmit_state.state = 'start'
        print('Starting traffic')
        res = api.set_transmit_state(ts)
        if len(res.errors):
            print (str(res.errors))
        assert len(res.errors) == 0, str(res.errors)

    def verify_no_other_packets(api, cap_port_names):
        """ Returns true if no bytes captured on a port
        api - snappi API handle
        cap_port_names - list of ports to examine
        returns True if condition passes, else asserts
        """
        for name in cap_port_names:
            print('Fetching capture from port %s' % name)
            capture_req = api.capture_request()
            capture_req.port_name = name
            pcap_bytes = api.get_capture(capture_req)
            print('Verifying empty capture from port %s' % name)
            assert not any(pcap_bytes), "Found packet(s) on %s" % name
        return True

    def verify_capture_on_port(api, exp_pkt, cap_port_name, pkt_compare_func=compare_pkts2):
        """ Returns true if last packet captured on specified port matches exp_packet
        api - snappi API handle
        exp_pkt - expected packet
        cap_port_name - single port to examine
        pkt_compare_func - optional custom compare function, allows ignoring selected fields, for example
        """
        cap_dict = {}
        print('Fetching capture from port %s' % cap_port_name)
        capture_req = api.capture_request()
        capture_req.port_name = cap_port_name
        pcap_bytes = api.get_capture(capture_req)

        cap_dict[cap_port_name] = []
        # assert any(pcap_bytes), "No packets captured on %s" % cap_port_name
        for ts, pkt in dpkt.pcap.Reader(pcap_bytes):
            if sys.version_info[0] == 2:
                raw = [ ord(b) for b in pkt]
            else:
                raw = list(pkt)
            cap_dict[cap_port_name].append(raw)

        brx = bytes(cap_dict[cap_port_name][-1]) # last pkt
        rx_pkt = Ether(brx)

        (equal, reason, p1,p2) = pkt_compare_func(exp_pkt, rx_pkt)

        if not equal:
            print ("Mismatched %s" % ( reason))
            print("\nExpected (masked):\n===============")
            p1.show()

            print("\nReceived (masked):\n===============")
            p2.show()

            print_pkts_side_by_side(p1,p2)

            assert equal, "Packets don't match: %s != %s" % (str(p1), str(p2))
        return True

    def verify_captures_on_port(api, exp_pkts, cap_port_name, pkt_compare_func=compare_pkts2):
        """ Returns true if all packets captured on specified port matches list of exp_packets
        Throws assertion if not true
        api - snappi API handle
        exp_pkts - list of expected packets
        cap_port_name - single port to examine
        pkt_compare_func - optional custom compare function, allows ignoring selected fields, for example
        """
        cap_dict = {}
        print('Fetching capture from port %s' % cap_port_name)
        capture_req = api.capture_request()
        capture_req.port_name = cap_port_name
        pcap_bytes = api.get_capture(capture_req)

        cap_dict[cap_port_name] = []
        # assert any(pcap_bytes), "No packets captured on %s" % cap_port_name
        for ts, pkt in dpkt.pcap.Reader(pcap_bytes):
            if sys.version_info[0] == 2:
                raw = [ ord(b) for b in pkt]
            else:
                raw = list(pkt)
            cap_dict[cap_port_name].append(raw)

        cap_pkts = cap_dict[cap_port_name]
        assert len(exp_pkts) == len(cap_pkts), "Expected %d pkts, captured %d" % (len(exp_pkts), len(cap_pkts))

        print ("Comparing %d expected pkts to %d captured pkts" % ( len(exp_pkts), len(cap_pkts)))
        
        i = 0;
        for pkt in cap_pkts:
            brx = bytes(cap_pkts[i])
            rx_pkt = Ether(brx)

            # print("[%d] %s =? %s" % (i, exp_pkts[i], rx_pkt))
            (equal, reason, p1,p2) = pkt_compare_func(exp_pkts[i], rx_pkt)

            if not equal:
                print ("Mismatched pkt #%d: %s" % (i, reason))
                print("\nExpected (masked):\n===============")
                p1.show()

                print("\nReceived (masked):\n===============")
                p2.show()

                print_pkts_side_by_side(p1,p2)

                assert equal, "Packets don't match: %s != %s" % (str(p1), str(p2))
            i+= 1
        return True


def results_ok(api, cfg, csv_dir=None):
    """
    Returns true if stats are as expected, false otherwise.
    """
    port_results, flow_results = utils.get_all_stats(api, print_output=False)
    if csv_dir is not None:
        utils.print_csv(csv_dir, port_results, flow_results)
    port_tx = sum([p.frames_tx for p in port_results if p.name == 'tx'])
    port_rx = sum([p.frames_rx for p in port_results if p.name == 'rx'])

    return port_tx == port_rx and all(
        [f.transmit == 'stopped' for f in flow_results]
    )

class SnappiFwdTestBase(Demo1Test):
    def setUp(self):
        Demo1Test.setUp(self)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Silence inecure warnings
        self.api = snappi.api(host='https://localhost:8080')

    def pkt_compare_func(self, exp_pkt, rx_pkt):
        """ Packet compare callback to filter certain fields"""
        return compare_pkts2(exp_pkt, rx_pkt,
                                        # no_payload=True,
                                        no_ip_chksum=True,
                                        no_tcp_chksum=True,
                                        no_tstamp=True)

class SnappiFwdTestJson(SnappiFwdTestBase):
    def setUp(self):
        SnappiFwdTestBase.setUp(self)

    @bt.autocleanup
    def runTest(self):

        # Config method 1 - use config file to configure flows, merge in settings.json
        # Note this method requires xternal JSON file be in sync with the P4 table programming values
        # and packet compare values defined below, which could be a maintenance burden
        self.cfg = utils.common.load_test_config(
            self.api, 'demo1-athena-packet-config.json', apply_settings=True
        )
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        ip_dst_addr = '10.1.0.1'
        ip_src_addr='192.168.0.1'
        ig_port = 1

        eg_port = 2
        l2ptr = 58
        bd = 9
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'

        print ("Send packet prior to configuring tables, verify packets are dropped...")
        capture_port_name = 'port2'
        SnappiPtfUtils.start_capture(self.api, [capture_port_name])
        SnappiPtfUtils.start_traffic(self.api)
        # Snappi flow-based test for dropped packets:
        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        assert all([stat.frames_rx == 0 for stat in flow_results]), "Received unexpected frames" 
        # Traditional PTF port-based test for dropped packets:
        assert(SnappiPtfUtils.verify_no_other_packets(self.api, [capture_port_name]))
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC addresses.
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))

        exp_pkt = ixia_tcp_packet_floating_instrum(eth_src=out_smac, eth_dst=out_dmac, pktlen=96,
                                ip_src=ip_src_addr, ip_dst=ip_dst_addr, ip_ttl=63, tcp_window=0)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt = Ether(exp_pkt.build())

        print ("Send packet after configuring tables, verify captured packets byte-by-byte...")
        SnappiPtfUtils.start_capture(self.api, [capture_port_name])
        SnappiPtfUtils.start_traffic(self.api)

        utils.wait_for(
            lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
            interval_seconds=2, timeout_seconds=10
        )
        SnappiPtfUtils.verify_capture_on_port(self.api, exp_pkt, capture_port_name, self.pkt_compare_func)

class SnappiFwdTest(SnappiFwdTestBase):
    def setUp(self):
        SnappiFwdTestBase.setUp(self)

    @bt.autocleanup
    def runTest(self):
        # Config method 2 - use inline snappi code to configure flows
        self.cfg = self.api.config()
        # when using ixnetwork extension, port location is chassis-ip;card-id;port-id
        port1, port2 = (
            self.cfg.ports
            .port(name='port1', location='localhost:5555')
            .port(name='port2', location='localhost:5556')
        )

        # configure layer 1 properties
        layer1, = self.cfg.layer1.layer1(name='layer1')
        layer1.port_names = [port1.name, port2.name]
        layer1.speed = layer1.SPEED_1_GBPS

        # Define capture properties
        cap = self.cfg.captures.capture(name='c1')[0]
        cap.port_names = [port2.name]
        cap.format = 'pcap'

        # layer1.media = layer1.FIBER
        # configure flow properties
        flow1 = self.cfg.flows.flow(name='port1-2')[-1]
        # flow endpoints
        flow1.tx_rx.port.tx_name = port1.name
        flow1.tx_rx.port.rx_name = port2.name
        # configure rate, size, frame count
        flow1.size.fixed = 100
        flow1.rate.percentage = 10
        flow1.duration.fixed_packets.packets = 1
        # configure protocol headers with defaults fields
        flow1.packet.ethernet().ipv4().tcp()

        # Header values used to define packet contents, will be reused in P4 table entries
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        ip_dst_addr = '10.1.0.1'
        ip_src_addr='192.168.0.1'

        eth = flow1.packet[0]
        eth.src.value = in_smac
        eth.dst.value = in_dmac

        ipv4 = flow1.packet[1]
        ipv4.dst.value = ip_dst_addr
        ipv4.src.value = ip_src_addr
        ipv4.time_to_live.value = 64

        tcp = flow1.packet[2]
        tcp.src_port.value = 1234
        tcp.dst_port.value = 80

        # push configuration
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)

        print ("Send packet prior to configuring tables, verify packets are dropped...")
        capture_port_name = 'port2'
        SnappiPtfUtils.start_capture(self.api, [capture_port_name])
        SnappiPtfUtils.start_traffic(self.api)
        # Snappi flow-based test for dropped packets:
        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        assert all([stat.frames_rx == 0 for stat in flow_results]), "Received unexpected frames" 
        # Traditional PTF port-based test for dropped packets:
        assert(SnappiPtfUtils.verify_no_other_packets(self.api, [capture_port_name]))
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.

        # Add'l match-action table values:
        ig_port = 1
        eg_port = 2
        l2ptr = 58
        bd = 9
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))

        # Config, capture and start all in one
        # utils.common.start_traffic(self.api, self.cfg) - error, port 1 not a capture port

        exp_pkt = ixia_tcp_packet_floating_instrum(eth_src=out_smac, eth_dst=out_dmac, pktlen=96,
                                ip_src=ip_src_addr, ip_dst=ip_dst_addr, ip_ttl=63, tcp_window=0)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt = Ether(exp_pkt.build())

        capture_port_name = 'port2'
        SnappiPtfUtils.start_capture(self.api, [capture_port_name])
        SnappiPtfUtils.start_traffic(self.api)

        utils.wait_for(
            lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
            interval_seconds=2, timeout_seconds=10
        )
        SnappiPtfUtils.verify_capture_on_port(self.api, exp_pkt, capture_port_name, self.pkt_compare_func)
            
            


class SnappiFwdTestJsonBidir(SnappiFwdTestBase):
    def setUp(self):
        SnappiFwdTestBase.setUp(self)

    @bt.autocleanup
    def runTest(self):

        # Config method 1 - use config file to configure flows, merge in settings.json
        # Note this method requires xternal JSON file be in sync with the P4 table programming values
        # and packet compare values defined below, which could be a maintenance burden
        self.cfg = utils.common.load_test_config(
            self.api, 'demo1-athena-packet-config-bidir.json', apply_settings=True
        )
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)

        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        ip_dst_addr = '10.1.0.1'
        ip_src_addr='192.168.0.1'
        ig_port = 1

        eg_port = 2
        l2ptr = 58
        bd = 9
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'

        capture_port_names = ['port1', 'port2']
        print ("Send packet prior to configuring tables, verify packets are dropped...")
        SnappiPtfUtils.start_capture(self.api, capture_port_names)
        SnappiPtfUtils.start_traffic(self.api)
        assert(SnappiPtfUtils.verify_no_other_packets(self.api, capture_port_names))
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC addresses.
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))
        
        # Configure reverse direction
        self.table_add(self.key_ipv4_da_lpm(ip_src_addr, 32),
                       self.act_set_l2ptr(l2ptr+1))
        self.table_add(self.key_mac_da(l2ptr+1),
                       self.act_set_bd_dmac_intf(bd+1, in_dmac, ig_port))
        self.table_add(self.key_send_frame(bd+1), self.act_rewrite_mac(in_smac))


        # Forward direction - in port2, out port1
        exp_pkt = ixia_tcp_packet_floating_instrum(eth_src=out_smac, eth_dst=out_dmac, pktlen=96,
                                ip_src=ip_src_addr, ip_dst=ip_dst_addr, ip_ttl=63, tcp_window=0)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt = Ether(exp_pkt.build())

        print ("Send packet after configuring tables, verify captured packets byte-by-byte...")
        SnappiPtfUtils.start_capture(self.api, capture_port_names)
        SnappiPtfUtils.start_traffic(self.api)

        # Wait for all packets to be received
        utils.wait_for(
            lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
            interval_seconds=2, timeout_seconds=10
        )
        SnappiPtfUtils.verify_capture_on_port(self.api, exp_pkt, 'port2', self.pkt_compare_func)

        # Reverse direction - in port2, out port1
        exp_pkt2 = ixia_tcp_packet_floating_instrum(eth_src=in_smac, eth_dst=in_dmac, pktlen=96,
                                ip_src=ip_dst_addr, ip_dst=ip_src_addr, ip_ttl=63, tcp_window=0,
                                tcp_sport=80, tcp_dport=1234)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt2 = Ether(exp_pkt2.build())
        SnappiPtfUtils.verify_capture_on_port(self.api, exp_pkt2, 'port1', self.pkt_compare_func)

class SnappiFwdTestBidir(SnappiFwdTestBase):
    def setUp(self):
        SnappiFwdTestBase.setUp(self)

    @bt.autocleanup
    def runTest(self):
        # Config method 2 - use inline snappi code to configure flows
        self.cfg = self.api.config()
        # when using ixnetwork extension, port location is chassis-ip;card-id;port-id
        port1, port2 = (
            self.cfg.ports
            .port(name='port1', location='localhost:5555')
            .port(name='port2', location='localhost:5556')
        )

        # configure layer 1 properties
        layer1, = self.cfg.layer1.layer1(name='layer1')
        layer1.port_names = [port1.name, port2.name]
        layer1.speed = layer1.SPEED_1_GBPS

        # Define capture properties
        cap = self.cfg.captures.capture(name='c1')[0]
        cap.port_names = [port1.name, port2.name]
        cap.format = 'pcap'


        # Header values used to define packet contents, will be reused in P4 table entries
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'
        ip_dst_addr = '10.1.0.1'
        ip_src_addr='192.168.0.1'

        # configure flow1 properties
        # flow1, flow2 = self.cfg.flows.flow(name='port1-2').flow(name='port2-1') # alternate technique: create multiple flows at once
        flow1, = self.cfg.flows.flow(name='port1-2')
        # flow endpoints
        flow1.tx_rx.port.tx_name = port1.name
        flow1.tx_rx.port.rx_name = port2.name
        # configure rate, size, frame count
        flow1.size.fixed = 100
        flow1.rate.percentage = 10
        flow1.duration.fixed_packets.packets = 1
        # configure protocol headers with defaults fields
        flow1.packet.ethernet().ipv4().tcp()

        eth = flow1.packet[0]
        eth.src.value = in_smac
        eth.dst.value = in_dmac

        ipv4 = flow1.packet[1]
        ipv4.dst.value = ip_dst_addr
        ipv4.src.value = ip_src_addr
        ipv4.time_to_live.value = 64

        tcp = flow1.packet[2]
        tcp.src_port.value = 1234
        tcp.dst_port.value = 80

        # flow2 
        self.cfg.flows.flow(name='port2-1')
        flow2 = self.cfg.flows[1] # alternate technique- access with index
        flow2.tx_rx.port.tx_name = port2.name
        flow2.tx_rx.port.rx_name = port1.name
        # configure rate, size, frame count
        flow2.size.fixed = 100
        flow2.rate.percentage = 10
        flow2.duration.fixed_packets.packets = 1
        # configure protocol headers with defaults fields
        flow2.packet.ethernet().ipv4().tcp()

        eth = flow2.packet[0]
        eth.src.value = out_smac
        eth.dst.value = out_dmac

        ipv4 = flow2.packet[1]
        ipv4.dst.value = ip_src_addr
        ipv4.src.value = ip_dst_addr
        ipv4.time_to_live.value = 64

        tcp = flow2.packet[2]
        tcp.src_port.value = 80
        tcp.dst_port.value = 1234

        # push configuration
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)

        print ("Send packet prior to configuring tables, verify packets are dropped...")
        SnappiPtfUtils.start_capture(self.api, cap.port_names)
        SnappiPtfUtils.start_traffic(self.api)
        assert(SnappiPtfUtils.verify_no_other_packets(self.api, cap.port_names))
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.

        # Add'l match-action table values:
        ig_port = 1
        eg_port = 2
        l2ptr = 58
        bd = 9
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))
        
        # Configure reverse direction
        self.table_add(self.key_ipv4_da_lpm(ip_src_addr, 32),
                       self.act_set_l2ptr(l2ptr+1))
        self.table_add(self.key_mac_da(l2ptr+1),
                       self.act_set_bd_dmac_intf(bd+1, in_dmac, ig_port))
        self.table_add(self.key_send_frame(bd+1), self.act_rewrite_mac(in_smac))


        # Forward direction - in port2, out port1
        exp_pkt = ixia_tcp_packet_floating_instrum(eth_src=out_smac, eth_dst=out_dmac, pktlen=96,
                                ip_src=ip_src_addr, ip_dst=ip_dst_addr, ip_ttl=63, tcp_window=0)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt = Ether(exp_pkt.build())

        print ("Send packet after configuring tables, verify captured packets byte-by-byte...")
        SnappiPtfUtils.start_capture(self.api, cap.port_names)
        SnappiPtfUtils.start_traffic(self.api)

        utils.wait_for(
            lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
            interval_seconds=2, timeout_seconds=10
        )
        SnappiPtfUtils.verify_capture_on_port(self.api, exp_pkt, 'port2', self.pkt_compare_func)

        # Reverse direction - in port2, out port1
        exp_pkt2 = ixia_tcp_packet_floating_instrum(eth_src=in_smac, eth_dst=in_dmac, pktlen=96,
                                ip_src=ip_dst_addr, ip_dst=ip_src_addr, ip_ttl=63, tcp_window=0,
                                tcp_sport=80, tcp_dport=1234)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt2 = Ether(exp_pkt2.build())
        SnappiPtfUtils.verify_capture_on_port(self.api, exp_pkt2, 'port1', self.pkt_compare_func)

class SnappiFwdTestBidirLpmRange(SnappiFwdTestBase):
    """
    Send 512 packets in each direction with incr. DIP
    LPM set to mask 8 LSBs
    Confirm only 256 packets arrived on each output
    """
    def setUp(self):
        SnappiFwdTestBase.setUp(self)

    @bt.autocleanup
    def runTest(self):
        # Config method 2 - use inline snappi code to configure flows
        self.cfg = self.api.config()
        # when using ixnetwork extension, port location is chassis-ip;card-id;port-id
        port1, port2 = (
            self.cfg.ports
            .port(name='port1', location='localhost:5555')
            .port(name='port2', location='localhost:5556')
        )

        # configure layer 1 properties
        layer1, = self.cfg.layer1.layer1(name='layer1')
        layer1.port_names = [port1.name, port2.name]
        layer1.speed = layer1.SPEED_1_GBPS

        # Define capture properties
        cap = self.cfg.captures.capture(name='c1')[0]
        cap.port_names = [port1.name, port2.name]
        cap.format = 'pcap'

        tx_count = 512
        compare_count = 256

        # Header values used to define packet contents, will be reused in P4 table entries
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'
        ip_dst_addr = '10.1.0.0'
        ip_src_addr='192.168.0.0'

        # configure flow1 properties
        # flow1, flow2 = self.cfg.flows.flow(name='port1-2').flow(name='port2-1') # Alternate - configure multi flows at once
        # flow1, = self.cfg.flows.flow(name='port1-2') # Alternate - configure one flow, take first element
        flow1 = self.cfg.flows.flow(name='port1-2')[-1] # Alternate - obtain last item
        # flow endpoints
        flow1.tx_rx.port.tx_name = port1.name
        flow1.tx_rx.port.rx_name = port2.name
        # configure rate, size, frame count
        flow1.size.fixed = 100
        flow1.rate.pps = 100
        flow1.duration.fixed_packets.packets = tx_count
        # configure protocol headers with defaults fields
        flow1.packet.ethernet().ipv4().tcp()

        eth = flow1.packet[0]
        eth.src.value = in_smac
        eth.dst.value = in_dmac

        ipv4 = flow1.packet[1]
        ipv4.dst.increment.start = ip_dst_addr
        ipv4.dst.increment.step = '0.0.0.1'
        ipv4.dst.increment.count = tx_count
        ipv4.src.value = ip_src_addr
        ipv4.time_to_live.value = 64

        tcp = flow1.packet[2]
        tcp.src_port.value = 1234
        tcp.dst_port.value = 80

        # flow2 
        flow2 = self.cfg.flows.flow(name='port2-1')[-1] # take last element of returned iterator
        flow2.tx_rx.port.tx_name = port2.name
        flow2.tx_rx.port.rx_name = port1.name
        # configure rate, size, frame count
        flow2.size.fixed = 100
        flow2.rate.pps = 100
        flow2.duration.fixed_packets.packets = tx_count
        # configure protocol headers with defaults fields
        flow2.packet.ethernet().ipv4().tcp()

        eth = flow2.packet[0]
        eth.src.value = out_smac
        eth.dst.value = out_dmac

        ipv4 = flow2.packet[1]
        ipv4.dst.increment.start = ip_src_addr
        ipv4.dst.increment.step = '0.0.0.1'
        ipv4.dst.increment.count = tx_count
        ipv4.src.value = ip_dst_addr
        ipv4.time_to_live.value = 64

        tcp = flow2.packet[2]
        tcp.src_port.value = 80
        tcp.dst_port.value = 1234

        # push configuration
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)

        print ("Send packet prior to configuring tables, verify packets are dropped...")
        SnappiPtfUtils.start_capture(self.api, cap.port_names)
        SnappiPtfUtils.start_traffic(self.api)
        time.sleep(tx_count/100)

        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        # Snappi flow-based test for dropped packets:
        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        assert all([stat.frames_rx == 0 for stat in flow_results]), "Received unexpected frames" 
        # Traditional PTF port-based test for dropped packets:
        assert(SnappiPtfUtils.verify_no_other_packets(self.api, cap.port_names))
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.

        # Add'l match-action table values:
        ig_port = 1
        eg_port = 2
        l2ptr = 58
        bd = 9

        # Create LPM entries with /24 prefixes
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 24),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))
        
        # Configure reverse direction
        self.table_add(self.key_ipv4_da_lpm(ip_src_addr, 24),
                       self.act_set_l2ptr(l2ptr+1))
        self.table_add(self.key_mac_da(l2ptr+1),
                       self.act_set_bd_dmac_intf(bd+1, in_dmac, ig_port))
        self.table_add(self.key_send_frame(bd+1), self.act_rewrite_mac(in_smac))


        # Forward direction - in port2, out port1
        exp_pkts = [ixia_tcp_packet_floating_instrum(eth_src=out_smac, eth_dst=out_dmac, pktlen=96,
                                ip_src=ip_src_addr, ip_dst='10.1.0.%d' % i, ip_ttl=63, tcp_window=0)/Padding('\x00\x00\x00\x00') for i in range(compare_count)]
        exp_pkts = [Ether(exp_pkts[i].build()) for i in range(len(exp_pkts))] # force recalc chksum, len,etc.

        print ("Send packet after configuring tables, verify captured packets byte-by-byte...")
        SnappiPtfUtils.start_capture(self.api, cap.port_names)
        SnappiPtfUtils.start_traffic(self.api)

        utils.get_all_stats(self.api, print_output=True)


        utils.wait_for(
            lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
            interval_seconds=2, timeout_seconds=10
        )

        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        assert all([stat.frames_rx == tx_count/2 for stat in flow_results]), "Did not receive expected %d frames on all flows" % tx_count/2

        SnappiPtfUtils.verify_captures_on_port(self.api, exp_pkts, 'port2', self.pkt_compare_func)

        # Reverse direction - in port2, out port1
        exp_pkts2 = [Ether(ixia_tcp_packet_floating_instrum(eth_src=in_smac, eth_dst=in_dmac, pktlen=96,
                                ip_src=ip_dst_addr, ip_dst='192.168.0.%d' % i, ip_ttl=63, tcp_window=0,
                                tcp_sport=80, tcp_dport=1234)/Padding('\x00\x00\x00\x00')) for i in range(compare_count)]
        exp_pkts2 = [Ether(exp_pkts2[i].build()) for i in range(len(exp_pkts2))] # force recalc chksum, len,etc.
        
        SnappiPtfUtils.verify_captures_on_port(self.api, exp_pkts2, 'port1', self.pkt_compare_func)

class SnappiFwdTest4PortMesh(SnappiFwdTestBase):
    """
    Send 512 packets in each direction with incr. DIP
    LPM set to mask 8 LSBs
    Confirm only 256 packets arrived on each output
    """
    def setUp(self):
        SnappiFwdTestBase.setUp(self)

    @bt.autocleanup
    def runTest(self):
        # Define # ports, indices, names - will reuse a lot
        self.NUMPORTS=4
        self.port_ndxs=list(range(self.NUMPORTS))
        port_names = ['port%d' % (i+1) for i in self.port_ndxs]

        self.cfg = self.api.config()
        # when using ixnetwork extension, port location is chassis-ip;card-id;port-id
        ports = [self.cfg.ports.port(name='port%d' % (i+1), location='localhost:%d' % (5555+i))[-1] for i in self.port_ndxs] # One core per port/direction
        # ports = [self.cfg.ports.port(name='port%d' % (i+1), location='localhost:%d;%d' % (5555,i+1) )[-1] for i in self.port_ndxs] # 1 core per direction, shared among ports

        # configure layer 1 properties
        layer1, = self.cfg.layer1.layer1(name='layer1')
        layer1.port_names = port_names
        layer1.speed = layer1.SPEED_1_GBPS

        # Define capture properties
        cap = self.cfg.captures.capture(name='c1')[0]
        cap.port_names = port_names
        cap.format = 'pcap'

        tx_count = 255

        # Header values used to define packet contents, will be reused in P4 table entries
        host_macs=['ee:00:00:00:00:%02x' % (i+1) for i in self.port_ndxs]
        switch_macs=['dd:00:00:00:00:%02x' % (i+1) for i in self.port_ndxs]
        ip_subnets=['192.168.%d.0' % (i+1) for i in self.port_ndxs]
        ip_hosts=['192.168.%d.1' % (i+1) for i in self.port_ndxs]

        i = 0
        for src in self.port_ndxs:
            for dst in self.port_ndxs:
                if src == dst:
                    continue # no hairpin switching

                print("Configuring flow[%d]: %s => %s" % (i, ports[src].name, ports[dst].name))
                flow = self.cfg.flows.flow(name='port%d-%d' %(src+1, dst+1))[-1]
                # flow endpoints
                flow.tx_rx.port.tx_name = ports[src].name
                flow.tx_rx.port.rx_name = ports[dst].name
                # configure rate, size, frame count
                flow.size.fixed = 100
                flow.rate.pps = 50
                flow.duration.fixed_packets.packets = tx_count
                # configure protocol headers with defaults fields
                flow.packet.ethernet().ipv4().tcp()

                eth = flow.packet[0]
                eth.src.value = host_macs[src]
                eth.dst.value = host_macs[dst]

                ipv4 = flow.packet[1]
                ipv4.dst.increment.start = ip_hosts[dst]
                ipv4.dst.increment.step = '0.0.0.1'
                ipv4.dst.increment.count = tx_count
                ipv4.src.value = ip_hosts[src]
                ipv4.time_to_live.value = 64

                tcp = flow.packet[2]
                tcp.src_port.value = 1234
                tcp.dst_port.value = 80

                i+=1

        print(self.cfg)

        # push configuration
        print ("Applying snappi config:\n%s" % self.cfg)
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)
        print ("Applied snappi config: OK")

        print ("Send packet prior to configuring tables, verify packets are dropped...")
        SnappiPtfUtils.start_capture(self.api, cap.port_names)
        SnappiPtfUtils.start_traffic(self.api)
        time.sleep(tx_count/100)

        # Snappi flow-based test for dropped packets:
        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        assert all([stat.frames_rx == 0 for stat in flow_results]), "Received unexpected frames" 
        # Traditional PTF port-based test for dropped packets:
        assert(SnappiPtfUtils.verify_no_other_packets(self.api, cap.port_names))

        port_results, flow_results = utils.get_all_stats(self.api, print_output=False)
        assert all([stat.frames_rx == 0 for stat in flow_results]), "Received unexpected frames" 
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.
        print ("Programming P4 tables...")
        for dst in self.port_ndxs:
            self.table_add(self.key_ipv4_da_lpm(ip_hosts[dst], 24),
                        self.act_set_l2ptr(dst))
            self.table_add(self.key_send_frame(dst), self.act_rewrite_mac(switch_macs[dst]))
            self.table_add(self.key_mac_da(dst),
                        self.act_set_bd_dmac_intf(dst, host_macs[dst], dst+1)) # port index 0..3 => dataplane port 1..4


        print ("Send packet after configuring tables, verify captured packets stats only...")
        SnappiPtfUtils.start_capture(self.api, cap.port_names)
        SnappiPtfUtils.start_traffic(self.api)

        utils.wait_for(
            lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
            interval_seconds=2, timeout_seconds=10
        )

        port_results, flow_results = utils.get_all_stats(self.api, print_output=True)
        assert all([stat.frames_rx == tx_count for stat in flow_results]), "Did not receive expected frames" 

