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

import logging
import ptf
import os
from ptf import config
import ptf.testutils as tu

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


class FwdTest(Demo1Test):
    @bt.autocleanup
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        ip_dst_addr = '10.1.0.1'
        ig_port = 1

        eg_port = 2
        l2ptr = 58
        bd = 9
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'

        # Before adding any table entries, the default behavior for
        # sending in an IPv4 packet is to drop it.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_dst=ip_dst_addr, ip_ttl=64)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_no_other_packets(self)
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))

        # Check that the entry is hit, expected source and dest MAC
        # have been written into output packet, TTL has been
        # decremented, and that no other packets are received.
        exp_pkt = tu.simple_tcp_packet(eth_src=out_smac, eth_dst=out_dmac,
                                       ip_dst=ip_dst_addr, ip_ttl=63)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, exp_pkt, [eg_port])
        
class FwdTestNoReload(Demo1TestBase):
    # @bt.autocleanup
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        ip_dst_addr = '10.1.0.1'
        ig_port = 1

        eg_port = 2
        l2ptr = 58
        bd = 9
        out_dmac = '02:13:57:ab:cd:ef'
        out_smac = '00:11:22:33:44:55'

        # Before adding any table entries, the default behavior for
        # sending in an IPv4 packet is to drop it.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_dst=ip_dst_addr, ip_ttl=64)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_no_other_packets(self)
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))

        # Check that the entry is hit, expected source and dest MAC
        # have been written into output packet, TTL has been
        # decremented, and that no other packets are received.
        exp_pkt = tu.simple_tcp_packet(eth_src=out_smac, eth_dst=out_dmac,
                                       ip_dst=ip_dst_addr, ip_ttl=63)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, exp_pkt, [eg_port])


class PrefixLen0Test(Demo1Test):
    @bt.autocleanup
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'
        ig_port = 1

        entries = []
        # 'ip_dst_addr' and 'prefix_len' fields represent the key to
        # add to the LPM table.  'pkt_in_dst_addr' is one IPv4 address
        # such that if a packet is sent in with that as the dest
        # address, it should match the given table entry, not one of
        # the others.  There may be many other such addresses, but we
        # just need one for this particular test.
        entries.append({'ip_dst_addr': '10.1.0.1',
                        'prefix_len': 32,
                        'pkt_in_dst_addr': '10.1.0.1',
                        'eg_port': 2,
                        'l2ptr': 58,
                        'bd': 9,
                        'out_dmac': '02:13:57:ab:cd:ef',
                        'out_smac': '00:11:22:33:44:55'})
        entries.append({'ip_dst_addr': '10.1.0.0',
                        'prefix_len': 16,
                        'pkt_in_dst_addr': '10.1.2.3',
                        'eg_port': 3,
                        'l2ptr': 59,
                        'bd': 10,
                        'out_dmac': '02:13:57:ab:cd:f0',
                        'out_smac': '00:11:22:33:44:56'})
        entries.append({'ip_dst_addr': '0.0.0.0',
                        'prefix_len': 0,
                        'pkt_in_dst_addr': '20.0.0.1',
                        'eg_port': 4,
                        'l2ptr': 60,
                        'bd': 11,
                        'out_dmac': '02:13:57:ab:cd:f1',
                        'out_smac': '00:11:22:33:44:57'})

        for e in entries:
            self.table_add(self.key_ipv4_da_lpm(e['ip_dst_addr'],
                                                e['prefix_len']),
                           self.act_set_l2ptr(e['l2ptr']))
            self.table_add(self.key_mac_da(e['l2ptr']),
                           self.act_set_bd_dmac_intf(e['bd'], e['out_dmac'],
                                                     e['eg_port']))
            self.table_add(self.key_send_frame(e['bd']),
                           self.act_rewrite_mac(e['out_smac']))

        ttl_in = 100
        for e in entries:
            ip_dst_addr = e['pkt_in_dst_addr']
            eg_port = e['eg_port']
            pkt_in = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                          ip_dst=ip_dst_addr, ip_ttl=ttl_in)
            exp_pkt = tu.simple_tcp_packet(eth_src=e['out_smac'],
                                           eth_dst=e['out_dmac'],
                                           ip_dst=ip_dst_addr,
                                           ip_ttl=ttl_in - 1)
            tu.send_packet(self, ig_port, pkt_in)
            tu.verify_packets(self, exp_pkt, [eg_port])
            # Vary TTL in for each packet tested, just to make them
            # easy to distinguish from each other.
            ttl_in = ttl_in - 10


class DupEntryTest(Demo1Test):
    @bt.autocleanup
    def runTest(self):
        ip_dst_addr = '10.0.0.1'
        l2ptr = 58

        def add_entry_once():
            self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                           self.act_set_l2ptr(l2ptr))

        add_entry_once()
        with self.assertP4RuntimeError():
            add_entry_once()


######################## snappi additions #########################


class ConfigTest(Demo1Test):
    def setUp(self):
        Demo1Test.setUp(self)
        self.api = snappi.api(host='https://localhost:8080')
        self.cfg = utils.common.load_test_config(
            self.api, 'demo1-athena-packet-config.json', apply_settings=True
        )
        res = self.api.set_config(self.cfg)
        assert len(res.errors) == 0, str(res.errors)

    @bt.autocleanup
    def runTest(self):
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

        # Before adding any table entries, the default behavior for
        # sending in an IPv4 packet is to drop it.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_dst=ip_dst_addr, ip_ttl=64)
        # tu.send_packet(self, ig_port, pkt)
        # tu.verify_no_other_packets(self)
        
        # Add a set of table entries that the packet should match, and
        # be forwarded out with the desired dest and source MAC
        # addresses.
        self.table_add(self.key_ipv4_da_lpm(ip_dst_addr, 32),
                       self.act_set_l2ptr(l2ptr))
        self.table_add(self.key_mac_da(l2ptr),
                       self.act_set_bd_dmac_intf(bd, out_dmac, eg_port))
        self.table_add(self.key_send_frame(bd), self.act_rewrite_mac(out_smac))

        # Config, capture and start all in one
        # utils.common.start_traffic(self.api, self.cfg) - error, port 1 not a capture port


        cap_port_names = ['port2']
        capture_state = self.api.capture_state()
        capture_state.state = 'start'
        capture_state.port_names = cap_port_names
        print('Starting capture on ports %s ...' % str(cap_port_names))
        res = self.api.set_capture_state(capture_state)
        if len(res.errors):
            print (str(res.errors))
        assert len(res.errors) == 0, str(res.errors)

        ts = self.api.transmit_state()
        ts.state = ts.START
        # Alternate semantics:
        # transmit_state.state = 'start'
        print('Starting traffic')
        res = self.api.set_transmit_state(ts)
        if len(res.errors):
            print (str(res.errors))
        assert len(res.errors) == 0, str(res.errors)

        cap_dict = {}
        for name in cap_port_names:
            print('Fetching capture from port %s' % name)
            capture_req = self.api.capture_request()
            capture_req.port_name = name
            pcap_bytes = self.api.get_capture(capture_req)

            cap_dict[name] = []
            for ts, pkt in dpkt.pcap.Reader(pcap_bytes):
                if sys.version_info[0] == 2:
                    raw = [ ord(b) for b in pkt]
                else:
                    raw = list(pkt)
                cap_dict[name].append(raw)

        brx = bytes(cap_dict['port2'][-1])
        rx_pkt = Ether(brx)

        # exp_pkt = tu.simple_tcp_packet(eth_src=out_smac, eth_dst=out_dmac,
        #                         ip_dst=ip_dst_addr, ip_ttl=63)

        # make the expected packet 4 bytes shorter to make the effective IP lengths equal. Athena will shorten by 4 bytes to account for added CRC.
        # The 4 pad bytes aren't added to the ip len field by scapy
        exp_pkt = ixia_tcp_packet_floating_instrum(eth_src=out_smac, eth_dst=out_dmac, pktlen=96,
                                ip_src=ip_src_addr, ip_dst=ip_dst_addr, ip_ttl=63, tcp_window=0)/Padding('\x00\x00\x00\x00')
        # Force field updates (chksums, len, etc.)
        exp_pkt = Ether(exp_pkt.build())

        # bex=bytes(exp_pkt)

        (equal, reason, p1,p2) = compare_pkts2(exp_pkt, rx_pkt,
                                        # no_payload=True,
                                        no_ip_chksum=True,
                                        no_tcp_chksum=True,
                                        no_tstamp=True)

        if equal:
            print ("Compare=%s: %s" % (equal, reason))
            print("\nExpected (masked):\n===============")
            p1.show()

            print("\nReceived (masked):\n===============")
            p2.show()
        else:
            print ("Mismatched %s" % ( reason))
            print("\nExpected (masked):\n===============")
            p1.show()

            print("\nReceived (masked):\n===============")
            p2.show()

            exl=len(p1)
            bex=bytes(p1)
            rxl=len(p2)
            brx=bytes(p2)
            maxlen= rxl if rxl>exl else exl

            print ("offset\t Exp \t Eq?\t Rx\n")
            for i in range(maxlen):
                if i < exl and i < rxl:
                    print ("[%d]\t %02x\t %s\t %02x" % (i, bex[i], "==" if brx[i]==bex[i] else "!=", brx[i]) )
                elif i < exl:
                    print ("[%d]\t %02x\t %s\t %s" % (i, bex[i], "!=", "--") )
                else:
                    print ("[%d]\t %s\t %s\t %02x" % (i, "--", "!=", brx[i]) )

            assert equal, "Rx %s != expected %s" % (brx, bex)

            
            

