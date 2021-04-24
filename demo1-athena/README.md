# Preface
This directory is an adaptation of [p4-guide/demo1](https://github.com/jafingerhut/p4-guide/tree/master/demo1) originally created by Andy Fingerhut. Specifically, the PTF directory contains a new test file [ptf/demo1-snappi.py](ptf/demo1-snappi.py) based on the original `demo1.py`.Instead of using [Scapy](https://scapy.readthedocs.io/en/latest/index.html) for sending and capturing packets, it has been modified to utilize 
the [Athena Software Traffic Generator](https://github.com/open-traffic-generator/athena) via the [snappi Python client library](https://github.com/open-traffic-generator/snappi).

`snappi` is a Python client which uses the [Open Traffic Generator](https://github.com/open-traffic-generator) API. This REST API talks to a variety of software and hardware-based traffic generators/analyzers via a unified data model, allowing you to "write tests once and run anywhere" at speeds from "slow simulations" up to Tbps.

This project comprises a simple P4 "switch" program which performs LPM Lookup on IP destination address, and switches packets to the correct egress port while performing MAC address rewrite. A few test programs in the PTF framework demonstrate the ease and power of snappi and athena as replacements for Scapy.

# References
* https://github.com/open-traffic-generator
* https://pypi.org/project/snappi/
* https://github.com/jafingerhut/p4-guide
* https://github.com/p4lang/ptf
* https://scapy.readthedocs.io

# Introduction
For background context, expand the section below to see the original content of demo1/readme.md. Proceed to [System Prerequisites](#system-prerequisities) for the "Snappi-fied" instructions.

<summary>Click ""details" arrow to see the original README</summary>
<details>

See [README-using-bmv2.md](../README-using-bmv2.md) for some things
that are common across different P4 programs executed using bmv2.

This article describes how to:

+ compile a simple demo P4 program using the `p4c` P4 compiler
+ execute the compiled program using the `simple_switch` software
  switch
+ add table entries to the running P4 program using the
  `simple_switch_CLI` command line utility, and
+ send packets to the running P4 program using `scapy`.

`simple_switch_CLI` uses a control message protocol that is not the
P4Runtime API.  If you are interested in adding table entries to the
running P4 program using the P4Runtime API instead, see See
[README-p4runtime.md](README-p4runtime.md).

# Compiling

To compile the P4_16 version of the code:

    p4c --target bmv2 --arch v1model demo1.p4_16.p4
                                     ^^^^^^^^^^^^^^ source code

If you see an error message about `mark_to_drop: Passing 1 arguments
when 0 expected`, then see
[`README-troubleshooting.md`](../README-troubleshooting.md#compiler-gives-error-message-about-mark_to_drop)
for what to do.

Running that command will create these files:

    demo1.p4_16.p4i - the output of running only the preprocessor on
        the P4 source program.
    demo1.p4_16.json - the JSON file format expected by BMv2
        behavioral model `simple_switch`.

Only the file with the `.json` suffix is needed to run your P4 program
using the `simple_switch` command.  You can ignore the file with
suffix `.p4i` unless you suspect that the preprocessor is doing
something unexpected with your program.

To compile the P4_14 version of the code:

    p4c --std p4-14 --target bmv2 --arch v1model demo1.p4_14.p4
                                                 ^^^^^^^^^^^^^^ source code
        ^^^^^^^^^^^ specify P4_14 source code

The .dot and .png files in the subdirectory 'graphs' were created with
the p4c-graphs program, which is also installed when you build and
install p4c:

     p4c-graphs -I $HOME/p4c/p4include demo1.p4_16.p4

The `-I` option is only necessary if you did _not_ install the P4
compiler in your system-wide /usr/local/bin directory.


# Running

To run the behavioral model with 8 ports numbered 0 through 7:

    sudo simple_switch --log-console -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 demo1.p4_16.json

To get the log to go to a file instead of the console:

    sudo simple_switch --log-file ss-log --log-flush -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 demo1.p4_16.json

CHECK THIS: If you see "Add port operation failed" messages in the
output of the simple_switch command, it means that one or more of the
virtual Ethernet interfaces veth0, veth2, etc. have not been created
on your system.  Search for "veth" in the file
[`README-using-bmv2.md`](../README-using-bmv2.md) (top level
directory of this repository) for a command to create them.

See the file
[`README-troubleshooting.md`](../README-troubleshooting.md) in case
you run into troubles.  It describes symptoms of some problems, and
things you can do to resolve them.

To run CLI for controlling and examining simple_switch's table
contents:

    simple_switch_CLI

General syntax for table_add commands at simple_switch_CLI prompt:

    RuntimeCmd: help table_add
    Add entry to a match table: table_add <table name> <action name> <match fields> => <action parameters> [priority]

You can find more comprehensive documentation about the `table_add`
and `table_set_default` commands
[here](https://github.com/p4lang/behavioral-model/blob/master/docs/runtime_CLI.md#table_add)
and
[here](https://github.com/p4lang/behavioral-model/blob/master/docs/runtime_CLI.md#table_set_default),
but you do not need to know all of that to understand and use the
example commands here.

----------------------------------------------------------------------
demo1.p4_16.p4 only
----------------------------------------------------------------------

The `table_set_default` commands without the `ingressImpl.` and
`egressImpl.` prefixes before `my_drop` used to work for the P4_16
version of this program, but starting some time around June 2019 this
is no longer the case.

    table_set_default ipv4_da_lpm ingressImpl.my_drop
    table_set_default mac_da ingressImpl.my_drop
    table_set_default send_frame egressImpl.my_drop

----------------------------------------------------------------------
demo1.p4_14.p4 only
----------------------------------------------------------------------

    table_set_default ipv4_da_lpm my_drop
    table_set_default mac_da my_drop
    table_set_default send_frame my_drop

----------------------------------------------------------------------
demo1.p4_14.p4 or demo1.p4_16.p4 (same commands work for both)
----------------------------------------------------------------------

    table_add ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58
    table_add mac_da set_bd_dmac_intf 58 => 9 02:13:57:ab:cd:ef 2
    table_add send_frame rewrite_mac 9 => 00:11:22:33:44:55

Another set of table entries to forward packets to a different output
interface:

    # Version with dotted decimal IPv4 address and : separators inside
    # of hexadecimal Ethernet addresses.
    table_add ipv4_da_lpm set_l2ptr 10.1.0.200/32 => 81
    table_add mac_da set_bd_dmac_intf 81 => 15 08:de:ad:be:ef:00 4
    table_add send_frame rewrite_mac 15 => ca:fe:ba:be:d0:0d

    # Version with hex values instead of the above versions.
    # Note: the prefix length after the / character must be decimal.
    # I tried 0x20 and simple_switch_CLI raised an exception and
    # exited.
    table_add ipv4_da_lpm set_l2ptr 0x0a0100c8/32 => 0x51
    table_add mac_da set_bd_dmac_intf 0x51 => 0xf 0x08deadbeef00 0x4
    table_add send_frame rewrite_mac 0xf => 0xcafebabed00d

You can examine the existing entries in a table with 'table_dump':

    table_dump ipv4_da_lpm
    ==========
    TABLE ENTRIES
    **********
    Dumping entry 0x0
    Match key:
    * ipv4.dstAddr        : LPM       0a010001/32
    Action entry: ingressImpl.set_l2ptr - 3a
    **********
    Dumping entry 0x1
    Match key:
    * ipv4.dstAddr        : LPM       0a0100c8/32
    Action entry: ingressImpl.set_l2ptr - 51
    ==========
    Dumping default entry
    Action entry: ingressImpl.my_drop - 
    ==========


The numbers on the "Dumping entry <number>" lines are 'table entry
handle ids'.  The table API implementation allocates a unique handle
id when adding a new entry, and you must provide that value to delete
the table entry.  The handle id is unique per entry, as long as the
entry remains in the table.  After removing an entry, its handle id
may be reused for a future entry added to the table.

Handle ids are _not_ unique across all tables.  Only the pair
<table,handle_id> is unique.


----------------------------------------------------------------------
scapy session for sending packets
----------------------------------------------------------------------
Any process that you want to have permission to send and receive
packets on Ethernet interfaces (such as the veth virtual interfaces)
must run as the super-user root, hence the use of `sudo`:

```bash
$ sudo scapy
```

```python
fwd_pkt1=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)

# Send packet at layer2, specifying interface
sendp(fwd_pkt1, iface="veth0")
sendp(drop_pkt1, iface="veth0")

fwd_pkt2=Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) / Raw('The quick brown fox jumped over the lazy dog.')
sendp(fwd_pkt2, iface="veth0")
```

----------------------------------------


# Patterns

The example table entries and sample packet given above can be
generalized to the following pattern.

If you send an input packet like this, specified as Python code when
using the Scapy library:

    input port: anything
    Ether() / IP(dst=<hdr.ipv4.dstAddr>, ttl=<ttl>)

and you create the following table entries:

    table_add ipv4_da_lpm set_l2ptr <hdr.ipv4.dstAddr>/32 => <l2ptr>
    table_add mac_da set_bd_dmac_intf <l2ptr> => <out_bd> <dmac> <out_intf>
    table_add send_frame rewrite_mac <out_bd> => <smac>

then the P4 program should produce an output packet like the one
below, matching the input packet in every way except, except for the
fields explicitly mentioned:

    output port: <out_intf>
    Ether(src=<smac>, dst=<dmac>) / IP(dst=<hdr.ipv4.dstAddr>, ttl=<ttl>-1)


----------------------------------------

# Last successfully tested with these software versions

For https://github.com/p4lang/p4c

```
$ git log -n 1 | head -n 3
commit 474ea783d2adf41c1b424e04cb0dc1981ce4b124
Author: Mihai Budiu <mbudiu@vmware.com>
Date:   Wed Oct 9 17:59:46 2019 -0700
```

For https://github.com/p4lang/behavioral-model

```
$ git log -n 1 | head -n 3
commit 33e221fd879c1aa2f16b04ab0adbf341619003ae
Author: Antonin Bas <abas@vmware.com>
Date:   Fri Sep 20 08:55:10 2019 -0700
```
</details>


# System Prerequisites
## Operating System - Ubuntu 20.04

This was tested using Ubuntu 20.04. Earlier versions of Ubuntu will probably work with some adaptation, but these probably install Python 2.7 by default so some adjustments might be necessary. This is beyond the scope of this tutorial.

## CPU Core Pinning
Due to the DPDK implementation, Athena requires 2 "pinned" CPU cores for each traffic engine to achieve full performance, plus one more core dedicated as the controller. The PTF tests in this tutorial require 5 and 7 cores, respectively.

Please check the CPU core count of your development machine or VM. Try `nproc`. The effective CPU count is proably twice this.

## Install P4 Development Dependencies
Run Andy's P4 dev environment installer:
```
cd p4-guide/bin
./install-p4dev-v4.sh # For Ubuntu >= 20.04 only
```

## Install Docker
You'll need Docker to run Athena.
There are various ways to install Docker. Below is but one method. See [Docker.com](https://www.docker.com/get-started).
```
sudo apt update
sudo apt install docker.io
sudo usermod -aG docker <USERNAME> 
sudo systemctl start docker
sudo systemctl enable docker
```
**NOTE**: the `usermod` command above lets you avoid needing `sudo` for all `docker` commands. You may need to re-login, or in the case of a VM, restart the OS, in order for it to take effect. You can verify `docker` group membership via the `id` command.

## Install Athena docker images
Pull the images from public repository:
TBD
```
docker pull ...
```
Tag the docker images with shorter names for convenience:
```
docker tag <...> athena-controller:latest
docker tag <...> athena-te:latest
```
## Install snappi python libraries
```
# install snappi & clone repo for test suites, useful helper scripts, deployment files, etc.
python -m pip install --upgrade snappi
```
You can use `snappi` in other projects! Just add `import snappi` to your Python programs.
## Optional - Install Athena Documentation/Examples
`cd` to a suitable directory to install these resources for use outside this tutorial.
```
git clone --recursive https://github.com/open-traffic-generator/athena
```
# Lets do the Demos!

## Compile P4 code
```
p4c -v --target bmv2 --arch v1model --p4runtime-files demo1.p4_16.p4rt.txt demo1.p4_16.p4
running cc -E -C -undef -nostdinc -x assembler-with-cpp -I /usr/local/share/p4c/p4include -o ./demo1.p4_16.p4i demo1.p4_16.p4
running /usr/local/bin/p4c-bm2-ss -I /usr/local/share/p4c/p4include --p4v=16 --p4runtime-files demo1.p4_16.p4rt.txt -o ./demo1.p4_16.json ./demo1.p4_16.p4i --arch v1model
```
## Create veth interfaces
```
sudo ../bin/veth_setup.sh
```
## Launch demo1 program in bmv2
```
sudo simple_switch_grpc --log-file ss-log --log-flush -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 --no-p4
```
## Optional - Monitor traffic on veths
In four separate console windows:
```
sudo tcpdump -eni veth2
sudo tcpdump -eni veth4
sudo tcpdump -eni veth6
sudo tcpdump -eni veth8
```
## PTF Tests Overview

### How to Run

The `runptf.sh` helper script, without further arguments, will run all tests. Use `sudo` to acquire root access.

To run a specific test, add `basename.classname` to the command, where `basename` is the base filename containing the PTF test (e.g. demo1-snappi.py is the filename, demo1-snappi is the basename) and `classname` is the Python classname containing the test (e.g. `SnappiFwdTestBidirLpmRange`).

Here's an example: `sudo ./runptf.sh demo1-snappi.SnappiFwdTestBidirLpmRange`

### Highlighted Tests
There a several tests inside [demo1-snappi.py](demo1-snappi.py) which you can inspect and run. Here we call out some in particular.
* [SnappiFwdTestJson](#run-snappifwdtestjson-ptf-test) - this test sends one packet between ports. This test is unique in that it uses a JSON file to define the Athena configuration instead of inline python to manipulate snappi objects.
* [SnappiFwdTest](#run-snappifwdtest-ptf-test) - same as [SnappiFwdTestJson](#run-snappifwdtest-ptf-test) but uses inline python to manipulate snappi objects.
* [SnappiFwdTestBidirLpmRange](#run-snappifwdtestbidirlpmrange-ptf-test) - tests bidirectional LPM forwarding between 2 ports, verify stats and full packet contents
* [SnappiFwdTest4PortMesh](#run-snappifwdtest4portmesh-ptf-test) - tests bidirectional LPM forwarding between 2 ports, verify stats and full packet contents

Please look at the code and also read [snappi snippets](#snappi-snippets) section below.

### Test Configuration
![Test Configuration](demo-setup.svg)
## Run All PTF tests
```
sudo ./runptf.sh
```

## Run SnappiFwdTestJson PTF Test
This test sends unidirectional traffic between two switch ports, then verifies packet forwarding/MAC rewrite using transmit/receive packet byte-by-byte comparison.
This test is unique among all the tests because it uses a JSON configuraiton file [demo1-athena-packet-config.json](demo1-athena-packet-config.json) instead of programmatic configuration. Snappi can work either way.


![SnappiFwdTestJson](SnappiFwdTestJson.svg)

### Test outline
<summary>Click the arrow to expand</summary>
<details>

* Configure Athena for one traffic flow, into `veth2` and out `veth4` respectively (dataplane ports 1 and 2 in the P4 code). The flow will send a single packet with IP and MAC addresses designed to forward from dataplane port 1 to port 2.
* Configure Athena to capture all the return traffic
* Start the traffic flow and capture the results
* Verify no packets were captured because the P4 dataplane forwawrding tables have not been programmed: the default action is `drop`.
* Configure the P4 tables to match on the DIP as configured in the traffic flow and forward to the correct egress ports also performing MAC rewrite.
* Start traffic flow a second time and capture everything. We wait until the received packet counts match the expected values on all flows (or timeout waiting).
* Verify the captured results has the correct number of packets for each flow.
* Perform a byte-by-byte comparison of the received packets, against the expected packets. The expected packets are modified version of th esent packets, with MAC rewrite in accordance with the intended switch behavior. We ignore portions of the packet during compare as follows:
  * The second half of the [Ixia "instrumentation" header](#about-ixia-header-and-flow-instrumentation) which follows the TCP header (since the contents vary)
  * The TCP checksum (due to the variable instrumentation contents)
  * The IP checksum (due to the variable instrumentation contents)
</details>


### Run the Test
```
sudo ./runptf.sh demo1-snappi.SnappiFwdTestJson
```

## Run SnappiFwdTest PTF Test
This test is identical to [SnappiFwdTestJson](#run-snappifwdtest-ptf-test) but uses inline python to manipulate snappi objects.

## Run SnappiFwdTestBidirLpmRange PTF test
This test sends bidirectional traffic between two switch ports, then verifies packet forwarding/MAC rewrite using both captured statistics and transmit/receive packet byte-by-byte comparison.


![SnappiFwdTestBidirLpmRange](SnappiFwdTestBidirLpmRange.svg)

### Test outline
<summary>Click the arrow to expand</summary>
<details>

* Configure Athena for two traffic flows, into `veth2` and `veth4`respectively (dataplane ports 1 and 2 in the P4 code). Each flow will send 512 packets into its port, incrementing the last byte of the DIP from 0 to 256 twice. For packets 257-512, the next highest digit of the DIP is incremented, which rolls into the next `/24` prefix and therefore should not get forwarded.
* Configure Athena to capture all the return traffic
* Start the traffic flows and capture the results
* Verify no packets were captured because the P4 dataplane forwawrding tables have not been programmed: the default action is `drop`.
* Configure the P4 tables to match on the DIPs as configured in the traffic flows and forward to the correct egress ports, also performing MAC rewrite.
* Start traffic flow a second time and capture everything. We wait until the received packet counts match the expected values on all flows (or timeout waiting).
* Verify the captured results has the correct number of packets for each flow.
* Perform a byte-by-byte comparison of the received packets, against the expected packets. The expected packets are modified version of th esent packets, with MAC rewrite in accordance with the intended switch behavior. We ignore portions of the packet during compare as follows:
  * The second half of the [Ixia "instrumentation" header](#about-ixia-header-and-flow-instrumentation) which follows the TCP header (since the contents vary)
  * The TCP checksum (due to the variable instrumentation contents)
  * The IP checksum (due to the variable instrumentation contents)
</details>

## Run SnappiFwdTest4PortMesh PTF test
This test sends 12 flows in a full mesh between 4 ports and verfies the received packet counts are correct. No detailed packet comparisons are performed; instead we rely upon flow-tracking statistics using the [Ixia "instrumentation" header](#about-ixia-header-and-flow-instrumentation). This is a very powerful built-in feature and is essentially the same magic which powers ful-line rate HW-based packet testers.

![SnappiFwdTest4PortMesh](SnappiFwdTest4PortMesh.svg)

### Test outline
<summary>Click the arrow to expand</summary>
<details>

* Configure Athena for 12 traffic flows, into `veth2`, `veth4`, `veth6` and `veth8` (dataplane ports 1-4 respectively in the P4 code). the 12 flows comprise a full-meash, full-duplex test of port forwarding. Each flow will send 256 packets into its port, incrementing the last byte of the DIP from 0 to 256. Each flow will emit packets at 50 packets per second. We wait until the received packet counts match the extecped values on all flows (or timeout waiting).
* Configure Athena to capture all the return traffic
* Start the traffic flows and capture the results
* Verify no packets were captured because the P4 dataplane forwawrding tables have not been programmed: the default action is `drop`.
* Configure the P4 tables to match on the DIPs as configured in the traffic flows and forward to the correct egress ports, also performing MAC rewrite.
* Start traffic flow a second time and capture everything. We wait until the received packet counts match the expected values on all flows (or timeout waiting).
* Verify the captured results has the correct number of packets for each flow.
</details>

### Run the Test
```
sudo ./runptf.sh demo1-snappi.SnappiFwdTestBidirLpmRange
```

## About Ixia header and Flow Instrumentation
Ixia packet testers utilize a proprietary flow-tracking technique which involves inserting a special "instrumentation header" into the packet. It gets inserted after the last valid protocol header, i.e. it forms the first portion of "payload." This header, which is decribed in the [ptf/scapy_contrib/ixia_scapy.py](ptf/scapy_contrib/ixia_scapy.py) Scapy file, contains several interesting fields:
* 12-byte fixed "signature" which serves as a marker to indicate start of header
* 4-byte `PGID` or "port group ID" field; think of this as a flow ID
* 32-bit sequence number which can be used to detect packet drops
* 32-bit timestamp which can be used to measure latency or delay
![Ixia-headers](ixia-headers.svg)

This technique was originally pioneered to enable hardware-based testers to perform real-time analysis of line-rate traffic prior to economically-viable protocol parsing engines (like P4 ASICs). The same technique can be done in CPUs (Athena) at lower speeds (approaching 100Gbps for larger packet sizes, limited by the packet-per-second rate).

# snappi snippets
Here we'd like to showcase some code snippets which typify some of the "idioms" of snappi.

## Get an api "handle"
The handle is a client stub which connects to the Atehan Controller REST server.
```
self.api = snappi.api(host='https://localhost:8080')
```
## Load a JSON config file
The `config` object is used to manipulate Athena configurations. You can create it a command at a time, or initialize it from a JSON file as shown below.
```
self.cfg = utils.common.load_test_config(
    self.api, 'demo1-athena-packet-config.json', apply_settings=True
)
res = self.api.set_config(self.cfg)
```

## Create a `config` object from scratch
In contrast to the previous example, here we'll obtain the object handle for an empty `config` object (maintained by the api object), and configure it a step at a time.
```
self.cfg = self.api.config()
port1, port2 = (
    self.cfg.ports
    .port(name='port1', location='localhost:5555')
    .port(name='port2', location='localhost:5556')
)
...<more config commands>...
```
## A note about SnappiIter objects
Many collection-type object classses in snappi are derived from `SnappiIter`. Examples include Ports, Flows etc. Manipulating these objects requires an understanding of Python iterators. For example:
```
flow1 = self.cfg.flows.flow(name='f1')[-1]
```
This line of code instantiates a new `Flow` object named `f1` and appends it to the `Flows` collection.
`self.cfg.flows` is a collection. Then `.flow()` is a factory methdo which creates a new `Flow` and appends it to `Flows`.

When you create a flow, the return value, e.g. from `self.cfg.flows.flow(name='f1')`, is an iterator to the `Flows` collection. To get back the `Flow` just created, use the `[-1]` accessor to get the last item in the collection.

Another idiom you may see in `snappi` examples is:
```
flow1, = self.cfg.flows.flow(name='f1')
```
The result on the right side of the `=` is an iterator as we explained above. To get the first item in the collection and assign to `flow1`, assign the iterator result to a list of variables consisting of `flow1` and a trailing commas,which means "discard remaining list values."

Another idiom you may encounter is:
```
flow1, flwo2 = self.cfg.flows.flow(name='f1').flow(name='f2')
```
This creates the first flow `f1` using `self.cfg.flows.flow(name='f1')`. The return of this factory methodd is the iterator, to which we append another flow via `.flow(.name='f2')`. The left side `flow1,flow2 =` assigns the two list members returned by the iterator to two variables.

Another idiomatic example:
```
self.cfg.flows.flow(name='f2')
flow2 = self.cfg.flows[1] # access with index
```
This appends a new flow to the `Flows` collection, then accesses it via a list index.

## Define many flows with auto-increment header fields
This snippet defines a full mesh of flows between 4 ports. Some of the constants are defined elsewhere (see [ptf/demo1-snappi.py](ptf/demo1-snappi.py) for details).

```
for src in self.port_ndxs:
    for dst in self.port_ndxs:
        if src == dst:
            continue # no hairpin switching i.e. port doesn't send to itself
        flow = self.cfg.flows.flow(name='f%d' %i)[-1]
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
```
Interesting parts of this snippet include:

Create a flow of `tx_count` packets of length 100, send at 50 PPS.
```
        flow.size.fixed = 100
        flow.rate.pps = 50
        flow.duration.fixed_packets.packets = tx_count
```

Get the second layer (IPv4 header), assign the DIP an initial value then auto-increment the least digit if the DIP (to exercise a `/24` subnet).
```
        ipv4 = flow.packet[1]
        ipv4.dst.increment.start = ip_hosts[dst]
        ipv4.dst.increment.step = '0.0.0.1'
        ipv4.dst.increment.count = tx_count
```


## Start traffic, Capture and wait for results
This snippet starts a capture, then starts traffic flows.
```
SnappiPtfUtils.start_capture(self.api, [capture_port_name])
SnappiPtfUtils.start_traffic(self.api)
```
The part which follows waits until all captures are done or quits after a timeout:
```
utils.wait_for(
    lambda: results_ok(self.api, self.cfg, ), 'stats to be as expected',
    interval_seconds=2, timeout_seconds=10
)
```
The most intersting part is the callback function invoked via `lambda` above:
```
def results_ok(api, cfg):
    """
    Returns true if stats are as expected, false otherwise.
    """
    port_results, flow_results = utils.get_all_stats(api)
    port_tx = sum([p.frames_tx for p in port_results if p.name == 'tx'])
    port_rx = sum([p.frames_rx for p in port_results if p.name == 'rx'])

    return port_tx == port_rx and all(
        [f.transmit == 'stopped' for f in flow_results]
    )
```
The `utils.wait_for()` helper method will keep calling `results_ok()` every `interval_seconds` until it returns `True` or it exceeds `timeout_seconds`.

`results_ok()` reads port and flow statistics maintained by Athena, then tests if the sum of all Tx and Rx stats counters are identical *and* all flows have stopped, signifying the test os over. The demonstrates the powerful flow-aware nature of Athena.

