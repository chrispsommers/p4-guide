# Introduction

See [README-using-bmv2.md](../README-using-bmv2.md) for some things
that are common across different P4 programs executed using bmv2.

This article describes how to:

+ compile a simple demo P4 program using the `p4c` P4 compiler
+ execute the compiled program using the `simple_switch_grpc` software
  switch
+ add table entries to the running P4 program using the P4Runtime API
  message protocol, using a small library of Python code to help you.
+ send packets to the running P4 program using `scapy`.

If you are interested in an example automated test for the
`demo1.p4_16.p4` program that uses the PTF library, see
[README-ptf.md](README-ptf.md).


# Compiling

To compile the P4_16 version of the code, in file `demo1.p4_16.p4`:

    p4c --target bmv2 --arch v1model --p4runtime-files demo1.p4_16.p4rt.txt demo1.p4_16.p4

Running that command will create these files:

    demo1.p4_16.p4i - the output of running only the preprocessor on
        the P4 source program.
    demo1.p4_16.json - the JSON file format expected by BMv2
        behavioral model `simple_switch_grpc`.
    demo1.p4_16.p4rt.txt - the text format of the file that describes
        the P4Runtime API of the program.

Only the last two files are needed to run your P4 program.  You can
ignore the file with suffix `.p4i` unless you suspect that the
preprocessor is doing something unexpected with your program.

The P4Runtime API is targeted for use with P4_16.  I do not know of
any plans to make it work with P4_14 programs.

The .dot and .png files in the subdirectory 'graphs' were created with
the p4c-graphs program, which is also installed when you build and
install p4c:

     p4c-graphs -I $HOME/p4c/p4include demo1.p4_16.p4

The `-I` option is only necessary if you did _not_ install the P4
compiler in your system-wide /usr/local/bin directory.


# Running simple_switch_grpc

To run the behavioral model with 8 ports numbered 0 through 7:

    sudo simple_switch_grpc --log-console -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 --no-p4

To get the log to go to a file instead of the console:

    sudo simple_switch_grpc --log-file ss-log --log-flush -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 --no-p4

CHECK THIS: If you see "Add port operation failed" messages in the
output of the `simple_switch_grpc` command, it means that one or more
of the virtual Ethernet interfaces veth0, veth2, etc. have not been
created on your system.  Search for "veth" in the file
[`README-using-bmv2.md`](../README-using-bmv2.md`) (top level
directory of this repository) for a command to create them.

See the file
[`README-troubleshooting.md`](../README-troubleshooting.md) in case
you run into troubles.  It describes symptoms of some problems, and
things you can do to resolve them.


# Using a Python interactive session as a controller

To start an interactive Python session that can be used to load the
compiled P4 program into the running `simple_switch_grpc` process, and
install table entries:

```bash
cd p4-guide/demo1
export PYTHONPATH="`realpath ../pylib`:$PYTHONPATH"
python

# NOTE: For most interactive Python sessions, typing Ctrl-D or the
# command `quit()` is enough to quit Python and go back to the shell.
# For this Python session, one or more of the commands below cause
# this interactive session to 'hang' if you try that.  In the most
# commonly used Linux/OSX shells you can type Ctrl-Z to put the Python
# process in the background and return to the shell prompt.  You may
# want to kill the process, e.g. using `kill -9 %1` in bash.
```

Enter these commands at the `>>> ` prompt of the Python session:

```python
# Note: 50051 is the default TCP port number on which the
# simple_switch_grpc process is listening for connections until
# 2020-Dec-03, when the default was changed to TCP port 9559, because
# 9559 was granted for use for this purpose by IANA shortly before
# then.

my_dev1_addr='localhost:9559'
my_dev1_id=0
import base_test as bt

# If the previous statement gave an error like "ModuleNotFoundError:
# No module named 'Queue'", then likely you are using Python3.  Good!
# Use the following line instead to get a Python3 version of that
# module.
import base_test_py3 as bt

# Convert the BMv2 JSON file demo1.p4_16.json, created by the p4c
# compiler, into the binary format file demo1.p4_16.bin expected by
# simple_switch_grpc.  We will send this binary file to
# simple_switch_grpc over the P4Runtime connection.

bt.bmv2_json_to_device_config('demo1.p4_16.json', 'demo1.p4_16.bin')

# Load the binary version of the compiled P4 program, and the text
# version of the P4Runtime info file, into the simple_switch_grpc
# 'device'.

bt.update_config('demo1.p4_16.bin', 'demo1.p4_16.p4rt.txt', my_dev1_addr, my_dev1_id)
# Result of successful bt.update_config() call is "P4Runtime
# SetForwardingPipelineConfig" output from simple_switch_grpc log.

h=bt.P4RuntimeTest()
h.setUp(my_dev1_addr, 'demo1.p4_16.p4rt.txt')
```

Note: Unless the `simple_switch_grpc` process crashes, or you kill it
yourself, you can continue to use the same running process, loading
different compiled P4 programs into it over time, repeating the
`bt.update_config` call above with the same or different file names.

----------------------------------------------------------------------
demo1.p4_16.p4
----------------------------------------------------------------------

```python
# The full names of the tables and actions begin with 'ingress.' or
# 'egress.', but some layer of software between here and there adds
# these prefixes for you, as long as the table/action name is unique
# after that point.

# assign default actions for tables using an empty key, represented by
# None in Python.

h.table_add(('ipv4_da_lpm', None), ('ingressImpl.my_drop', []))
h.table_add(('mac_da', None), ('ingressImpl.my_drop', []))
h.table_add(('send_frame', None), ('egressImpl.my_drop', []))

# add new non-default table entries by filling in at least one key field

# bt.ipv4_to_binary takes an IPv4 address written as a string in
# dotted decimal notation, e.g. '10.1.2.3', and converts it to a
# string with binary contents expected by the table add operation.

# bt.mac_to_binary is similar, but takes a MAC address as a string,
# with colons separating each byte, specified in hex,
# e.g. '00:de:ad:be:ef:ff'.

# bt.stringify takes a non-negative integer 'n' as its parameter.  It
# returns a string with binary contents expected by the Python
# P4Runtime client operations.

# Note: stringify will only work if you are using a version of
# p4lang/PI repository code from 2021-Mar or later, in particular with
# the changes made in this PR: https://github.com/p4lang/PI/pull/538
# Before that change, you must send bit strings with the full bit
# width of the value as declared in the P4 source code.

# Define a few small helper functions that help construct parameters
# for the function table_add()

def key_ipv4_da_lpm(h, ipv4_addr_string, prefix_len):
    return ('ipv4_da_lpm', [h.Lpm('hdr.ipv4.dstAddr',
                            bt.ipv4_to_binary(ipv4_addr_string), prefix_len)])

def act_set_l2ptr(l2ptr_int_val):
    return ('set_l2ptr', [('l2ptr', bt.stringify(l2ptr_int_val))])

def key_mac_da(h, l2ptr_int_val):
    return ('mac_da', [h.Exact('meta.fwd_metadata.l2ptr',
                       bt.stringify(l2ptr_int_val))])

def act_set_bd_dmac_intf(bd_int_val, dmac_string, intf_int_val):
    return ('set_bd_dmac_intf',
            [('bd', bt.stringify(bd_int_val)),
             ('dmac', bt.mac_to_binary(dmac_string)),
             ('intf', bt.stringify(intf_int_val))])

def key_send_frame(h, bd_int_val):
    return ('send_frame', [h.Exact('meta.fwd_metadata.out_bd',
                           bt.stringify(bd_int_val))])

def act_rewrite_mac(smac_string):
    return ('rewrite_mac', [('smac', bt.mac_to_binary(smac_string))])

h.table_add(key_ipv4_da_lpm(h, '10.1.0.1', 32), act_set_l2ptr(58))
h.table_add(key_mac_da(h, 58), act_set_bd_dmac_intf(9, '02:13:57:ab:cd:ef', 2))
h.table_add(key_send_frame(h, 9), act_rewrite_mac('00:11:22:33:44:55'))

```

Another set of table entries to forward packets to a different output
interface:

```python
h.table_add(key_ipv4_da_lpm(h, '10.1.0.200', 32), act_set_l2ptr(81))
h.table_add(key_mac_da(h, 81), act_set_bd_dmac_intf(15, '08:de:ad:be:ef:00', 4))
h.table_add(key_send_frame(h, 15), act_rewrite_mac('ca:fe:ba:be:d0:0d'))

# There is preliminary support for reading the entries of a table that
# you can try like this, but right now it prints the P4Runtime
# messages returned without performing any translation of table,
# search key field, action, or parameter ids to the corresponding
# names, so it is not very convenient.

# If someone wants to beat me to implementing such a thing, take a
# look at the code in base_test.py, especially the table_dump_data
# method.

h.table_dump_data('ipv4_da_lpm')
```

You can also examine the existing entries in a table using the
`simple_switch_CLI` command (best from a separate terminal window)
with the 'table_dump' command:

```bash
simple_switch_CLI
```

```
table_dump ipv4_da_lpm
==========
TABLE ENTRIES
**********
Dumping entry 0x0
Match key:
* ipv4.dstAddr        : LPM       0a010001/32
Action entry: set_l2ptr - 3a
**********
Dumping entry 0x1
Match key:
* ipv4.dstAddr        : LPM       0a0100c8/32
Action entry: set_l2ptr - 51
==========
Dumping default entry
Action entry: my_drop - 
==========
```

WARNING: Nothing in these programs will stop you from modifying the
table entries, or other switch state, from the `simple_switch_CLI`
program, but if you do so, you will likely cause state maintained by
the P4Runtime API to become stale with respect to what is in the
switch.  Don't do this unless you like causing yourself confusion.


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

# This packet will only be forwarded if you created the 'second set'
# of example table entries above (or your own, which this packet can
# match).
fwd_pkt3=Ether() / IP(dst='10.1.0.200') / TCP(sport=5793, dport=80)
sendp(fwd_pkt3, iface="veth0")
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


# Last successfully tested with these software versions

For https://github.com/p4lang/p4c

```
$ git log -n 1 | head -n 3
commit 4e64e1dcc54ad9edbdcf6c8542b9a13b16192cf3
Author: Mihai Budiu <mbudiu@vmware.com>
Date:   Sat Apr 3 02:49:09 2021 -0700
```

For https://github.com/p4lang/behavioral-model

```
$ git log -n 1 | head -n 3
commit 27c235944492ef55ba061fcf658b4d8102d53bd8
Author: Thomas Dreibholz <dreibh@simula.no>
Date:   Wed Mar 24 19:42:48 2021 +0100
```

For https://github.com/p4lang/PI

```
$ git log -n 1 | head -n 3
commit 4961fb9fb7a03b8fe7f1511f05fc7a0238b1d88c
Author: Antonin Bas <abas@vmware.com>
Date:   Thu Mar 11 20:28:34 2021 -0800
```
