# Introduction

See [README-using-bmv2.md](../README-using-bmv2.md) for some things
that are common across different P4 programs executed using bmv2.

This article describes how to run an automated test of a P4 program
using a Python library called [`ptf`](https://github.com/p4lang/ptf)
for "Packet Test Framework"

As of 2021-Apr-05, this has only been tested to work on the following systems:

+ The Ubuntu 20.04 Desktop Linux VM available for download at [this
  link](https://drive.google.com/file/d/13SwWBEnApknu84fG9otwbL5NC78tut-d/view?usp=sharing),
  built from versions of the open source P4 development tools as of
  2021-Apr-05.
+ An Ubuntu 20.04 Desktop Linux system where all open source P4
  development tools have been installed using the script named
  [`install-p4dev-v4.sh` in this
  repository](../bin/README-install-troubleshooting.md), which
  installs all Python libraries for Python3, not Python2.


# Compiling and running simple_switch_grpc

These can be done using the same commands described in the [demo1
P4Runtime README](README-p4runtime.md).


# Running the PTF test and understanding the output

Note that the instructions below assume that you have compiled the P4
program `demo1.p4_16.p4` using the command described at the link
above, producing these output files:

+ `demo1.p4_16.p4rt.txt`
+ `demo1.p4_16.json`

If you prefer to use different file names, then edit the file
`runptf.sh` to replace those names with the ones you used.

The script `runptf.sh` also starts the `ptf` command with a mapping
between switch port numbers and Linux interface names that is similar
to, but not identical with, the mapping given when starting the
`simple_switch_grpc` process.  It assumes that `veth0` and `veth1` are
a linked pair of virtual Ethernet interfaces, such that sending a
packet to one will always be transmitted to the other one of the pair,
and also `veth2` and `veth3` are a linked pair, etc. exactly as the
`veth_setup.sh` script in this repository creates them.

To run the automated tests:
```bash
sudo ./runptf.sh
```

If successful, you will see output in the terminal similar to this:
```
$ sudo  ./runptf.sh 
/usr/local/lib/python3.8/dist-packages/ptf-0.9.1-py3.8.egg/EGG-INFO/scripts/ptf:19: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
2021-04-05 06:41:05,397 - root - INFO - Importing platform: eth
2021-04-05 06:41:05,397 - root - DEBUG - Configuration: {'list': False, 'list_test_names': False, 'allow_user': False, 'test_spec': '', 'test_file': None, 'test_dir': 'ptf', 'test_order': 'default', 'test_order_seed': 2746, 'platform': 'eth', 'platform_args': None, 'platform_dir': '/usr/local/lib/python3.8/dist-packages/ptf-0.9.1-py3.8.egg/ptf/platforms', 'interfaces': [(0, 0, 'veth1'), (0, 1, 'veth3'), (0, 2, 'veth5'), (0, 3, 'veth7'), (0, 4, 'veth9'), (0, 5, 'veth11'), (0, 6, 'veth13'), (0, 7, 'veth15')], 'device_sockets': [], 'log_file': 'ptf.log', 'log_dir': None, 'debug': 'verbose', 'profile': False, 'profile_file': 'profile.out', 'xunit': False, 'xunit_dir': 'xunit', 'relax': False, 'test_params': "grpcaddr='localhost:9559';p4info='demo1.p4_16.p4rt.txt';config='demo1.p4_16.json'", 'failfast': False, 'fail_skipped': False, 'default_timeout': 2.0, 'default_negative_timeout': 0.1, 'minsize': 0, 'random_seed': None, 'disable_ipv6': False, 'disable_vxlan': False, 'disable_erspan': False, 'disable_geneve': False, 'disable_mpls': False, 'disable_nvgre': False, 'disable_igmp': False, 'disable_rocev2': False, 'qlen': 100, 'test_case_timeout': None, 'socket_recv_size': 4096, 'port_map': {(0, 0): 'veth1', (0, 1): 'veth3', (0, 2): 'veth5', (0, 3): 'veth7', (0, 4): 'veth9', (0, 5): 'veth11', (0, 6): 'veth13', (0, 7): 'veth15'}}
2021-04-05 06:41:05,398 - root - INFO - port map: {(0, 0): 'veth1', (0, 1): 'veth3', (0, 2): 'veth5', (0, 3): 'veth7', (0, 4): 'veth9', (0, 5): 'veth11', (0, 6): 'veth13', (0, 7): 'veth15'}
2021-04-05 06:41:05,398 - root - INFO - Autogen random seed: 34319770
2021-04-05 06:41:05,400 - root - INFO - *** TEST RUN START: Mon Apr  5 06:41:05 2021
demo1.FwdTest ... ok

----------------------------------------------------------------------
Ran 1 test in 0.940s

OK
demo1.DupEntryTest ... ok

----------------------------------------------------------------------
Ran 1 test in 0.018s

OK
```

The line `demo1.FwdTest ... ok` indicates that a test named `FwdTest`
was run, and it passed, i.e. no failures that it checks for were
detected, and similarly the line `demo1.DupEntryTest ... ok` indicates
that a test named `DupEntryTest` passed.

You can see the Python code for what these automated tests do in the
file [`ptf/demo1.py`](ptf/demo1.py).  Some comments there may be
useful in finding documentation for many of the functions and methods
used in that test program.

Besides the few log messages that appear on the terminal, running the
tests also causes the following files to be written:

+ `ptf.log` - Log messages generated by some functions in the `ptf`
  library, mingled with showing when each test case starts and ends.
  This can be very handy when developing new test scripts, to see what
  is going on in more detail.  Adding your own `print` and
  `logging.debug` calls to the Python test program is also useful for
  this.
+ `ptf.pcap` - A pcap file that can be read like any other.  There is
  a header _before_ the Ethernet header recorded in this pcap file
  that records the port number that the packets were recorded passing
  over.  Packets sent and received on all switch ports are recorded in
  this same file, mingled together.
