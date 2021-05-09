#! /bin/bash

T="`realpath ../testlib`"
# # T="`realpath ../../otg/snappi-tests/tests/utils`:`realpath ../testlib`"
# T="`realpath ../../otg/snappi-tests/tests/utils`"
if [ x"${PYTHONPATH}" == "x" ]
then
    P="${T}"
else
    P="${T}:${PYTHONPATH}"
fi

echo "P is: $P"

# Only show a list of tests
#ptf --pypath "$P" --test-dir ptf --list
#exit 0

# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.

./run_ixia-c.sh

ptf \
    --pypath "$P" \
    -i 0@veth1 \
    -i 1@veth3 \
    -i 2@veth5 \
    -i 3@veth7 \
    -i 4@veth9 \
    -i 5@veth11 \
    -i 6@veth13 \
    -i 7@veth15 \
    --test-params="grpcaddr='localhost:9559';p4info='demo1.p4_16.p4rt.txt';config='demo1.p4_16.json'" \
    --test-dir ptf $@

./stop_ixia-c.sh