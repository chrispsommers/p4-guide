#! /bin/bash

T="`realpath ../../testlib`"
if [ x"${PYTHONPATH}" == "x" ]
then
    P="${T}"
else
    P="${T}:${PYTHONPATH}"
fi

#echo "P is: $P"

# Only show a list of tests
#ptf --pypath "$P" --test-dir . --list
#exit 0

# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.

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
    --test-params="grpcaddr='localhost:9559';p4info='registeraccess.p4info.txt';config='registeraccess.json'" \
    --test-dir .


# Add the option below to the ptf command line if you want to test
# only a restricted list of tests, not all of them.

#    --test-file testnamelist.txt \
