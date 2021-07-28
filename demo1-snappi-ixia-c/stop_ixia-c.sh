#! /bin/bash
echo "Killing Ixia-C traffic engines and controller..."

docker ps |awk -- '/ixia-c/ { print $1}' | xargs docker kill