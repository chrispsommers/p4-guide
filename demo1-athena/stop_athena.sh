#! /bin/bash
echo "Killing Athena traffic engines and controller..."

docker ps |awk -- '/athena/ { print $1}' | xargs docker kill