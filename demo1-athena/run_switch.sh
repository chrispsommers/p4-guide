#! /bin/bash
echo "Starting P4 switch..."
sudo simple_switch_grpc --log-file ss-log --log-flush -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 --no-p4