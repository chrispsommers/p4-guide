#! /bin/bash
SCAPYINSTALLPATH=/usr/local/lib/python3.8/dist-packages/scapy

if [ -e $SCAPYINSTALLPATH-original ]
then
    echo 'Removing T-Rex scapy package and restoring scapy package'
    sudo rm -rf $SCAPYINSTALLPATH
    sudo mv $SCAPYINSTALLPATH-original $SCAPYINSTALLPATH
else
    echo "Already using original scapy package"
fi