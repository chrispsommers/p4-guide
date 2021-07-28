#! /bin/bash
SCAPYINSTALLPATH=/usr/local/lib/python3.8/dist-packages/scapy
TREXPATH=/opt/trex
TREXVER=v2.90

echo 'Renaming scapy package and installing T-Rex scapy package'
sudo mv $SCAPYINSTALLPATH $SCAPYINSTALLPATH-original
sudo cp -r $TREXPATH/$TREXVER/external_libs/scapy-2.4.3/scapy $SCAPYINSTALLPATH