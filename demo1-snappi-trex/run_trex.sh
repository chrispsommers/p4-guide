#! /bin/bash
TREXPATH=/opt/trex/v2.90

if [ -e /etc/trex_cfg.yaml ]
then
    echo "Starting T-Rex Server"
    (cd $TREXPATH; ./t-rex-64 -i)
else
    echo "T-Rex has not been set up. Run 'sudo ./trex_setup.sh'"
fi