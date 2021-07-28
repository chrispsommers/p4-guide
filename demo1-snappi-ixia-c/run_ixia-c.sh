#! /bin/bash
CONTROLLER=ixiacom/ixia-c-controller:latest
ENGINE=ixiacom/ixia-c-traffic-engine:latest
echo "Starting IXia-c traffic engines and controller..."

docker run  --name ixia-c-te1 --rm --net=host --privileged -d -e OPT_LISTEN_PORT="5555" -e ARG_CORE_LIST="2 3 4" -e ARG_IFACE_LIST="virtual@af_packet,veth3" -e OPT_NO_HUGEPAGES="Yes" $ENGINE 
docker run  --name ixia-c-te2 --rm --net=host --privileged -d -e OPT_LISTEN_PORT="5556" -e ARG_CORE_LIST="2 5 6" -e ARG_IFACE_LIST="virtual@af_packet,veth5" -e OPT_NO_HUGEPAGES="Yes" $ENGINE 
docker run  --name ixia-c-te3 --rm --net=host --privileged -d -e OPT_LISTEN_PORT="5557" -e ARG_CORE_LIST="2 7 8" -e ARG_IFACE_LIST="virtual@af_packet,veth7" -e OPT_NO_HUGEPAGES="Yes" $ENGINE 
docker run  --name ixia-c-te4 --rm --net=host --privileged -d -e OPT_LISTEN_PORT="5558" -e ARG_CORE_LIST="2 9 10" -e ARG_IFACE_LIST="virtual@af_packet,veth9" -e OPT_NO_HUGEPAGES="Yes" $ENGINE 
docker run --rm --name ixia-c-controller -d --net=host $CONTROLLER --http-port 8080 --log-out --disable-app-usage-reporter --accept-eula
