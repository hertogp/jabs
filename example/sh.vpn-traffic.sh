#!/bin/bash

# convert ad.dot to image:
# dot -Tsvg ad.dot > ad.svg
# dot -Tpng ad.dot > ad.png

# input file
LOGS=$1
# dot output filename
DOTF=${LOGS%.csv}.dot
# filename for the enriched log file
VPNF=${LOGS%.csv}+vpns.csv
# image output filename
IMGF=${LOGS%.csv}.png


# read $LOG -> write enriched logs to $VPNF and dotify to $DOTF
# then turn dot-file into image

dfm r:$LOGS \
    src_vpn=ipl:subnets.csv,src,vpn \
    dst_vpn=ipl:subnets.csv,dst,vpn \
    src,dst,srv,count,src_vpn,dst_vpn=keep: \
    count=sum: \
    w:$VPNF \
    $DOTF,VPN-traffic=dotify:src_vpn^src,dst_vpn^dst,srv \
    -v -d

dot -Tpng $DOTF > $IMGF

