#!/bin/bash

# run this to update the base protocol information used to link log information
# to protocol and port nrs used in ipr-module ('80/tcp' -> (http, 80, 6)

# get ipv4 assigned protocol nrs
wget -N https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv
wget -N https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv

# get ARP related assigned numbers
wget -N https://www.iana.org/assignments/arp-parameters/arp-parameters-1.csv

