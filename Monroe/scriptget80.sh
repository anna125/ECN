#!/bin/bash

nodeid="$(head -n 1 /etc/nodeid)"

date="$(date -I)"

if [ -z "$1" ]
then
	test="aa"
else
	test=$1
fi

round=0
address=0
dport=80
iface=$2
while read ip
do

part=$((address/500))
address=$((address+1))

python -u traceboxget.py $ip $dport $iface >> res_${test}_get80_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

done < alexaip${test}
