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
dport=443
iface=$2

while read ip
do

echo $dport
part=$((address/500))
address=$((address+1))

#test0 standard SYN
echo "test0;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "IP/tcp({dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test1 standard ECN
echo "test1;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=0})/tcp({flags=194,dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test2 ECT(0)
echo "test2;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=2})/tcp({dst=$dport})"  $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test3 ECT(0) + ECN
echo "test3;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=2})/tcp({flags=194,dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test4 ECT(1)
echo "test4;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=1})/tcp({dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test5 ECT(1)  + ECN
echo "test5;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=1})/tcp({flags=194,dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test6 CE
echo "test6;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=3})/tcp({dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}

#test7 CE  + ECN
echo "test7;$ip;$dport" >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}
tracebox -i $iface -p "ip({ecn=3})/tcp({flags=194,dst=$dport})" $(awk '{print $1}' <<<"$ip") -m 25 -t 0.5 >> res_${test}_syn443_${date}_part_${part}_port_${dport}_iface_${iface}_${nodeid}


done < alexaip${test}
