from subprocess import call
import subprocess
import sys
from scapy.all import *


#test0
mss = 1460
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)
dport = int(sys.argv[2])
dest = sys.argv[1]
interface = sys.argv[3]

print "test0;"+str(dest)+";"+str(dport)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface,timeout=2)

if (synack_response is None):
	print "test0;"+str(dest)+";"+str(dport)+";nosyn"
	exit()

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)

payload = "GET / HTTP/1.0\\r\\nHOST: %s\\r\\n\\r\\n" % (dest)

flagtcp="IP/tcp({flags=0x10,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test1 standard ECN
print "test1;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=0})/tcp({flags=80,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test2 ECT(0)
print "test2;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=2})/tcp({flags=16,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test3 ECT(0) + ECN
print "test3;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=2})/tcp({flags=80,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test4 ECT(1)
print "test4;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=1})/tcp({flags=16,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test5 ECT(1)  + ECN
print "test5;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=1})/tcp({flags=80,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test6 CE
print "test6;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=3})/tcp({flags=16,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])

#test7 CE  + ECN
print "test7;"+str(dest)+";"+str(dport)
seq = random.randint(1024,65535)
sport = random.randint(1024,65535)

ip_packet = IP(dst=dest)
syn_packet = TCP(sport=sport, dport=dport, flags='SECE', seq=seq, window = 29200, options=[('MSS', mss)])

packet = ip_packet/syn_packet
synack_response =     sr1(packet, verbose=False,iface=interface)

next_seq = seq + 1
my_ack = synack_response.seq + 1
ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, window = 29200, ack=my_ack)

send(ip_packet/ack_packet, verbose=False, iface=interface)
flagtcp="ip({ecn=3})/tcp({flags=80,dst=%i,src=%i,seq=%i,ack=%i})/raw('%s')"%(dport,sport,next_seq,my_ack,payload)
call(['tracebox', '-i', interface, '-p', flagtcp,'-m','25','-t','0.5', dest])


