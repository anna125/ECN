
import sys
import logging
import subprocess
import traceback
from datetime import datetime
import random
from scapy.all import *

import socket
import collections
from struct import *
import time

from twisted.plugin import IPlugin
from zope.interface import implementer

from pathspider.base import Spider
from pathspider.base import ISpider
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

Connection = collections.namedtuple("Connection", ["client", "port", "state"])
SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "host", "ecnstate",
                                                       "connstate"])

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2

USER_AGENT = "pathspider"

## Chain functions

def tcpcompleted(rec, tcp, rev): # pylint: disable=W0612,W0613
    return not tcp.fin_flag

def ecnsetup(rec, ip):
    rec['ecn_zero'] = False
    rec['ecn_one'] = False
    rec['ce'] = False
    return True

def ecnflags(rec, tcp, rev):
    SYN = 0x02
    CWR = 0x40
    ECE = 0x80

    flags = tcp.flags

    if flags & SYN:
        if rev == 0:
            rec['fwd_syn_flags'] = flags
        if rev == 1:
            rec['rev_syn_flags'] = flags

    return True

def ecncode(rec, ip, rev):
    EZ = 0x01
    EO = 0x02
    CE = 0x03

    if (ip.traffic_class & EZ == EZ):
        rec['ecn_zero'] = True
    if (ip.traffic_class & EO == EO):
        rec['ecn_one'] = True
    if (ip.traffic_class & CE == CE):
        rec['ce'] = True

    return True

## ECNSpider main class

@implementer(ISpider, IPlugin)
class ECNSpiderA(Spider):

    def activate(self, worker_count, libtrace_uri):
        super().activate(worker_count=worker_count,
                         libtrace_uri=libtrace_uri)
        self.tos = None # set by configurator
        self.conn_timeout = 10

    def config_zero(self):
        """
        Disables RST response via iptables.
        """
        logger = logging.getLogger('ecnspidera')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP'])
        logger.debug("Configurator disable RST")

        logger = logging.getLogger('ecnspidera')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")

    def config_one(self):
        """
        Disables RST response via iptables.
        """

        logger = logging.getLogger('ecnspidera')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP'])
        logger.debug("Configurator disable RST")

        logger = logging.getLogger('ecnspidera')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")


    def connect(self, job, pcs, config):
        """
        Performs a TCP connection.
        """

        if ":" in job[0]:
            af = socket.AF_INET6
            vers = 6
        else:
            af = socket.AF_INET
            vers = 4
        if config == 0:
            try:
                sock = socket.socket(af)
                sock.settimeout(self.conn_timeout)
                sock.connect((job[0], job[1]))

                return Connection(sock, sock.getsockname()[1], CONN_OK)
            except TimeoutError:
                return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT)
            except OSError:
                return Connection(sock, sock.getsockname()[1], CONN_FAILED)

        else:
            try:

#create a socket for ECN connection
                sock = socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.settimeout(self.conn_timeout)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                packet = ''   
#retry the local ip address for the correct checksum
                s = socket.socket(af, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 0))  # connecting to a UDP address doesn't send packets
                source_ip = s.getsockname()[0]
                dest_ip = job[0] 

            # ip header fields
                ihl = 5
                version = vers
                tos = 0
                tot_len = 20 + 20   # python seems to correctly fill the total length, dont know how ??
                id = random.randint(1024, 65535)   #Id of this packet
                frag_off = 0
                ttl = 255
                protocol = socket.IPPROTO_TCP
                check = 10  # python seems to correctly fill the checksum
                saddr = socket.inet_aton ( source_ip )  #Spoof the source ip address if you want to
                daddr = socket.inet_aton ( dest_ip )
                ihl_version = (version << 4) + ihl
 
# the ! in the pack format string means network order
                ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

# tcp header fields
                source =  random.randint(1024, 65535)   # source port
                dest = job[1]   # destination port
                seq = 0
                ack_seq = 0
                doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
                fin = 0
                syn = 1
                rst = 0
                psh = 0
                ack = 0
                urg = 0
                cwr = 0
                ece = 0
                ns = 0
                window = socket.htons (5840)    #   maximum allowed window size
                check = 0
                urg_ptr = 0

                offset_res = (doff << 4) + ns
                tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5) + (cwr << 6) + (ece << 7) 
 
# the ! in the pack format string means network order
                tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
 
# pseudo header fields
                source_address = socket.inet_aton( source_ip )
                dest_address = socket.inet_aton(dest_ip)
                placeholder = 0
                protocol = socket.IPPROTO_TCP
                tcp_length = len(tcp_header)
                psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
                psh = psh + tcp_header;
 
                tcp_checksum = checksum(psh)

# make the tcp header again and fill the correct checksum
                tcp_header = pack('!HHLLBBHHH' , source, job[1], seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
 
# final full packet - syn packets dont have any data
                packet = ip_header + tcp_header
 
#Send the packet finally - the port specified has no effect
                sock.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target


#read the seq number from ack
                s_addr2 = ""
                while (s_addr2!=job[0]):
                    a = sock.recvfrom(4096)
               #packet string from tuple
                    a = a[0]
     
    #take first 20 characters for the ip header
                    ip_header2 = a[0:20]
    #now unpack them :)
                    iph2 = unpack('!BBHHHBBH4s4s' , ip_header2)
     
                    version_ihl2 = iph2[0]
                    version2 = version_ihl2 >> 4
                    ihl2 = version_ihl2 & 0xF
     
                    iph_length2 = ihl2 * 4
     
                    ttl2 = iph2[5]
                    protocol2 = iph2[6]
                    s_addr2 = socket.inet_ntoa(iph2[8]);
                    d_addr2 = socket.inet_ntoa(iph2[9]);
                    tcp_header2 = a[iph_length2:iph_length2+20]
                    tcp_header2 = a[iph_length2:iph_length2+20]
     
                    #now unpack them :)
                    tcph2 = unpack('!HHLLBBHHH' , tcp_header2)
     
                    source_port2 = tcph2[0]
                    dest_port2 = tcph2[1]
                    seq2 = tcph2[2]
                    ack2 = tcph2[3]
                    doff_reserved2 = tcph2[4]
                    tcph_length2 = doff_reserved2 >> 4
                    h_size2 = iph_length2 + tcph_length2 * 4
                    data_size2 = len(a) - h_size2
      
    #get data from the packet
                    data = a[h_size2:]

    ### send ack to syn/ack
                tos = 0
     
    # the ! in the pack format string means network order
                ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
     
    # tcp header fields
#                    source =  random.randint(1024, 65535)   # source port
                seq = ack2
                ack_seq = seq2+1
                doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
                fin = 0
                syn = 0
                rst = 0
                psh = 0
                ack = 1
                urg = 0
                cwr = 0
                ece = 0
                window = socket.htons (5840)    #   maximum allowed window size
                check = 0
                urg_ptr = 0

                offset_res = (doff << 4) + 0
                tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5) + (cwr << 6) + (ece << 7)
     
    # the ! in the pack format string means network order
                tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)

    # make the tcp header again and fill the correct checksum
                tcp_header = pack('!HHLLBBHHH' , source, job[1], seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
     
    # final full packet - syn packets dont have any data
                packet = ip_header + tcp_header
     
    #Send the packet finally - the port specified has no effect
                sock.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target

    ###########################################

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((source_ip, source))
                print ("#:")
                print (job[0])

################################

################################

                return Connection(sock, sock.getsockname()[1], CONN_OK)
            except TimeoutError:
                return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT)
            except OSError:
                return Connection(sock, sock.getsockname()[1], CONN_FAILED)
                sock.close()


    def post_connect(self, job, conn, pcs, config):
        """
        Close the socket gracefully.
        """

        if conn.state == CONN_OK:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, True)
        else:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, False)

        try:
            conn.client.shutdown(socket.SHUT_RDWR)
        except:
            pass

        try:
            conn.client.close()
        except:
            pass

        return rec

    def create_observer(self):
        """
        Creates an observer with ECN-related chain functions.
        """

        logger = logging.getLogger('ecnspider3')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, ecnsetup],
                            ip4_chain=[basic_count, ecncode],
                            ip6_chain=[basic_count, ecncode],
                            tcp_chain=[ecnflags, tcpcompleted])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def merge(self, flow, res):
        """
        Merge flow records.
        
        Includes the configuration and connection success or failure of the
        socket connection with the flow record.
        """

        logger = logging.getLogger('ecnspider3')
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "connstate": res.connstate,
                    "ecnstate": res.ecnstate,
                    "observed": False }
        else:
            flow['connstate'] = res.connstate
            flow['ecnstate'] = res.ecnstate
            flow['observed'] = True

        logger.debug("Result: " + str(flow))
        self.outqueue.put(flow)

ecnspider = ECNSpiderA()
