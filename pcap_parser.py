#!python3

import dpkt
import socket
from datetime import datetime, timedelta
from Constants import *
import csv_parser
import RTT

import sys
import time
from decimal import Decimal

TCPDUMP_MAGIC = 0xa1b2c3d4
TCPDUMP_MAGIC_NANO = 0xa1b23c4d
PMUDPCT_MAGIC = 0xd4c3b2a1
PMUDPCT_MAGIC_NANO = 0x4d3cb2a1

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

DLT_NULL = 0
DLT_EN10MB = 1
DLT_EN3MB = 2
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
DLT_PFSYNC = 18
DLT_PPP_SERIAL = 50
DLT_PPP_ETHER = 51
DLT_ATM_RFC1483 = 100
DLT_RAW = 101
DLT_C_HDLC = 104
DLT_IEEE802_11 = 105
DLT_FRELAY = 107
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_LTALK = 114
DLT_PFLOG = 117
DLT_PRISM_HEADER = 119
DLT_IP_OVER_FC = 122
DLT_SUNATM = 123
DLT_IEEE802_11_RADIO = 127
DLT_ARCNET_LINUX = 129
DLT_APPLE_IP_OVER_IEEE1394 = 138
DLT_MTP2_WITH_PHDR = 139
DLT_MTP2 = 140
DLT_MTP3 = 141
DLT_SCCP = 142
DLT_DOCSIS = 143
DLT_LINUX_IRDA = 144
DLT_USER0 = 147
DLT_USER1 = 148
DLT_USER2 = 149
DLT_USER3 = 150
DLT_USER4 = 151
DLT_USER5 = 152
DLT_USER6 = 153
DLT_USER7 = 154
DLT_USER8 = 155
DLT_USER9 = 156
DLT_USER10 = 157
DLT_USER11 = 158
DLT_USER12 = 159
DLT_USER13 = 160
DLT_USER14 = 161
DLT_USER15 = 162
DLT_IEEE802_11_RADIO_AVS = 163
DLT_BACNET_MS_TP = 165
DLT_PPP_PPPD = 166
DLT_GPRS_LLC = 169
DLT_GPF_T = 170
DLT_GPF_F = 171
DLT_LINUX_LAPD = 177
DLT_BLUETOOTH_HCI_H4 = 187
DLT_USB_LINUX = 189
DLT_PPI = 192
DLT_IEEE802_15_4 = 195
DLT_SITA = 196
DLT_ERF = 197
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_AX25_KISS = 202
DLT_LAPD = 203
DLT_PPP_WITH_DIR = 204
DLT_C_HDLC_WITH_DIR = 205
DLT_FRELAY_WITH_DIR = 206
DLT_IPMB_LINUX = 209
DLT_IEEE802_15_4_NONASK_PHY = 215
DLT_USB_LINUX_MMAPPED = 220
DLT_FC_2 = 224
DLT_FC_2_WITH_FRAME_DELIMS = 225
DLT_IPNET = 226
DLT_CAN_SOCKETCAN = 227
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_IEEE802_15_4_NOFCS = 230
DLT_DBUS = 231
DLT_DVB_CI = 235
DLT_MUX27010 = 236
DLT_STANAG_5066_D_PDU = 237
DLT_NFLOG = 239
DLT_NETANALYZER = 240
DLT_NETANALYZER_TRANSPARENT = 241
DLT_IPOIB = 242
DLT_MPEG_2_TS = 243
DLT_NG40 = 244
DLT_NFC_LLCP = 245
DLT_INFINIBAND = 247
DLT_SCTP = 248
DLT_USBPCAP = 249
DLT_RTAC_SERIAL = 250
DLT_BLUETOOTH_LE_LL = 251
DLT_NETLINK = 253
DLT_BLUETOOTH_LINUX_MONITOR = 253
DLT_BLUETOOTH_BREDR_BB = 255
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_PROFIBUS_DL = 257
DLT_PKTAP = 258
DLT_EPON = 259
DLT_IPMI_HPM_2 = 260
DLT_ZWAVE_R1_R2 = 261
DLT_ZWAVE_R3 = 262
DLT_WATTSTOPPER_DLM = 263
DLT_ISO_14443 = 264

if sys.platform.find('openbsd') != -1:
    DLT_LOOP = 12
    DLT_RAW = 14
else:
    DLT_LOOP = 108
    DLT_RAW = 12

dltoff = {DLT_NULL: 4, DLT_EN10MB: 14, DLT_IEEE802: 22, DLT_ARCNET: 6,
          DLT_SLIP: 16, DLT_PPP: 4, DLT_FDDI: 21, DLT_PFLOG: 48, DLT_PFSYNC: 4,
          DLT_LOOP: 4, DLT_LINUX_SLL: 16}


class PktHdr(dpkt.Packet):
    """pcap packet header.
    TODO: Longer class information....
    Attributes:
        __hdr__: Header fields of pcap header.
        TODO.
    """
    __hdr__ = (
        ('tv_sec', 'I', 0),
        ('tv_usec', 'I', 0),
        ('caplen', 'I', 0),
        ('len', 'I', 0),
    )


class LEPktHdr(PktHdr):
    __byte_order__ = '<'


class FileHdr(dpkt.Packet):
    """pcap file header.
    TODO: Longer class information....
    Attributes:
        __hdr__: Header fields of pcap file header.
        TODO.
    """

    __hdr__ = (
        ('magic', 'I', TCPDUMP_MAGIC),
        ('v_major', 'H', PCAP_VERSION_MAJOR),
        ('v_minor', 'H', PCAP_VERSION_MINOR),
        ('thiszone', 'I', 0),
        ('sigfigs', 'I', 0),
        ('snaplen', 'I', 1500),
        ('linktype', 'I', 1),
    )


class LEFileHdr(FileHdr):
    __byte_order__ = '<'

class Reader(object):
    """Simple pypcap-compatible pcap file reader.
    TODO: Longer class information....
    Attributes:
        __hdr__: Header fields of simple pypcap-compatible pcap file reader.
        TODO.
    """

    def __init__(self, fileobj):
        self.name = getattr(fileobj, 'name', '<%s>' % fileobj.__class__.__name__)
        self.__f = fileobj
        buf = self.__f.read(FileHdr.__hdr_len__)
        self.__fh = FileHdr(buf)
        self.__ph = PktHdr
        if self.__fh.magic in (PMUDPCT_MAGIC, PMUDPCT_MAGIC_NANO):
            self.__fh = LEFileHdr(buf)
            self.__ph = LEPktHdr
        elif self.__fh.magic not in (TCPDUMP_MAGIC, TCPDUMP_MAGIC_NANO):
            raise ValueError('invalid tcpdump header')
        if self.__fh.linktype in dltoff:
            self.dloff = dltoff[self.__fh.linktype]
        else:
            self.dloff = 0
        self._divisor = 1E6 if self.__fh.magic in (TCPDUMP_MAGIC, PMUDPCT_MAGIC) else Decimal('1E9')
        self.snaplen = self.__fh.snaplen
        self.filter = ''
        self.__iter = iter(self)

    @property
    def fd(self):
        return self.__f.fileno()

    def fileno(self):
        return self.fd

    def datalink(self):
        return self.__fh.linktype

    def setfilter(self, value, optimize=1):
        return NotImplementedError

    def readpkts(self):
        return list(self)

    def __next__(self):
        return next(self.__iter)

    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback.
        Return the number of packets processed, or 0 for a savefile.
        Arguments:
        cnt      -- number of packets to process;
                    or 0 to process all packets until EOF
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    ts, pkt = next(iter(self))
                except StopIteration:
                    break
                callback(ts, pkt, *args)
                processed += 1
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    def __iter__(self):
        while 1:
            buf = self.__f.read(PktHdr.__hdr_len__)
            if not buf:
                break
            hdr = self.__ph(buf)
            buf = self.__f.read(hdr.caplen)
            yield (hdr.tv_sec + (hdr.tv_usec / self._divisor), buf, hdr.len)

# above are part of the source code of the library, i need to patch the __iter__ method under reader class to extract the actual size of each packet
# reference: https://github.com/kbandla/dpkt/blob/master/dpkt/pcap.py

class Flow(object):
    __slots__ = ('flowType', 
                'firstPacketArrivalTime',
                'lastPacketArrivalTime',
                'numPackets',
                'totalBytes',
                'totalOverhead',
                'consecArrvialTimes',
                'syn',
                'reset',
                'fin',
                'srcIP',
                'destIP',
                'srcPort',
                'destPort',
                'protocol',
                'flowId',
                'totalDataBytes',
                'ongoingTimebound')
    def __init__(self, id, type_, firstPacketTime, firstPacketOverhead, sizeInBytes):
        """
            firstPacketTime: first packet time stamp
            id: 4-tuple to identify the flow
            type_: either TCP or UDP
            take the ethPacket from the pcap reader and parse the fields
            to the corresponding attributes
        """
        # identification of the flow
        self.srcIP = id[0]
        self.destIP = id[1]
        self.srcPort = id[2]
        self.destPort = id[3]
        #keep track of both directions as one flow
        self.flowType = type_
        self.flowId = (self.srcIP, self.destIP, self.srcPort, self.destPort, self.flowType)

        # in timestamp unit
        self.firstPacketArrivalTime = firstPacketTime
        # TODO: below are the bookkeeping information to be updated for each iteration

        
        self.lastPacketArrivalTime = self.firstPacketArrivalTime
        self.numPackets = 1
        self.totalBytes = sizeInBytes
        self.totalOverhead = firstPacketOverhead
        self.totalDataBytes = self.totalBytes - self.totalOverhead
        self.consecArrvialTimes = [] # in seconds

        # for TCP only
        # use the following fields to determine the TCP states
        self.syn = 0
        self.reset = 0
        self.fin = 0
        self.ongoingTimebound = 0

    def __str__(self):
        return self.flowId1

    def __eq__(self, otherFlow):
        return otherFlow.flowId == this.flowId

if __name__ == "__main__":

    f = open('./univ1_pt9', 'rb')
    pcap = Reader(f)
    count = 0
    for timeStamp, buf, actual_size in pcap:
        # upate the trace file time first
        if traceFileEndsTime < timeStamp:
            traceFileEndsTime = timeStamp

        # the following update the per packets statistics

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        ethernetFrame = dpkt.ethernet.Ethernet(buf)
        datagram = ethernetFrame.data

        is_ip = False
        # bookkeeping for link layer packet statistics
        linkLayerPackets["Ethernet"]["counts"] += 1
        linkLayerPackets["Ethernet"]["totalBytes"] += actual_size
        allpacket_sizes.append(actual_size)
        if isinstance(datagram, dpkt.ip6.IP6):
            continue
        if isinstance(datagram, dpkt.ip.IP) and isinstance(datagram.data, dpkt.icmp.ICMP):
            # we consider ICMP as a network layer
            tcp_or_udp = False
            icmp = networkLayerPackets["icmp"]
            icmp["totalBytes"] += datagramSize
            icmp["counts"] += 1

            nonip_sizes.append(datagramSize)
            allpacket_sizes.append(datagramSize)
        elif isinstance(datagram, dpkt.ip.IP):
            # get the transport layer segments
            segment = datagram.data

            datagramSize = datagram.len
            datagramHeaderSize = datagram.hl * 4
            is_ip = True
            ipv4 = networkLayerPackets["ipv4"]
            ipv4["headerSize"] += datagramHeaderSize
            ipv4["totalBytes"] += datagramSize
            ipv4["counts"] += 1

            ip_sizes.append(datagramSize)
            ip_headers.append(datagramHeaderSize)
            if len(ip_sizes) != len(ip_headers):
                print(len(ip_sizes), len(ip_headers))
                print("something wrong")
            allpacket_sizes.append(datagramSize)
        elif isinstance(datagram, dpkt.arp.ARP):
            arp = networkLayerPackets["arp"]
            datagramSize = actual_size - ETHERNET_HEADER_SIZE
            arp["totalBytes"] += datagramSize
            arp["counts"] += 1

            nonip_sizes.append(datagramSize)
            allpacket_sizes.append(datagramSize)
        else:
            others = networkLayerPackets["others"]
            datagramSize = actual_size - ETHERNET_HEADER_SIZE
            others["totalBytes"] += datagramSize
            others["counts"] += 1

            nonip_sizes.append(datagramSize)
            allpacket_sizes.append(datagramSize)
            # continue

        # up to here is for sure has transport segment inside it
        tcp_or_udp = True
        # default to a TCP layer segments
        isTCP = True

        if isinstance(datagram, dpkt.ip.IP):
            datagramSize = datagram.len
            datagramHeaderSize = (datagram.hl * 32 / 8)

        segmentsName = "others"
        if type(segment) == dpkt.tcp.TCP:
            # perform tcp action
            tcpHeaderSize = segment.off * 4
            tcpSize = datagramSize - datagramHeaderSize
            
            if tcpSize < 0:
                print("datagram size {} : datagram header size {}: tcp header size {}".format(datagramSize, datagramHeaderSize,tcpHeaderSize))

            segmentsName = "tcp"
            trans = transportLayerPackets["tcp"]

            trans["headerSize"] += tcpHeaderSize
            trans["totalBytes"] += tcpSize
            trans["counts"] += 1

            tcp_sizes.append(tcpSize)
            tcp_headers.append(tcpHeaderSize)
            allpacket_sizes.append(tcpSize)
        elif type(segment) == dpkt.udp.UDP:
            isTCP = False
            segmentsName = "udp"

            udpSize = datagramSize - datagramHeaderSize
            trans = transportLayerPackets["udp"]
            trans["headerSize"] += UDP_HEADER_SIZE
            trans["totalBytes"] += udpSize
            trans["counts"] += 1

            udp_sizes.append(udpSize)
            udp_headers.append(UDP_HEADER_SIZE)
            allpacket_sizes.append(udpSize)
        else:
            tcp_or_udp = False
            trans = transportLayerPackets["others"]
            size = datagramSize - datagramHeaderSize
            trans["totalBytes"] += size
            trans["counts"] += 1

        # stop constructing the flow when it is not a IP datagram
        if not is_ip:
            continue

        # stop constructing the flow when it is not a tcp/udp segments
        if not tcp_or_udp:
            continue
        #at this stage, in IP protocol
        # datagramSize = datagram.len
        # datagramHeaderSize = datagram.hl * 4

        # get the id of the flow
        srcIp = socket.inet_ntoa(bytes(datagram.src))
        destIp = socket.inet_ntoa(bytes(datagram.dst))
        srcPort = segment.sport
        dstPort = segment.dport
        
        # default to udp segment
        overhead = 0 # for flow construction, we dont care about headsize of UDP
        type_ = "UDP"
        # get the size of this packet
        packetLength = actual_size
        # but this is TCP segment
        if isTCP:
            type_ = "TCP"

            tcpHeaderSize = segment.off * 4
            # overhead includes ip header + eth header + tcp header
            overhead = tcpHeaderSize + datagramHeaderSize + ETHERNET_HEADER_SIZE
        flowId = (srcIp, destIp, srcPort, dstPort, type_)
        

        # this is a new flow, create a object in the dictionary
        if flowId not in parsedFlows:
            # keep track of all flows in the pcap file
            flowObj = Flow(flowId, type_, timeStamp, overhead, packetLength)
            if isTCP and (segment.flags & dpkt.tcp.TH_SYN):
                flowObj.syn = 1
            parsedFlows[flowId] = flowObj
            # iterate next packet
            continue

        flowObj = parsedFlows[flowId]
        # start the bookkeeping process
        #--------------------------------------------------------Record Timestamp--------------------------------------------------------------------------

        # 1. elapsed time operation and update the fields
        currentPacketArrivalTime = datetime.fromtimestamp(timeStamp)
        lastPacketArrivalTime = datetime.fromtimestamp(flowObj.lastPacketArrivalTime)
        # use different unit: https://markhneedham.com/blog/2015/07/28/python-difference-between-two-datetimes-in-milliseconds/
        delta = currentPacketArrivalTime - lastPacketArrivalTime

        # in milicdons
        preciseElapsed = (delta.days * 86400000) + (delta.seconds * 1000) + (float(delta.microseconds/1000))

        # updated last packet arrival time
        flowObj.lastPacketArrivalTime = timeStamp

        #---------------------------------------------------------------------------------------------------------------------------------------
        # 2. update the overhead size
        if isTCP:
            flowObj.totalOverhead += overhead
        # 3. update the total byte size
        flowObj.numPackets += 1
        flowObj.totalBytes += packetLength
        # 4. update the payload data size
        flowObj.totalDataBytes = flowObj.totalBytes - flowObj.totalOverhead
        # 5. update the consecutive arrvial time
        flowObj.consecArrvialTimes.append(preciseElapsed)
        if isTCP:
            # check the packet timebound, indicate the packet is on going for this flow
            if flowObj.syn and not flowObj.fin and not flowObj.reset:
                flowObj.ongoingTimebound = 1

            # 4. may need to update the final state of connection using the fields in TCP
            if segment.flags & dpkt.tcp.TH_FIN:
                flowObj.fin = 1
            elif segment.flags & dpkt.tcp.TH_RST:
                flowObj.reset = 1
            elif segment.flags & dpkt.tcp.TH_SYN:
                flowObj.syn = 1

    print("aggreate flows begin:")
    
    # combine the flow together if they belong to opposite direction
    for (srcIp, destIp, srcPort, dstPort, type_) in parsedFlows:
        forwardDir = (srcIp, destIp, srcPort, dstPort, type_)
        oppositeDir = (destIp, srcIp, dstPort, srcPort, type_)
        
        # recall each forward flow is unique inside the parsedFlow datastructure
        if forwardDir not in aggregatedFlow:
            if oppositeDir in aggregatedFlow:


                # combine the flows by updating the flow that is inside the aggreggate flow dictionary
                oppositeFlow = aggregatedFlow[oppositeDir]
                forwardFlow = parsedFlows[forwardDir]

                oppositeFlow.firstPacketArrivalTime = min(forwardFlow.firstPacketArrivalTime, oppositeFlow.firstPacketArrivalTime)
                oppositeFlow.lastPacketArrivalTime = max(forwardFlow.lastPacketArrivalTime, oppositeFlow.lastPacketArrivalTime)
                oppositeFlow.numPackets += forwardFlow.numPackets

                oppositeFlow.totalBytes += forwardFlow.totalBytes
                oppositeFlow.totalOverhead += forwardFlow.totalOverhead
                oppositeFlow.totalDataBytes += forwardFlow.totalDataBytes

                if oppositeFlow.totalBytes != oppositeFlow.totalDataBytes + oppositeFlow.totalOverhead:
                    print("bug here")

                oppositeFlow.consecArrvialTimes.extend(forwardFlow.consecArrvialTimes)

                if not oppositeFlow.syn and forwardFlow.syn:
                    oppositeFlow.syn = 1
                if not oppositeFlow.reset and forwardFlow.reset:
                    oppositeFlow.reset = 1
                if not oppositeFlow.fin and forwardFlow.fin:
                    oppositeFlow.fin = 1
            else:
                # this is the new flow to the aggregated flow
                forwardFlow = parsedFlows[forwardDir]
                aggregatedFlow[forwardDir] = forwardFlow

    # sanity check
    print("parsedFlow final length: ",len(parsedFlows.keys()))
    print("aggregated flow final length: ", len(aggregatedFlow.keys()))

    #csv_parser.parse_packet_stats()
    csv_parser.parse_to_xlsx()
    f.close()



