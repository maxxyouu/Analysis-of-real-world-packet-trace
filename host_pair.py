import dpkt
import socket
from datetime import datetime, timedelta
import csv_parser
from Constants import *
import RTT
from statistics import median

class ACKS(object):
    """
    an object for each pair of host to store median srtts
    """
    __slots__ = ('flowid',
                 'median_srtts'
                )
    def __init__(self, id_, startTime, first_srtt):
        """
        flowid is the srcip and dstip
        """
        self.flowid = id_
        self.median_srtts = [(first_srtt, startTime)]
        
    def __eq__(self, other):
        return other.flowid == self.flowid


def map_median_srtts_to_host_pairs(mapper):
    """
    assume mapper is a dictionary contains the following:
    key: flowid
    Value: ACK_Mapper object

    return a dictionary of ACK objects that has mapping of median srtts for each pair host connection
    """
    # key: (srcip, dstip); value : ACK object
    median_srtts = {}
    for flowid in mapper:
        # for each TCP flows within the single pair hosts
        mapperObj = mapper[flowid]

        # ignore connections that have no flows
        if len(mapperObj.srtt) == 0:
            continue

        representive_srtt = median(mapperObj.srtt)
        host_pair = (flowid[0], flowid[1])

        # get the start time as in minute and seconds
        time = datetime.fromtimestamp(mapperObj.start_time)
        # convert the time to miliseconds
        miliseconds = time.minute * 60 * 1000 + time.second * 1000 + float(time.microsecond / 1000)

        if host_pair not in median_srtts:
            median_srtts[host_pair] = ACKS(host_pair, miliseconds, representive_srtt)
        else:# update ACKS object
            acks = median_srtts[host_pair]
            acks.median_srtts.append((representive_srtt, miliseconds))
    return median_srtts

def establish_host_connections():
    """
    find all the pair-host connections and return a dictionary contains
    
    key: srcIP, dstIP
    value:[ (srcIp, destIp, srcPort, dstPort, 'TCP') ]
    """

    def _get_flowid(datagram, segment):
        srcIp = socket.inet_ntoa(bytes(datagram.src))
        destIp = socket.inet_ntoa(bytes(datagram.dst))
        srcPort = segment.sport
        dstPort = segment.dport
        return (srcIp, destIp, srcPort, dstPort, 'TCP')

    host_pair_connections = {}
    f = open('./univ1_pt9', 'rb')
    pcap = dpkt.pcap.Reader(f)

    # find the top three connection hosts
    for timeStamp, buf in pcap:
        #  Unpack the Ethernet frame (mac src/dst, ethertype)
        ethernetFrame = dpkt.ethernet.Ethernet(buf)
        datagram = ethernetFrame.data

        if not isinstance(datagram, dpkt.ip.IP):
            continue

        # get the transport layer segments since for sure IP datagram
        segment = datagram.data
        
        # ignore anything that is not tcp segment
        if type(segment) != dpkt.tcp.TCP:
            continue

        # get the id of the flow    
        flowid = _get_flowid(datagram, segment)

        # bookkeeping for the host pair (combine both direction)
        if (flowid[0], flowid[1]) not in host_pair_connections:
            host_pair_connections[(flowid[0], flowid[1])] = set()
        host_pair_connections[(flowid[0], flowid[1])].add(flowid)

    f.close()
    return host_pair_connections


if __name__ == "__main__":

    host_pair_connections = establish_host_connections()

    top_pairs = list(host_pair_connections.items())
    top_pairs.sort(key=lambda x: len(x[1]), reverse=True)
    print(len(top_pairs))
    counter = 0
    # ignore the consecutive ones, since they both duplicate of each other
    for i in range(0, HOST_PAIR_NUM * 2, 2):

        srcip, dstip = top_pairs[i][0]

        print(srcip, dstip)
        target = top_pairs[i][1]
        opposite = [(dstip, srcip, dstport, srcport, type_) for srcip, dstip, srcport, dstport, type_ in target]

        # collect data from the forwarding direction
        mapper = RTT.map_acks(list(target), opposite, False)
        median_srtt_mappings = map_median_srtts_to_host_pairs(mapper)
        csv_parser.parse_host_pair_stats("host pair {}A.xlsx".format(counter), median_srtt_mappings)

        # collecting data from from the opposite direction
        mapper = RTT.map_acks(opposite, list(target), False)
        median_srtt_mappings = map_median_srtts_to_host_pairs(mapper)
        csv_parser.parse_host_pair_stats("host pair {}B.xlsx".format(counter), median_srtt_mappings)

        # for naming
        counter += 1