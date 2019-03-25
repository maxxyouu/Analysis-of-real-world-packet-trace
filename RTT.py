import dpkt
import socket
from datetime import datetime, timedelta
import csv_parser
from Constants import *


class ACK_mapper(object):
    __slots__ = ('flowid',
                'unack_packet_seqs',
                'expected_ack_seq',
                'duplicate_packet_seqs',
                'srtt',
                'r',
                'last_srtt',
                'rttvar',
                'ack_time',
                'start_time')
    def __init__(self, flowid, initial_packet_seq, expected_ack_num, timestamp):
        self.flowid = flowid

        # keep track of a list of unacked packet's equence number
        self.unack_packet_seqs = {initial_packet_seq: timestamp}
        self.expected_ack_seq = {expected_ack_num: initial_packet_seq}
        # a list of duplicated packet sequence number, DONOT sample rtt from those
        self.duplicate_packet_seqs = set()
        # estimated rtt
        self.srtt= []
        # sample rtt
        self.r = []
        self.last_srtt = 0
        self.rttvar = 0
        # time received the ack
        self.ack_time = []
        # all time are relative to the first ack time
        self.start_time = timestamp;
    
    def __eq__(self, other):
        return other.flowid == this.flowid

                
def expect_ack(segment, datagram):
    datagramHeaderSize = datagram.hl * 4
    tcpHeaderSize = segment.off * 4
    datagramSize = datagram.len
    tcpPayloadSize = datagramSize - datagramHeaderSize - tcpHeaderSize
    return segment.seq + tcpPayloadSize


def map_acks(targetFlows, oppositeTargetFlow, write_to_notebook, excel_file_name=""):
    """
    bookkeeping the flows from target direction toward the opposite direction
    """
    mapper = {}
    f = open('./univ1_pt9', 'rb')
    pcap = dpkt.pcap.Reader(f)
    for timeStamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        ethernetFrame = dpkt.ethernet.Ethernet(buf)
        datagram = ethernetFrame.data
        if not isinstance(datagram, dpkt.ip.IP) and not isinstance(datagram, dpkt.ip6.IP6):
            continue
        # get the transport layer segments since for sure IP datagram
        segment = datagram.data
        
        # ignore anything that is not tcp segment
        if type(segment) != dpkt.tcp.TCP:
            continue

        # get the id of the flow
        srcIp = socket.inet_ntoa(bytes(datagram.src))
        destIp = socket.inet_ntoa(bytes(datagram.dst))
        srcPort = segment.sport
        dstPort = segment.dport
    
        flowid = (srcIp, destIp, srcPort, dstPort, 'TCP')
        # ignore flow that we are not interested
        if flowid not in oppositeTargetFlow and flowid not in targetFlows:
            continue

        # found the target flow
        if flowid in targetFlows:
            
            # first time to see this targer flow?
            if flowid not in mapper:
                # when create this object, we record the starting time of this flow
                mapper[flowid] = ACK_mapper(flowid, segment.seq, expect_ack(segment, datagram), timeStamp)
                continue
            
            # the current segment is not first sent by the sender

            obj = mapper[flowid]
            # dupliacate packet case
            if segment.seq in obj.unack_packet_seqs.keys():
                obj.duplicate_packet_seqs.add(segment.seq)
            else: # add new packet into the unack list
                obj.unack_packet_seqs[segment.seq] = timeStamp
                obj.expected_ack_seq[expect_ack(segment, datagram)] = segment.seq
        else: 
            # not in the target flow, is the segment comes from the opposite direction?
            if flowid in oppositeTargetFlow:
                # get the corresponing trrget flow id
                i = oppositeTargetFlow.index(flowid)
                _id = targetFlows[i]

                 # case where B sends to A before A sends to B (currently measuring)
                if not _id in mapper:
                    continue

                targetObj = mapper[_id]

                # two more cases: does the target flow has already seen?
                if segment.flags & dpkt.tcp.TH_ACK and segment.ack in targetObj.expected_ack_seq:
                    # get the corresponding packet from this ack sent from the other side
                    corresponding_packet = targetObj.expected_ack_seq[segment.ack]
                    if corresponding_packet not in targetObj.duplicate_packet_seqs:
                        # print("receivd packet")
                        # the packet comes from the opposite direction is the ack of one of the non duplicated packet
                        # get the packet seq that this ack correspond to
                        seq = targetObj.expected_ack_seq[segment.ack]
                        # get the packet last arrival time
                        last_arrvial_time = targetObj.unack_packet_seqs[seq]

                        # get the elapsed in miliseconds
                        currentPacketArrivalTime = datetime.fromtimestamp(timeStamp)
                        lastPacketArrivalTime = datetime.fromtimestamp(last_arrvial_time)
                        delta = currentPacketArrivalTime - lastPacketArrivalTime
                        elapsedMilisonds = (delta.days * 86400000) + (delta.seconds * 1000) + (float(delta.microseconds/1000))
                        
                        # check if this is the first RTT
                        if len(targetObj.r) == 0:
                            #print("initialize rtt measurement")
                            targetObj.last_srtt = elapsedMilisonds
                            targetObj.rttvar = float(elapsedMilisonds / 2)
                            # add initial estimated rtt
                            targetObj.srtt.append(elapsedMilisonds)
                        else:
                            #print("subsequent rtt measurement")
                            # subsequent RTT measurement
                            new_rttvar = (1-beta) * targetObj.rttvar + beta * abs(targetObj.last_srtt - elapsedMilisonds)
                            new_srtt = (1 -alpha) * targetObj.last_srtt + alpha * elapsedMilisonds
                            targetObj.last_srtt = new_srtt
                            targetObj.rttvar = new_rttvar
                            # add new estimated rtt
                            targetObj.srtt.append(new_srtt)
                                            
                        # add new sampled rtt for above two cases
                        targetObj.r.append(elapsedMilisonds)
                        # store tthe received time since the the first packet is arrived
                        timeSince = datetime.fromtimestamp(targetObj.start_time)
                        delta = currentPacketArrivalTime - timeSince
                        # time is stored in milisecond
                        ack_time = (delta.days * 86400000) + (delta.seconds * 1000) + (float(delta.microseconds/1000))
                        #print(ack_time)
                        targetObj.ack_time.append(ack_time)
    # create excel file to store the bookkeeping information about the flow
    f.close()
    # write to the notebook if necessary
    if write_to_notebook:
        csv_parser.parse_rtt_stats(excel_file_name, mapper)
    return mapper

# important: consider each flow direction sepately
if __name__ == "__main__":

    #targetFlows,  oppositeTargetFlow
    # the following are collection point to 41.177.241.254, 3389 for example
    oppositeTargetFlow = [ # longest duration flow
                    ("244.3.93.198", "41.177.241.254", 1904, 3389, 'TCP'),
                    ("41.177.241.108", "244.3.93.198", 3389, 4112, 'TCP'),
                    ("244.3.210.254", "41.177.244.185", 5900, 51175, 'TCP'),
                    # largest tcp in terms of byte and packet num
                    ("244.3.176.224", "244.3.153.33", 445, 1803, 'TCP'),
                    ("41.177.244.177", "244.3.210.254", 54781, 19813, 'TCP'),
                    ("244.108.194.56", "41.177.26.15", 2428, 80, 'TCP')
                    ]
    targetFlows = [ # longest duration flow
                    ('41.177.241.254','244.3.93.198', 3389, 1904, 'TCP'),
                    ('244.3.93.198', '41.177.241.108', 4112, 3389, 'TCP'),
                    ('41.177.244.185', '244.3.210.254', 51175, 5900, 'TCP'),
                    # largest tcp in terms of byte and packet num
                    ('244.3.153.33', '244.3.176.224', 1803, 445, 'TCP'),
                    ('244.3.210.254', '41.177.244.177', 19813, 54781, 'TCP'),
                    ('41.177.26.15', '244.108.194.56', 80, 2428, 'TCP')
                    ]

    map_acks(targetFlows, oppositeTargetFlow, True,  "RTT-AtoB.xlsx")
    map_acks(oppositeTargetFlow, targetFlows, True, "RTT-BtoA.xlsx")
    # pick the top three

                       
        



        




