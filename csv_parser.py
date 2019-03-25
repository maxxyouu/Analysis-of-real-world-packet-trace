
#!python3
from Constants import *
from datetime import datetime, timedelta
import xlsxwriter


def parse_host_pair_stats(name, host_pair_result):
    """
    make a spreadsheet for each host pair in the same workbook
    """
    print("writing host pair workbook")
    dataBook = xlsxwriter.Workbook(name)
    # parse data into csv file so that able to read from exel
    headerProperties = dataBook.add_format({'bold':True, 'align':'center', 'valign':'vcenter'})
    dataCellProperties = dataBook.add_format({'align':'center', 'valign': 'vcenter'})

    for host_pair in host_pair_result:
        print("finally")
        srcIp, dstIP = host_pair
        # each host pair has a worksheet for the current direction
        pageSheet = dataBook.add_worksheet("{} {}".format(srcIp, dstIP))
        pageSheet.write('A1', 'start time', headerProperties)
        pageSheet.write('B1', 'median srtt', headerProperties)
        acks = host_pair_result[host_pair]
        for row, srtt in list(enumerate(acks.median_srtts)):
            pageSheet.write(row+1, 0, srtt[1], dataCellProperties) # start time
            pageSheet.write(row+1, 1, srtt[0], dataCellProperties)
    dataBook.close()


def parse_rtt_stats(name, mapper):
    print("writing RTT workbook")
    dataBook = xlsxwriter.Workbook(name)
    # parse data into csv file so that able to read from exel
    headerProperties = dataBook.add_format({'bold':True, 'align':'center', 'valign':'vcenter'})
    dataCellProperties = dataBook.add_format({'align':'center', 'valign': 'vcenter'})

    # make a spreadsheet for each flow
    for target in mapper:
        ackMapper = mapper[target]
        pageSheet = dataBook.add_worksheet("{} {}".format(ackMapper.flowid[2], ackMapper.flowid[3]))
        pageSheet.write('A1', 'sample RTT', headerProperties)
        pageSheet.write('B1', 'estimated RTT', headerProperties)
        pageSheet.write('C1', 'ack received time', headerProperties)
        
        for row, sampleRtt in list(enumerate(ackMapper.r)):
            pageSheet.write(row+1, 0, sampleRtt, dataCellProperties)
        for row, estimatedRtt in list(enumerate(ackMapper.srtt)):
            pageSheet.write(row+1, 1, estimatedRtt, dataCellProperties)
        for row, time in list(enumerate(ackMapper.ack_time)):
            pageSheet.write(row+1, 2, time, dataCellProperties)
    dataBook.close()

def parse_packet_stats():
    print("writing per packet workbook")

    dataBook = xlsxwriter.Workbook('packet_data.xlsx')
    # parse data into csv file so that able to read from exel
    headerProperties = dataBook.add_format({'bold':True, 'align':'center', 'valign':'vcenter'})
    dataCellProperties = dataBook.add_format({'align':'center', 'valign': 'vcenter'})

    allPageSheet = dataBook.add_worksheet("all_packets")
    nonipPageSheet = dataBook.add_worksheet("nonip")

    tcpPageSheet = dataBook.add_worksheet("tcp")
    udpPageSheet = dataBook.add_worksheet("udp")
    ipPageSheet = dataBook.add_worksheet("ip")

    # initialize header fields
    allPageSheet.write('A1', 'packet size', headerProperties)
    for row, size in list(enumerate(allpacket_sizes)):
        allPageSheet.write(row+1, 0, size, dataCellProperties)

    nonipPageSheet.write('A1', 'packet size', headerProperties)
    for row, size in list(enumerate(nonip_sizes)):
        nonipPageSheet.write(row+1, 0, size, dataCellProperties)

    tcpPageSheet.write('A1', 'packet size', headerProperties)
    for row, size in list(enumerate(tcp_sizes)):
        tcpPageSheet.write(row+1, 0, size, dataCellProperties)

    udpPageSheet.write('A1', 'packet size', headerProperties)
    for row, size in list(enumerate(udp_sizes)):
        udpPageSheet.write(row+1, 0, size, dataCellProperties)

    ipPageSheet.write('A1', 'packet size', headerProperties)
    for row, size in list(enumerate(ip_sizes)):
        ipPageSheet.write(row+1, 0, size, dataCellProperties)

    # extra header field for ip, tcp, udp
    tcpPageSheet.write('B1', 'header size', headerProperties)
    for row, size in list(enumerate(tcp_headers)):
        tcpPageSheet.write(row+1, 1, size, dataCellProperties)

    udpPageSheet.write('B1', 'header size', headerProperties)
    for row, size in list(enumerate(udp_headers)):
        udpPageSheet.write(row+1, 1, size, dataCellProperties)

    ipPageSheet.write('B1', 'header size', headerProperties)
    for row, size in list(enumerate(ip_headers)):
        ipPageSheet.write(row+1, 1, size, dataCellProperties)

    dataBook.close()
    # for the "type of packet" statistics
    # the following are for display result in table format, not excel format
    for link in linkLayerPackets:
        linklayer = linkLayerPackets[link]
        print("{}".format(link))
        for attribute in linklayer:
            print("{}: {}".format(attribute, linklayer[attribute]))

    for net in networkLayerPackets:
        networkLayer = networkLayerPackets[net]
        print("{}".format(net))
        for attribute in networkLayer:
            print("{}: {}".format(attribute, networkLayer[attribute]))

    for trans in transportLayerPackets:
        transLayer = transportLayerPackets[trans]
        print("{}".format(trans))
        for attribute in transLayer:
            print("{}: {}".format(attribute, transLayer[attribute]))

    print(len(ip_headers), len(ip_sizes))



def parse_to_xlsx():
    print("writing flow workbook")
    dataBook = xlsxwriter.Workbook('flow_data.xlsx')
    # parse data into csv file so that able to read from exel
    headerProperties = dataBook.add_format({'bold':True, 'align':'center', 'valign':'vcenter'})
    dataCellProperties = dataBook.add_format({'align':'center', 'valign': 'vcenter'})

    # add a page sheet
    tcpPageSheet = dataBook.add_worksheet("TCP data")
    udpPageSheet = dataBook.add_worksheet("UDP data")

    for pageSheet in [tcpPageSheet, udpPageSheet]:
        pageSheet.write('A1', 'srcIP', headerProperties)  # write header
        pageSheet.write('B1', 'dstIP', headerProperties)  # write header
        pageSheet.write('C1', 'srcPort', headerProperties)
        pageSheet.write('D1', 'dstPort', headerProperties)  # write header  # write header
        pageSheet.write('E1', 'firstPacketArrivalTime', headerProperties)  # write header
        pageSheet.write('F1', 'lastPacketArrivalTime', headerProperties)  # write header
        pageSheet.write('G1', 'numPackets', headerProperties)  # write header
        pageSheet.write('H1', 'totalOverhead', headerProperties)
        pageSheet.write('I1', 'totalDataBytes', headerProperties)
        pageSheet.write('J1', 'flowType', headerProperties)
        pageSheet.write('K1', 'duration', headerProperties)

    tcpPageSheet.write('L1', "connection state", headerProperties)
    tcpPageSheet.write('M1', "overhead ratio", headerProperties)
    # write the inter arrival time using the saparetate page sheet
    row, col = 1, 0
    for key in aggregatedFlow:
        flow = aggregatedFlow[key]
            
        pageSheet = udpPageSheet
        if flow.flowType == "TCP":
            pageSheet = tcpPageSheet                            

        # write all the common attributes between TCP and UDP
        pageSheet.write(row, 0, flow.srcIP, dataCellProperties)
        pageSheet.write(row, 1, flow.destIP, dataCellProperties)
        pageSheet.write(row, 2, flow.srcPort, dataCellProperties)
        pageSheet.write(row, 3, flow.destPort, dataCellProperties)
        pageSheet.write(row, 4, flow.firstPacketArrivalTime, dataCellProperties)
        pageSheet.write(row, 5, flow.lastPacketArrivalTime, dataCellProperties)
        pageSheet.write(row, 6, flow.numPackets, dataCellProperties)
        pageSheet.write(row, 7, flow.totalOverhead, dataCellProperties)
        pageSheet.write(row, 8, flow.totalDataBytes, dataCellProperties)
        pageSheet.write(row, 9, flow.flowType, dataCellProperties)

        # find the duration of connection in milisond or micro seconds
        a = datetime.fromtimestamp(flow.firstPacketArrivalTime)
        b = datetime.fromtimestamp(flow.lastPacketArrivalTime)
        delta = b - a
        #divmod(c.days * 86400 + c.seconds + c.microseconds, 60)
        preciseElapsed = (delta.days * 86400000) + (delta.seconds * 1000) + (float(delta.microseconds/1000))
        pageSheet.write(row, 10, preciseElapsed, dataCellProperties)

        if flow.flowType == "TCP":
             # write the connection state into the page sheet
            if flow.fin:
                pageSheet.write(row, 11, "Finished", dataCellProperties)
            elif flow.reset:
                pageSheet.write(row, 11, "Reset", dataCellProperties)
            elif flow.ongoingTimebound:
                pageSheet.write(row, 11, "ongoing", dataCellProperties)
            elif flow.syn:
                pageSheet.write(row, 11, "Request", dataCellProperties)
            else:
                pageSheet.write(row, 11, "ongoing", dataCellProperties)
            # no failed or ongoing connection since the packet only take place for 5 miniutes
            # write the total bytes
            if flow.totalDataBytes == 0:
                pageSheet.write(row, 12, 9999, dataCellProperties)
            else:
                pageSheet.write(row, 12, float(flow.totalOverhead / flow.totalDataBytes), dataCellProperties)
            
        row += 1


    # inter arrival time statistics
    print("writing inter-arrival time")
    tcpConsecArrivalTime = []
    udpConsecArrivalTime = []
    for key in aggregatedFlow:
        flow = aggregatedFlow[key]
        if flow.flowType == "TCP":
            tcpConsecArrivalTime.extend(flow.consecArrvialTimes)
        else:
            udpConsecArrivalTime.extend(flow.consecArrvialTimes)
    allConsecArrivalTime = tcpConsecArrivalTime + udpConsecArrivalTime

    pageSheet = dataBook.add_worksheet("TCP inter-arrival time")
    pageSheet.write('A1', 'inter arrival time', headerProperties)  # write header
    for row, interArrivalTime in list(enumerate(tcpConsecArrivalTime)):
        pageSheet.write(row, 0, interArrivalTime, dataCellProperties)

    # write consecutive arrival time for each connection
    pageSheet = dataBook.add_worksheet("UDP inter-arrival time")
    pageSheet.write('A1', 'inter arrival time', headerProperties)  # write header
    for row, interArrivalTime in list(enumerate(udpConsecArrivalTime)):
        pageSheet.write(row, 0, interArrivalTime, dataCellProperties)

    pageSheet = dataBook.add_worksheet("All inter-arrival time")
    pageSheet.write('A1', 'inter arrival time', headerProperties)  # write header
    for row, interArrivalTime in list(enumerate(allConsecArrivalTime)):
        pageSheet.write(row, 0, interArrivalTime, dataCellProperties)


    dataBook.close()
