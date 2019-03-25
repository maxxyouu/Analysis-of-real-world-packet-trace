# global variable to store the trace file endtime
traceFileEndsTime = 0

# key is the id of the flow, value is the object
parsedFlows = {}

packetACKmapper = {}

infinity = 9999

# timestamp 5 mins before the end of the trace file, done from the previous trace file
timeBound = 1261069177.0

aggregatedFlow = {}

ETHERNET_HEADER_SIZE = 18
UDP_HEADER_SIZE = 8
HOST_PAIR_NUM = 3
beta = float(1/4)
alpha = float(1/8)

# per packet statistics data structures
# [a,b]; a is the count of the packet type; b is the accumulated bytes for that packet type
linkLayerPackets = {
                    "Ethernet":{"totalBytes":0, "counts":0}}
networkLayerPackets = {
                        "ipv4":{"headerSize":0, "totalBytes":0, "counts":0}, 
                        "ipv6":{"headerSize":0, "totalBytes":0, "counts":0}, 
                        "icmp":{"totalBytes":0, "counts":0}, 
                        "arp":{"totalBytes":0, "counts":0}, 
                        "others":{"totalBytes":0, "counts":0}}
transportLayerPackets = {
                        "tcp":{"headerSize":0, "totalBytes":0, "counts":0}, 
                        "udp":{"headerSize":0, "totalBytes":0, "counts":0},
                        "others":{"totalBytes":0, "counts":0}}

# size distribution for each one
allpacket_sizes = []
tcp_sizes = []
udp_sizes = []
ip_sizes = []
nonip_sizes = []

# size distribution of headers
tcp_headers = []
udp_headers = []
ip_headers = []


