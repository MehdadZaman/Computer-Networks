# Mehdad Zaman
# 112323211
# CSE 310 Homework 2

import dpkt

import socket


class TCPFlow:
    def __init__(self):
        self.sourcePort = 0
        self.sourceIP = ''
        self.destinationPort = 0
        self.destinationIP = ''

        self.senderThroughPut = 0

        self.orangeRequest = []
        self.orangeResponse = []

        self.firstTimeStamp = 0
        self.lastTimeStamp = 0

        self.finAckReceived = False

        self.receiverAck = 0
        self.numSentReceiverAcks = 0

        self.numTimeouts = 0
        self.numTripDups = 0

        self.shiftCount = 0

        self.sentSeqs = set()

        # Part B (1): Congestion Window Calculator
        self.synTimeSent = 0
        self.synAckTimeReceived = 0
        self.rttTime = 0
        self.nextRTT = 0
        self.currentCongestionWindowSize = 0
        self.congestionWindowSizes = []

    def __str__(self):
        retString = ('Source port: ' + str(self.sourcePort) +
                     ' Source IP address: ' + self.sourceIP +
                     ' Destination port: ' + str(self.destinationPort) +
                     ' Destination IP address: ' + self.destinationIP + '\n')

        for i in range(min(len(self.orangeRequest), len(self.orangeResponse))):
            retString += 'Transaction: ' + str(i + 1) + '\n'
            retString += 'Sent - Sequence Number: ' + str(self.orangeRequest[i].seq) + ' Ack Number: ' + str(
                self.orangeRequest[i].ack) + ' Window: ' + str(self.orangeRequest[i].win << self.shiftCount) + '\n'
            retString += 'Received - Sequence Number: ' + str(self.orangeResponse[i].seq) + ' Ack Number: ' + str(
                self.orangeResponse[i].ack) + ' Receive Window Size: ' + str(
                self.orangeResponse[i].win << self.shiftCount) + '\n'

        retString += 'Number of Bytes sent: ' + str(self.senderThroughPut) + ' bytes\n'
        retString += 'Period: ' + str(self.lastTimeStamp - self.firstTimeStamp) + ' seconds\n'
        retString += 'Throughput: ' + str(self.senderThroughPut / (self.lastTimeStamp - self.firstTimeStamp)) + ' bytes per second\n'

        if len(self.congestionWindowSizes) > 3:
            retString += 'First three congestion window sizes: ' + str(self.congestionWindowSizes[0:3]) + '\n'
        else:
            retString += 'First couple congestion window sizes: ' + str(self.congestionWindowSizes) + '\n'

        retString += 'Triple Ack Retransmissions: ' + str(self.numTripDups) + '\n'
        retString += 'Timeout Retransmissions: ' + str(self.numTimeouts) + '\n'

        return retString


if __name__ == '__main__':
    print('Enter .pcap filename:')

    filename = input()
    sender = '130.245.145.12'
    receiver = '128.208.2.198'

    pcapFile = dpkt.pcap.Reader(open(filename, 'rb'))

    tcpSynFlow = 0
    tcpFinFlow = 0

    currentTCPConnections = {}
    allTCPConnections = []

    for ts, packet in pcapFile:

        eth = dpkt.ethernet.Ethernet(packet)

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data

                # sender packet
                if socket.inet_ntoa(ip.src) == sender:
                    if (tcp.flags & dpkt.tcp.TH_SYN > 0) and (
                            (str(tcp.sport) + 'to' + str(tcp.dport)) not in currentTCPConnections):
                        # Part A (1): TCP Flow Counter
                        tcpSynFlow += 1
                        currentTCPConnections[str(tcp.sport) + 'to' + str(tcp.dport)] = TCPFlow()
                        currentFlow = currentTCPConnections[str(tcp.sport) + 'to' + str(tcp.dport)]

                        # Part A (2a): TCP Flow Information
                        currentFlow.sourcePort = tcp.sport
                        currentFlow.sourceIP = socket.inet_ntoa(ip.src)
                        currentFlow.destinationPort = tcp.dport
                        currentFlow.destinationIP = socket.inet_ntoa(ip.dst)

                    elif (tcp.flags & dpkt.tcp.TH_SYN > 0) and (
                            (str(tcp.sport) + 'to' + str(tcp.dport)) in currentTCPConnections):
                        continue
                    elif (str(tcp.sport) + 'to' + str(tcp.dport)) not in currentTCPConnections:
                        continue

                    currentFlow = currentTCPConnections[str(tcp.sport) + 'to' + str(tcp.dport)]

                    if tcp.flags & dpkt.tcp.TH_FIN > 0:
                        # Part A (1): TCP Flow Counter
                        tcpFinFlow += 1

                    if (tcp.flags & dpkt.tcp.TH_SYN == 0) and (tcp.flags & dpkt.tcp.TH_ACK > 0):
                        # Part A (2c): first timeStamp (only considering time of first non-syn ack)
                        if (len(currentFlow.orangeRequest) == 0) and (len(tcp.data) > 0):
                            currentFlow.firstTimeStamp = ts

                            # Part B (1): Congestion Window Calculator
                            currentFlow.nextRTT = ts + (currentFlow.rttTime / 2)

                        # Part A (2b): first two transaction requests
                        if (len(currentFlow.orangeRequest) < 2) and (len(tcp.data) > 0):
                            if len(currentFlow.orangeRequest) == 1:
                                if tcp.seq != currentFlow.orangeRequest[0].seq:
                                    currentFlow.orangeRequest.append(tcp)
                            else:
                                currentFlow.orangeRequest.append(tcp)

                    # Part A (2c): sender throughput (only including packets that are not in the SYN or FIN)
                    if (tcp.flags & dpkt.tcp.TH_FIN > 0 and (len(tcp.data) > 0)) or \
                            ((tcp.flags & dpkt.tcp.TH_FIN == 0) and (tcp.flags & dpkt.tcp.TH_SYN == 0) and (
                                    (len(currentFlow.orangeRequest) > 0) and (not currentFlow.finAckReceived))):
                        currentFlow.senderThroughPut += len(tcp)

                        # Part B (2): Retransmission - type checker
                        if tcp.seq in currentFlow.sentSeqs:
                            if (tcp.seq == currentFlow.receiverAck) and (currentFlow.numSentReceiverAcks >= 4):
                                currentFlow.numTripDups += 1
                            else:
                                currentFlow.numTimeouts += 1
                        else:
                            currentFlow.sentSeqs.add(tcp.seq)

                    # Part B (1): Congestion Window Calculator
                    # Calculating RTT time
                    if tcp.flags & dpkt.tcp.TH_SYN > 0:
                        currentFlow.synTimeSent = ts

                    # Part B (1): Congestion Window Calculator
                    if (tcp.flags & dpkt.tcp.TH_FIN > 0 and (len(tcp.data) > 0)) or \
                            ((tcp.flags & dpkt.tcp.TH_FIN == 0) and (tcp.flags & dpkt.tcp.TH_SYN == 0) and
                             ((len(currentFlow.orangeRequest) > 0) and (not currentFlow.finAckReceived))):
                        if ts <= currentFlow.nextRTT:
                            currentFlow.currentCongestionWindowSize += 1
                        else:
                            currentFlow.congestionWindowSizes.append(currentFlow.currentCongestionWindowSize)
                            currentFlow.currentCongestionWindowSize = 1
                            currentFlow.nextRTT = ts + (currentFlow.rttTime / 2)

                    # Reset if final teardown
                    if currentFlow.finAckReceived and (tcp.flags & dpkt.tcp.TH_ACK > 0):
                        allTCPConnections.append(currentFlow)
                        currentTCPConnections.pop(str(tcp.sport) + 'to' + str(tcp.dport))

                # receiver packet
                elif socket.inet_ntoa(ip.src) == receiver:
                    if (str(tcp.dport) + 'to' + str(tcp.sport)) in currentTCPConnections:
                        currentFlow = currentTCPConnections[str(tcp.dport) + 'to' + str(tcp.sport)]

                        # Part A (2b): window size shift recorder (window size calculation)
                        if (tcp.flags & dpkt.tcp.TH_SYN > 0) and (tcp.flags & dpkt.tcp.TH_ACK > 0):
                            for opt_type, opt_data in dpkt.tcp.parse_opts(tcp.opts):
                                if opt_type == 3:
                                    currentFlow.shiftCount = int.from_bytes(opt_data, byteorder='big')

                        # Part A (2b): first two transaction responses
                        if len(currentFlow.orangeResponse) < 2:
                            for i in currentFlow.orangeRequest:
                                if i.ack == tcp.seq:
                                    currentFlow.orangeResponse.append(tcp)
                                    break

                        # Part A (2c): Last acknowledgement sent timestamp
                        if tcp.flags & dpkt.tcp.TH_ACK > 0:
                            currentFlow.lastTimeStamp = ts

                        # Part A (2c): Last FIN_ACK acknowledgement for sender to remove
                        if tcp.flags & dpkt.tcp.TH_FIN > 0:
                            currentFlow.finAckReceived = True

                        # Part B (2): Retransmission - duplicate ack counter
                        if tcp.ack == currentFlow.receiverAck:
                            currentFlow.numSentReceiverAcks += 1
                        else:
                            currentFlow.receiverAck = tcp.ack
                            currentFlow.numSentReceiverAcks = 1

                        # Part B (1): Congestion Window Calculator
                        if (tcp.flags & dpkt.tcp.TH_SYN > 0) and (tcp.flags & dpkt.tcp.TH_ACK > 0) and (
                                currentFlow.rttTime == 0):
                            currentFlow.synAckTimeReceived = ts
                            currentFlow.rttTime = currentFlow.synAckTimeReceived - currentFlow.synTimeSent

    print('Number of TCP Flows: ' + str(min(tcpSynFlow, tcpFinFlow)) + '\n')
    counter = 1
    for tcpConnection in allTCPConnections:
        print('TCP Flow: ' + str(counter) + '\n')
        print(tcpConnection)
        counter += 1

    # Any remaining TCP flows are printed
    for tcpConnection in currentTCPConnections:
        print('TCP Flow: ' + str(counter) + '\n')
        print(currentTCPConnections[tcpConnection])
        counter += 1
