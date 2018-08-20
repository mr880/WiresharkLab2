#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
import sys
import operator
from datetime import timedelta
import time
from itertools import groupby

# convert IP addresses to printable strings
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.
#list is your list
#distance would be .5 from our scenario
#number_of_ports will be 4 from our scenario
def distance_limit ( list , distance , num_of_ports):

    length = len(list)

    if (length <= num_of_ports):
        #
        # print "Length of the list is not less than number of ports"
        # print "Length of your list ", length
        # print "Number of ports you are looking for" , num_of_ports
        return

    i = 0
    tracker = 0

    output_list = []
    while i < length - 1:

        tuple_value = list[i]
        distance_lm = tuple_value[1]

        tps = list[i+1]
        dls = tps[1]

        limit = (dls - distance_lm).total_seconds()

        if (limit <= distance):

            output_list.append(tuple_value)
            tracker += 1
        else:


            tracker = 0

        if (tracker == num_of_ports):

            return output_list
        i+=1


    return output_list

def TrimList(list , limit):


    output_list = []
    length = len(list)

    i = 0

    while i < length:

        tuple_value = list.pop()

        limit_value = tuple_value[0]

        if (limit <= limit_value):

            output_list.append(tuple_value)

        i+=1
    output_list.reverse()
    return output_list

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))
    final_scan_udp = []
    final_udp = []
    final_tcp = []
    final_scan_tcp = []
    test = []
    test2= []
    test3 = []
    test4 = []
    porttest = []
    list_of_times = []
    list_of_tcp = []
    list_of_tcp2 = []
    list_of_udp = []
    list_of_udp2 = []
    scan_tcp = []
    scan_tcp2 = []
    scan_udp = []
    scan_udp2= []

    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        eth = dpkt.ethernet.Ethernet(packet)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        #struct_time = time.strptime(str(time_string), "%Y-%m-%d %H:%M:%S.%f")
        #print int(time_string.total_seconds())


        ip = eth.data
        tcp = ip.data


        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            if inet_to_str(ip.dst) == target_ip:
                list_of_tcp.append((ip , time_string))
                scan_tcp.append((ip, time_string))
                list_of_tcp2.append((time_string, ip))
                scan_tcp2.append((time_string,ip))

        if ip.p == dpkt.ip.IP_PROTO_UDP:
            upd = ip.data

            if inet_to_str(ip.dst) == target_ip:
                list_of_udp.append((ip, time_string))
                list_of_udp2.append((time_string,ip))
                scan_udp.append((ip, time_string))
                scan_udp2.append((time_string, ip))

    list_of_tcp2.sort()
    list_of_tcp.sort()
    scan_tcp.sort()
    scan_udp.sort()
    scan_tcp2.sort()
    scan_udp2.sort()
    list_of_udp.sort()
    list_of_udp2.sort()

    for x in scan_udp:
        for y in scan_udp2:
            dif = (x[1]-y[0]).total_seconds()
            if (dif <= W_s and dif > 0 ):

                if x[1] not in test4:
                    test4.append(x[1])
                    final_scan_udp.append((x[0], x[1]))
                if y[0] not in test4:
                    test4.append(y[0])

                    final_scan_udp.append((y[1], y[0]))

                else:
                    pass

    final_scan_udp.sort(key=lambda x: x[0].data.dport, reverse=False)

    listlist4 = TrimList(final_scan_udp, N_s)

    for x in list_of_udp:
        for y in list_of_udp2:
            #print "x[0]: ", x[0], "y[1]: ", y[1]
            if(x[0].data.dport == y[1].data.dport ):
                # print "x[0]: ", x[0]
                # print "y[1]: ", y[1]
                #list_of_tcp2 = [(y[0], y[1], y[2] + 1) for y in list_of_tcp2]

                dif = (x[1] - y[0]).total_seconds()

                if (dif <= W_p and dif > 0 ):
                    # print x[1], x[0]
                    # print y[0], y[1]

                    if x[1] not in test3:
                        test3.append(x[1])


                        final_udp.append((x[0], x[1]))
                    if y[0] not in test3:
                        test3.append(y[0])



                        final_udp.append((y[1], y[0]))

                    else:
                        pass

    final_udp.sort(key=lambda x: x[0].data.dport, reverse=False)

    listlist3 = TrimList(final_udp, N_p)

    for x in scan_tcp:
        for y in scan_tcp2:
            dif = (x[1]-y[0]).total_seconds()
            if (dif <= W_s and dif > 0 ):

                if x[1] not in test2:
                    test2.append(x[1])
                    final_scan_tcp.append((x[0], x[1]))
                if y[0] not in test2:
                    test2.append(y[0])

                    final_scan_tcp.append((y[1], y[0]))

                else:
                    pass

    final_scan_tcp.sort(key=lambda x: x[0].data.dport, reverse=False)

    listlist2 = TrimList(final_scan_tcp, N_s)

    for x in list_of_tcp:
        for y in list_of_tcp2:
            #print "x[0]: ", x[0], "y[1]: ", y[1]
            if(x[0].data.dport == y[1].data.dport ):
                # print "x[0]: ", x[0]
                # print "y[1]: ", y[1]
                #list_of_tcp2 = [(y[0], y[1], y[2] + 1) for y in list_of_tcp2]

                dif = (x[1] - y[0]).total_seconds()

                if (dif <= W_p and dif > 0 ):
                    # print x[1], x[0]
                    # print y[0], y[1]

                    if x[1] not in test:
                        test.append(x[1])
                        porttest.append(x[0].data.dport)

                        final_tcp.append((x[0], x[1]))
                    if y[0] not in test:
                        test.append(y[0])
                        porttest.append(y[1].data.dport)


                        final_tcp.append((y[1], y[0]))

                    else:
                        pass

    final_tcp.sort(key=lambda x: x[0].data.dport, reverse=False)

    listlist = TrimList(final_tcp, N_p)


    newestlist = distance_limit(listlist, W_p, N_p)
    newestlist2 = distance_limit(listlist2, W_s, N_s)
    newestlist3 = distance_limit(listlist3, W_p, N_p)
    newestlist4 = distance_limit(listlist4, W_s, N_s)

    print "Reports for TCP:"

    prev = 0
    if listlist is not None:
        for m in listlist:
            if m[0] is not None:
                if prev != m[0].data.dport:
                    print "Probe: "
                    print "Packet [Timestamp: ", m[1], " Port: ", m[0].data.dport, "Source IP: ", inet_to_str(m[0].src), "]"

                    prev = m[0].data.dport
                else:
                    print "Packet [Timestamp: ", m[1], " Port: ", m[0].data.dport, "Source IP: ", inet_to_str(m[0].src), "]"


    prev = 0
    print "Scans: "
    if listlist2 is not None:
        for m in listlist2:
            print "Packet [Timestamp: ", m[1], " Port: ", m[0].data.dport, "Source IP: ", inet_to_str(m[0].src), "]"
        print "Reports for UDP"
        print "Probes: "



    if newestlist3 is not None:
        for m in newestlist3:

            if prev != m[0].data.dport:
                print "Probe: "
                print "Packet [Timestamp: ", m[1], " Port: ", m[0].data.dport, "Source IP: ", inet_to_str(m[0].src), "]"

                prev = m[0].data.dport
            else:
                print "Packet [Timestamp: ", m[1], " Port: ", m[0].data.dport, "Source IP: ", inet_to_str(m[0].src), "]"






    print "Scans:"
    if newestlist4 is not None:
        for m in newestlist4:
            print "Packet [Timestamp: ", m[1], " Port: ", m[0].data.dport, "Source IP: ", inet_to_str(m[0].src), "]"
# execute a main function in Python
if __name__ == "__main__":
    main()
