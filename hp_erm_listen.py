#!/usr/bin/env python3

import socket
import struct

from scapy.layers.l2 import Ether

# FIXME: it would nice to get this from sys/socket.h
SO_TIMESTAMPNS_OLD = 35
SO_TIMESTAMPNS_NEW = 64
SO_TIMESTAMPNS = SO_TIMESTAMPNS_OLD
SCM_TIMESTAMPNS = SO_TIMESTAMPNS

HP_ERM_PORT = 7932
HP_ERM_HLEN = 12  # bytes of proprietary HP header, which we will ignore

class HP_ERM_Handler(object):
    def __init__(self):
        self.open_socket()

    def open_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS_NEW, 1)
        s.bind(('0.0.0.0', HP_ERM_PORT))
        self.skt = s

    def get_message(self):
        data, ancdata, flags, address = self.skt.recvmsg(10240, 1024)

        timestamp = None
        src_ip = None
        src_port = None

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == SO_TIMESTAMPNS_NEW:
                # this is a __kernel_sock_timeval
                # FIXME: may be arch dependent
                print(len(cmsg_data))
                tv_sec, tv_nsec = struct.unpack("=QQ", cmsg_data)
                timestamp = (tv_sec, tv_nsec)

        packet = data[HP_ERM_HLEN:]

        # show the timestamp
        print(timestamp)

        # just print with scapy for now
        p = Ether(packet)
        p.show()

if __name__ == "__main__":
    h = HP_ERM_Handler()

    for i in range(100):
        h.get_message()
