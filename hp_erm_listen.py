#!/usr/bin/env python3

import socket
import struct
import os

import time

debug = False
if debug:
    from scapy.layers.l2 import Ether

# FIXME: it would nice to get this from sys/socket.h
SO_TIMESTAMPNS_OLD = 35
SO_TIMESTAMPNS_NEW = 64
SO_TIMESTAMPNS = SO_TIMESTAMPNS_OLD
SCM_TIMESTAMPNS = SO_TIMESTAMPNS

HP_ERM_PORT = 7932
HP_ERM_HLEN = 12  # bytes of proprietary HP header, which we will ignore

PCAP_GLOBAL_HEADER_FORMAT = "IHHiIII"
PCAP_RECORD_HEADER_FORMAT = "IIII"
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

PCAP_MAGIC_NS = 0xA1B23C4D

LINKTYPE_ETHERNET = 1

DATE_FMT = "%y%m%d-%H%M%S"


class PCAPWriter(object):
    def __init__(self, filename):
        if os.path.exists(filename):
            raise Exception(f"File {filename} exists")

        self.file = None

        self.file = open(filename, "wb")
        self.write_global_header()

    def __del__(self):
        self.close()

    def close(self):
        if self.file:
            self.file.close()

    def sync(self):
        self.file.flush()
        os.fsync(self.file)

    def write_global_header(self, snaplen=65535, network=LINKTYPE_ETHERNET):
        self.file.write(
            struct.pack(
                PCAP_GLOBAL_HEADER_FORMAT,
                PCAP_MAGIC_NS,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                snaplen,
                network,
            )
        )

    def write_packet(self, packet, timestamp):
        self.file.write(
            struct.pack(
                PCAP_RECORD_HEADER_FORMAT,
                timestamp[0],
                timestamp[1],
                len(packet),
                len(packet),
            )
        )

        self.file.write(packet)


class HP_ERM_Handler(object):
    def __init__(
        self, rotate=False, rounded=False,
    ):
        self.rotate = rotate
        self.rounded = rounded
        self.open_socket()
        self.pcaps = {}
        self.pcap_filename_prefix = "unset"

    def open_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS_NEW, 1)
        s.bind(("0.0.0.0", HP_ERM_PORT))
        self.skt = s

    def handle_message(self, rotate=False):
        (packet, timestamp, src_ip, src_port) = self.get_message()
        self.save_message(packet, timestamp, src_ip, src_port)

    def get_message(self):
        data, ancdata, flags, address = self.skt.recvmsg(10240, 1024)

        timestamp = None
        src_ip, src_port = address

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == SO_TIMESTAMPNS_NEW:
                # this is a __kernel_sock_timeval
                # FIXME: may be arch dependent
                tv_sec, tv_nsec = struct.unpack("=QQ", cmsg_data)
                timestamp = (tv_sec, tv_nsec)

        packet = data[HP_ERM_HLEN:]

        if debug:
            # show the timestamp
            print(src_ip, src_port)
            print(timestamp)

            # just print with scapy for now
            p = Ether(packet)
            p.show()

        return (packet, timestamp, src_ip, src_port)

    def save_message(self, packet, timestamp, src_ip, src_port):
        pcap_file = self.get_pcap_file(timestamp, src_ip, src_port)
        pcap_file.write_packet(packet, timestamp)

    def rotate_pcap_file(self, timestamp, src_ip, src_port):
        pf = self.pcaps.get((src_ip, src_port), None)
        if pf:
            pf["file"].close()

        start = timestamp[0]
        if self.rounded:
            start = start - (start % self.rotate)

        pcap_filename_fmt = (
            f"{self.pcap_filename_prefix}_{src_ip}_{src_port}_{DATE_FMT}.pcap"
        )
        pcap_filename = time.strftime(pcap_filename_fmt, time.localtime(start))

        pcap_file = PCAPWriter(filename=pcap_filename)

        self.pcaps[(src_ip, src_port)] = {
            "file": pcap_file,
            "rotate_at": start + self.rotate,
        }

    def get_pcap_file(self, timestamp, src_ip, src_port):
        if (src_ip, src_port) not in self.pcaps:
            if self.rotate:
                self.rotate_pcap_file(timestamp, src_ip, src_port)
            else:
                pcap_filename = f"{self.pcap_filename_prefix}_{src_ip}_{src_port}.pcap"

                pcap_file = PCAPWriter(filename=pcap_filename)
                self.pcaps[(src_ip, src_port)] = {
                    "file": pcap_file,
                }

        pcap_data = self.pcaps[(src_ip, src_port)]

        if self.rotate:
            if timestamp[0] >= pcap_data["rotate_at"]:
                self.rotate_pcap_file(timestamp, src_ip, src_port)
                pcap_data = self.pcaps[(src_ip, src_port)]

        return pcap_data["file"]


if __name__ == "__main__":
    h = HP_ERM_Handler(rotate=10, rounded=True)

    while True:
        h.handle_message()
