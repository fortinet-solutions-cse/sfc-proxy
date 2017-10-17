#!/usr/bin/python3

# This program uses the hexdump module. Install it through pip (pip3 install
# hexdump) or download it at https://pypi.python.org/pypi/hexdump
#
#  __  __               _____ _
# |  \/  |             / ____| |
# | \  / | __ _  ___  | |    | |__   __ _ _ __   __ _  ___ _ __
# | |\/| |/ _` |/ __| | |    | '_ \ / _` | '_ \ / _` |/ _ \ '__|
# | |  | | (_| | (__  | |____| | | | (_| | | | | (_| |  __/ |
# |_|  |_|\__,_|\___|  \_____|_| |_|\__,_|_| |_|\__, |\___|_|
#                                                __/ |
#                                               |___/
#
#  Port As       Port Bs
#     +            +
#     |            |
#     |            |
#     |            |
# +---+------------+---+
# |                    |
# |    MAC Changer     |
# |                    |
# +---+------------+---+
#     |            |
#     |            |
#     |            |
#     |            |
#     +            +
#   Port A         Port B
#
#  Changes mac randomly from Port A to Port As.
#  Forwards packets from Port Bs to Port B.

import hexdump
import socket
import argparse
import sys
import struct
import collections
import threading
import random
import time

from uuid import getnode as get_mac

# ************************************************
#  Global definition of data structures and sockets
# ************************************************

scktA = None
scktAs = None
scktB = None
scktBs = None

ifA = None
ifAs = None
ifB = None
ifBs = None

# ************************************************
#  Util functions
# ************************************************

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)


def bytes_to_hex(bytes):
    return " "\
        .join("{:02X}".format(x) for x in bytes)

def pack_namedtuple(struct_fmt, nt):
    arg_values = []
    arg_values.append( struct_fmt )
    for x in nt._fields:
        arg_values.append( getattr(nt, x) )
    return struct.pack( *arg_values )

def pf(str):
    print(str)
    sys.stdout.flush()

# ************************************************
#  Class definitions for network headers
# ************************************************


class MetaStruct(type):
    def __new__(cls, clsname, bases, dct):
        nt = collections.namedtuple(clsname, dct['fields'])

        def new(cls, record):
            return super(cls, cls).__new__(
                cls, *struct.unpack(dct['struct_fmt'], record))
        dct.update(__new__=new)
        return super(MetaStruct, cls).__new__(cls, clsname, (nt,), dct)

    def __str__(self):
        return "".join("{}({}) ".format(x, getattr(self, x)) for x in self._fields)

class StructEthHeader(object, metaclass=MetaStruct):
    fields = 'eth_dst eth_src eth_type'
    struct_fmt = '!6s6sH'

    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)

    def __str__(self):
        return ("StructEthHeader(eth_dst=" + bytes_to_mac(getattr(self, 'eth_dst'))
            + ', eth_src=' + bytes_to_mac(getattr(self, 'eth_src'))
            + ', eth_type=' + str(getattr(self, 'eth_type')) + ")")


class StructNshHeader(object, metaclass=MetaStruct):
    fields = 'nsh_flags_length nsh_md_type nsh_np nsh_sph nsh_ctx1 nsh_ctx2 nsh_ctx3 nsh_ctx4'
    struct_fmt = '!HBBLLLLL'

    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)

    def __str__(self):
        str1 = super().__str__()
        str2 = (' nsh_spi=' + str(self.get_nsh_spi())
            + ", nsh_si=" + str(self.get_nsh_si()))
        return str1 + str2

    def get_nsh_spi(self):
        return ((getattr(self, 'nsh_sph') & 0xFFFFFF00) >> 8)

    def get_nsh_si(self):
        return (getattr(self, 'nsh_sph') & 0x000000FF)

    def make_nsh_sph_with_spi(self, new_nsh_spi):
        return (new_nsh_spi << 8) + self.get_nsh_si()

    def make_nsh_sph_with_si(self, new_nsh_si):
        return (self.get_nsh_spi() << 8) + new_nsh_si

    def make_nsh_sph_with_spi_si(self, new_nsh_spi, new_nsh_si):
        return (new_nsh_spi << 8) + new_nsh_si


class StructUdpHeader(object, metaclass=MetaStruct):

    fields = 'udp_src_port udp_dst_port udp_data_length udp_checksum'
    struct_fmt = '!HHHH'
    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)


class StructIpHeader(object, metaclass=MetaStruct):
    fields = 'ip_ver_ihl_type ip_total_length ip_id ip_flags_frag_offset ip_time2live ip_protocol ip_hdr_checksum ip_src ip_dst'
    struct_fmt = '!HHHHBBH4s4s'
    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)
    def __str__(self):
        str_ip_src = socket.inet_ntoa(getattr(self, 'ip_src'))
        str_ip_dst = socket.inet_ntoa(getattr(self, 'ip_dst'))
        str1 = super().__str__()
        str2 = ' str_ip_src=' + str_ip_src + ", str_ip_dst=" + str_ip_dst
        return str1 + str2

class StructTcpHeaderWithoutOptions(object, metaclass=MetaStruct):
    fields = 'tcp_src_port tcp_dst_port tcp_seq_number tcp_ack tcp_byte_data_offset tcp_flags tcp_win_size tcp_checksum tcp_urgent_ptr'
    struct_fmt = '!HHLLBBHHH'
    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)
    def __str__(self):
        str1 = super().__str__()
        (fin, syn, rst, psh, ack, urg) = parse_tcp_flags(getattr(self, 'tcp_flags'))
        tcp_flags_str = get_tcp_flags_str(fin, syn, rst, psh, ack, urg)
        str2 = ' tcp_flags_str=' + tcp_flags_str
        return str1 + str2


""" https://tools.ietf.org/html/rfc793
            96 bit pseudo header
    +--------+--------+--------+--------+
    |           Source Address          |
    +--------+--------+--------+--------+
    |         Destination Address       |
    +--------+--------+--------+--------+
    |  zero  |  PTCL  |    TCP Length   |
    +--------+--------+--------+--------+
  The TCP Length is the TCP header length plus the data length in
  octets (this is not an explicitly transmitted quantity, but is
  computed), and it does not count the 12 octets of the pseudo
  header.
"""


class StructPseudoHeader(object, metaclass=MetaStruct):
    fields = 'src dst zero protocol tcp_length'
    struct_fmt = '!4s4sBBH'

    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)


class StructVxLanGPEHeader(object, metaclass=MetaStruct):
    fields = 'vxlan_flags vxlan_reserved1 next_proto vni vxlan_reserved2'
    struct_fmt = '!BHB3sB'

    def pack(self):
        return pack_namedtuple(self.struct_fmt, self)

    def __str__(self):
        vxlan_flags = getattr(self, 'vxlan_flags')
        vxlan_reserved1 = getattr(self, 'vxlan_reserved1')
        next_proto = getattr(self, 'next_proto')
        vni = getattr(self, 'vni')
        vxlan_reserved2 = getattr(self, 'vxlan_reserved2')
        str1 = super().__str__()

        str2 = ' flags=' + str(vxlan_flags) + ', reserved1=' + \
           str(vxlan_reserved1) + ', next protocol=' + str(next_proto) + \
           ', vni=' + str(vni) + ', reserved2=' + ', next protocol=' +  \
           str(next_proto) + ', vni=' + str(int.from_bytes(vni, byteorder='big')) + \
           ', reserved2=' + str(vxlan_reserved2)
        return str1 + str2


def print_frame(source, frame):
    print("Full frame: {}".format(source))
    hexdump.hexdump(frame)


def print_msg_hdr(outer_eth_header,
        nsh_header, eth_nsh_header,
        ip_header, udp_header,
        tcp_header_without_opt, tcp_options, tcp_payload):
    if outer_eth_header != None:
        pf(str(StructEthHeader(outer_eth_header)))
    if nsh_header != None:
        pf(str(StructNshHeader(nsh_header)))
    if eth_nsh_header != None:
        pf(str(StructEthHeader(eth_nsh_header)))
    if ip_header != None:
        pf(str(StructIpHeader(ip_header)))
    if udp_header != None:
        pf(str(StructUdpHeader(udp_header)))
    if tcp_header_without_opt != None:
        str_tcp_options = ''
        if tcp_options != None:
            str_tcp_options = ' tcp_options=' + bytes_to_hex(tcp_options)
        pf(str(StructTcpHeaderWithoutOptions(tcp_header_without_opt))
            + str_tcp_options)
    if tcp_payload != None:
        pf('tcp_payload(' + str(tcp_payload) + ')')




# ************************************************
#  Parsers
# ************************************************

"""Ethernet Frame consists of:
6 Byte Destination MAC address
6 Byte Source MAC address
2 Byte Ethertype
46 - 1500 Bytes Payload
"""


def parse_ethernet(frame):
    header_length = 14
    header = frame[:header_length]
    """
    ## In case 802.1Q tag compensation were required
    dst, src, type_code = struct.unpack("!6s6sH", header)
    if type_code == 0x8100:  # Encountered an 802.1Q tag, compensate.
        header_length = 18
        header = frame[:header_length]
        type_code = struct.unpack("!16xH", header)
    """
    payload = frame[header_length:]
    return header, payload

def make_ethernet_header_swap(header):
    outer_eth_header_nt = StructEthHeader(header)
    # Swap src <-> dst
    nt = outer_eth_header_nt._replace(
        eth_dst=getattr(outer_eth_header_nt, 'eth_src'),
        eth_src=getattr(outer_eth_header_nt, 'eth_dst'))
    return nt.pack()

def make_outer_ethernet_nsh_header(inner_eth_header):
    outer_eth_nsh_header_nt = StructEthHeader(inner_eth_header)

    mac_src=struct.pack("!6s", bytes.fromhex((hex(get_mac())[2:])))
    # EtherType: "Network Service Header" 0x894F
    nt = outer_eth_nsh_header_nt._replace(
        eth_dst=getattr(outer_eth_nsh_header_nt, 'eth_dst'),
        eth_src=mac_src,
        eth_type=0x894F)
    return nt.pack()

#####################################################################
"""
https://www.ietf.org/id/draft-ietf-sfc-nsh-05.txt
NSH MD-type 1 -> four Context Headers 4-byte each
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Ver|O|C|R|R|R|R|R|R|   Length  |  MD-type=0x1  | Next Protocol |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Service Path Identifer               | Service Index |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                Mandatory Context Header                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                Mandatory Context Header                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                Mandatory Context Header                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                Mandatory Context Header                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
def parse_nsh(packet):
    header_length = 8
    context_length = 16
    header = packet[:header_length + context_length]
    payload = packet[header_length + context_length:]
    return header, payload

def make_nsh_decr_si(nsh_header):
    nt = StructNshHeader(nsh_header)
    # Decrement NSH Service Index
    nt = nt._replace( nsh_sph=nt.make_nsh_sph_with_si(nt.get_nsh_si() - 1) )
    return nt.pack()

def make_nsh_mdtype1(nsh_spi, nsh_si):
    # NSH MD-type 1 -> 8 bytes Base Header + four Context Headers 4-byte each
    nsh_header = bytes(8 + 16)
    # Version MUST be set to 0x0 by the sender, in this first revision of NSH.
    # For an MD Type of 0x1 (i.e. no variable length metadata is present),
    #  the C bit MUST be set to 0x0.
    # The Length MUST be of value 0x6 for MD Type equal to 0x1
    nt = StructNshHeader(nsh_header)
    nt = nt._replace(
        nsh_flags_length=0x6,
        nsh_md_type= 0x1, # MD Type = 0x1, four Context Headers
        nsh_np=0x3, # Ethernet
        nsh_sph=nt.make_nsh_sph_with_spi_si(nsh_spi, nsh_si),
        nsh_ctx1=0,
        nsh_ctx2=0,
        nsh_ctx3=0,
        nsh_ctx4=0
        )
    return nt.pack()

#####################################################################

"""Internet Header Format (RFC791)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

def parse_ip(packet):
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    header = packet[:header_length_in_bytes]
    payload = packet[header_length_in_bytes:]
    return header, payload

def make_ip_header(header, new_ip_total_length):
    nt = StructIpHeader(header)
    # Change the Total Length
    nt = nt._replace( ip_total_length=new_ip_total_length )
    # Change the Header Checksum
    nt = nt._replace( ip_hdr_checksum=calculate_ip_checksum(nt.pack()) )
    return nt.pack()

def make_ip_header_swap(header):
    ip_header_nt = StructIpHeader(header)
    # Swap src <-> dst
    nt = ip_header_nt._replace(
        ip_src=getattr(ip_header_nt, 'ip_dst'),
        ip_dst=getattr(ip_header_nt, 'ip_src'))
    return nt.pack()
#####################################################################


def parse_udp(packet):
    header_length = 8
    header = packet[:header_length]
    payload = packet[header_length:]
    return header, payload

#####################################################################


"""  TCP Header Format (RFC793)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
def parse_tcp(packet):
    header_basic_length = 20
    header_without_options = packet[:header_basic_length]
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    # Data Offset: 4 bits - The number of 32 bit words in the TCP Header.
    data_offset = getattr(nt, 'tcp_byte_data_offset') >> 4
    header_length = data_offset * 4
    options = packet[header_basic_length:header_length]
    payload = packet[header_length:]
    return header_without_options, options, payload


def make_ip_package(ip_header, header_without_options, options, payload):
    # Modify the TCP Checksum
    new_tcp_checksum = calculate_tcp_checksum(ip_header,
        header_without_options, options, payload)
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    nt_new_header_without_options = nt._replace(
        tcp_checksum=new_tcp_checksum)

    new_ip_payload = nt_new_header_without_options.pack() + options + payload
    # Modify the IP Header (total_length and IP checksum
    new_ip_total_length = len(ip_header + new_ip_payload)
    new_ip_header = make_ip_header(ip_header, new_ip_total_length)

    return new_ip_header + new_ip_payload


def make_tpc_hdr_ack(header_without_options, port, num_bytes_added):
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    new_tcp_ack = getattr(nt, 'tcp_ack')

    (tcp_fin_f, tcp_syn_f, tcp_rst_f, tcp_psh_f, tcp_ack_f,
        tcp_urg_f) = parse_tcp_flags(getattr(nt, 'tcp_flags'))

    # If packet does not belong to TCP 3-Way Handshake:
    # reduce the ACK according to the added bytes
    if ( (tcp_ack_f == True) and (tcp_syn_f == False) ):
        new_tcp_ack -= num_bytes_added
    nt_new_header_without_options = nt._replace(tcp_ack=new_tcp_ack)
    return nt_new_header_without_options.pack()


def make_tpc_hdr_seq(header_without_options, port, num_bytes_added):
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    new_tcp_seq = getattr(nt, 'tcp_seq_number')

    (tcp_fin_f, tcp_syn_f, tcp_rst_f, tcp_psh_f, tcp_ack_f,
        tcp_urg_f) = parse_tcp_flags(getattr(nt, 'tcp_flags'))
    if ( (tcp_ack_f == True) and (tcp_syn_f == False) ):
        new_tcp_seq += num_bytes_added

    nt_new_header_without_options = nt._replace(tcp_seq_number=new_tcp_seq)
    return nt_new_header_without_options.pack()


def get_tpc_sync(header_without_options):
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    (tcp_fin_f, tcp_syn_f, tcp_rst_f, tcp_psh_f, tcp_ack_f,
        tcp_urg_f) = parse_tcp_flags(getattr(nt, 'tcp_flags'))
    return tcp_syn_f


def goes_from_server_to_client(header_without_options, port):
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    return ( port == getattr(nt, 'tcp_src_port') )


def goes_from_client_to_server(header_without_options, port):
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    return ( port == getattr(nt, 'tcp_dst_port') )


def has_correct_port(header_without_options, port):
    nt = StructTcpHeaderWithoutOptions(header_without_options)
    return (( port == getattr(nt, 'tcp_src_port') ) or
        ( port == getattr(nt, 'tcp_dst_port') ) )


def parse_tcp_flags(flags):
    fin = (flags & 1) > 0
    syn = (flags & (1 << 1)) > 0
    rst = (flags & (1 << 2)) > 0
    psh = (flags & (1 << 3)) > 0
    ack = (flags & (1 << 4)) > 0
    urg = (flags & (1 << 5)) > 0
    return fin, syn, rst, psh, ack, urg


def get_tcp_flags_str(fin, syn, rst, psh, ack, urg):
    str = ""
    str += 'U' if urg else '-'
    str += 'A' if ack else '-'
    str += 'P' if psh else '-'
    str += 'R' if rst else '-'
    str += 'S' if syn else '-'
    str += 'F' if fin else '-'
    return str

#Base on #https://github.com/secdev/scapy/blob/master/scapy/utils.py
def calculate_checksum(pkt):
    import array
    if len(pkt) % 2 == 1:
        pkt += b'\0'
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    if struct.pack("H",1) == "\x00\x01": # big endian
        return s & 0xffff
    else:
        return (((s>>8)&0xff)|s<<8) & 0xffff

def calculate_tcp_checksum(
        ip_header, header_without_options, options, payload):
    # create a 96 bit pseudo header
    ip_header_nt = StructIpHeader(ip_header)
    pseudo_header_nt = StructPseudoHeader(b'\x00' * 12)
    pseudo_header_nt = pseudo_header_nt._replace(
        src=getattr(ip_header_nt, 'ip_src'),
        dst=getattr(ip_header_nt, 'ip_dst'),
        zero=0,
        protocol=getattr(ip_header_nt, 'ip_protocol'),
        tcp_length=len(header_without_options + options + payload) )

    # skipping the checksum field itself
    header_without_options_nt = StructTcpHeaderWithoutOptions(header_without_options)
    header_without_options_nt = header_without_options_nt._replace(tcp_checksum=0)

    return calculate_checksum(
        pseudo_header_nt.pack()
        + header_without_options_nt.pack()
        + options
        + payload)

def calculate_ip_checksum(pkt):
    # skipping the checksum field itself
    pkt = pkt[0:10] + b'\0' + b'\0' + pkt[12:len(pkt)]
    return calculate_checksum(pkt)

def need_reset_tcp_connection(tcp_header_without_options):
    nt = StructTcpHeaderWithoutOptions(tcp_header_without_options)
    (tcp_fin_f, tcp_syn_f, tcp_rst_f, tcp_psh_f, tcp_ack_f,
        tcp_urg_f) = parse_tcp_flags(getattr(nt, 'tcp_flags'))
    return tcp_rst_f


"""
   VXLAN GPE Header
   https://tools.ietf.org/html/draft-ietf-nvo3-vxlan-gpe-04

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |R|R|Ver|I|P|B|O|       Reserved                |Next Protocol  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                VXLAN Network Identifier (VNI) |   Reserved    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""


def parse_vxlan_gpe(packet):
    header_length = 8
    header = packet[:header_length]
    payload = packet[header_length:]
    return header, payload

from enum import Enum
class Sockets(Enum):
     output_socket = 1
     input_socket = 2

def ip2str(ip_bytes):
    return str(socket.inet_ntoa(ip_bytes))

def mac2str(mac_bytes):
    return ':'.join(format(b, 'x') for b in mac_bytes)

def macDb2str(mac_db):
    tmp_str=""
    for key_mac, socket_value  in mac_db.items():
        tmp_str += "   " + mac2str(key_mac) + " in " + str(socket_value.value) + "(" + str(socket_value.name) + ")\n"
    return tmp_str

def randomMAC():
    return bytes([ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ])

def change_dst_mac(header):
    eth_header_nt = StructEthHeader(header)
    # Change dst
    nt = eth_header_nt._replace(eth_dst=randomMAC())
    return nt.pack()


def changeMacAndForward(frame, output_socket):

   (eth_header, eth_payload) = parse_ethernet(frame)

   new_eth_header = change_dst_mac(eth_header)

   new_pkt = new_eth_header + eth_payload

   pf("Changing Mac")

   while new_pkt:
       pf("   Length of packet: " + str(len(new_pkt)))
       if len(new_pkt) >= 4096:
           pf("Error: packet really large: " + str(new_pkt))
           pf("Discarding packet")
           new_pkt = []
       else:
           sent = output_socket.send(new_pkt)
           new_pkt = new_pkt[sent:]
           pf("   Packet sent")


def forward(frame, output_socket):

   new_pkt = frame

   pf("Forwarding packet")

   while new_pkt:
       pf("   Length of packet: " + str(len(new_pkt)))
       if len(new_pkt) >= 4096:
           pf("Error: packet really large: " + str(new_pkt))
           pf("Discarding packet")
           new_pkt = []
       else:
           sent = output_socket.send(new_pkt)
           new_pkt = new_pkt[sent:]
           pf("   Packet sent")


# ************************************************
#  Socket listeners
# ************************************************

def loopA():

    global scktA
    global scktAs

    while True:
        frame, source = scktA.recvfrom(65565)
        changeMacAndForward(frame, output_socket=scktAs)


def loopAs():

    global scktAs
    global scktA

    while True:
        frame, source = scktAs.recvfrom(65565)
        forward(frame, output_socket=scktA)

def loopB():

    global scktB
    global scktBs

    while True:
        frame, source = scktB.recvfrom(65565)
        changeMacAndForward(frame, output_socket=scktBs)


def loopBs():

    global scktBs
    global scktB

    while True:
        frame, source = scktBs.recvfrom(65565)
        forward(frame, output_socket=scktB)


def setup_sockets():

    global scktA
    global scktB
    global scktAs
    global scktBs

    global ifA
    global ifB
    global ifAs
    global ifBs

    scktA = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    scktA.bind((ifA, 0))

    scktB = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    scktB.bind((ifB, 0))

    scktAs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    scktAs.bind((ifAs, 0))

    scktBs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    scktBs.bind((ifBs, 0))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Python3 script to change mac addresses from port A to As,'
                                                 ' and forward packets from port Bs to B',
                                     prog='mac_changer',
                                     usage='%(prog)s [options]',
                                     add_help=True)

    parser.add_argument('-a', '--ifA',
                        help='Specify the A interface, where traffic is forwarded from As')
    parser.add_argument('-as', '--ifAs',
                        help='Specify the As interface, where traffic is forwarded from A')
    parser.add_argument('-b', '--ifB',
                        help='Specify the B interface, where traffic is forwarded from Bs')
    parser.add_argument('-bs', '--ifBs',
                        help='Specify the Bs interface, where traffic is forwarded from B')

    args = parser.parse_args()

    if (args.ifA is None) or (args.ifB is None) or (args.ifAs is None) or (args.ifBs is None):
        parser.print_help()
        sys.exit(-1)

    pf("args.ifA(" + str(args.ifA) + ")")
    pf("args.ifB(" + str(args.ifB) + ")")
    pf("args.ifAs(" + str(args.ifAs) + ")")
    pf("args.ifBs(" + str(args.ifBs) + ")")

    ifA = args.ifA
    ifB = args.ifB
    ifAs = args.ifAs
    ifBs = args.ifBs

    setup_sockets()

    threadA = threading.Thread(target=loopA, name="loopA")
    threadA.daemon = True
    threadB = threading.Thread(target=loopB, name="loopB")
    threadB.daemon = True
    threadAs = threading.Thread(target=loopAs, name="loopAs")
    threadAs.daemon = True
    threadBs = threading.Thread(target=loopBs, name="loopBs")
    threadBs.daemon = True

    threadA.start()
    threadB.start()
    threadAs.start()
    threadBs.start()

    while True:
        time.sleep(1)

    pf("v0.1 - Threads active - Listening...")

