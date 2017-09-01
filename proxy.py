#!/usr/bin/python3

# This program uses the hexdump module. Install it through pip (pip3 install
# hexdump) or download it at https://pypi.python.org/pypi/hexdump
#
#  _   _  _____ _    _   _____
# | \ | |/ ____| |  | | |  __ \
# |  \| | (___ | |__| | | |__) | __ _____  ___   _
# | . ` |\___ \|  __  | |  ___/ '__/ _ \ \/ / | | |
# | |\  |____) | |  | | | |   | | | (_) >  <| |_| |
# |_| \_|_____/|_|  |_| |_|   |_|  \___/_/\_\\__, |
#                                             __/ |
#                                            |___/
#
#  +-----------------------------------+
#  |                                   |
#  |          Service Function         |
#  |       (nsh and vxlan unaware)     |
#  |                                   |
#  +-------+-------------------+-------+
#          |                   |
#          |                   |
#   encapsulated          encapsulated
#   out                   in
#          |  ^                | |
#          |  |                | |
#          |  |                | v
#          |                   |
#  +-------+-------------------+-------+
#  |                                   |
#  |               Proxy               |
#  |        NSH and VXLAN aware        |
#  |                                   |
#  +-----------------+-----------------+
#                    |
#                    |
#          unencapsulated interface
#                    |
#                  ^ | |
#                  | | |
#                  | | v
#                    |
#         +----------+-----------+ Network
#

import hexdump
import socket
import argparse
import sys
import struct
import collections
import threading

from uuid import getnode as get_mac

# ************************************************
#  Global definition of data structures and sockets
# ************************************************

sessions = {}
sessions_reply_info= {}
mac_database = {}

sckt_encap = None
sckt_unencap_in = None
sckt_unencap_out = None

encap_if = None
unencap_in_if = None
unencap_out_if = None


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

# ************************************************
#  Loops for encapsulating / unencapsulating
# ************************************************
def ip2str(ip_bytes):
    return str(socket.inet_ntoa(ip_bytes))

def mac2str(mac_bytes):
    return ':'.join("{0!r}".format(b) for b in mac_bytes)

def unencapsulate_packet(frame):

    (outer_eth_header, outer_eth_payload) = parse_ethernet(frame)
    outer_eth_header_nt = StructEthHeader(outer_eth_header)
    outer_eth_type = getattr(outer_eth_header_nt, 'eth_type')

    if (outer_eth_type == 0x0800):  # EtherType: IPv4 0x0800
        next_eth_payload = outer_eth_payload

        (ip_header, ip_payload) = parse_ip(next_eth_payload)
        ip_header_nt = StructIpHeader(ip_header)
        ip_protocol = getattr(ip_header_nt, 'ip_protocol')

        if ip_protocol == 17:  # UDP is protocol 17
            (udp_header, udp_payload) = parse_udp(ip_payload)
            reset_connection = True
            udp_header_nt = StructUdpHeader(udp_header)
            dst_port=getattr(udp_header_nt,'udp_dst_port')

            if dst_port == 4790:

                (vxlan_header, vxlan_payload)=parse_vxlan_gpe(udp_payload)
                vxlan_header_nt=StructVxLanGPEHeader(vxlan_header)


                (eth_nsh_header, eth_nsh_payload)=parse_ethernet(vxlan_payload)
                eth_nsh_header_nt = StructEthHeader(eth_nsh_header)

                (nsh_header, nsh_payload) = parse_nsh(eth_nsh_payload)
                nsh_header_nt = StructNshHeader(nsh_header)


                (inner_eth_header, inner_eth_payload) = parse_ethernet(nsh_payload)
                inner_eth_header_nt = StructEthHeader(inner_eth_header)

                (inner_ip_header, inner_ip_payload) = parse_ip(inner_eth_payload)
                inner_ip_header_nt = StructIpHeader(inner_ip_header)

                (inner_tcp_header_without_options, inner_tcp_options, inner_tcp_payload) = parse_tcp(inner_ip_payload)
                inner_tcp_header_nt = StructTcpHeaderWithoutOptions(inner_tcp_header_without_options)

                eth_dst = getattr(inner_eth_header_nt,"eth_dst")
                eth_src = getattr(inner_eth_header_nt,"eth_src")
                eth_type = getattr(inner_eth_header_nt,"eth_type")

                ip_dst = getattr(inner_ip_header_nt, "ip_dst")
                ip_src = getattr(inner_ip_header_nt, "ip_src")

                tcp_dst_port = getattr(inner_tcp_header_nt, "tcp_dst_port")
                tcp_src_port = getattr(inner_tcp_header_nt, "tcp_src_port")


                #First check if this is a reply to an existing session
                #Build a key with mac/ip swapped
                isReply=False

                key = (eth_dst, eth_src, eth_type, ip_dst, ip_src, tcp_dst_port, tcp_src_port)
                swapped_key = (eth_src, eth_dst, eth_type, ip_src, ip_dst, tcp_src_port, tcp_dst_port)
                pf("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
                pf("^^^ Receiving packet encapsulated ^^^")
                pf("^^ " + ip2str(ip_src)+":"+str(tcp_src_port)+
                   "->"+ip2str(ip_dst)+":"+str(tcp_dst_port))
                pf("^^ "+mac2str(eth_src)+"->"+mac2str(eth_dst)+ ", proto 17 ^^")
                pf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

                global sessions
                if swapped_key in sessions:
                    isReply = True
                    pf("   Session found. Seems to be a reply")
                    sessions_reply_info[swapped_key] = (outer_eth_header,
                                         ip_header,
                                         udp_header,
                                         vxlan_header,
                                         eth_nsh_header,
                                         nsh_header)


                #Replies do not create new sessions
                if not isReply:
                    sessions[key]=(outer_eth_header,
                                         ip_header,
                                         udp_header,
                                         vxlan_header,
                                         eth_nsh_header,
                                         nsh_header)

                pf("   # of sessions: "+ str(len(sessions)))


                new_pkt=nsh_payload

                pf("   Sending packet deencapsulated")

                # Send all data
                global sckt_unencap_in
                global sckt_unencap_out
                global mac_database

                egress_socket = None

                if eth_dst in mac_database:
                    if mac_database[eth_dst] == Sockets.input_socket:
                        egress_socket = sckt_unencap_out
                        mac_database[eth_src] = Sockets.output_socket
                        pf("   Dst mac in database. Leaving via 'out' interface")
                    else:
                        egress_socket = sckt_unencap_in
                        mac_database[eth_src] = Sockets.input_socket
                        pf("   Dst mac in database. Leaving via 'in' interface")
                else:
                    egress_socket = sckt_unencap_out
                    mac_database[eth_src] = Sockets.output_socket
                    mac_database[eth_dst] = Sockets.input_socket
                    pf("   Dst mac not in database. Leaving via 'out' interface")

                pf("   ****")
                pf("   **** MAC database: "+str(mac_database))
                pf("   ****")

                while new_pkt:
                    sent = egress_socket.send(new_pkt)
                    new_pkt = new_pkt[sent:]
                    pf("   Packet sent")



def encapsulate_request_packet(frame):


    (outer_eth_header, outer_eth_payload) = parse_ethernet(frame)
    outer_eth_header_nt = StructEthHeader(outer_eth_header)
    outer_eth_type = getattr(outer_eth_header_nt, 'eth_type')

    if (outer_eth_type == 0x0800):  # EtherType: IPv4 0x0800
        next_eth_payload = outer_eth_payload

        (ip_header, ip_payload) = parse_ip(next_eth_payload)
        ip_header_nt = StructIpHeader(ip_header)
        ip_protocol = getattr(ip_header_nt, 'ip_protocol')

        if ip_protocol == 6: #TCP
            #In this case check if this belongs to an existing session and add the VxLAN/NSH header

            (tcp_header_without_options, tcp_options, tcp_payload) = parse_tcp(ip_payload)
            tcp_header_nt = StructTcpHeaderWithoutOptions(tcp_header_without_options)

            eth_dst = getattr(outer_eth_header_nt, "eth_dst")
            eth_src = getattr(outer_eth_header_nt, "eth_src")
            eth_type = getattr(outer_eth_header_nt, "eth_type")

            ip_dst = getattr(ip_header_nt, "ip_dst")
            ip_src = getattr(ip_header_nt, "ip_src")

            tcp_dst_port = getattr(tcp_header_nt, "tcp_dst_port")
            tcp_src_port = getattr(tcp_header_nt, "tcp_src_port")


            key = (eth_dst, eth_src, eth_type, ip_dst, ip_src, tcp_dst_port, tcp_src_port)

            pf("\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
            pf("vvv Receiving packet unencapsulated  (In) vvv")
            pf("vv " + ip2str(ip_src) + ":" + str(tcp_src_port) +
               "->" + ip2str(ip_dst) + ":" + str(tcp_dst_port))
            pf("vv " + mac2str(eth_src) + "->" + mac2str(eth_dst) + ", proto 6 vv")
            pf("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")


            if key in sessions:
                pf("   Session found")

                (new_outer_eth_header,
                 new_ip_header,
                 new_udp_header,
                 new_vxlan_header,
                 new_eth_nsh_header,
                 new_nsh_header) = sessions[key]

                #Swap headers and send

                new_outer_eth_header_swapped = make_ethernet_header_swap(new_outer_eth_header)
                new_ip_header_swapped = make_ip_header_swap(new_ip_header)
                new_nsh_header_decremented = make_nsh_decr_si(new_nsh_header)

                new_eth_nsh_header_swapped = make_ethernet_header_swap(new_eth_nsh_header)


                new_pkt = new_outer_eth_header_swapped + \
                          new_ip_header_swapped + \
                          new_udp_header + \
                          new_vxlan_header + \
                          new_eth_nsh_header_swapped + \
                          new_nsh_header_decremented + \
                          frame

                pf("   Sending packet encapsulated")
                global sckt_encap

                while new_pkt:
                    sent = sckt_encap.send(new_pkt)
                    new_pkt = new_pkt[sent:]
                    pf("   Packet sent")

            else:
                pf("   Packet received, not matching session")
                exit(-1)


def encapsulate_reply_packet(frame):


    (outer_eth_header, outer_eth_payload) = parse_ethernet(frame)
    outer_eth_header_nt = StructEthHeader(outer_eth_header)
    outer_eth_type = getattr(outer_eth_header_nt, 'eth_type')

    if (outer_eth_type == 0x0800):  # EtherType: IPv4 0x0800
        next_eth_payload = outer_eth_payload

        (ip_header, ip_payload) = parse_ip(next_eth_payload)
        ip_header_nt = StructIpHeader(ip_header)
        ip_protocol = getattr(ip_header_nt, 'ip_protocol')

        if ip_protocol == 6: #TCP
            #In this case check if this belongs to an existing session and add the VxLAN/NSH header

            (tcp_header_without_options, tcp_options, tcp_payload) = parse_tcp(ip_payload)
            tcp_header_nt = StructTcpHeaderWithoutOptions(tcp_header_without_options)

            eth_dst = getattr(outer_eth_header_nt, "eth_dst")
            eth_src = getattr(outer_eth_header_nt, "eth_src")
            eth_type = getattr(outer_eth_header_nt, "eth_type")

            ip_dst = getattr(ip_header_nt, "ip_dst")
            ip_src = getattr(ip_header_nt, "ip_src")

            tcp_dst_port = getattr(tcp_header_nt, "tcp_dst_port")
            tcp_src_port = getattr(tcp_header_nt, "tcp_src_port")

            swapped_key = (eth_src, eth_dst, eth_type, ip_src, ip_dst, tcp_src_port, tcp_dst_port)

            pf("\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
            pf("vvv Receiving packet unencapsulated (Out) vvv")
            pf("vv " + ip2str(ip_src) + ":" + str(tcp_src_port) +
               "->" + ip2str(ip_dst) + ":" + str(tcp_dst_port))
            pf("vv " + mac2str(eth_src) + "->" + mac2str(eth_dst) + ", proto 6 vv")
            pf("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")

            if swapped_key in sessions:
                pf("   Session found")

                (new_outer_eth_header,
                 new_ip_header,
                 new_udp_header,
                 new_vxlan_header,
                 new_eth_nsh_header,
                 new_nsh_header) = sessions[swapped_key]

                (reply_outer_eth_header,
                 reply_ip_header,
                 reply_udp_header,
                 reply_vxlan_header,
                 reply_eth_nsh_header,
                 new_nsh_header) = sessions_reply_info[swapped_key]

                new_nsh_header_decremented = make_nsh_decr_si(new_nsh_header)

                #Swap headers and send

                new_reply_outer_eth_header_swapped = make_ethernet_header_swap(reply_outer_eth_header)
                new_reply_ip_header_swapped = make_ip_header_swap(reply_ip_header)

                new_reply_eth_nsh_header_swapped = make_ethernet_header_swap(reply_eth_nsh_header)

                new_pkt = new_reply_outer_eth_header_swapped + \
                          new_reply_ip_header_swapped + \
                          reply_udp_header + \
                          reply_vxlan_header + \
                          new_reply_eth_nsh_header_swapped + \
                          new_nsh_header_decremented + \
                          frame

                pf("   Sending packet encapsulated")

                global sckt_encap

                while new_pkt:
                    sent = sckt_encap.send(new_pkt)
                    new_pkt = new_pkt[sent:]
                    pf("   Packet sent")

            else:
                pf("   Packet received, not matching session")
                exit(-2)


# ************************************************
#  Socket listeners
# ************************************************

def unencapsulating_loop():

    global sckt_encap
    global sckt_unencap_out
    global unencap_out_if

    while True:
        frame, source = sckt_encap.recvfrom(65565)
        unencapsulate_packet(frame)


def encapsulating_requests_loop():

    global sckt_unencap_in
    global encap_if

    while True:
        frame, source = sckt_unencap_in.recvfrom(65565)
        encapsulate_request_packet(frame)


def encapsulating_replies_loop():

    global sckt_unencap_out
    global encap_if

    while True:
        frame, source = sckt_unencap_out.recvfrom(65565)
        encapsulate_reply_packet(frame)


def setup_sockets():

    global sckt_encap
    global sckt_unencap_in
    global sckt_unencap_out

    global encap_if
    global unencap_in_if
    global unencap_out_if

    sckt_encap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sckt_encap.bind((encap_if, 0))

    sckt_unencap_in = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sckt_unencap_in.bind((unencap_in_if, 0))

    sckt_unencap_out = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sckt_unencap_out.bind((unencap_out_if, 0))


if __name__ == "__main__":


    parser = argparse.ArgumentParser(description='Python3 script to emulate an SFC proxy,'
                                                 ' removing VxLAN and NSH headers',
                                     prog='proxy.py',
                                     usage='%(prog)s [options]',
                                     add_help=True)

    parser.add_argument('-e', '--encap_if',
                        help='Specify the interface where VxLAN/NSH traffic is encapsulated')
    parser.add_argument('-uin', '--unencap_in_if',
                        help='Specify the interface accepting VxLAN/NSH traffic unencapsulated')
    parser.add_argument('-uout', '--unencap_out_if',
                        help='Specify the interface where VxLAN/NSH traffic is sent unencapsulated')

    args = parser.parse_args()

    if (args.encap_if is None) or (args.unencap_in_if is None) or (args.unencap_out_if is None):
        parser.print_help()
        sys.exit(-1)

    pf("args.encap_if(" + str(args.encap_if) + ")")
    pf("args.unencap_in_if(" + str(args.unencap_in_if) + ")")
    pf("args.unencap_out_if(" + str(args.unencap_out_if) + ")")

    encap_if = args.encap_if
    unencap_in_if = args.unencap_in_if
    unencap_out_if = args.unencap_out_if

    setup_sockets()

    unencapsulating_thread = threading.Thread(target=unencapsulating_loop, name="unencapsulating thread")
    encapsulating_requests_thread = threading.Thread(target=encapsulating_requests_loop, name="encapsulating requests thread")
    encapsulating_replies_thread = threading.Thread(target=encapsulating_replies_loop, name="encapsulating replies thread")

    unencapsulating_thread.start()
    encapsulating_requests_thread.start()
    encapsulating_replies_thread.start()

    pf("v0.99 - Threads active - Listening...")

