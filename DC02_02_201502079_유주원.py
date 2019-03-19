import socket
import struct

def pasing_ethernet_header(data):
    ethernet_header = struct.unpack("!6B6B2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print('<'*6 + "Packet Capture Strart" + '>'*6)
    print('='*8 + "ethernet_header" + '='*8)
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append("{0:0{1}x}".format(i, 2))
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def pasing_ip_header(data):
    ip_header = struct.unpack("!2B2H2s2B2s8B", data)
    ip_version = ip_header[0] // (2**4)
    ip_length = (ip_header[0] % (2**4)) * 4
    ip_diff = ip_header[1] // (2**2)
    ip_expl = ip_header[1] % (2**2)
    ip_total = ip_header[2]
    ip_iden = ip_header[3]
    ip_flags = "0x"+ip_header[4].hex()
    ip_time = ip_header[5]
    ip_proto = ip_header[6]
    ip_head_ch = "0x"+ip_header[7].hex()


    print('='*8 + "ip_header" + '='*8)
    print("ip_version:", ip_version)
    print("ip_Length:", ip_length)
    print("differentiated_service_codepoint:", ip_diff)
    print("explicit_congestion_notification:", ip_expl)
    print("total_length:", ip_total)
    print("identification", ip_iden)
    print("flags:", ip_flags)
    print(">>>reserved_bit:", int(ip_flags,0)//(2**15))
    print(">>>not_fragments:", ( (int(ip_flags,0)) % (2**15) ) // (2**14) )
    print(">>>fragments:", ( (int(ip_flags,0)) % (2**14) ) // (2**13) )
    print(">>>fragments_offset:", ((int(ip_flags,0)) % (2**13)))
    print("Time to live:", ip_time)
    print("protocol:", ip_proto)
    print("header checksum:", ip_head_ch)
    print("source_ip_addreses:",data[8],end='')
    convert_ip_address(data[9:12])
    print("\ndest_ip_address:",data[12], end='')
    convert_ip_address(data[13:16])
    print()
    return ip_proto

def convert_ip_address(data):
    ip_addr = list()
    for addr in data:
        print(".",end='')
        print(addr,end='')

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2H2I2s3H", data)
    tcp_src = tcp_header[0]
    tcp_drc = tcp_header[1]
    tcp_seq = tcp_header[2]
    tcp_ack = tcp_header[3]
    tcp_len = int(("0x"+tcp_header[4].hex()),0) // (2**12)
    tcp_flag = int(("0x"+tcp_header[4].hex()),0) % (2**12)
    tcp_res = tcp_flag // (2**9)
    tcp_non = ( (tcp_flag % (2**9)) // (2**8) )
    tcp_cwr = ( (tcp_flag % (2**8)) // (2**7) )
    tcp_urg = ( (tcp_flag % (2**6)) // (2**5) )
    tcp_acke = ( (tcp_flag % (2**5)) // (2**4) )
    tcp_pus = ( (tcp_flag % (2**4)) // (2**3) )
    tcp_reset = ( (tcp_flag % (2**3)) // (2**2) )
    tcp_syn = ( (tcp_flag % (2**2)) // (2**1) )
    tcp_fin = tcp_flag % 2
    tcp_win = tcp_header[5]
    tcp_che = tcp_header[6]
    tcp_urg_p = tcp_header[7]

    print('='*8+"tcp_header"+'='*8)
    print("src_port:", tcp_src)
    print("dec_port:", tcp_drc)
    print("seq_num:", tcp_seq)
    print("ack_num:", tcp_ack)
    print("header_len:", tcp_len)
    print("flags:", tcp_flag)
    print(">>>reserved:", tcp_res)
    print(">>>nonce:", tcp_non)
    print(">>>cwr:",tcp_cwr)
    print(">>>urgent:", tcp_urg)
    print(">>>ack:", tcp_acke)
    print(">>>push:", tcp_pus)
    print(">>>reset:", tcp_reset)
    print(">>>syn:", tcp_syn)
    print(">>>fin", tcp_fin)
    print(">>>window_size_value:", tcp_win)
    print(">>>checksum:", tcp_che)
    print(">>>urgent_pointer:", tcp_urg_p)

def parsing_udp_header(data):
    udp_header= struct.unpack("!3H2s", data)
    udp_src = udp_header[0]
    udp_dst = udp_header[1]
    udp_len = udp_header[2]
    udp_head_che = "0x"+udp_header[3].hex()

    print('='*8 + "udp_header" + '='*8)
    print("src_port:", udp_src)
    print("dst_port:", udp_dst)
    print("leng:", udp_len)
    print("header checksum:", udp_head_che)

     

#[DC][02]HW02_201502079 유주원

recv_socket=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
while True:
    data = recv_socket.recvfrom(65565)
    pasing_ethernet_header(data[0][0:14])
    type = pasing_ip_header(data[0][14:34])
    if type == 6:
        parsing_tcp_header(data[0][34:54])
    else:
        if type==17:
            parsing_udp_header(data[0][34:42])

