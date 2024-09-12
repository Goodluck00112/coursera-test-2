import socket, struct, binascii

def create_socket(interface):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
        print(f"[*] Bound to {interface}")
        return sock
    except socket.error as msg:
        print(f"[!] Error: {str(msg)}")
        return None

def mac_address(bytes_addr):
    return ':'.join(f'{byte:02x}' for byte in bytes_addr)

def unpack_ethernet_frame(data):
    eth_header = struct.unpack('!6s6sH', data[:14])
    return mac_address(eth_header[0]), mac_address(eth_header[1]), socket.ntohs(eth_header[2]), data[14:], data[:14]

def unpack_ip_packet(data):
    ip_header = data[:20]
    ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
    ihl = (ip_fields[0] & 0xF) * 4
    return ip_fields[0] >> 4, ihl, ip_fields[5], ip_fields[6], socket.inet_ntoa(ip_fields[8]), socket.inet_ntoa(ip_fields[9]), data[ihl:], ip_header

def unpack_tcp_segment(data):
    tcp_header = data[:20]
    tcp_fields = struct.unpack('!HHLLBBHHH', tcp_header)
    offset = (tcp_fields[4] >> 4) * 4
    return tcp_fields[0], tcp_fields[1], tcp_fields[2], tcp_fields[3], offset, data[offset:], tcp_header

def unpack_udp_segment(data):
    udp_header = data[:8]
    udp_fields = struct.unpack('!HHHH', udp_header)
    return udp_fields[0], udp_fields[1], udp_fields[2], data[8:], udp_header

def sniff_packets(interface):
    sock = create_socket(interface)
    if not sock: return

    try:
        while True:
            raw_data, _ = sock.recvfrom(65536)
            dest_mac, src_mac, eth_protocol, data, eth_header = unpack_ethernet_frame(raw_data)
            print(f'\nEthernet Frame:\nDst: {dest_mac}, Src: {src_mac}, Proto: {eth_protocol}\nHex: {binascii.hexlify(eth_header).decode()}')

            if eth_protocol == 0x0800:  # IPv4
                version, ihl, ttl, protocol, src_ip, dst_ip, data, ip_header = unpack_ip_packet(data)
                print(f'\nIP Packet:\nVer: {version}, IHL: {ihl}, TTL: {ttl}, Proto: {protocol}, Src: {src_ip}, Dst: {dst_ip}\nHex: {binascii.hexlify(ip_header).decode()}')

                if protocol == 6:  # TCP
                    src_port, dst_port, seq, ack, offset, data, tcp_header = unpack_tcp_segment(data)
                    print(f'\nTCP Segment:\nSrc Port: {src_port}, Dst Port: {dst_port}, Seq: {seq}, Ack: {ack}\nHex: {binascii.hexlify(tcp_header).decode()}')
                elif protocol == 17:  # UDP
                    src_port, dst_port, length, data, udp_header = unpack_udp_segment(data)
                    print(f'\nUDP Segment:\nSrc Port: {src_port}, Dst Port: {dst_port}, Len: {length}\nHex: {binascii.hexlify(udp_header).decode()}')
                elif protocol == 1:  # ICMP
                    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
                    print(f'\nICMP Packet:\nType: {icmp_type}, Code: {code}, Checksum: {checksum}')
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")
        sock.close()

if __name__ == "__main__":
    sniff_packets('eth0')
    sniff_packets('lo')
