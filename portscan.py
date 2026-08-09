import socket
import struct
from concurrent.futures import ThreadPoolExecutor
import random 

def create_TCP_header( #takes only int values
        source_port,
        destination_port,
        sequence_number,
        checksum=0,
        ack_number=0,
        data_offset=5, #for a SYN scan the syze will be 20 bytes, therefore 5 groups of 4 bytes, 
        reserved=0,
        tcp_flags=2,
        window_size=65534,
        urgent_pointer=0
        ):
    
    '''
    TCP HEADER          

    source_port         2 bytes
    destination_port    2 bytes
    sequence_number     4 bytes
    ack_number          4 bytes
    data_offset         4 bits
    reserved            6 bits
    tcp_flags           6 bits
    window_size         2 bytes
    checksum            2 bytes
    urgent_pointer      2 bytes
    optional_data
    '''

    temp_value = ((data_offset << 4 | reserved) << 8) | tcp_flags #combining the bits that does not form bytes, so they can be used on the struct function

    return struct.pack("!HHLLHHHH", source_port, destination_port, sequence_number, ack_number, temp_value, window_size, checksum, urgent_pointer)     

'''

def create_IP_header(
        source_ip,
        destination_ip,
        checksum=0,
        version=4,
        ihl=5,
        type_of_service=0,
        total_length=40,
        id=12345,
        flags=0,
        fragg_offset=0,
        ttl=64,
        protocol=6
        ): 

    version + IHL     1 byte   
    type of service   1 byte   
    total length      2 bytes  
    identification    2 bytes  
    flags + frag off  2 bytes  
    TTL               1 byte   
    protocol          1 byte  
    header checksum   2 bytes  
    source IP         4 bytes  
    destination IP    4 bytes 

    src_ip = socket.inet_aton(source_ip)
    dst_ip = socket.inet_aton(destination_ip)

    temp_value1 = (version << 4) | ihl
    temp_value2 = (flags << 13) | fragg_offset

    return struct.pack("!BBHHHBBH4s4s", temp_value1, type_of_service, total_length, id, temp_value2, ttl, protocol, checksum, src_ip, dst_ip)

'''

def calculate_pseudo_header(
        source_ip,              #4 bytes
        destination_ip,         #4 bytes
        tcp_length=20,          #1 byte
        reserved=0,             #1 byte
        protocol=6,             #2 bytes
        ):

    src_ip = socket.inet_aton(source_ip)
    dst_ip = socket.inet_aton(destination_ip)

    return struct.pack("!4s4sBBH", src_ip, dst_ip, reserved, protocol, tcp_length)

def calculate_checksum(
        pseudo_header=b'',
        tcp_header=b'',
        tcp_payload=b'',
        ip_header=b''
        ): 
    total_value = pseudo_header + tcp_header + tcp_payload + ip_header     #b'\x00\x00\x00...'

    if len(total_value) % 2:
        total_value += b'\x00'

    sum_groups = 0
    for i in range(0, len(total_value), 2): 
        sum_groups += (total_value[i] << 8) | total_value[i+1]  #sum of all the bytes in a 16 bit group

    low16bits = sum_groups 
    
    while sum_groups >> 16:
        carry = sum_groups >> 16                                    # getting the carry from the total sum
        low16bits = sum_groups & 0xFFFF                             # low 16 bits 
        low16bits += carry                                          # summing the low16bits with the carry that is now with low bits 

        sum_groups = sum_groups >> 16

    return ~low16bits & 0xFFFF                                      #doing ones complement and using a mask to restrict for 16 bits

    
def get_source_ip(destination_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((destination_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()

def evaluate_flags(flag): 
    if (flag & 0x12) == 0x12:
        return "Open"
    elif (flag & 0x04) == 0x04: 
        return "Closed"



def create_syn_packet(port) : 

    '''
    random values for sequence, window and source port
    so it is not as suspect as having all values the same 
    '''
    seq_number = random.randint(1, 4294967295)  
    window_size = random.randint(62727, 65534)  
    src_port = random.randint(5000, 62439)      

    tcp_header = create_TCP_header(source_port=src_port, destination_port=port, sequence_number=seq_number, window_size=window_size)
    syn_pseudo_header = calculate_pseudo_header(source_ip=source_ip, destination_ip=destination_ip)
    syn_packet_checksum = calculate_checksum(pseudo_header=syn_pseudo_header, tcp_header=tcp_header)
    syn_packet = create_TCP_header(source_port=src_port, destination_port=port, sequence_number=seq_number, checksum=syn_packet_checksum, window_size=window_size)

    """ # Methods used to create the IP header that would be necessary in a Windows OS
    ip_header = create_IP_header(source_ip=src_ip, destination_ip=dst_ip)
    ip_header_checksum = calculate_checksum(ip_header=ip_header)
    ip_header = create_IP_header(source_ip=src_ip, destination_ip=dst_ip, checksum=ip_header_checksum)
    """

    final_packet = syn_packet   # + ip_header

    return [final_packet,src_port]

def socket_dealing(port): 
    port_n_state = [port, "n/a"]

    lst_syn_packlet = create_syn_packet(port)

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw_socket.settimeout(3)
    raw_socket.sendto(lst_syn_packlet[0], (destination_ip, port))

    sender_src_ip = ""                      #the analyzed packet must have the same source ip as the destination one from the first packet, so the packet received is indeed the one expected
    sender_src_port = 0
    sender_destination_port = 0
    tcp_recv = 0x0

    while (sender_src_ip != destination_ip) or (sender_src_port != port) or (sender_destination_port != lst_syn_packlet[1]):
        try: 
            received_data = raw_socket.recv(65535)

            first_byte = received_data[0]           # first byte contains version and IP packet length
            ihl = first_byte & 0x0F                 # takes the version out
            ip_header_size = ihl * 4 
            tcp_recv = received_data[ip_header_size:]


            sender_src_ip = socket.inet_ntoa(received_data[12:16])  # getting the source ip from the received ip header
            sender_src_port = struct.unpack("!H", tcp_recv[0:2])[0]                   # getting the source port from the received tcp header
            sender_destination_port = struct.unpack("!H", tcp_recv[2:4])[0]                   # getting the destination port from the received tcp header

        except socket.timeout:
            port_n_state[1] = "TimedOut"
            return port_n_state 
        finally:
            raw_socket.close()   

    port_n_state = [port, evaluate_flags(tcp_recv[13])]
    
    return port_n_state

def syn_scan(ports_to_be_scanned): 
    

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = executor.map(socket_dealing, ports_to_be_scanned)


    print("port     state")

    amountClosed = 0
    amountTimedOut = 0

    for result in results: 
        port_n = result[0]
        port_state = result[1]

        if port_state == "Open": 
            print(f"{port_n}  open")
        elif port_state == "Closed": 
            amountClosed += 1
        elif port_state == "TimedOut": 
            amountTimedOut += 1    

    print(f"{amountClosed} ports closed and {amountTimedOut} ports timed out")


destination_ip = input("Target's IP Address: ")
source_ip = get_source_ip(destination_ip)
global scan_quietness

scan_type = int(input("Choose the corresponding value to your interest\n1. TCP-SCAN\n2. SYN-SCAN\n3. OS-FINGERPRINT"))

if scan_type == 3:
    #todo OS fingerprint

else: 
    
    scan_quietness = int(input("How fast do you want the scan to be? \n"))
    scan_pattern = int(input("Choose the corresponding value to your interest\n1. Scan on well known ports (0-1024)\n2. Complete Scan (0-65535)\n"))

    if scan_pattern == 1: 
        ports_to_be_scanned = range(1,1025)
    elif scan_pattern == 2: 
        ports_to_be_scanned = range(1,65536)

    if scan_type == 1: 
        #todo TCP full SCAN
    else: 
        syn_scan(ports_to_be_scanned)






