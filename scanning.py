import socket
import struct
from concurrent.futures import ThreadPoolExecutor
import random 
from functools import partial
import select
import xml.etree.ElementTree as ET
import urllib.request
import csv

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
        protocol,               #2 bytes
        protocol_length,        #1 byte
        reserved=0,             #1 byte
        ):

    src_ip = socket.inet_aton(source_ip)
    dst_ip = socket.inet_aton(destination_ip)

    return struct.pack("!4s4sBBH", src_ip, dst_ip, reserved, protocol, protocol_length)

def calculate_checksum(
        pseudo_header=b'',
        tcp_header=b'',
        tcp_payload=b'',
        ip_header=b'',
        udp_header=b''
        ): 
    
    total_value = pseudo_header + tcp_header + tcp_payload + ip_header + udp_header     #b'\x00\x00\x00...'

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

    
def get_source_ip(destination_ip="8.8.8.8"): #using Google DNS to get the source IP address of the machine
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((destination_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()

def evaluate_flags(protocol, flag): 

    if protocol == "tcp":
        if (flag & 0x12) == 0x12:       #syn+ack flag
            return "Open"
        elif (flag & 0x04) == 0x04:     #rst flag
            return "Closed"
        
    elif protocol == "icmp":
        if (flag & 0x03) == 0x03:   #destination unreachable
            return "Closed"
        else: 
            return "Filtered"

def ip_header_remover(packet):

    '''
    this method removes the IP header from the received packet so the 
    desired header can be processed
    '''

    first_byte = packet[0]           # first byte contains version and IP packet length
    ihl = first_byte & 0x0F          # takes the version out
    ip_header_size = ihl * 4 
    return packet[ip_header_size:]   #returns the desired header

def packet_validation(received_packet,destination_ip=0, source_port=0, destination_port=0, isTCP=False, isUDP=False, containsICMP=False): 
    
    '''
    method to check if the received packet is the expected response packet, since the 
    socket collects all the packets from the defined protocol
    It checks known values, if the destination port is the same as the source port on the response packet and vice versa,
    and the ip address

    '''
    sender_src_ip = ""                      #the analyzed packet must have the same source ip as the destination one from the first packet, so the packet received is indeed the one expected
    sender_src_port = 0
    sender_destination_port = 0

    if isUDP:
        if (not containsICMP): 
            udp_recv = ip_header_remover(received_packet)
                
        elif containsICMP: 
            icmp_recv = ip_header_remover(received_packet)      
            udp_recv = ip_header_remover(icmp_recv[8:])         # removes everything except the original UDP header


        sender_src_ip = socket.inet_ntoa(received_packet[12:16])            # getting the source ip from the received ip header
        sender_src_port = struct.unpack("!H", udp_recv[0:2])[0]             # getting the source port from the received udp header
        sender_destination_port = struct.unpack("!H", udp_recv[2:4])[0]     # getting the destination port from the received udp header
                           
    if isTCP: 

        tcp_recv = ip_header_remover(received_packet)   

        sender_src_ip = socket.inet_ntoa(received_packet[12:16])                        
        sender_src_port = struct.unpack("!H", tcp_recv[0:2])[0]                         # getting the source port from the received tcp header
        sender_destination_port = struct.unpack("!H", tcp_recv[2:4])[0]                 # getting the destination port from the received tcp header

    if (sender_src_ip == destination_ip) and (sender_src_port == destination_port) and (sender_destination_port == source_port):
        return True
    return False

def create_SYN_packet(port, destination_ip, source_ip): 

    '''
    random values for sequence, window and source port
    so it is not as suspect as having all values the same 
    '''
    seq_number = random.randint(1, 4294967295)  
    window_size = random.randint(62727, 65534)  
    src_port = random.randint(5000, 62439)      


    tcp_header = create_TCP_header(source_port=src_port, destination_port=port, sequence_number=seq_number, window_size=window_size)
    syn_pseudo_header = calculate_pseudo_header(source_ip=source_ip, destination_ip=destination_ip, protocol=6, protocol_length=20)
    syn_packet_checksum = calculate_checksum(pseudo_header=syn_pseudo_header, tcp_header=tcp_header)
    syn_packet = create_TCP_header(source_port=src_port, destination_port=port, sequence_number=seq_number, checksum=syn_packet_checksum, window_size=window_size)

    """ 
    Methods used to create the IP header that would be necessary in a Windows OS
    ip_header = create_IP_header(source_ip=src_ip, destination_ip=dst_ip)
    ip_header_checksum = calculate_checksum(ip_header=ip_header)
    ip_header = create_IP_header(source_ip=src_ip, destination_ip=dst_ip, checksum=ip_header_checksum)
    """

    final_packet = syn_packet   # + ip_header

    return [final_packet,src_port]

def syn_scan(port, destination_ip, source_ip, quietness): 

    '''
    this method creates a SYN packet from scratch and sends it to the specified destination_ip and port;
    after waiting for the response, it can be a timeout, which means the port is filtered, 
    or a SYN+ACK packet, which means the port is open, or a RST packet, which means the port is closed
    '''

    port_n_state = [port, "n/a"]

    lst_syn_packet = create_SYN_packet(port, destination_ip, source_ip)

    raw_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw_tcp_socket.settimeout(quietness[0])
    

    try: 
        raw_tcp_socket.sendto(lst_syn_packet[0], (destination_ip, port))
        while True:
            try: 
                
                received_data = raw_tcp_socket.recv(65535)
                tcp_recv = ip_header_remover(received_data)

                isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=lst_syn_packet[1], destination_port=port, received_packet=received_data, isTCP=True)
                if isExpectedPacket:
                    break

            except socket.timeout:
                port_n_state[1] = "TimedOut"
                return port_n_state 
    finally:
        raw_tcp_socket.close()   

    port_n_state = [port, evaluate_flags(protocol="tcp", flag=tcp_recv[13])]
    
    return port_n_state

def tcp_scan(port, destination_ip, quietness): 

    '''
    this method attempts a TCP connection using a TCP socket
    if the connection is established, the port is open, if it is refused, the port is closed
    '''

    port_n_state = [port, "n/a"]

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(quietness[0])

    try: 
        tcp_socket.connect((destination_ip, port))
        port_n_state[1] = "Open"

    except ConnectionRefusedError:
        port_n_state[1] = "Closed"
        
    except socket.timeout:
        port_n_state[1] = "TimedOut"

    finally: 
        tcp_socket.close()

    return port_n_state

def tlv(type, value):
    return  bytes([type]) + bytes([len(value)]) + value

def read_tlv(tlv): 
    length = tlv[1]
    return [tlv[0], tlv[2: 2 + length], tlv[2+length:]] # kind, value of that kind and left tlv


def oid_bytes_creator(OID): 
    oid_bytes = (OID[0] * 40 + OID[1]).to_bytes(1, 'big')

    for i in range(2,len(OID)): 
        ##todo: check if the following values are less than <=127
        oid_bytes += OID[i].to_bytes(1, 'big')

    return oid_bytes

def snmp_data(community_string, version=1, OID=[[1,3,6,1,2,1,1,1,0]]): 

    """ 
    this methods creates the SNMP data (which is the payload of the UDP packet)
    the data must be encapsulated in a TLV format (Type-Length-Value) 
    """

    binding_total_vlv = 0

    if len(OID) == 1: 
        oid_bytes = oid_bytes_creator(OID)
        oid_tlv = tlv(0x06, oid_bytes)
        null_tlv = tlv(0x05, b'')
        binding_total_vlv = oid_tlv + null_tlv

    else: 
        for j in len(OID): 
            # OIDs are encapsulated on the same sequence box, therefore they need to be calculated together
            oid_bytes = oid_bytes_creator(OID)

            oid_tlv = tlv(0x06, oid_bytes)
            null_tlv = tlv(0x05, b'')
            binding_total_vlv += oid_tlv + null_tlv
    
    varbinds_tlv = tlv(0x30, binding_total_vlv)
    error_index_tlv = tlv(0x02, bytes([0]))
    error_status_tlv = tlv(0x02, bytes([0]))
    request_id_tlv = tlv(0x02, bytes([random.randint(1,255 )]))
    get_request_tlv = tlv(0xA0, request_id_tlv + error_status_tlv + error_index_tlv + varbinds_tlv)
    octet_string = tlv(0x04, community_string.encode('utf-8'))
    version_tlv = tlv(0x02, bytes([version]))

    return tlv(0x30, version_tlv + octet_string + get_request_tlv)
          
def create_UDP_header(
        source_port,
        destination_port,
        length=8,
        checksum=0, 
        data=b''):

    return struct.pack("!HHHH", source_port, destination_port, length, checksum) + data
    
def create_UDP_packet(port, destination_ip, source_ip, length, data=b''): 

    src_port = random.randint(5000, 62439)  #random port so it is not the same for every packet, which would be suspicious

    udp_header = create_UDP_header(source_port=src_port, destination_port=port, length=length, data=data)
    udp_pseudo_header = calculate_pseudo_header(source_ip=source_ip, destination_ip=destination_ip, protocol=17, protocol_length=length)
    udp_packet_checksum = calculate_checksum(pseudo_header=udp_pseudo_header, tcp_header=udp_header)
    udp_packet = create_UDP_header(source_port=src_port, destination_port=port, length=length, checksum=udp_packet_checksum, data=data)

    return [udp_packet, src_port]

def udp_scan(port, destination_ip, source_ip, quietness=[5,], isTargeted = False, osFingerprinting = False): 

    '''
    creates a UDP packet from scratch and sends to the specified destination_ip
    if it is a targeted scan, it will send to specific ports only, since UDP is highly reactive
    to the payload sent with the header. The payload would be specific to the popular service that runs behind that port
    the non targeted scan will send a general and non specific header to every port
    '''

    port_n_state = [port, "n/a"]

    if isTargeted:
        
        if port == 53: #DNS
            id = random.randint(0,65534)
            dns_header = struct.pack("!HHHHHH", 
                id,     # ID
                256,    #
                1,      #
                0, 
                0, 
                0
            )                    
            dns_message = struct.pack("!B6sB3sBHH", 
                6,          #length
                b'google',  # QNAME "google.com"
                3, 
                b'com',     
                0,          #0
                1,          #QTYPE(A=1)
                1)          #QCLASS(IN=1
            udp_data = dns_header + dns_message

        elif port == 67: #DHCP
            xid = random.randint(0,65534)
            src_ip = socket.inet_aton(source_ip)
            fake_mac = random.randbytes(6)
            mac_padded = fake_mac + bytes(10)

            dhcp_fields = struct.pack("!BBBBLHH4sLLL", 
                1,      # opcode = BOOTREQUEST
                1,      # hardware type = 1 for ethernet
                6,      # hlen = mac address length
                0,      # hops = 0
                xid,    # transactionID
                0,      # seconds since the process began
                0,      # flags = 0
                src_ip, # ciaddr
                0,      # yiaddr = 0
                0,      # server ip = 0
                0,      # gateway ip = 0
            )
            dhcp_fields += mac_padded   #fake chaddr
            dhcp_fields += bytes(64)    #sname
            dhcp_fields += bytes(128)   #file

            dhcp_options = struct.pack("!BBBB", 99, 130, 83, 99) #delimiter for options
            dhcp_options += bytes([53, 1, 8])   # DHCP message type = DHCPINFORM
            dhcp_options += bytes([0xFF])       #end of message

            udp_data = dhcp_fields + dhcp_options

        elif port == 69: #TFTP
            udp_data = (
                (1).to_bytes(2, byteorder='big')    #OPCODE = Read (1)
                + "tst.txt".encode()                #Filename
                + (0).to_bytes(1, byteorder='big')  #0
                + "netascii".encode()               #Mode = netascii
                + (0).to_bytes(1, byteorder='big')  #0
                )

        elif port == 111: #portmapper

            xid = random.randint(0, 0xFFFFFFFF)
            rpc_header = struct.pack("!IIIIII", 
                xid,        # ID
                0,          # message type = CALL
                2,          # RPC version = 2
                100000,     # program = Portmapper
                2,          # program version = 2
                0,          # procedure = NULL
            )
            rpc_authentication = struct.pack("!IIII",
                0,          # cred flavor = AUTH_NULL
                0,          # cred length = 0
                0,          # verifier flavor = AUTH_NULL
                0           # verifier length = 0
            )
            udp_data = rpc_header + rpc_authentication
            
        elif port == 123: #NTP

            first_byte = ((0 << 2 | 3) << 3) | 3                    # leap indicator=0 (2 bits) + version=3 (3 bits) + mode=3 (3 bits)
            udp_data = struct.pack("!B", first_byte) + bytes(47)    # bytes(47) creates a string of 47 bytes with value 0 

        elif port == 137: #NetBios
            transaction_id = random.randint(0, 65535)
            
            netbios_header = struct.pack("!HHHHHH", transaction_id, 0, 1, 0, 0, 0)
            netbios_question = bytes([0x20]) + "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".encode() + bytes([0x00]) + struct.pack("!HH", 0x0021, 0x0001) #len byte + compressed requisition for everything (*) + type and class
            udp_data = netbios_header + netbios_question

        elif port == 1900: #SSDP
            message = (
                "M-SEARCH * HTTP/1.1\r\n"                # type of message = M-Search  
                f"HOST: {destination_ip}:1900\r\n"       # unicast search to the target IP
                "MAN: \"ssdp:discover\"\r\n"             # type of search
                "MX: 1\r\n"                              # time to wait to reply 
                "ST: ssdp:all\r\n"                       #service targeted = all
                "\r\n" 
            ) 
            udp_data = message.encode()


        lst_udp_packet = create_UDP_packet(port, destination_ip, source_ip, data=udp_data, length = 8 + len(udp_data))

    elif port == 161 and isTargeted: #SNMP 
        
        wordlist = ["public", "private"] #todo > find a wordlist.txt to use instead of an array
        validWord = False

        try: 
            raw_icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            raw_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

            for word in wordlist: 

                if osFingerprinting: 
                    sentOID = [1,3,6,1,2,1,1,1,0], [1,3,6,1,2,1,1,2,0]
                    udp_data = snmp_data(word, OID=[sentOID])
                else: 
                    udp_data = snmp_data(word)
                    
                lst_udp_packet_snmp = create_UDP_packet(port, destination_ip, source_ip, data=udp_data, length = 8 + len(udp_data))
                raw_udp_socket.sendto(lst_udp_packet_snmp[0], (destination_ip, port))

                while True:
                    returned, _, _ = select.select([raw_udp_socket, raw_icmp_socket], [], [], quietness[0])

                    if raw_udp_socket in returned:
                        received_data = raw_udp_socket.recv(65535)
                        isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=lst_udp_packet_snmp[1], destination_port=port, received_packet=received_data, isUDP = True)

                        if isExpectedPacket: 
                            validWord = True
                            break # Open, because UDP would only be sent if the port is open

                    elif raw_icmp_socket in returned: 

                        received_data = raw_icmp_socket.recv(65535)
                        
                        icmp_recv = ip_header_remover(received_data) 

                        if icmp_recv[0] == 0x03:            #checking if the icmp type is destination unreacheable (type 3), which is the desired type for this case
                            isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=lst_udp_packet_snmp[1], destination_port=port,
                                                                  received_packet=received_data, isUDP = True, containsICMP= True) #only error ICMP contains UDP, therefore is checked after
                            if isExpectedPacket: 
                                port_n_state[1] = evaluate_flags(protocol="icmp", flag=icmp_recv[1])
                                if port_n_state[1] == "Closed":
                                    break
                            else: 
                                continue
                        else: 
                            continue

                    else: 
                        break #next word

                if validWord and osFingerprinting: 
                   snmp_findings = process_snmp_reply(received_packet=received_data)   
                   return snmp_findings   
                elif validWord: 
                    port_n_state[1] = "Open"
                    return port_n_state
                elif port_n_state[1] == "Closed":
                    return port_n_state
                            
            if not validWord:
                port_n_state[1] = "Open | Filtered" #can be filtered because the community string may fail the authentication process
                return port_n_state

        finally:
            raw_udp_socket.close()
            raw_icmp_socket.close()

    else: 
        lst_udp_packet = create_UDP_packet(port, destination_ip, source_ip, length = 8)

    raw_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)     #socket to send and receive UDP packets
    raw_icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)       #socket to receive  ICMP packets

    try:
        raw_udp_socket.sendto(lst_udp_packet[0], (destination_ip, port))

        while True:

            returned, _, _ = select.select([raw_udp_socket, raw_icmp_socket], [], [], quietness[0])

            if raw_udp_socket in returned:
                received_data = raw_udp_socket.recv(65535)
                isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=lst_udp_packet[1], received_packet=received_data, isUDP = True)

                if isExpectedPacket:
                    port_n_state[1] = "Open"
                    break
                    

            elif raw_icmp_socket in returned: 
                
                received_data = raw_icmp_socket.recv(65535)     #received data: Sender IP HEADER + ICMP HEADER + OUR IP HEADER + OUR UDP HEADER
                icmp_recv = ip_header_remover(received_data)    

                if icmp_recv[0] == 0x03:            #checking if the icmp type is destination unreacheable (type 3), which is the desired type for this case
                    port_n_state[1] = evaluate_flags(protocol="icmp", flag=icmp_recv[1])
                else: 
                    continue

                isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=lst_udp_packet[1], received_packet=received_data, isUDP = True, containsICMP= True)
                if isExpectedPacket: 
                    break
                
            else:
                port_n_state[1] = "Open | Filtered"
    finally: 
        raw_udp_socket.close()
        raw_icmp_socket.close()

    return port_n_state

def port_scan(type_of_scan, ports_to_be_scanned, destination_ip, quietness, showClosed, source_ip = 0, isTargeted=False):
    '''
    acts as both a router and activation of a specific scan function
    '''

    # partial functions allows the IP address and other parameters to be included on the threading process  
    syn_partial = partial(syn_scan, destination_ip=destination_ip, source_ip=source_ip, quietness=quietness) 
    tcp_partial = partial(tcp_scan, destination_ip=destination_ip, quietness=quietness)
    udp_partial = partial(udp_scan, destination_ip=destination_ip, source_ip=source_ip, quietness=quietness, isTargeted=isTargeted)

    if type_of_scan == "syn":
        desired_function = syn_partial
    elif type_of_scan == "tcp":
        desired_function = tcp_partial
    elif type_of_scan == "udp":
        desired_function = udp_partial

    with ThreadPoolExecutor(max_workers=quietness[1]) as executor:
            results = executor.map(desired_function, ports_to_be_scanned)

    printing_results(type_of_scan, results, isTargeted, showClosed)
 

def printing_results(type_of_scan, results, isTargeted=False, showClosed=False): 

    print(f"{'port':<8}      {'state'}")
    
    amountTimedOut = 0
    amountClosed = 0

    for result in results: 
        
        port_n = result[0]
        port_state = result[1]

        if type_of_scan == "tcp" or type_of_scan == "syn":   
            
            if port_state == "Open": 
                print(f"{port_n}|{type_of_scan}  open")
            elif port_state == "TimedOut": 
                amountTimedOut += 1
            else:
                if showClosed:
                    print(f"{port_n}|{type_of_scan}  closed")
                else: 
                    amountClosed += 1

        elif type_of_scan == "udp": 
        
            if port_state == "Open": 
                print(f"{port_n}|{type_of_scan}  open")
            elif port_state == "Open | Filtered":
                print(f"{port_n}|{type_of_scan}  Open | Filtered")
            elif port_state == "Filtered":
                if isTargeted:
                    print(f"{port_n}|{type_of_scan}  filtered")
                amountTimedOut += 1
            else:
                if showClosed:
                    print(f"{port_n}|{type_of_scan}  closed")
                else: 
                    amountClosed += 1

    if showClosed:    
        print(f"\n{amountClosed} ports closed and {amountTimedOut} ports filtered")
    else: 
        print(f"\n{amountTimedOut} ports filtered")

def os_syn_scan(destination_ip, source_ip): 

    raw_tcp_socket_os = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw_tcp_socket_os.settimeout(5)
    portNotFiltered = False         # if an open or closed port was found

    for port in range(1,65536): 

        if portNotFiltered: #stops as soon as an open or closed port is found
            break

        syn_packet = create_SYN_packet(port, destination_ip, source_ip)
        
        
        raw_tcp_socket_os.sendto(syn_packet[0], (destination_ip, port))
        while True:
            try:     
                received_data = raw_tcp_socket_os.recv(65535)
                tcp_recv = ip_header_remover(received_data)

                isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=syn_packet[1], destination_port=port, received_packet=received_data, isTCP=True)
                if isExpectedPacket:
                    portNotFiltered = True
                    break

            except socket.timeout:
                continue

    raw_tcp_socket_os.close()    

    if portNotFiltered: 

        #IP Header info
        # packet_size = struct.unpack("!H", received_data[2:4])[0]
        ttl = received_data[8]

        '''
        containsDF = False # Don't Fragment Flag   
        if ((struct.unpack("!B", received_data[6:8])[0] >> 14) & 0x01) == 1: #shifting to remove the fragment offset, mf and null bit 
            containsDF = True
        '''

        #TCP Header info 
        window_size = struct.unpack("!H", tcp_recv[14:16])[0]

        #TCP Options info
        containsOptions = True if (tcp_recv[12] >> 4) > 5 else False    #if the value of the DataOffset is more than 5, there are options

        options_order = [] 
        windowScale_value = 0

        if containsOptions:
            # option format is [kind][length][value]

            # containsNOP = False
            # containsSACK = False
            # containsMSS = False
            containsWindScale = False
            

            kindIndex = 20
            while tcp_recv[kindIndex] != 0: #check if kind is of type 0 (END)
                
                kind = tcp_recv[kindIndex]

                options_order.append(kind)   #adds the kind to a list of the order of the kinds that appear for future analysis

                if kind == 1:       # Checking for No-Operation (NOP) option
                    # containsNOP = True
                    kindIndex += 1  # NOP does not contain length or a value, therefore it is necessary to skip to the next byte
                    continue 

                optionLength = struct.unpack("!B", tcp_recv[kindIndex + 1])[0] 
         
                if kind != 4: #sackOK does not contain a value, only kind and length
                    if kind == 2:   #MSS has 2 bytes of value
                        optionValue = struct.unpack("!H", tcp_recv[kindIndex + 2 : kindIndex + optionLength])[0] 
                    else: 
                        optionValue = struct.unpack("!B", tcp_recv[kindIndex + 2 : kindIndex + optionLength])[0] 

                '''
                if kind == 2:       #MSS
                    containsMSS = True
                    MSS_value = optionValue

                elif kind == 4:     #SACK-Permitted (sackOK)
                    # containsSACK = True
                '''

                if kind == 3:     #window scale
                    containsWindScale = True
                    windowScale_value = optionValue

                kindIndex += optionLength # next kind index is at the next byte after the end of the option that came before

        if containsOptions: 
                syn_scan_result = os_fingerprint_evaluator(ttl, window_size, windowScale_value, options_order)
        else: 
            syn_scan_result = os_fingerprint_evaluator(ttl, window_size, windowScale_value, options_order, containsOptions = False)

        return syn_scan_result

    return "Indeterminate"

def os_fingerprint_evaluator(timeToLive, windowSize, windowScaleValue, optionsOrder, containsOptions=True):

    linuxMachine = 0
    windowsMachine = 0

    denominator = 2

    if timeToLive <= 64: 
        linuxMachine += 1
    elif timeToLive <= 128:
        windowsMachine += 1

    if windowSize == 29200 or windowSize == 64240:
        linuxMachine += 1
    elif windowSize == 65535 or windowSize == 8192: 
        windowsMachine += 1

    if containsOptions: 

        denominator = 4

        if windowScaleValue == 7: 
            linuxMachine += 1
        elif windowScaleValue == 8:
            windowsMachine += 1 

        if optionsOrder ==  [2, 4, 8, 1, 3]:         #mss,sok,ts,nop,ws
            linuxMachine += 1
        elif optionsOrder == [2, 1, 3, 1, 1, 4]:    #mss,nop,ws,nop,nop,sok
            windowsMachine += 1 

    #calculating probability
    chance = 0.0

    if linuxMachine > windowsMachine: 
        chance = linuxMachine/denominator
        operational_system = "Linux"

    elif windowsMachine > linuxMachine: 
        chance = windowsMachine/denominator
        operational_system = "Windows"

    if chance >= 0.75: 
        return operational_system
    else: 
        return "Indeterminate"


def process_snmp_reply(received_packet, sent_OIDs): 

    results = []
    containers = []
    kinds = []
    values = []

    udp_data = ip_header_remover(received_packet)[8:]
    intl_sequence = read_tlv(udp_data)  #unwraps the first sequence container
    results.append(intl_sequence[0])
    results.append(intl_sequence[1])
    left_tlv = intl_sequence[1]         #contains version, community str and pdu

    
    while True: 

        item = read_tlv(left_tlv)
        kinds.append(item[0]) 
        values.append(item[1]) 
        left_tlv = item[2]

        if item[0] == 0x30 or item[0] == 0xA2:  
            containers.append(item[1])

        if left_tlv == b'' and containers:
            left_tlv = containers.pop(0)
        elif left_tlv == b'': 
            break

    findings = []

    for i in range(len(kinds) - 1):
        if kinds[i] == 0x06: 
            finding = values[i + 1]
            if kinds[i+1] == 0x04:  
                findings.append(finding.decode("utf-8")) 
            else: 
                received_oid = finding
                identificador = received_oid[5:]    #1.3.6.1.4.1.identificador with identificador meaning all the digits comming after the base OID

                id_num = 0
                j = 0
                while True: 
                    temp_var = identificador[j]
                    if (temp_var >> 7) & 1 == 1:        # if first bit is 1, means there is another byte right after
                        id_num = (id_num << 7) | (temp_var & 0x7F)  #move the last 7 valid bits and add the new found ones
                    else:                               # first bit is 0, meaning it is the last byte that should be added to the ID
                        id_num = (id_num << 7) | (temp_var & 0x7F)
                        break   # break because there is no more left
                    j += 1

                os = "Indeterminate"
                if id_num == 311: 
                    os = "Microsoft"
                elif id_num == 8072: 
                    os = "Linux"

                findings.append("OS: " + os) 

    if not findings: 
        return "Indeterminate"
    
    return findings


def os_finterprinting(destination_ip, source_ip ): 

    syn_scan_evaluation = os_syn_scan(destination_ip, source_ip) 
    snmp_request_evaluation = udp_scan(destination_ip, source_ip, osFingerprinting=True)

    print("\nSYN Scan OS Finding:" + syn_scan_evaluation)
    print("\nSNMP OS Finding: ")
    if snmp_request_evaluation == "Indeterminate": 
        print("Indeterminate")
    else: 
        print("\n System Description: " + snmp_request_evaluation[0])
        print("\n System Object: " + snmp_request_evaluation[1])

def xml_parser(xml_data, xml_type):
        
    results = []
    
    if xml_type == "ssdp":
        root = ET.fromstring(xml_data)

        device = root.find("{*}device")
        try: 
            results.append(device.find('{*}deviceType').text)
        except:
            results.append("N/A")

        try: 
            results.append(device.find('{*}friendlyName').text)
        except:
                    results.append("N/A")

        try:
            results.append(device.find('{*}manufacturer').text)
        except:
                    results.append("N/A")

        try:
            results.append(device.find('{*}modelName').text)
        except:
                    results.append("N/A")

    return results

def ssdp_scan(source_ip): 

    port = 1900
    destination_ip = "239.255.255.250" 

    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: 239.255.255.250:1900\r\n"           #multicast channel
        "MAN: \"ssdp:discover\"\r\n"             
        "MX: 1\r\n"                              
        "ST: ssdp:all\r\n"                          #all services would reply
        "\r\n" 
    ) 
    udp_data = message.encode()

    ssdp_packet_lst = create_UDP_packet(port=port, destination_ip=destination_ip, source_ip=source_ip, length=8+len(udp_data), data=udp_data)

    raw_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    raw_udp_socket.settimeout(5)

    ssdp_replies = []

    try: 

        raw_udp_socket.sendto(ssdp_packet_lst[0], (destination_ip, port))
        while True:
            try: 
            
                received_data = raw_udp_socket.recv(65535)
                udp_data = ip_header_remover(received_data)[8:]
                ssdp_replies.append(udp_data) 


            except socket.timeout:  #if it times out that means there is no more devices on the network 
                break
    finally:
        raw_udp_socket.close()   

    results = []

    for reply in ssdp_replies: 
        ssdp_response = reply.decode("utf-8",errors="replace")

        location_index = ssdp_response.lower().find("location:")  
        if location_index == -1: 
            continue #there is no location on this xml

        end_of_line = ssdp_response.find("\r\n", location_index)
        location_line = ssdp_response[location_index:end_of_line]   #location: http...    
        url = location_line.split(":", 1)[1].strip()                #starts at http...

        try:
            with urllib.request.urlopen(url) as raw_xml:
                xml_data = raw_xml.read().decode()
        except Exception:
            continue

        xml_data = xml_parser(xml_data, "ssdp") 
        if xml_data in results: #if that device's response was already accounted for, it will not be added again
            continue
        else:
            results.append(xml_data)

    print()
    if not results: 
        print("No devices found on the network")
    else: 
        print("SSDP Results: \n")
        for i in range(len(results)):
            lines = [
                f"Device: {results[i][1]}",
                f"Device Type: {results[i][0]}",
                f"Manufacturer: {results[i][2]}",
                f"Model Name: {results[i][3]}",
            ]
            width = max(len(line) for line in lines)
            for line in lines:
                print(f"| {line:<{width}} |")
            print()

def create_arp_packet(mac_address, source_ip, target_ip):

    '''
    creates an ARP packet from scratch encapsulating it in an Ethernet frame
    '''

    eth_header = struct.pack("!6s6sH", b'\xff\xff\xff\xff\xff\xff', mac_address, 0x0806) #broadcast + mac address + ARP type
    arp_header = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac_address, socket.inet_aton(source_ip), bytes(6), socket.inet_aton(target_ip)) #ARP header

    return eth_header + arp_header

def arp_packet_sending(network, host, source_ip, data_link_socket):

    mac_address = data_link_socket.getsockname()[4]

    complete_ip_address = network + str(host)

    arp_packet = create_arp_packet(mac_address, source_ip, target_ip=complete_ip_address)
    data_link_socket.send(arp_packet)

def mac_dictionary_loader(): 

    mac_dict = {}

    with open("./mac-vendors-export.csv", newline="") as f:
        reader = csv.reader(f)
        next(reader)          

        for line in reader:
            vendor_mac_code = line[0].replace(":", "")
            mac_dict[vendor_mac_code] = line[1]

    return mac_dict

def compare_mac_addresses(mac_address, dictionary): #https://maclookup.app/

    return dictionary.get(mac_address[0:3].hex().upper(), "Unknown Vendor")

def arp_scan(source_ip, mac_vendor_dictionary):

    network_ip_arr = source_ip.split('.')
    network_ip = network_ip_arr[0] + '.' + network_ip_arr[1] + '.' + network_ip_arr[2] + '.'
    host = range(1, 255)

    try: 
        data_link_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        data_link_socket.settimeout(5)
        data_link_socket.bind(("eth0", 0))    # vincula o socket à interface eth0
        
        for host in range(1, 255):
            arp_packet_sending(network_ip, host, source_ip, data_link_socket)

        data_found = []

        while True:
        
            try: 

                received_data = data_link_socket.recv(65535)
                if received_data[12:14] == b'\x08\x06' and received_data[20:22] == b'\x00\x02':  #checking if the packet is  ARP and a reply
                    data_found.append([received_data[6:12], received_data[28:32]])    # mac address and IP address from the host that replied
                else:
                    continue

            except socket.timeout:  
                break

    finally: 
        data_link_socket.close()

    if data_found != []: 
        print("ARP Results: \n")
        print(f"{'MAC Address':<20}{'IP Address':<18}{'Vendor'}")

        found_ips = []

        for data in data_found:

            if data is None:
                continue

            found_mac_address = data[0]
            found_ip_address = socket.inet_ntoa(data[1]) 

            if found_ip_address in found_ips: #ignore in case there are multiple replies from the same host
                continue
            found_ips.append(found_ip_address)

            octets = []

            for byte in found_mac_address:
                octets.append(f"{byte:02X}")      
            mac_target_str = ":".join(octets)   

            mac_vendor = compare_mac_addresses(found_mac_address, mac_vendor_dictionary)
            print(f"{mac_target_str:<20}{found_ip_address:<18}{mac_vendor}")
    else: 
        print("No device was found through ARP scan")

def scanmenu(): 

    print("For the following questions: type only the number indicated by the alternative.\n")

    scan_number = int(input("Choose the corresponding value to your interest\n1. TCP-SCAN\n2. SYN-SCAN\n3. UDP-SCAN\n4. OS-FINGERPRINT\n5. Network Scanning\n"))

    scan_dictionary = {1:"tcp", 2:"syn", 3:"udp", 4:"os", 5:"net"}

    try: 
        scan_type = scan_dictionary[scan_number] 
    except: 
        raise ValueError("Invalid Scan Number")
    
    destination_ip = 0 #since net scan does not need an ip address or values below
    scan_quietness = 0
    udp_specificity = False
    targeted_ports = 0
    showClosed = 0

    if scan_type != "net": 

        destination_ip = input("Target's IP Address: ")

        if scan_type != "os": 

            scan_quietness = int(input("How fast do you want the scan to be (scale 1-4, 4 being fast and 1 slower)?\n1. Slow\n2. Normal \n3. Fast \n4. Ultra Fast\n"))
            showClosed = bool(input("Show closed ports (can pollute the output)?\n0. No\n1. Yes \n"))
                              
            if scan_type == "udp": 

                udp_specificity = int(input("Which ports to target? \n1. Specific Common UDP Ports  \n2. 1-1024 ports (less reliable)\n"))

            else: 

                targeted_ports = int(input("Which ports to target? \n1. Scan on well known ports (1-1024)\n2. Complete Scan (0-65535)\n")) 


    parsing_scanoptions(scan_type, destination_ip, scan_quietness, udp_specificity, targeted_ports, showClosed)
    
def parsing_scanoptions(scan_type, destination_ip=0, scan_quietness=0, udp_specificity = False, targeted_ports = 0, showClosed=False): 

    
    source_ip = get_source_ip() 

    if scan_type == "os": 

        os_finterprinting(destination_ip, source_ip)

    elif scan_type == "net": 

        ssdp_scan(source_ip)
        print()
        arp_scan(source_ip, mac_dictionary_loader())

    else: 

        quietness_dictionary = {1:[4,50], 2:[3,100], 3:[1.5,250], 4:[0.75,350]}
        quietness_vl = quietness_dictionary[scan_quietness]

        if udp_specificity: 
            port_range = [53, 67, 69, 111, 123, 137, 161, 1900]

        else:
            ports_dictionary = {1: range(1,1025), 2: range(1,65536), 1024: range(1,1025), 65535: range(1,65536)} 
            port_range = ports_dictionary[targeted_ports]

        port_scan(type_of_scan = scan_type , ports_to_be_scanned=port_range, destination_ip=destination_ip, quietness=quietness_vl, source_ip=source_ip, isTargeted= udp_specificity, showClosed=showClosed)
  


    

    
