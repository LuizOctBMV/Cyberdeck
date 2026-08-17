import socket
import struct
from concurrent.futures import ThreadPoolExecutor
import random 
from functools import partial
import select

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

    
def get_source_ip(destination_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((destination_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()

def evaluate_flags(protocol, flag): 

    if protocol == "tcp":
        if (flag & 0x12) == 0x12:
            return "Open"
        elif (flag & 0x04) == 0x04: 
            return "Closed"
        
    elif protocol == "icmp":
        if (flag & 0x03) == 0x03: 
            return "Closed"
        else: 
            return "Filtered"

def ip_header_remover(packet):
    '''

    this method removes the IP header from the received packet so the 
    desired header can be processed
    e.g. a TCP packet was received and it is necessary to analyze it, 
    therefore first it is important to separate the IP header from the TCP header
    
    '''
    first_byte = packet[0]           # first byte contains version and IP packet length
    ihl = first_byte & 0x0F          # takes the version out
    ip_header_size = ihl * 4 
    return packet[ip_header_size:]   #returns the desired header

def packet_validation(destination_ip, source_port, destination_port, received_packet, isTCP=False, isUDP=False, containsICMP=False): 
    
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
        if (not containsICMP): #no ICMP header
            udp_recv = ip_header_remover(received_packet)
                
        elif containsICMP: 
            icmp_recv = ip_header_remover(received_packet)      # removes the sender IP header
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

                isExpectedPacket = packet_validation(destination_ip=destination_ip, source_port=lst_syn_packet[1], destination_port=port, received_packet=received_data)
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

def snmp_port_scan(community_string, version=1, OID=[1,3,6,1,2,1,1,1,0]): 
    oid_bytes = (OID[0] * 40 + OID[1]).to_bytes(1, 'big')
    
    for i in range(2,len(OID)): 
        ##todo: check if the following values are less than <=127
        oid_bytes += OID[i].to_bytes(1, 'big')

    oid_tlv = tlv(0x06, oid_bytes)
    null_tlv = tlv(0x05, b'')
    seq_vl1_tlv = tlv(0x30, oid_tlv + null_tlv)
    error_index_tlv = tlv(0x02, bytes([0]))
    error_status_tlv = tlv(0x02, bytes([0]))
    request_id_tlv = tlv(0x02, bytes([random.randint(1,255 )]))
    get_request_tlv = tlv(0xA0, request_id_tlv + error_status_tlv + error_index_tlv + seq_vl1_tlv)
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

    src_port = random.randint(5000, 62439)  

    udp_header = create_UDP_header(source_port=src_port, destination_port=port, length=length, data=data)
    udp_pseudo_header = calculate_pseudo_header(source_ip=source_ip, destination_ip=destination_ip, protocol=17, protocol_length=length)
    udp_packet_checksum = calculate_checksum(pseudo_header=udp_pseudo_header, tcp_header=udp_header)
    udp_packet = create_UDP_header(source_port=src_port, destination_port=port, length=length, checksum=udp_packet_checksum, data=data)

    return [udp_packet, src_port]

def udp_scan(port, destination_ip, source_ip, quietness, isTargeted = False): 

    port_n_state = [port, "n/a"]

    if isTargeted:
        
        if port == 53: #DNS
            id = random.randint(0,65534)
            dns_header = struct.pack("!HHHHHH", 
                id, 
                256, 
                1, 
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
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {destination_ip}:1900\r\n"       #unicast search to the target IP
                "MAN: \"ssdp:discover\"\r\n"             
                "MX: 1\r\n"                              
                "ST: ssdp:all\r\n"                       #all services would reply
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

                udp_data = snmp_port_scan(word)
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

                if validWord: 
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

def port_scan(type_of_scan, ports_to_be_scanned, destination_ip, quietness, scan_display, source_ip, isTargeted):
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

    printing_results(type_of_scan, results, scan_display, isTargeted)
 



def printing_results(type_of_scan, results, scan_display, isTargeted=False): 

    print("port     state")
    
    amountClosed = 0
    amountTimedOut = 0
    amountFiltered = 0

    for result in results: 
        
        port_n = result[0]
        port_state = result[1]

        if type_of_scan == "tcp":   
            
            if port_state == "Open": 
                print(f"{port_n}  open")
            elif port_state == "TimedOut": 
                amountTimedOut += 1
            else:
                if scan_display == 1: 
                    amountClosed += 1
                else: 
                    print(f"{port_n}  closed")

        elif type_of_scan == "udp": 
        

            if port_state == "Open": 
                print(f"{port_n}  open")
            elif port_state == "Open | Filtered":
                print(f"{port_n}  Open | Filtered")
            elif port_state == "Filtered":
                if isTargeted and scan_display != 1:
                    print(f"{port_n}  filtered")
                amountFiltered += 1
            else:
                if scan_display == 1: 
                    amountClosed += 1
                else: 
                    print(f"{port_n}  closed")
            
            
    if scan_display == 1:
        print(f"{amountClosed} ports closed and {amountTimedOut} ports filtered")
    elif scan_display != 1 and not isTargeted: 
        print(f"{amountTimedOut} ports filtered")

def devicescanning():
    destination_ip = input("Target's IP Address: ")

    print("Type only the number indicated by the alternative")
    scan_type = int(input("Choose the corresponding value to your interest\n1. TCP-SCAN\n2. SYN-SCAN\n3. UDP-SCAN\n4. OS-FINGERPRINT\n5. Network Scanning\n "))

    if scan_type == 4:
        #todo OS fingerprinting
        print("#todo")
    elif scan_type == 5: 
        #todo Network Scanning 
        print("todo")

    else: 
        source_ip = get_source_ip(destination_ip)

        scan_quietness = int(input("How fast do you want the scan to be (scale 1-4, 4 being fast and 1 slower)?\n1. Slow\n2. Normal \n3. Fast \n4. Ultra Fast\n"))

        # timeout / number of workers
        if scan_quietness == 1:  
            quietness = [4,50]
        elif scan_quietness == 2:
            quietness = [3,100]
        elif scan_quietness == 3:
            quietness = [1.5,250]
        elif scan_quietness == 4:
            quietness = [0.75,350]

        scan_display = int(input("Display results\n1. Only opened ports \n2. Opened and closed ports\n"))
        

        if scan_type == 3:
            scan_specificity = int(input("Target Specific UDP ports or all 1024\n1. Specific Common UDP Ports  \n2. 1-1024 ports\n"))

            isTargeted = True if scan_specificity == 1 else False
            ports_to_be_scanned = [53, 67, 69, 111, 123, 137, 161, 1900] if isTargeted == True else range(1,1025)

            port_scan(type_of_scan = "udp", ports_to_be_scanned=ports_to_be_scanned, destination_ip=destination_ip, quietness=quietness, scan_display=scan_display, isTargeted=isTargeted, source_ip=source_ip)

        else:
            scan_pattern = int(input("Choose the corresponding value to your interest\n1. Scan on well known ports (1-1024)\n2. Complete Scan (0-65535)\n"))
            
            if scan_pattern == 1: 
                ports_to_be_scanned = range(1,1025)
            elif scan_pattern == 2: 
                ports_to_be_scanned = range(1,65536)

            if scan_type == 1: 
                port_scan(type_of_scan = "tcp", ports_to_be_scanned=ports_to_be_scanned, destination_ip=destination_ip, quietness=quietness, scan_display=scan_display)
            elif scan_type == 2:
                
                port_scan(type_of_scan = "syn", ports_to_be_scanned=ports_to_be_scanned, destination_ip=destination_ip, quietness=quietness, scan_display=scan_display, source_ip=source_ip)

    

devicescanning()

