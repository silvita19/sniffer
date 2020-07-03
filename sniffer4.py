import socket
import struct
import binascii

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket. htons(0x0003))

while True:

    print ('CONDORI LANZA SILVIA EUGENIA')
    print ('CI:6164141 LP')
    print ()

    
    packet = s.recvfrom(65565)

    packet = packet[0]

    #ethernet header
    eth_length = 14
    eth_header = packet[0:eth_length]
      
    eth = struct.unpack("!6s6sH",eth_header)

    destination_mac = binascii.hexlify(eth[0:5])
    source_mac = binascii.hexlify(eth[6:12])
    #eth_protocol = eth[2]
    eth_protocol = socket.ntohs(eth[2])
    
    print("\tEthernet Header")
    print ('Destination MAC : ' + eth_addr(packet[0:5]))
    print (' Source MAC : ' + eth_addr(packet[6:12]))
    print (' Protocol : ' + str(eth_protocol)) 
    print('')

  

       
    
    #print('Ethernet Destination: ' + str(destination_mac))
    #print('Ethernet source Mac : ' + str(source_mac))
    #print('Ethernet protocol : ' + str(eth_protocol))
    

   #IP HEADER
    ip_header = packet[eth_length:eth_length+20]

   
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
   
    version_ihl = iph[0]
    version = version_ihl >> 4

    ihl = version_ihl & 0xF


    iph_length = ihl * 4

    
    ip_tos = iph[1] # char
    ip_len = iph[2] # short int
    ip_id = iph[3]  # short int
    ip_off = iph[4] # short int
    #------------------
    ip_ttl = iph[5] #char
    ip_p = iph[6]   #char
    ip_sum = iph[7] #shor int

    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    print("\tIP Header")
    print('IP Version : ' + str(version) )
    print('IP Header Length (IHL) : ' , ihl, 'DWORDS or',str(ihl*32//8) ,'bytes')
    print('Type of Service (TOS): ',str(ip_tos))
    print('IP Total Length: ',ip_len, ' DWORDS ',str(ip_len*32//8) ,'bytes')
    print('Identification: ',ip_id)
    print('flags: ',ip_off)
    
    print('TTL : ' + str(ip_ttl))
    print('Protocol : ' + str(ip_p) )
    print('Chksum: ',ip_sum)
    print('Source Address IP : ' + str(s_addr) )
    print('Destination Address IP: ' + str(d_addr))
    print("")


    #tcp header
    tcp_header = packet[34:54]

    
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)



    source_port = tcph[0]   # uint16_t
    dest_port = tcph[1]     # uint16_t
    sequence = tcph[2]      # uint32_t
    acknowledgement = tcph[3]   # uint32_t
    doff_reserved = tcph[4]     # uint8_t
    tcph_length = doff_reserved >> 4

    tcph_flags = tcph[5]            #uint8_t
    tcph_window_size = tcph[6]      #uint16_t
    tcph_checksum = tcph[7]         #uint16_t
    tcph_urgent_pointer = tcph[8]   #uint16_t
    
    print("\tTCP Header")
    
    print("Source Port:",source_port)
    print("Destination Port:",dest_port)
    print("Sequence Number:",sequence)
    print("Acknowledge Number:",acknowledgement)
    print("Header Length:",tcph_length,'DWORDS or ',str(tcph_length*32//8) ,'bytes')

    print("Urgent Flag:",tcph_flags)

    print("Acknowledgement Flag:")
    print("Push Flag:")
    print("Reset Flag:")
    print("Synchronise Flag:")
    print("Finish Flag:")

    print("Window Size:",tcph_window_size)
    print("Checksum:",tcph_checksum)
    print("Urgent Pointer:",tcph_urgent_pointer)
    print("")

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    #get data from the packet
    data = packet[h_size:]

    print ('Data : ' + str(data))
    print ()


    
   
    #print ("Destination MAC:" + binascii.hexlify(eth_header[0]) + " Source MAC:" + binascii.hexlify(eth_header[1]) + " Type:" + binascii.hexlify(eth_header[2]))   
   
   