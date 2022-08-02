from scapy.all import *
from collections import Counter
from prettytable import PrettyTable

def displayAllIPs(packets):
    
    src_ip=[]
    for pkt in packets:
        if IP in pkt:
            try:
                src_ip.append(pkt[IP].src)
            except:
                pass
    cnt=Counter()

    for ip in src_ip:
        cnt[ip]+=1

    table=PrettyTable(["IP","Count"])

    for ip, count in cnt.most_common():
        table.add_row([ip,count])

    print(table)
#----------------------
def displayLocalIP(packets):
    src_ip=[]
    for pkt in packets:
        if (IP in pkt) and ("192.168" in pkt[IP].src):
            try:
                src_ip.append(pkt[IP].src)
            except:
                pass
    cnt=Counter()

    for ip in src_ip:
        cnt[ip]+=1

    table=PrettyTable(["IP","Count"])

    for ip, count in cnt.most_common():
        table.add_row([ip,count])

    print(table)
#-----------------------
def network_conversation(packet):
    try:
        protocol=packet.transport_layer
        source_address=packet.ip.src
        source_port=packet[packet.transport_layer].srcport
        destination_address=packet.ip.dst
        destination_port=packet[packet.transport_layer].dstport
        return (f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}')
    except AttributeError as e:
        pass
#--------------------------    
def alldata():
    import pyshark
    capture=pyshark.FileCapture('TCPCaptureFile.pcap')
    chat=[]
    for packet in capture:
        result=network_conversation(packet)
        if result!=None:
            chat.append(result)
    return chat
        
        

def __main__():
    print("man in the middle attack prevent and detection using pre distributed key")
    packets=rdpcap('TCPCaptureFile.pcap')
    print("1: Display All IPs")
    print("2: Display Local IPs")
    print("3: All source to destination")
    choice=int(input("Enter: "))
    if choice==1:
        displayAllIPs(packets)
    if choice==2:
        displayLocalIP(packets)
    if choice==3:
        chats=[]
        chats=alldata()
        table=PrettyTable(["SRC","DST"])
        for i in chats:
            temp=(i.split("-->"))
            table.add_row([temp[0],temp[1]])
        print(table)
        
        
__main__()