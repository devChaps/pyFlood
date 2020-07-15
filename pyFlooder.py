import os
import socket
import string
import time
from scapy.all import *
from scapy.all import RandShort, RandIP
from scapy.layers.inet import ICMP,Ether,TCP,UDP,ICMP,IP
import sys
 
print('Enter server name: ')
ServerName = input()
 
ipbase = "192.168.0."
synpacket = ""
 
ServerAddress = socket.gethostbyname(ServerName)
Serverfqdn = socket.getfqdn(ServerName)
 
port_result = 0
 
 
print('Address for ' + ServerName + " is: " + ServerAddress + "\n")
print('FQDN: ' + Serverfqdn)
 
 
socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 
 
def tcpSend(ServerAddress, port):
    newPort = RandShort()
    for i in range(0,99):
        pkt = sr1(IP(dst = ServerAddress)/TCP(sport = newPort, dport = port, flags = "S"))
     
   
   
   
     
 
 
def pingsweep():
    for i in range(0,255):
        result = os.system('ping -n 1 ' + ipbase + str(i) + '| find "TTL"')
        print(result)
        return
       
       
       
def vanillaScan(ServerAddress):
    for i in range(0, 65535):
        result = socket_obj.connect_ex((ServerAddress, i))
        if result == 0:
            print('Port ' + str(i) + " Is Open")
        else:
            print('Port ' + str(i) + " Is Closed")
       
               
       
 
 
print('----------------- SCAN TYPE -----------------\n')
print('1) Ping Sweep\n')
print('2) Vanilla Scan\n')
print('3) TCP Payload\n')
print('4) UDP Payload\n')
 
ui = input()
 
if ui == '1':
    print('starting ping sweep...\n')
    pingsweep()
elif ui == '2':
    print('starting vanilla scan')
    vanillaScan(ServerAddress)
elif ui == '3':
    print('TCP Payload')
    tcpSend(ServerAddress, 8080)