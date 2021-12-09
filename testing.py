#https://www.youtube.com/watch?v=J4gDm7M_j10&ab_channel=NetPwn
#https://buildmedia.readthedocs.org/media/pdf/scapy/latest/scapy.pdf
import socket
import time
from datetime import datetime
import random
import sys
dateTimeObj = datetime.now()
from ping3 import ping
from scapy.all import *

def findingIP(ip):
    resp = ping(ip)
    if resp == False:
        return False
    else:
        return ("1 IP address (1 host up)")

def finalPrint(closedPortsCounter,portNum,state,service):
    print('Not shown:', closedPortsCounter, 'closed ports' )
    print("PORT\tSTATE\tSERVICE")
    print(portNum,"\t",state,"\t",service)

def tcpSYNscan(scan,ip,numOfPorts):
    if numOfPorts == 'all':
        portsToScan = 200
    else:
        portsToScan = 100
    #Variables 
    startTime = time.time()
    closedPortsCounter = 0
    print('Starting port scan at ', dateTimeObj) 
    #get the ip address from target input
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        try:
            for i in range(0,portsToScan):
                tcpRequest = IP(dst=ip)/TCP(dport=i,flags="S")
                tcpResponse = sr1(tcpRequest,timeout=1,verbose=False)
                try:
                    if tcpResponse.getlayer(TCP).flags == "SA":
                        state = 'Open'
                        portNum = i
                        service = socket.getservbyport(portNum)
                        RSTpacket = sr(IP(dst='glasgow.smith.edu')/TCP(dport= i , flags="R"),timeout=10)
                        send(RSTpacket)
                except AttributeError:
                    closedPortsCounter = closedPortsCounter + 1
        except Exception as err:
            print(err)
    else:
        ports = list(range (1, portsToScan))
        #randomly shuffles the ports from the list and replaces the list with the randomized order
        random.shuffle (ports) 
        try:
            for port in ports:
                tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
                tcpResponse = sr1(tcpRequest,timeout=1,verbose=False)
                try:
                    if tcpResponse.getlayer(TCP).flags == "SA":
                        state = 'Open'
                        portNum = port
                        service = socket.getservbyport(portNum)
                        RSTpacket = sr(IP(dst='glasgow.smith.edu')/TCP(dport= port , flags="R"),timeout=10)
                        send(RSTpacket)
                except AttributeError:
                    closedPortsCounter = closedPortsCounter + 1
        except Exception as err:
            print(err)

    endTime = time.time()
    finalPrint(closedPortsCounter,portNum,state,service)
    print('scan done!', findingIP(ip) ,f'scanned in {endTime-startTime:.2f} seconds')

def main():
    tcpSYNscan('order','glasgow.smith.edu','all')

if __name__ == "__main__":
    main()