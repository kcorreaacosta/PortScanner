import socket
import time
from datetime import datetime
import random
import sys
dateTimeObj = datetime.now()
from ping3 import ping
import sys  # https://www.geeksforgeeks.org/command-line-arguments-in-python/
from scapy.all import *

#https://www.delftstack.com/howto/python/python-ping/
def findingIP(ip):
    resp = ping(ip)
    if resp == False:
        return False
    else:
        return ("1 IP address (1 host up)")

#will print the table of open ports
def finalPrint(closedPortsCounter,portNum,state,service):
    print('Not shown:', closedPortsCounter, 'closed ports' )
    print("PORT\tSTATE\tSERVICE")
    print(portNum,"\t",state,"\t",service)

def portScan(scan,ip,numOfPorts):
    global portNum
    if numOfPorts == 'all':
        portsToScan = 200
    else:
        portsToScan = 100
## Variables 
    startTime = time.time()
    closedPortsCounter = 0
    print('Starting port scan at ', dateTimeObj) 
    #get the ip address from target input
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        try:
            for port in range(0,portsToScan):
                # initiates the streaming socket 
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                # this time out the code at 2 miliseconds 
                s.settimeout(0.02) 

                # connects to a remote socket at the target_ip address
                result = s.connect_ex((target_ip, port))  

                # if 0 connection is successful
                if result == 0:
                    state = 'Open'
                    portNum=port
                    service = socket.getservbyport(portNum)
                # the port is closed and counter is increased 
                else: 
                    closedPortsCounter = closedPortsCounter + 1 
                # closes the socket
                s.close()
        except Exception as err:
            print(err)
    else:
        ports = list(range (1, portsToScan))
        #randomly shuffles the ports from the list and replaces the list with the randomized order
        random.shuffle (ports) 
        try:
            for port in ports:
                # initiates the streaming socket 
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

                # this time out the code at 2 miliseconds 
                s.settimeout(0.02) 

                # connects to a remote socket at the target_ip address
                result = s.connect_ex((target_ip, port))  
                # if 0 connection is successful
                if result == 0:
                    state = 'Open'
                    portNum = port
                    service = socket.getservbyport(portNum)
                # the port is closed and counter is increased 
                else: 
                    closedPortsCounter = closedPortsCounter + 1
                # closes the socket
                s.close()
        except Exception as err:
            print(err)

    endTime = time.time()
    finalPrint(closedPortsCounter,portNum,state,service)
    print('scan done!', findingIP(ip) ,f'scanned in {endTime-startTime:.2f} seconds')

###################################################################################
def tcpSYNscan(scan,ip,numOfPorts):
    global portNum
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
    # print(sys.argv)
    findingIP(sys.argv[3])
    if sys.argv[1] == "normal":
        portScan(sys.argv[2], sys.argv[4], sys.argv[3])
    # elif sys.argv[1] == "syn":
    else: 
        tcpSYNscan(sys.argv[2], sys.argv[4], sys.argv[3])

if __name__ == "__main__":
    main()