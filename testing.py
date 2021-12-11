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

given_file = open("wellKnownPorts.txt", "r")
lines = given_file.readlines()
wellKnownPorts = []

for line in lines: 
    contents = line.split(",")
    for i in contents: 
        tempVariable = int(i)
        wellKnownPorts.append(tempVariable)
given_file.close()

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

def portScan(scan,ip,numOfPorts):
    # global portNum
    ## Variables 
    startTime = time.time()
    closedPortsCounter = 0
    portNum = None
    state = None
    service = None
    portsToScan = 0 

    if numOfPorts == 'all':
        portsToScan = 200
    elif numOfPorts == 'well-known':
        portsToScan = wellKnownPorts
    else:
        print("Choice to scan all or well-known ports")

    print('Starting port scan at ', dateTimeObj) 
    #get the ip address from target input
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        try:
            for port in range(len(portsToScan)):
                print(port)
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
    elif scan == 'random':
        ports = list(range (1, len(portsToScan)))
        #randomly shuffles the ports from the list and replaces the list with the randomized order
        random.shuffle (ports) 
        try:
            for port in ports:
                print(port)
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
    else: 
        print("Choice to scan in order or randomly")

    endTime = time.time()
    finalPrint(closedPortsCounter,portNum,state,service)
    print('scan done!', findingIP(ip) ,f'scanned in {endTime-startTime:.2f} seconds')

def main():
    portScan('random','glasgow.smith.edu','well-known')

if __name__ == "__main__":
    main()