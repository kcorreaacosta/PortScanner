# Kiara and Ileanna 
# Resources: Adrianna(TA), Professor Cho, 
# We brainstormed/debugged with Kathleen

import socket
import time
from datetime import datetime
import random
dateTimeObj = datetime.now()
from ping3 import ping
from scapy.all import *
from main import *

#open up the text file and get all of the integers to be in a list
given_file = open("wellKnownPorts.txt", "r")
lines = given_file.readlines()
wellKnownPorts = []

for line in lines: 
    contents = line.split(",")
    for i in contents: 
        tempVariable = int(i)
        wellKnownPorts.append(tempVariable)
given_file.close()

#will print the table of open ports
def finalPrint(closedPortsCounter,portNum,state,service):
    print('Not shown:', closedPortsCounter, 'closed ports' )
    print("PORT\tSTATE\tSERVICE")
    print(portNum,"\t",state,"\t",service)

def tcpFINscan(scan,ip,numOfPorts):
    if numOfPorts == 'all':
        # portsToScan = [*range(10,25,1)]
        portsToScan = 65535
    elif numOfPorts == 'well-known':
        portsToScan = wellKnownPorts
    else:
        print("Choice to scan all or well-known ports")
    #Variables 
    closedPortsCounter = 0
    portNum = None
    state = None
    service = None

    print('Starting TCP FIN scan at ', dateTimeObj) 
    #get the ip address from target input
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        try:
            if portsToScan ==65535:
                for i in range(1,portsToScan):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(('', i))
                    # this time out the code at 2 miliseconds 
                    s.settimeout(0.02) 

                    # connects to a remote socket at the target_ip address
                    result = s.connect_ex((ip, i)) 
                    
                    #if this is 0 then there is an open ports
                    if result == 0:
                        state = "Open"
                        portNum = i # getting port number
                        service = socket.getservbyport(portNum, "tcp")

                    #sends out a request to connect to all ports
                    tcpRequest = IP(dst=ip)/TCP(dport= i, flags="F")
                    tcpResponse = sr1(tcpRequest,verbose=0, timeout = 1)
                    s.close()

                    #if no response then the ports are closed
                    if tcpResponse is None:
                        closedPortsCounter = closedPortsCounter + 1
        except Exception as err:
            print(err)
        else:
            try:
                for i in range(1,len(portsToScan)):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(('', i))
                    # this time out the code at 2 miliseconds 
                    s.settimeout(0.02) 

                    # connects to a remote socket at the target_ip address
                    result = s.connect_ex((ip, i)) 

                    #if this is 0 then there is an open ports
                    if result == 0:
                        state = "Open"
                        portNum = i # getting port number
                        service = socket.getservbyport(portNum, "tcp")

                    #sends out a request to connect to all ports
                    tcpRequest = IP(dst=ip)/TCP(dport= i, flags="F")
                    tcpResponse = sr1(tcpRequest,verbose=0, timeout = 1)
                    s.close()
                    
                    #if no response then the ports are closed
                    if tcpResponse is None:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
    elif scan == "random":
        if portsToScan ==65535:
            ports = list(range (1, portsToScan))
            #randomly shuffles the ports from the list and replaces the list with the randomized order
            random.shuffle (ports) 
            try:
                for port in ports:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(('', port))
                    # this time out the code at 2 miliseconds 
                    s.settimeout(0.02) 

                    # connects to a remote socket at the target_ip address
                    result = s.connect_ex((ip, port)) 

                    #if this is 0 then there is an open ports
                    if result == 0:
                        state = "Open"
                        portNum = port # getting port number
                        service = socket.getservbyport(portNum, "tcp")

                    #sends out a request to connect
                    tcpRequest = IP(dst=ip)/TCP(dport= port, flags="F")
                    tcpResponse = sr1(tcpRequest,verbose=0, timeout = 1)
                    s.close()
                    
                    #if there is no response then it is closed
                    if tcpResponse is None:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
        else:
            ports = list(range (1, len(portsToScan)))
            #randomly shuffles the ports from the list and replaces the list with the randomized order
            random.shuffle (ports) 
            try:
                for port in ports:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(('', port))
                    # this time out the code at 2 miliseconds 
                    s.settimeout(0.02) 

                    # connects to a remote socket at the target_ip address
                    result = s.connect_ex((ip, port)) 

                    #if this is 0 then there is an open ports
                    if result == 0:
                        state = "Open"
                        portNum = port # getting port number
                        service = socket.getservbyport(portNum, "tcp")

                    #sends out a request to connect
                    tcpRequest = IP(dst=ip)/TCP(dport= port, flags="F")
                    tcpResponse = sr1(tcpRequest,verbose=0, timeout = 1)
                    s.close()

                    #if there is no response then it is closed
                    if tcpResponse is None:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
    else: 
        print("Choice to scan in order or randomly")

    finalPrint(closedPortsCounter,portNum,state,service)