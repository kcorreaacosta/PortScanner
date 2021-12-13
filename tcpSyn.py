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

def tcpSYNscan(scan,ip,numOfPorts):
    if numOfPorts == 'all':
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

    print('Starting TCP SYN scan at ', dateTimeObj) 
    #get the ip address from target input
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        if portsToScan == 65535:
            try:
                for i in range(1,portsToScan):
                    #sending the request to connect
                    tcpRequest = IP(dst=ip)/TCP(dport=i,flags="S")
                    tcpResponse = sr1(tcpRequest,timeout=1,verbose=False)
                    try:
                        if tcpResponse.getlayer(TCP).flags == "SA":
                            state = 'Open'
                            portNum = i
                            service = socket.getservbyport(portNum)
                            #sending a response back
                            RSTpacket = sr(IP(dst=ip)/TCP(dport= i , flags="R"),timeout=10)
                            send(RSTpacket)
                    except AttributeError:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
        else:
            try:
                for i in range(1,len(portsToScan)):
                    #sending the request to connect
                    tcpRequest = IP(dst=ip)/TCP(dport=i,flags="S")
                    tcpResponse = sr1(tcpRequest,timeout=1,verbose=False)
                    try:
                        #if there is an open port that answers
                        if tcpResponse.getlayer(TCP).flags == "SA":
                            state = 'Open'
                            portNum = i
                            service = socket.getservbyport(portNum)
                            #sending a response back
                            RSTpacket = sr(IP(dst=ip)/TCP(dport= i , flags="R"),timeout=10)
                            send(RSTpacket)
                    except AttributeError:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
    elif scan == 'random':
        if portsToScan == 65535:
            ports = list(range (1, portsToScan))
            #randomly shuffles the ports from the list and replaces the list with the randomized order
            random.shuffle (ports) 
            try:
                for port in ports:
                    #sending the request to connect
                    tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
                    tcpResponse = sr1(tcpRequest,timeout=1,verbose=False)
                    try:
                        #if there is an open port that answers
                        if tcpResponse.getlayer(TCP).flags == "SA":
                            state = 'Open'
                            portNum = port
                            service = socket.getservbyport(portNum)
                            #sending a response back
                            RSTpacket = sr(IP(dst=ip)/TCP(dport= port , flags="R"),timeout=10)
                            send(RSTpacket)
                    except AttributeError:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
        else:
            #if we use len of portsToScan then we get an error
            ports = list(range (1, len(wellKnownPorts)))
            #randomly shuffles the ports from the list and replaces the list with the randomized order
            random.shuffle (ports) 
            try:
                for port in ports:
                    #sending the request to connect
                    tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
                    tcpResponse = sr1(tcpRequest,timeout=1,verbose=False)
                    try:
                        #if there is an open port that answers
                        if tcpResponse.getlayer(TCP).flags == "SA":
                            state = 'Open'
                            portNum = port
                            service = socket.getservbyport(portNum)
                            #sending a response back
                            RSTpacket = sr(IP(dst=ip)/TCP(dport= port , flags="R"),timeout=10)
                            send(RSTpacket)
                    except AttributeError:
                        closedPortsCounter = closedPortsCounter + 1
            except Exception as err:
                print(err)
    else: 
        print("Choice to scan in order or randomly")

    finalPrint(closedPortsCounter,portNum,state,service)