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

def portScan(scan,ip,numOfPorts):
    if numOfPorts == 'all':
        portsToScan = 65535
    elif numOfPorts == 'well-known':
        portsToScan = wellKnownPorts
    else:
        print("Choice to scan all or well-known ports")
    
    ## Variables 
    closedPortsCounter = 0
    portNum = None
    state = None
    service = None

    print('Starting port scan at ', dateTimeObj) 
    #get the ip address from target input  
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        try:
            if portsToScan == 65535:
                for port in range(portsToScan):
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
            else:
                for port in range(1,len(portsToScan)):
                    
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
        if portsToScan == 65535:
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
        else:
            ports = list(range (1, len(portsToScan)))
            
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
    else: 
        print("Choice to scan in order or randomly")

    finalPrint(closedPortsCounter,portNum,state,service)