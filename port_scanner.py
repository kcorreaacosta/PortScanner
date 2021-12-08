import socket
import time
from datetime import datetime
import random
import sys
dateTimeObj = datetime.now()
from ping3 import ping

#https://www.delftstack.com/howto/python/python-ping/
def findingIP(ip):
    resp = ping(ip)
    if resp == False:
        return False
    else:
        return ("1 IP address (1 host up)")

def portScan(scan,ip,numOfPorts):
## Variables 
    startTime = time.time()
    closedPortsCounter = 0
    print('Starting port scan at ', dateTimeObj) 
    #get the ip address from target input
    target_ip = socket.gethostbyname(ip)
    print('Interesting ports on ', target_ip,':')
    if scan == 'order':
        try:
            for port in range(0,numOfPorts):
                # initiates the streaming socket 
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

                # this time out the code at 2 miliseconds 
                s.settimeout(0.02) 

                # connects to a remote socket at the target_ip address
                result = s.connect_ex((target_ip, port))  

                # if 0 connection is successful
                if result == 0:
                    state = 'Open'
                    service = socket.getservbyport(port)
                # the port is closed and counter is increased 
                else: 
                    closedPortsCounter = closedPortsCounter + 1
                    state = 'Closed' 
                # closes the socket
                s.close()
        except Exception as err:
            print(err)
    else:
        ports = list(range (1, numOfPorts))
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
                    service = socket.getservbyport(port)
                # the port is closed and counter is increased 
                else: 
                    closedPortsCounter = closedPortsCounter + 1
                    state = 'Closed' 
                # closes the socket
                s.close()
        except Exception as err:
            print(err)

    endTime = time.time()
    print('Not shown:', closedPortsCounter, 'closed ports' )
    print("PORT\tSTATE\tSERVICE")
    print(port,"\t",state,"\t",service)
    print('scan done!', findingIP(ip) ,f'scanned in {endTime-startTime:.2f} seconds')

def main():
    findingIP('glasgow.smith.edu')
    portScan('order','glasgow.smith.edu',100)


if __name__ == "__main__":
    main()