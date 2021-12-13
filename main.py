# Kiara and Ileanna 
# Resources: Adrianna(TA), Professor Cho, 
# We brainstormed/debugged with Kathleen
import time
from datetime import datetime
import sys
dateTimeObj = datetime.now()
from ping3 import ping
import sys  # https://www.geeksforgeeks.org/command-line-arguments-in-python/
from scapy.all import *
from portScanner import *
from tcpSyn import *
from tcpFIN import *

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

def main():
    
    startTime = time.time()
    if sys.argv[1] == "normal":
        portScan(sys.argv[2], sys.argv[4], sys.argv[3])
    elif sys.argv[1] == "syn":
        tcpSYNscan(sys.argv[2], sys.argv[4], sys.argv[3])
    elif sys.argv[1] == "fin":
        tcpFINscan(sys.argv[2], sys.argv[4], sys.argv[3]) 
    endTime = time.time()
    print('scan done!', findingIP(sys.argv[4]) ,f'scanned in {endTime-startTime:.2f} seconds')

if __name__ == "__main__":
    main()