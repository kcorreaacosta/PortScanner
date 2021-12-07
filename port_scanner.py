import os
import socket
import time
from datetime import datetime
import random
dateTimeObj = datetime.now()


# # finds if the IP is alive
# # https://stackoverflow.com/questions/2953462/pinging-servers-in-python
# def findingIP():
#     hostname =  
#     response = os.system("ping -c 1 " + hostname)
#     if response == 0:
#         print (hostname, 'is up!')
#         portScan()
#     else:
#         print (hostname, 'is down!')

## Variables 
startTime = time.time()
closedPortsCounter = 0 

# ports = list(rangle (1, 65535))
# randomly shuffles the ports from the list and replaces the list with the randomized order
#  random.shuffle (ports) 

# def portScan():
targetInput = input('What you want to scan?: ')
print('Starting port scan ', dateTimeObj) 
#get the ip address from target input
target_ip = socket.gethostbyname(targetInput)
print('Interesting ports on: ', target_ip)
try:
    for port in range(1,100):
        # initiates the streaming socket 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

        # this time out the code at 2 miliseconds 
        s.settimeout(0.02) 

        # connects to a remote socket at the target_ip address
        result = s.connect_ex((target_ip, port))  

        # if 0 connection is successful
        if result == 0:
            print("Port {} is open".format(port))
        # the port is closed and counter is increased 
        else: 
            closedPortsCounter = closedPortsCounter + 1 
        # closes the socket
        s.close()
except Exception as err:
    print(err)

endTime = time.time()
print('Not shown:', closedPortsCounter, 'closed ports' )
print(f'scan done! scanned in {endTime-startTime:.2f} seconds')