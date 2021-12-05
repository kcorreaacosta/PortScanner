import os
import socket
import time
from datetime import datetime
import random
dateTimeObj = datetime.now()


#finds if the IP is alive
#https://stackoverflow.com/questions/2953462/pinging-servers-in-python
# def findingIP():
#     hostname = "https://www.hackthissite.org/" 
#     response = os.system("ping -c 1 " + hostname)
#     if response == 0:
#         print (hostname, 'is up!')
#         portScan()
#     else:
#         print (hostname, 'is down!')


#loop through the ports
#def portScan():

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# here we asking for the target website or host
target = input('What you want to scan?: ')
print('Starting port scan ', dateTimeObj) 
# next line gives us the ip address of the target
target_ip = socket.gethostbyname(target)
print('Interesting ports on: ', target_ip)
 
# function for scanning ports

def port_scan(port):
    try:
        s.connect((target_ip, port))
        return True 
    except:
        return False
 
start = time.time()
closed = 0
# here we are scanning port 0 to 65,535 in order
for port in range(130, 180): 
    # if port_scan(port):
    #     socket.getservbyport() 
    #     print(f'port {port} is open')
    try:
        result = s.connect_ex((target_ip,port))
        if result == 0:
            print("hi")
            print("Port {} is open".format(port))
            # s.close()
        # if port_scan(port):
        #     socket.getservbyport() 
        #     print("hello")
        #     print(f'port {port} is open')
        # else:
        #     # closed = closed + 1
        #     print("hi")

    except Exception as err:
        print(err)

end = time.time()
#print('Not shown:', closed, 'closed ports' )
print(f'scan done! scanned in {end-start:.2f} seconds')

s.close()