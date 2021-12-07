import socket
import time
from datetime import datetime
dateTimeObj = datetime.now()

## Variables 
startTime = time.time()
counter = 0 

# def portScan():
target = input('What you want to scan?: ')
print('Starting port scan ', dateTimeObj) 
target_ip = socket.gethostbyname(target)
print ("Please wait, scanning remote host", target_ip)
try:
    for port in range(1,50):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((target_ip, port))  
        print(port)
        if result == 0:
            print(f'port {port} is open')
        else: 
            counter = counter + 1 
        print('Not shown:', closed, 'closed ports' )
        sock.close()
except Exception as err:
    print(err)
endTime = time.time()
print(f'scan done! scanned in {end-start:.2f} seconds')