# PortScanner
CSC 251 Final Project - Port Scanner

Files included: main.py, portScanner.py, tcpSyn.py, tcpFIN.py, wellKnownPorts.txt

How to run: port_scanner.py mode(normal/SYN/FIN) order(order/random) numOfPorts(all/well-known)
    Example: python3 port_scanner.py normal order well-known glasgow.smith.edu

Note: When we would test run, if you run the program for too long on a terminal two errors would occur. 

~ socket.error: [Errno 48] Address already in use is fixed if you open in a new terminal and run again. 
(https://stackoverflow.com/questions/19071512/socket-error-errno-48-address-already-in-use)

~ PORT STATE SERVICE showing up as NONE NONE NONE is fixed if you open in a new terminal and run again.

