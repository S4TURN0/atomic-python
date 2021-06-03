import socket
import sys
import threading

def getServiceName(port, proto):
    try:
        name = socket.getservbyport(int(port), proto)
    except:
        return None
    return name

def scan(RPORT):
    MESSAGE = "ping"
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if client == -1:
        print("udp socket creation failed")
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    if sock1 == -1:
        print("icmp socket creation failed")
    try:
        client.sendto(MESSAGE.encode('utf_8'), (UDP_IP, RPORT))
        sock1.settimeout(0.1)
        data, addr = sock1.recvfrom(1024)
    except socket.timeout:
        serv = getServiceName(RPORT, 'udp')
        if not serv:
            pass
        else:
            if not RPORT in PORTS: PORTS.append(RPORT)

    except socket.error as sock_err:
            if (sock_err.errno == socket.errno.ECONNREFUSED):
                print(sock_err('Connection refused'))
            client.close()
            sock1.close()

UDP_IP = sys.argv[1]
PORTS = []

def port():
    START_PORT = int(sys.argv[2])
    END_PORT = int(sys.argv[3])
    for ports in range(START_PORT,END_PORT+1):
        scan(ports)

thds = []

for x in range(int(sys.argv[4])):
    thd = threading.Thread(target=port)
    thd.start()
    thds.append(thd)

for y in thds:
    y.join()

for x in PORTS: print("Port: {} {} -- open/filtred".format(x,getServiceName(x, 'udp')))