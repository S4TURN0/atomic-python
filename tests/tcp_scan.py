#!/usr/bin/python3
import socket
import threading
from queue import Queue

print_lock = threading.Lock()

target = 'example.com'

def portscan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        con = s.connect_ex((target,port))
        with print_lock:
            if con == 0:
                print('Port', port)
        con.close()
    except:
        pass

def threader():
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()

q = Queue()

for x in range(1):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

for worker in range(1,1000):
    q.put(worker)

q.join()