import threading
import time
import random
from queue import Queue

def spawn_thread():
    
    num = 10

    for y in range(num):
        x = random.randrange(num)

        with print_lock:    
            if not x in b:
                b.append(x)

if __name__ == '__main__':
    a = []
    b = []

    print_lock = threading.Lock()

    for i in range(100):
        time.sleep(0.00001)
        q = threading.Thread(target=spawn_thread)
        q.start()
        a.append(q) 

    for x in a:
        x.join()
   
    print(sorted(b))