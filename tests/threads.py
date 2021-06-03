import threading

class thd(threading.Thread):
    def __ini__(self, id, count, lock):
        self.id = id
        self.count = count
        self.lock = lock
        threading.Thread.__init__(self)
    
    def run(self):
        for i in range(self.count):
            with self.lock:
                print('[%s] ==> %s' % (self.id, i))

stdoutmutex = threading.Lock()
threads = []

for i in range(10):
    thread = thd(i, 10, stdoutmutex)
    thread.start()
    threads.append(thread)

for x in threads:
    x.join()
