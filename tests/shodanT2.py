#!/usr/bin/env python
import socket
import shodan
from shodan.helpers import get_ip


SPI = '<api>'
api = shodan.Shodan(SPI)
addr = input('Informe o domínio: ')
ip = str


ip = socket.gethostbyname(addr)


host = api.host('{}'.format(ip))
print('IP: {}'.format(host['ip_str']))

for item in host['data']:
    print('Porta: {}'.format(item['port']))


'''try:
    sock = socket.socket(socket.AF_INET)
    connect = sock.connect_ex((ip))
except socket.gaierror:
    print("[!] Não foi possivel se conectar ao dominio:",ip,"\n")'''

'''def run_shodan_search(target):
    if shodan_api is None:
        pass
    else:
        try:
            target_results = self.shodan_api.search(target)
            return target_results
        except shodan.APIError as error:
            pass '''