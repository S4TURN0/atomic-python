#!/usr/bin/python3
import socket
import argparse
import requests


parse = argparse.ArgumentParser(description="Esse código serve para realizar um portscan")
parse.add_argument('-d','--dest',required=True,type=str,dest="destino",help="Insira o endereço de destino")
parse.add_argument('-p',help="Insira a porta para ser escaneada")
parse.add_argument('-f','--fuzz',action="store_true",dest="fuzzing",help="Realizar um fuzzing ao encontrar portas web abertas")
parse.add_argument('-w',type=str,help="Adicionar uma wordlist para a realização do fuzzing (OPCIONAL)")
args = parse.parse_args()

# Função para realizar o portscan
def port_scan(ports):
    print("\n[+] Inciando o portscan no destino: ",ip,"\n")

    fuzz = []    

    for port in ports:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        connect = sock.connect_ex((ip,port))

        if connect == 0:
            try:
                service = socket.getservbyport(port)
                print("[+] Conexão aberta:", port,service)
            except Exception as e:
                print("[+] Conexão aberta:", port,"unknown")
            
            if port in [80,443,8080,8443]:
                fuzz.append(port)
        sock.close()
    print("\n[+] O portscan foi realizado com sucesso!!\n")

    if args.fuzzing == True and fuzz != None:
        fuzzing(fuzz)

# Função para realizar o web fuzzing
def fuzzing(ports):
    print('\n[+] Iniciando o Web Fuzzing\n')

    if 443 in ports:
        with open('wordlists/common.txt','r') as words:
            for word in words.readlines():
                url = "https://{}/{}".format(domain,word)
                req = requests.get(url)
                print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))

    elif 80 in ports:
        with open('wordlists/common.txt','r') as words:
            for word in words.readlines():
                url = "http://{}/{}".format(domain,x)
                req = requests.get(url)
                print("[+] Status: {} Wordlist: {} ".format(req.status_code,word.rstrip("\n")))

# Função para gerenciamento de wordlists
def wordlist():
    words = open(args.w,'r')
    for word in words.readlines():
        pass

try:
    domain = args.destino
    ip = socket.gethostbyname(domain)
    ports = args.p

    if ports == None:        
        ports = []
        for x in range(0,1024):
            ports.append(x)
        port_scan(ports)

    elif '-' in ports:
        start_port, end_port = ports.split("-")
        start_port, end_port = int(start_port), int(end_port)
        ports = [ p for p in range(start_port, end_port+1)]
        port_scan(ports)

    elif ',' in ports:
        x = ports.split(",")
        ports = [ int(p) for p in x]
        port_scan(ports)
    
    else:
        ports = [int(ports)]
        port_scan(ports)

except socket.gaierror:
    print("\n[-] Não foi possivel se conectar ao servidor")
except KeyboardInterrupt:
    print("\n[-] Portscan cancelado!")