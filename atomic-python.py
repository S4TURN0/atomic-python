#!/usr/bin/python3
import socket
import argparse
import requests

parse = argparse.ArgumentParser(description="Esse código serve para realizar um portscan")
parse.add_argument('-a','--auto',action="store_true",dest="automation",help="Realizar discoberta de subdominios")
parse.add_argument('-d','--dest',type=str,dest="destino",help="Insira o endereço de destino")
parse.add_argument('-p',help="Insira a porta para ser escaneada")
parse.add_argument('-s','--subs',action="store_true",dest="subdomain",help="Realizar discoberta de subdominios")
parse.add_argument('-ps','--scan',action="store_true",dest="portscan",help="Realizar escaneamento de portas")
parse.add_argument('-f','--fuzz',dest="fuzzing",help="Realizar um fuzzing ao encontrar portas web abertas")
parse.add_argument('-hc',help="Para especificar os códigos que deseja esconder")
parse.add_argument('-sc',help="Para especificar os códigos que deseja mostrar") 
parse.add_argument('-w',type=str,help="Adicionar uma wordlist para a realização do fuzzing (OPCIONAL)")
args = parse.parse_args()

# Função para realizar a descoberta de subdominios
def subdomain():
    print("\n[+] Iniciando a descoberta de subdominios\n")

    url = 'https://dns.bufferover.run/dns?q='+domain
    req = requests.get(url)
    subs = []

    for x in req.json()['FDNS_A']:
        
        domains = x.split(',')
        subs.append(domains[1])

    # Remover subdominios duplicados
    uniq_subs = list(dict.fromkeys(subs))

    for x in uniq_subs: 
        print(x)

    print("\n[+] ",len(uniq_subs)," Sub-dominios encontrados!")
    return uniq_subs

# Função inicial para gerenciar as portas e iniciar o escaneamento
def port_scan(ip,ports):
    if ports == None:              
        # Montando a lista de portas padrões
        ports = []
        for x in [80,443]: 
            ports.append(x)

        # Iniciando o escaneamento com as portas definidas
        return connect_ports(ip,ports)

    elif '-' in ports:
        # Montando a lista de portas padrões
        start_port, end_port = ports.split("-")
        start_port, end_port = int(start_port), int(end_port)
        ports = [ p for p in range(start_port, end_port+1)]

        # Iniciando o escaneamento com as portas definidas                
        return connect_ports(ip,ports)

    elif ',' in ports:
        # Montando a lista de portas padrões    
        x = ports.split(",")
        ports = [ int(p) for p in x]

        # Iniciando o escaneamento com as portas definidas
        return connect_ports(ip,ports)
            
    else: 
        ports = [int(ports)]
        return connect_ports(ip,ports)    

# Função para realizar o portscan
def connect_ports(ip,ports):
    print("[+] Inciando o portscan no destino: ",ip,"\n")

    port_found = []

    for port in ports:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        connect = sock.connect_ex((ip,port))

        if connect == 0:
            port_found.append(port)
            try:
                service = socket.getservbyport(port, 'tcp')
                print("[+] Conexão aberta:", port,service)
            except Exception as e:
                print("[+] Conexão aberta:", port,"unknown")
        
            sock.close()

    print("\n[+] O portscan foi realizado com sucesso!!\n")
    return port_found

# Função para realizar o web fuzzing
def fuzzing(url):
    print('\n[+] Iniciando o Web Fuzzing\n')

    wordlist(url,args.w) if args.w != None else wordlist(url,'wordlists/common.txt')

# Função para gerenciamento de wordlists
def wordlist(url,arquivo):
    with open(arquivo,'r') as words:   
    
        if args.automation != False:
            try:
                url = "https://{}/".format(domain)
                req = requests.get(url)
            except:
                url = "http://{}/".format(domain)
                req = requests.get(url)     

        for word in words.readlines():    
                
            req = requests.get(url+word)

            if args.sc != None:
                if ',' in args.sc:
                    x = args.sc.split(",")
                    status = [ int(p) for p in x]
                   
                    if req.status_code in status:    
                        print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))
                else:
                    if req.status_code == int(args.sc):    
                        print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))

            elif args.hc != None:
                if ',' in args.hc:
                    x = args.hc.split(",")
                    status = [ int(p) for p in x]
                   
                    if not req.status_code in status:    
                        print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))
                else:
                    if req.status_code != int(args.hc):    
                        print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))
           
            else: print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))

# Função para execução automatica os scripts 
def auto():
    domains = subdomain()
    for domain in domains:
        port = port_scan(domain,ports)
        print(port)
        if (80 or 443) in port:
            fuzzing(domain)

if __name__ == "__main__":
    try:
        if args.destino != None:
            domain = args.destino
            ip = socket.gethostbyname(domain)
            ports = args.p
        
        if args.automation: auto()

        if args.subdomain: subdomain()

        if args.portscan == True or args.p != None: port_scan(ip,ports)

        if args.fuzzing: 
            url = args.fuzzing
            fuzzing(url)

    except socket.gaierror:
        print("\n[-] Não foi possivel se conectar ao servidor")
    except KeyboardInterrupt:
        print("\n[-] Portscan cancelado!")