import socket

def getServiceName(port, proto):
    try:
        name = socket.getservbyport(int(port), proto)
    except:
        return '{} {}'.format(port,'unknown')
    return "{} {}".format(port,name)

def get_ip_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
    except:
        return None
    return ip

# Função inicial para gerenciar as portas e iniciar o escaneamento
def port_scan(ip,ports):
    if ports == None:              
        # Montando a lista de portas padrões
        ports = []
        for x in [1,1025]: 
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
    print("[*] Inciando o portscan no destino: ",ip,"\n")

    port_found = []
    start,end = ports
    try:
        for port in range(start,end+1):
            print

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            connect = sock.connect_ex((ip,port))

            if connect == 0:
                port_found.append(port)
                print("Conexão aberta:", getServiceName(port,'tcp'))        
                sock.close()
    except socket.gaierror:
        print("[!] Não foi possivel se conectar ao dominio:",ip,"\n")
    return port_found