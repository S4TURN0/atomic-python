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
def port_scan(domain,ports):
    try:
        if ports == None:         
            # Montando a lista de portas padrões
            ports = []
            for x in range(1,1025): 
                ports.append(x)
            return connect_ports(domain,ports)

        elif '-' in ports:
            # Montando a lista de portas padrões
            start_port, end_port = ports.split("-")
            start_port, end_port = int(start_port), int(end_port)
            ports = [ p for p in range(start_port, end_port+1)]             
            return connect_ports(domain,ports)

        elif ',' in ports:
            # Montando a lista de portas padrões    
            ports = ports.split(",")
            ports = [int(i) for i in ports]
            return connect_ports(domain,ports)
                
        else: 
            ports = [int(ports)]
            return connect_ports(domain,ports)    
    except ValueError:
        print("[!] Error: Invalid port value")
        
# Função para realizar o portscan
def connect_ports(domain,ports):
    print("\n[*] Inciando o portscan no destino: ",domain,"\n")
    port_found = []
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            connect = sock.connect_ex((domain,port))
            if connect == 0:
                port_found.append(port)
                print("Conexão aberta:", getServiceName(port,'tcp'))        
                sock.close()
        if len(port_found) == 0:
            print("[!] Não foi possível encontrar portas abertas para este destino!")
    except socket.gaierror:
        print("[!] Não foi possivel se conectar ao dominio:",domain,"\n")
    return port_found