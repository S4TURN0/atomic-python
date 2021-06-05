from .subdomains import subdomain
from .port_scan import port_scan
from .fuzzing import fuzzing

# Função para execução automatica dos scripts 
def auto(*args):
    domain,ports,wordlist,sc,hc = args
    domains = subdomain(domain)
    for domain in domains:
        port = port_scan(domain,ports)
        if (80 or 443) in port:
            fuzzing(domain,sc,hc,True,None,wordlist)