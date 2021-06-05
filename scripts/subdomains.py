import requests

# Função para realizar a descoberta de subdominios
def subdomain(domain):
    print("\n[*] Iniciando a descoberta de subdominios\n")

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

    print("\n[+] ",len(uniq_subs)," Sub-dominios encontrados!\n")
    return uniq_subs