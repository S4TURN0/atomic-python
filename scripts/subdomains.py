import requests
import re
from config.keys import *

# Variaveis globais
global subs
subs = []

# Função para realizar a descoberta de subdominios
def subdomain(domain):
    print("\n[*] Iniciando a descoberta de subdominios\n")

    anubis(domain)    
    bufferover(domain)
    crt(domain)
    certspotter(domain)
    riddler(domain)
    hackertarget(domain)
    securitytrails(domain)

    # Remover subdominios duplicados
    uniq_subs = list(dict.fromkeys(subs))
    uniq_subs.sort()
    for x in uniq_subs: 
        print(x)

    print("\n[+] ",len(uniq_subs)," Sub-dominios encontrados!\n")
    return uniq_subs

def certspotter(domain):
    params = (
            ('domain', domain),
            ('include_subdomains', 'true'),
            ('expand', 'dns_names'),
        )
    # Insira sua chave de API em Bearer
    header = {"Authorization": "Bearer "+cert_api()}
    response = requests.get('https://api.certspotter.com/v1/issuances',headers=header, params=params).json()

    for a in response:
        try:
            a = a['dns_names']
            for b in a:
                if len(b) > 0:          
                    b = re.match("^[^*\.]\S[\w\d.\-]+\."+domain,b)
                    if b != None:
                        subs.append(b.group(0))
        except:
            pass

def bufferover(domain):
    sub = 'https://dns.bufferover.run/dns?q='+domain
    req = requests.get(sub).json()['FDNS_A']
    if req != None:
        for x in req:
            if x != None:
                domains = x.split(',')
                subs.append(domains[1])

def riddler(domain):
    url = 'https://riddler.io/search/exportcsv?q=pld:'+domain
    response = requests.get(url)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    for x in sub:
        subs.append(x)

def anubis(domain):
    url = 'https://jldc.me/anubis/subdomains/'+domain
    response = requests.get(url)
    for x in response:
        if x != b'[]':
            subs.append(x)

def crt(domain):
    url = 'https://crt.sh/?q=%.'+domain+'&output=json'
    response = requests.get(url)

    for x in response.json():
        x = x['name_value']
        x = re.search("^[^\.\*]\S[\w\d.\-]+\."+domain,x)
        try:    
            subs.append(x.group(0))
        except: pass

def hackertarget(domain):
    headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Accept': 'text/html, */*; q=0.01',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    }

    data = {
    'theinput': domain,
    'thetest': 'hostsearch',
    'name_of_nonce_field': '607046fd11',
    '_wp_http_referer': '/find-dns-host-records/'
    }

    response = requests.post('https://hackertarget.com/find-dns-host-records/', headers=headers, data=data)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    for x in sub:
        subs.append(x)

def securitytrails(domain):
    url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"

    querystring = {"children_only":"false","include_inactive":"false"}

    # Insira sua chave de API em APIKEY
    headers = {
        "Accept": "application/json",
        "APIKEY": sec_api()
    }
    try:    
        response = requests.request("GET", url, headers=headers, params=querystring)
        for x in response.json()['subdomains']:
            subs.append('{}.{}'.format(x,domain))
    except:
        pass