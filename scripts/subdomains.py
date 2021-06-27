import requests,re,json,time
from dns import resolver
from dns.exception import DNSException
from config.keys import *

# Variaveis globais
global subs
subs = []
active_subs = []

# Função para realizar a descoberta de subdominios
def subdomain(domain):
    print("\n[*] Iniciando a descoberta de subdominios\n\n")

    anubis(domain)    
    bufferover(domain)
    crt(domain)
    certspotter(domain)
    dnsdb(domain)
    riddler(domain)
    hackertarget(domain)
    passivetotal(domain)
    securitytrails(domain)
    virustotal(domain)
    
    print('\n\n[*] Removendo subdominios duplicados')
    uniq_subs = list(dict.fromkeys(subs))
    uniq_subs.sort()

    print('\n[+] {} Subdominios encontrados!'.format(len(uniq_subs)))

    print('\n[*] Filtrando por subdominios ativos\n')

    for x in uniq_subs: 
        subdomain_check(x,'A')

    print("\n[+] {} Subdominios Ativos!\n".format(len(active_subs)))
    return uniq_subs

def subdomain_check(sub,query):
    try:
        conn = resolver.query(sub,query)
        print(conn.qname)
        active_subs.append(conn.qname)
    except DNSException as e:
        #print('Error DNS: {}'.format(e))
        pass

def certspotter(domain):
    print("[+] Consultando certspotter")
    params = (
            ('domain', domain),
            ('include_subdomains', 'true'),
            ('expand', 'dns_names'),
        )
    # Insira sua chave de API em Bearer
    header = {"Authorization": "Bearer "+cert_api()}
    response = requests.get('https://api.certspotter.com/v1/issuances',headers=header, params=params).json()
    #print('\nCertPotter: {}'.format(response))
    for a in response:
        try:
            a = a['dns_names']
            for b in a:
                if len(b) > 0:
                    b = re.match("[^\*\.].*\."+domain+"$",b)
                    if b != None:
                        subs.append(b.group(0))
        except:
            pass

def bufferover(domain):
    print("[+] Consultando bufferover")
    sub = 'https://dns.bufferover.run/dns?q='+domain
    req = requests.get(sub).json()['FDNS_A']
    if req != None:
        for x in req:
            domains = x.split(',')[1]
            if re.search('.*\.'+domain+'$',domains):
                subs.append(domains)

def riddler(domain):
    print("[+] Consultando riddler")
    url = 'https://riddler.io/search/exportcsv?q=pld:'+domain
    response = requests.get(url)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    for x in sub:
        subs.append(x)

def anubis(domain):
    print("[+] Consultando anubis")
    url = 'https://jldc.me/anubis/subdomains/'+domain
    response = requests.get(url)
    resp = json.loads(response.content.decode('utf-8'))

    for x in resp:
        if x != b'[]':
            subs.append(x)

def crt(domain):
    print("[+] Consultando crt.sh")
    url = 'https://crt.sh/?q=%.'+domain+'&output=json'
    response = requests.get(url)
    for x in response.json():
        sub = x['name_value']
        if sub != None:
            try:
                sub = re.sub(r'^[\n\.\*]+','',sub)
                sub = re.findall(r".*\."+domain,sub)
                subs.append(sub[0])
            except Exception as e: pass #print('Error: {}'.format(e))

def hackertarget(domain):
    print("[+] Consultando hackertarget")
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
    print("[+] Consultando securitytrails")
    url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"

    querystring = {"children_only":"false","include_inactive":"false"}

    # Insira sua chave de API em APIKEY
    headers = {
        "Accept": "application/json",
        "APIKEY": sec_api()
    }
    try:    
        response = requests.request("GET", url, headers=headers, params=querystring)
        #print('\nSecurity Trails: {}'.format(response.json()))
        for x in response.json()['subdomains']:
            sub = '{}.{}'.format(x,domain)
            subs.append(sub)
    except:
        pass

def passivetotal(domain):
    print("[+] Consultando passivetotal")
    headers = {
        'Content-Type': 'application/json',
    }
    # Insira sua credencial de acesso como tupla = (user,pass)
    keys = tuple(riskiq_api()) 

    data = '{"query":"'+domain+'"}'

    response = requests.post('https://api.passivetotal.org/v2/enrichment', headers=headers, data=data, auth=keys).json()

    for x in response['subdomains']:
        sub = '{}.{}'.format(x,domain)
        subs.append(sub)

def dnsdb(domain):
    print("[+] Consultando dnsdb")
    try:
        # Insira sua chave de API em X-API-Key
        headers = {
            'Accept': 'application/x-ndjson',
            'X-API-Key': dnsdb_api(),
        }

        response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'\.$/A', headers=headers)
        sub = re.findall('[\w\d\.\-]+\.'+domain,response.text)
        for x in sub:
            subs.append(x)

        response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'\.$/CNAME', headers=headers)
        sub = re.findall('[\w\d\.\-]+\.nubank\.com\.br',response.text)
        for x in sub:
            subs.append(x)

        #response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'\.$/NS', headers=headers)
        #sub = re.findall('[\w\d\.\-]+\.nubank\.com\.br',response.text)
        #for x in sub:
            #subs.append(x)

        #response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'\.$/MX', headers=headers)
        #sub = re.findall('[\w\d\.\-]+\.'+domain,response.text)
        #for x in sub:
            #subs.append(x)

    except Exception as e: print('Error: {}'.format(e))

def virustotal(domain):
    try:
        print('[+] Consultando Virustotal')

        # Insira sua chave de API em x-apikey
        headers = {
        'x-apikey': virustotal_api(),
        }

        regex_sub = []
        response = requests.get('https://www.virustotal.com/api/v3/domains/'+domain+'/subdomains?limit=40', headers=headers)
        cursor = response.json()['meta']['cursor']
        regex_sub.append(re.findall('[\w\d\.\-]+\.'+domain, response.text))

        while True:
            try:
                response = requests.get('https://www.virustotal.com/api/v3/domains/'+domain+'/subdomains?limit=40&cursor='+cursor, headers=headers)
                regex_sub.append(re.findall('[\w\d\.\-]+\.'+domain, response.text))
                cursor = response.json()['meta']['cursor']
                time.sleep(5)
            except: break

        for sub in regex_sub:
            for x in sub:
                subs.append(x)
    except Exception as e: 
        #print('VirusTotal: {}'.format(e))
        pass