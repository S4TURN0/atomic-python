import requests,re,time
from dns import *
from config.keys import *

# Variaveis globais
subs = []
active_subs = []

# Função para realizar a descoberta de subdominios
def subdomain(args):
    print("\n[*] Iniciando a descoberta de subdominios\n\n")

    global domain
    domain = args

    alienvault()
    anubis()    
    bufferover()
    chaos()
    crt()
    certspotter()
    dnsdb()
    riddler()
    hackertarget()
    passivetotal()
    securitytrails()
    threatcrowd()
    virustotal()
    shodan()
    zoomeye()

    if len(subs) > 0:
        print('\n\n[*] Removendo subdominios duplicados')

        uniq_subs = list(dict.fromkeys(subs))
        uniq_subs.sort()

        print('\n[+] {} Subdominios únicos encontrados!'.format(len(uniq_subs)))
        print('\n[*] Filtrando por subdominios válidos\n')

        for x in uniq_subs:
            subdomain_check(x)

        print("\n[+] {} Subdominios válidos encontrados!\n".format(len(active_subs)))
        return active_subs
    else: print("\n[*] Não foi possível encontrar subdominios para este destino!\n")

def subdomain_check(sub):
    try:
        conn = resolver.query(sub,'a')
        print(conn.qname)
        active_subs.append(conn.qname)
    except resolver.NoAnswer:
        try:
            conn = resolver.query(sub,'aaaa')
            print(conn.qname)
            active_subs.append(conn.qname)
        except:
            return
    except resolver.NoNameservers:
        return
    except resolver.NXDOMAIN:
        return
    except exception.Timeout:
        return
    except KeyboardInterrupt:
        exit()

def certspotter():
    print("[+] Consultando certspotter")

    params = {'domain':domain,'include_subdomains':'true','expand':'dns_names'}
    api = cert_api()
    header = {"Authorization": "Bearer "+api}
    response = requests.get('https://api.certspotter.com/v1/issuances',headers=header, params=params).json()

    for a in response:
        try:
            a = a['dns_names']
            for b in a:
                if len(b) > 0:
                    b = re.match("[^\*\.].*\."+domain+"$",b)
                    if b != None:
                        subs.append(b.group(0))
        except:
            print('[!] Error: {}'.format(response['message']))
            return

def bufferover():
    print("[+] Consultando bufferover")
    sub = 'https://dns.bufferover.run/dns?q='+domain
    req = requests.get(sub).json()['FDNS_A']
    if req != None:
        for x in req:
            domains = x.split(',')[1]
            if re.search('.*\.'+domain+'$',domains):
                subs.append(domains)

def riddler():
    print("[+] Consultando Riddler")
    url = 'https://riddler.io/search/exportcsv?q=pld:'+domain
    response = requests.get(url)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    for x in sub:
        subs.append(x)

def anubis():
    print("[+] Consultando anubis")
    url = 'https://jldc.me/anubis/subdomains/'+domain
    response = requests.get(url)
    resp = json.loads(response.content.decode('utf-8'))

    for x in resp:
        if x != b'[]':
            subs.append(x)

def crt():
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

def hackertarget():
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

def securitytrails():
    url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"

    querystring = {"children_only":"false","include_inactive":"true"}

    # Insira sua chave de API em APIKEY
    try:
        headers = {
            "Accept": "application/json",
            "APIKEY": sec_api()
        }

        print("[+] Consultando securitytrails")
        response = requests.request("GET", url, headers=headers, params=querystring)

        for x in response.json()['subdomains']:
            sub = '{}.{}'.format(x,domain)
            subs.append(sub)
    except:
        print('[!] Error: '+response.json()['message'])
        return

def passivetotal():
    print("[+] Consultando passivetotal")
    try:
        headers = {'Content-Type': 'application/json',}
        keys = tuple(passive_api())
        data = {"query":domain}

        response = requests.post('https://api.passivetotal.org/v2/enrichment', headers=headers, json=data, auth=keys).json()
        try:
            for x in response['subdomains']:
                if not '*' in x:
                    sub = '{}.{}'.format(x,domain)
                    subs.append(sub)
        except:
            print('[!] Error: '+response['message'])
            return
    except:
        return
        
def dnsdb():
    print("[+] Consultando dnsdb")
    try:
        headers = {
            'Accept': 'application/x-ndjson',
            'X-API-Key': dnsdb_api(),
            'Content-type':'application/x-www-form-urlencoded'
        }
        params = {'limit':'0','swclient': 'ScoutWebsite','version':'2.2.0'}

        response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'[\.]?+$/A', params=params,headers=headers)
       
        if response.status_code == 403:
            print('[!] '+response.text)     
            return

        sub = re.findall('[\w\d\.\-]+\.'+domain,response.text)
        for x in sub:
            subs.append(x)
  
        response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'[\.]?+$/AAAA',params=params, headers=headers)
        sub = re.findall('[\w\d\.\-]+\.'+domain,response.text)
        for x in sub:
            subs.append(x)

        response = requests.get('https://api.dnsdb.info/dnsdb/v2/regex/rrnames/.*\.'+domain+'[\.]?+$/CNAME',params=params, headers=headers)
        sub = re.findall('[\w\d\.\-]+\.nubank\.com\.br',response.text)
        for x in sub:
            subs.append(x)

    except Exception:
        return

def virustotal():
    try:
        print('[+] Consultando virustotal')

        # Insira sua chave de API como valor do x-apikey
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

    except: 
        print('[!] Error: '+response.json()['error']['message'])
        return

def shodan():
    try:    
        print('[+] Consultando shodan')

        params = {'key':shodan_api()}
        response = requests.get('https://api.shodan.io/dns/domain/nubank.com.br', params=params)

        for sub in response.json()['subdomains']:
            subs.append('{}.{}'.format(sub,domain))

    except Exception:
        if response.status_code == 401:
            print('[!] Error: This server could not verify that you are authorized to access the document you requested.')
        return

def threatcrowd():
    try:
        print('[+] Consultando threatcrowd')
        params = {"domain": domain}
        response =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params=params).json()
        for sub in response['subdomains']:
            subs.append(sub)
    except:
        return

def alienvault():
    try:
        print('[+] Consultando alienvault')
        response = requests.get("https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/passive_dns").json()
        for sub in response['passive_dns']:
            subs.append(sub['hostname'])
    except: return

def chaos():
    try:
        print("[+] Consultando chaos")
        headers = {
            'Authorization': chaos_api(),
        }
        response = requests.get('https://dns.projectdiscovery.io/dns/'+domain+'/subdomains', headers=headers).json()
        for sub in response['subdomains']:
            subs.append('{}.{}'.format(sub,domain))
    except:
        print('[!] Error: '+response['error'])
        return

def zoomeye():
    print('[+] Consultando zoomeye')
    api,cookie = zoomeye_api()
        
    # Subdomains by cookies
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=utf-8',
        'Cube-Authorization': cookie,
        'Connection': 'keep-alive',
    }
    params = {'q':domain,'p':1,'s':100000,'type':1}
    
    try:    
        response = requests.get('https://www.zoomeye.org/domain/search', headers=headers, params=params).json()
        for x in response['list']:
            subs.append(x['name'])
    except Exception:

        # Subdomains by api
        headers = {'API-KEY': api}
        page = 1
        while True:
            try:
                params = {'q':domain,'page':page,'type':1}

                response = requests.get('https://api.zoomeye.org/domain/search', headers=headers, params=params).json()
                if len(response['list']) == 0: break
                for x in response['list']:
                    subs.append(x['name'])
                page +=1
            except: 
                print('[!] Error: '+response['message'])
                break
    except: return