def virustotal(domain,requests,api,re,time):
    try:
        print('[+] Consultando virustotal')

        # Insira sua chave de API como valor do x-apikey
        headers = {
        'x-apikey': api,
        }
        subs = []
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
        return subs
    except: 
        print('[!] Error: '+response.json()['error']['message'],'\n')
        return