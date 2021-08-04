def virustotal(domain,requests,api):
    try:
        print('[+] Consultando virustotal')

        headers = {'x-apikey': api}
        subs = []

        response = requests.get('https://www.virustotal.com/api/v3/domains/'+domain+'/subdomains?limit=40', headers=headers)
        for querys in response.json()['data']:
            subs.append(querys['id'])
        while True:
            try:
                response = requests.get(response['links']['next'], headers=headers).json()
                for querys in response['data']:
                    subs.append(querys['id'])
            except: break
        return subs
    except:
        print('[!] Error: '+response.json()['error']['message'],'\n')
        return