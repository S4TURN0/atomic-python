def passivetotal(domain,requests,api):
    print("[+] Consultando passivetotal")
    try:
        headers = {'Content-Type': 'application/json',}
        keys = tuple(api)
        data = {"query":domain}
        subs = []

        response = requests.post('https://api.passivetotal.org/v2/enrichment', headers=headers, json=data, auth=keys).json()
        try:
            for x in response['subdomains']:
                if not '*' in x:
                    sub = '{}.{}'.format(x,domain)
                    subs.append(sub)
            return subs
        except:
            print('[!] Error: '+response['message'],'\n')
            return
    except:
        return
