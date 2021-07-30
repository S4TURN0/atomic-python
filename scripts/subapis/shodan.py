def shodan(domain,requests,api):
    print('[+] Consultando shodan')
    params = {'key':api}
    subs = []
    try:    
        response = requests.get('https://api.shodan.io/dns/domain/nubank.com.br', params=params)
        for sub in response.json()['subdomains']:
            subs.append('{}.{}'.format(sub,domain))
        return subs
    except Exception:
        if response.status_code == 401:
            print('[!] Error: This server could not verify that you are authorized to access the document you requested.\n')
        return