def chaos(domain,requests,api):
    print("[+] Consultando chaos")
    headers = {'Authorization': api}
    subs = []
    try:
        response = requests.get('https://dns.projectdiscovery.io/dns/'+domain+'/subdomains', headers=headers).json()
        for sub in response['subdomains']:
            subs.append('{}.{}'.format(sub,domain))
        return subs
    except:
        print('[!] Error: '+response['error'])
        return