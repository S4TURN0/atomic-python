def alienvault(domain,requests):
    print('[+] Consultando alienvault')
    subs = []
    try:
        response = requests.get("https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/passive_dns").json()
        for sub in response['passive_dns']:
            subs.append(sub['hostname'])
        return subs
    except: return