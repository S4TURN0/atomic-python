def bufferover(domain,requests,re):
    print("[+] Consultando bufferover")
    subs = []
    sub = 'https://dns.bufferover.run/dns?q='+domain
    req = requests.get(sub).json()['FDNS_A']
    if req != None:
        for x in req:
            domains = x.split(',')[1]
            if re.search('.*\.'+domain+'$',domains):
                subs.append(domains)
        return subs