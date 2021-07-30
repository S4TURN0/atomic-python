def dnsdb(domain,requests,api,re):
    print("[+] Consultando dnsdb")
    try:
        subs = []
        headers = {
            'Accept': 'application/x-ndjson',
            'X-API-Key': api,
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
        
        return subs
    except Exception:
        return