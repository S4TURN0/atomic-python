def dnsdb(domain,requests,api,json):
    print("[+] Consultando dnsdb")
    try:
        subs = []
        headers = {
            'Accept': 'application/x-ndjson',
            'X-API-Key': api,
            'Content-type':'application/x-www-form-urlencoded'
        }
        params = {'limit':'0','swclient': 'ScoutWebsite','version':'2.2.0'}
        response = requests.get('https://api.dnsdb.info/dnsdb/v2/glob/rrnames/*.'+domain+'./ANY', params=params,headers=headers)
        if response.status_code == 200:
            for record in response.iter_lines():
                record = json.loads(record)
                try:
                    if record['obj']['rrtype'] in ['A','AAAA','CNAME']:
                        subs.append(record['obj']['rrname'])
                except:
                    continue
            return subs
        else:
            print('[!] '+response.text)  
            return
    except Exception:
        return