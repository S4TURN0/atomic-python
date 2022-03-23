from config.keys import random_api
import requests,json

def dnsdb(domain):
    try:
        api = random_api('dnsdb')
        if api != "API_KEY":
            print("[+] Consultando dnsdb")
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
            elif response.status_code == 403: print('[!] Dnsdb: Invalid API Key')
            else: print('[!] Dnsdb: '+response.text)
            return subs
        return
    except Exception:
        return