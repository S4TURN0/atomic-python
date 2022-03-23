from config.keys import random_api
import requests

def chaos(domain):
    api = random_api('chaos')
    if api != "API_KEY":
        print("[+] Consultando chaos")
        headers = {'Authorization': api}
        subs = []
        try:
            response = requests.get('https://dns.projectdiscovery.io/dns/'+domain+'/subdomains', headers=headers,timeout=5)
            if response.status_code == 200:
        
                for sub in response.json()['subdomains']:
                    subs.append(sub+'.'+domain)
                            
            elif response.status_code == 401: print('[!] Chaos: Invalid API Key')
            elif response.status_code == 429: print('[!] Chaos: Too many requests')
            else: print('[!] Chaos: '+response.json()['error'])

        except requests.exceptions.ReadTimeout:
            print('[!] Chaos: Connection Timeout with this domain')
        except:
            return
        return subs
    return