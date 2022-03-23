from config.keys import random_api
import requests

def passivetotal(domain):
    API = random_api('passivetotal')
    try:
        if API[1] != "API_KEY":
            print("[+] Consultando passivetotal")
            headers = {'Content-Type': 'application/json',}
            data = {"query":domain}
            subs = []
            response = requests.post('https://api.passivetotal.org/v2/enrichment', headers=headers, json=data, auth=API)

            if response.status_code == 200:
                for x in response.json()['subdomains']:
                    if not '*' in x:
                        sub = '{}.{}'.format(x,domain)
                        subs.append(sub)
                return subs
            elif response.status_code == 401: 
                print('[!] Passivetotal: Invalid API Key')
            else:
                print('[!] Passivetotal: '+response.json()['message'])
                return
    except:
        return