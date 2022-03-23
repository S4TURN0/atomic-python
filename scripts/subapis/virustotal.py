from config.keys import random_api
import requests

def virustotal(domain):
    try:
        api = random_api('virustotal')
        if api != "API_KEY":
            print('[+] Consultando virustotal')
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey':api,'domain':domain}
            response = requests.get(url, params=params)
            try: 
                subs = response.json()['subdomains']
                for sub in response.json()['domain_siblings']:subs.append
            except:
                pass
            return subs
        return None
    except:
        if response.status_code == 403: print('[!] VirusTotal: Invalid API Key')
        elif response.json()['verbose_msg']: print('[!] VirusTotal:',response.json()['verbose_msg'])
        else:
            print('[!] VirusTotal: ',response.json())
        return None