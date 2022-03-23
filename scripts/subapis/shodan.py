from config.keys import random_api
import requests

def shodan(domain):
    api = random_api('shodan')
    if api != "API_KEY":
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
                print('[!] Shodan: Invalid API Key.')
            return
    return