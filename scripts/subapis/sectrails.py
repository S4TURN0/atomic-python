from config.keys import random_api
from requests import get

def sectrails(domain):
    api = random_api('sectrails')
    if api != "API_KEY":
        print("[+] Consultando securitytrails")
        url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"
        querystring = {"children_only":"false","include_inactive":"true"}
        headers = {"Accept": "application/json","APIKEY": api}
        subs = []
        response = get(url, headers=headers, params=querystring)

        if response.status_code == 200:
            for x in response.json()['subdomains']:
                sub = '{}.{}'.format(x,domain)
                subs.append(sub)
        elif response.status_code == 403: 
            print('[!] SecurityTrails: Invalid API Key')
        else:
            print('[!] SecurityTrails: '+response.json()['message'])
        return subs
    return