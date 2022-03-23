from config.keys import random_api
import requests,re

def certspotter(domain):
    subs = []
    params = {'domain':domain,'include_subdomains':'true','expand':'dns_names'}
    api = random_api('certspotter')

    if api != "API_KEY":
        print("[+] Consultando certspotter")
        header = {"Authorization": "Bearer "+api}
        response = requests.get('https://api.certspotter.com/v1/issuances',headers=header, params=params).json()
        try:
            for a in response:
                a = a['dns_names']
                for b in a:
                    if len(b) > 0:
                        b = re.match("[^\*\.].*\."+domain+"$",b)
                        if b != None:
                            subs.append(b.group(0))
        except:
            print('[!] Certspotter: {}'.format(response['message']))
            return
        return subs
    return