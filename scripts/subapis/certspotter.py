import re

def certspotter(domain,requests,api):
    print("[+] Consultando certspotter")
    subs = []
    params = {'domain':domain,'include_subdomains':'true','expand':'dns_names'}

    header = {"Authorization": "Bearer "+api}
    response = requests.get('https://api.certspotter.com/v1/issuances',headers=header, params=params).json()
    
    for a in response:
        try:
            a = a['dns_names']
            for b in a:
                if len(b) > 0:
                    b = re.match("[^\*\.].*\."+domain+"$",b)
                    if b != None:
                        subs.append(b.group(0))
        except:
            print('[!] Error: {}\n'.format(response['message']))
            return
    return subs