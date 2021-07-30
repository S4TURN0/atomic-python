def sectrails(domain,requests,api):
    print("[+] Consultando securitytrails")

    url = "https://api.securitytrails.com/v1/domain/"+domain+"/subdomains"
    querystring = {"children_only":"false","include_inactive":"true"}
    headers = {"Accept": "application/json","APIKEY": api}
    subs = []
    # Insira sua chave de API em APIKEY
    try:
        response = requests.request("GET", url, headers=headers, params=querystring)
        for x in response.json()['subdomains']:
            sub = '{}.{}'.format(x,domain)
            subs.append(sub)
        return subs
    except:
        print('[!] Error: '+response.json()['message'],'\n')
        return