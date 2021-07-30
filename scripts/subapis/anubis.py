def anubis(domain,requests,json):
    print("[+] Consultando anubis")
    subs = []
    url = 'https://jldc.me/anubis/subdomains/'+domain
    response = requests.get(url)
    resp = json.loads(response.content.decode('utf-8'))
    if len(resp) > 0:    
        for x in resp:
            if x != b'[]':
                subs.append(x)
        return subs