def anubis(*args):
    print("[+] Consultando anubis")
    domain,requests,json,re = args
    subs = []
    url = 'https://jldc.me/anubis/subdomains/'+domain
    response = requests.get(url)
    resp = json.loads(response.content.decode('utf-8'))
    if len(resp) > 0:    
        for x in resp:
            if x != b'[]':
                try:
                    sub = re.sub(r'^[\n\*\.]+','',x)
                    subs.append(sub)
                except Exception: pass
        return subs