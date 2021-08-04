def crt(*args):
    print("[+] Consultando crt.sh")
    domain,requests,re = args[0],args[1],args[3]
    subs =[]
    url = 'https://crt.sh/?q=%.'+domain+'&output=json'
    response = requests.get(url)
    for x in response.json():
        sub = x['name_value']
        if sub != None:
            try:
                sub = re.sub(r'^[\n\.\*]+','',sub)
                sub = re.findall(r".*\."+domain,sub)
                subs.append(sub[0])
            except Exception as e: pass #print('Error: {}'.format(e))
    return subs