def riddler(*args):
    print("[+] Consultando riddler")
    domain,requests,re = args[0],args[1],args[3]
    subs = []
    response = requests.get('https://riddler.io/search/exportcsv?q=pld:'+domain)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    if len(sub) > 0:
        for x in sub:
            subs.append(x)
        return subs