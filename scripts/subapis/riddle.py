def riddler(domain,requests,re):
    print("[+] Consultando riddler")
    subs = []
    url = 'https://riddler.io/search/exportcsv?q=pld:'+domain
    response = requests.get(url)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    if len(sub) > 0:
        for x in sub:
            subs.append(x)
        return subs