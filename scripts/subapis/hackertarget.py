def hackertarget(*args):
    print("[+] Consultando hackertarget")
    domain,requests,re = args[0],args[1],args[3]
    subs = []
    headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Accept': 'text/html, */*; q=0.01',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    }

    data = {
    'theinput': domain,
    'thetest': 'hostsearch',
    'name_of_nonce_field': '607046fd11',
    '_wp_http_referer': '/find-dns-host-records/'
    }

    response = requests.post('https://hackertarget.com/find-dns-host-records/', headers=headers, data=data)
    sub = re.findall("[\w\d.\-]+\."+domain,response.text)
    for x in sub:
        subs.append(x)
    return subs