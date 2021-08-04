def threatcrowd(*args):
    print('[+] Consultando threatcrowd')
    domain,requests = args[0],args[1]
    params = {"domain": domain}
    subs = []
    try:
        response =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params=params).json()
        for sub in response['subdomains']:
            subs.append(sub)
        return subs
    except:
        return
