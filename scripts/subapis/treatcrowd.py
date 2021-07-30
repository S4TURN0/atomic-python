def threatcrowd(domain,requests):
    print('[+] Consultando threatcrowd')
    params = {"domain": domain}
    subs = []
    try:
        response =  requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/", params=params).json()
        for sub in response['subdomains']:
            subs.append(sub)
        return subs
    except:
        return
