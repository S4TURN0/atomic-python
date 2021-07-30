def zoomeye(domain,requests,zoomeye_api):
    print('[+] Consultando zoomeye')

    subs = []
    api,cookie = zoomeye_api
    
    # Subdomains by cookies
    headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=utf-8',
            'Cube-Authorization': cookie,
            'Connection': 'keep-alive',
    }
    params = {'q':domain,'p':1,'s':100000,'type':1}    
    try:    
        response = requests.get('https://www.zoomeye.org/domain/search', headers=headers, params=params).json()
        for x in response['list']:
            subs.append(x['name'])
        return subs
    except Exception:

        # Subdomains by api
        headers = {'API-KEY': api}
        page = 1
        while True:
            try:
                params = {'q':domain,'page':page,'type':1}
                response = requests.get('https://api.zoomeye.org/domain/search', headers=headers, params=params).json()
                if len(response['list']) == 0: break
                for x in response['list']:
                    subs.append(x['name'])
                    page +=1
            except: 
                if 'message' in response:
                    print('[!] Error: '+response['message'])
                break
        return subs
    except: return