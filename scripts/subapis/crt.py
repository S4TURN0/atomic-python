import requests,re

def crt(*args):
    print("[+] Consultando crt.sh")
    domain = args[0]
    subs =[]
    url = 'https://crt.sh/?q=%.'+domain+'&output=json'
    try:
        response = requests.get(url)
        print(response)
        for x in response.json():
            sub = x['name_value']
            if sub != None:
                try:
                    sub = re.search('^[\w\d\.\-]+\.'+domain,sub).group(0).lower()
                    subs.append(sub)
                except Exception as e: pass #print('Error: {}'.format(e))
        return subs
    except KeyboardInterrupt:
        print("\n[!] Execução cancelada!")
        exit()
    except Exception:
        print(Exception)