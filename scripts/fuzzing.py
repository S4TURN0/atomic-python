import requests

# Função para gerenciamento de wordlists
def fuzzing(*args):

    domain,sc,hc,auto,url,arquivo = args

    if arquivo == None:
        arquivo = 'wordlists/common.txt'

    with open(arquivo,'r') as words:
    
        if auto != False:
            try:
                url = "https://{}/".format(domain)
                req = requests.get(url)
            except:
                url = "http://{}/".format(domain)
                req = requests.get(url)     
        
        print('\n[*] Iniciando o Web Fuzzing no site... ', url,"\n")

        for word in words.readlines():    
                
            req = requests.get(url+word)

            if sc != None:
                if ',' in sc:
                    x = sc.split(",")
                    status = [ int(p) for p in x]
                   
                    if req.status_code in status:    
                        print("[+] Status: {} Wordlist: /{}  ".format(req.status_code,word.rstrip("\n")))
                else:
                    if req.status_code == int(sc):    
                        print("[+] Status: {} Wordlist: /{}  ".format(req.status_code,word.rstrip("\n")))

            elif hc != None:
                if ',' in hc:
                    x = hc.split(",")
                    status = [ int(p) for p in x]
                   
                    if not req.status_code in status:    
                        print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))
                else:
                    if req.status_code != int(hc):    
                        print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))
           
            else: print("[+] Status: {} Wordlist: {}  ".format(req.status_code,word.rstrip("\n")))
