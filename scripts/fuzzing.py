import requests
import urllib3

urllib3.disable_warnings()

def template(code,path):
    print("[+] Status: {} URL: {}".format(code,path))

def fuzzing(*args):
    # Função para gerenciamento de wordlists

    domain,sc,hc,auto,url,arquivo = args
    try:
        with open(arquivo,'r') as words:
            if auto != False:
                try:
                    url = "https://{}/".format(domain)
                    req = requests.get(url,verify=False)
                except requests.exceptions.SSLError as e:
                    return
                except:
                    url = "http://{}/".format(domain)
                    req = requests.get(url)   

            print('\n[*] Iniciando o Web Fuzzing no site: ', url,"\n")

            for word in words.readlines():

                word = word.rstrip("\n")
                url_word = url+word
                req = requests.get(url_word,verify=False,timeout=10)
                
                if sc != None:
                    if ',' in sc:
                        x = sc.split(",")
                        status = [ int(p) for p in x]
                    
                        if req.status_code in status:
                            template(req.status_code,url_word)
                    else:
                        if req.status_code == int(sc):    
                            template(req.status_code,url_word)
                            
                elif hc != None:
                    if ',' in hc:
                        x = hc.split(",")
                        status = [ int(p) for p in x]
                    
                        if not req.status_code in status:    
                            template(req.status_code,url_word)
                    else:
                        if req.status_code != int(hc):    
                            template(req.status_code,url_word)           
                else: 
                    template(req.status_code,url_word)
    except requests.exceptions.InvalidSchema:
        print("[!] Error: Invalid Schema. ex: http:// https://")
    except requests.exceptions.MissingSchema:
        print("[!] Error: Invalid URL. No schema supplied. ex: http://example.com/")
    except requests.exceptions.ConnectionError:
        print("[!] Error: Failed to establish a new connection")
    except requests.exceptions.ReadTimeout:
        print("\n[!] Error: Failed to establish a new connection")
    except requests.exceptions.InvalidURL:
        print("[!] Error: Invalid URL")
    except urllib3.exceptions.LocationParseError:
        print("[!] Error: Invalid URL")
    except KeyboardInterrupt:
        print("[!] Execução cancelada!")
        exit()