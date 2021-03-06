import requests,re
import threading
from lib.subslib import *
from config.keys import *
from dns import *
from queue import Queue

q = Queue()

# Função para realizar a descoberta de subdominios
def subdomain(domain):
    print("\n[*] Iniciando a descoberta de subdominios\n")

    global active_subs
    active_subs = []
    list_subs = []
    sub = []
    try:
        resolver.query('google.com','a')
        for x in [alienvault,anubis,bufferover,crt,hackertarget,riddler,threatcrowd]:
            list_subs.append(x(domain,requests,json,re))

        for x in [certspotter,chaos,dnsdb,passivetotal,sectrails,shodan,virustotal]:
            list_subs.append(x(domain))
    except resolver.NoNameservers:
        print("[!] Error: Failed to establish a new connection")
    except requests.exceptions.ConnectionError:
        print("[!] Error: Failed to establish a new connection")
    except KeyboardInterrupt:
        print("\n[!] Execução cancelada!")
        exit()

    if None in list_subs:list_subs = list(filter(None,list_subs))
    if len(list_subs) > 0:
        print('\n\n[*] Removendo subdominios duplicados')
        for subs in list_subs:
            for x in subs:
                sub.append(x)

        uniq_subs = list(dict.fromkeys(sub))
        print('\n[+] {} Subdominios únicos encontrados!'.format(len(uniq_subs)))
        print('\n[*] Filtrando por subdominios válidos\n')

        for x in range(100):
            t = threading.Thread(target=subdomain_check,daemon=True).start()

        for worker in uniq_subs:
            q.put(worker)
        q.join()

        if len(active_subs) > 0:
            print("\n[+] {} Subdominios válidos encontrados!\n".format(len(active_subs)))
        else:
            print("[!] Não foi possível encontrar subdominios válidos para este destino!\n")
        return active_subs
    else: print("\n[!] Não foi possível encontrar subdominios para este destino!\n")

# Função para filtrar subdominios ativos
def subdomain_check():
    while True:
        sub = q.get()
        try:
            resolver.query(sub,'a')
            print(sub)
            active_subs.append(sub)
        except resolver.NoAnswer:
            try:
                resolver.query(sub,'aaaa')
                print(sub)
                active_subs.append(sub)
            except: continue
        except KeyboardInterrupt:
            exit()
        except: continue
        finally:q.task_done()