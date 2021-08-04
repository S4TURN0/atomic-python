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
    
    for x in [alienvault,anubis,bufferover,crt,hackertarget,riddler,threatcrowd]:
        list_subs.append(x(domain,requests,json,re))

    list_subs.append(certspotter(domain,requests,cert_api()))    
    list_subs.append(chaos(domain,requests,chaos_api()))
    list_subs.append(dnsdb(domain,requests,dnsdb_api(),re))
    list_subs.append(passivetotal(domain,requests,passive_api()))
    list_subs.append(sectrails(domain,requests,sec_api()))
    list_subs.append(shodan(domain,requests,shodan_api()))
    list_subs.append(virustotal(domain,requests,virus_api()))
    list_subs.append(zoomeye(domain,requests,zoomeye_api()))

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

        print("\n[+] {} Subdominios válidos encontrados!\n".format(len(active_subs)))
        return active_subs
    else: print("\n[*] Não foi possível encontrar subdominios para este destino!\n")

# Função para filtrar subdominios ativos
def subdomain_check():
    while True:
        sub = q.get()
        try:
            conn = resolver.query(sub,'a')
            print(conn.qname)
            active_subs.append(conn.qname)
        except resolver.NoAnswer:
            try:
                conn = resolver.query(sub,'aaaa')
                print(conn.qname)
                active_subs.append(conn.qname)
            except: continue
        except KeyboardInterrupt:
            exit()
        except: continue
        finally:q.task_done()