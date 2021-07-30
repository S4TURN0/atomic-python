from lib.subslib import *
from config.keys import *
import requests,re,time
from dns import *

# Função para realizar a descoberta de subdominios
def subdomain(domain):
    print("\n[*] Iniciando a descoberta de subdominios\n")

    global active_subs
    active_subs = []
    list_subs = []
    sub = []

    list_subs.append(alienvault(domain,requests))
    list_subs.append(anubis(domain,requests,json))
    list_subs.append(bufferover(domain,requests,re))
    list_subs.append(certspotter(domain,requests,cert_api()))    
    list_subs.append(chaos(domain,requests,chaos_api()))
    list_subs.append(crt(domain,requests,re))
    list_subs.append(dnsdb(domain,requests,dnsdb_api(),re))
    list_subs.append(hackertarget(domain,requests,re))
    list_subs.append(passivetotal(domain,requests,passive_api()))
    list_subs.append(riddler(domain,requests,re))
    list_subs.append(sectrails(domain,requests,sec_api()))
    list_subs.append(shodan(domain,requests,shodan_api()))
    list_subs.append(threatcrowd(domain,requests))
    list_subs.append(virustotal(domain,requests,virus_api(),re,time))
    list_subs.append(zoomeye(domain,requests,zoomeye_api()))

    if None in list_subs:list_subs = list(filter(None,list_subs))
    if len(list_subs) > 0:

        print('\n\n[*] Removendo subdominios duplicados')
        for subs in list_subs:
            for x in subs:
                sub.append(x)

        uniq_subs = list(dict.fromkeys(sub))
        uniq_subs.sort()

        print('\n[+] {} Subdominios únicos encontrados!'.format(len(uniq_subs)))
        print('\n[*] Filtrando por subdominios válidos\n')

        for x in uniq_subs:
            subdomain_check(x)

        print("\n[+] {} Subdominios válidos encontrados!\n".format(len(active_subs)))
        return active_subs
    else: print("\n[*] Não foi possível encontrar subdominios para este destino!\n")

# Função para filtrar subdominios ativos
def subdomain_check(sub):
    try:
        conn = resolver.query(sub,'a')
        print(conn.qname)
        active_subs.append(conn.qname)
    except resolver.NoAnswer:
        try:
            conn = resolver.query(sub,'aaaa')
            print(conn.qname)
            active_subs.append(conn.qname)
        except:
            return
    except resolver.NoNameservers:
        return
    except resolver.NXDOMAIN:
        return
    except exception.Timeout:
        return
    except KeyboardInterrupt:
        exit()