#!/usr/bin/python3
from lib.scriptslib import *
from utils.banner import banners
import argparse

parse = argparse.ArgumentParser(description="Esse código serve para realizar um portscan")
parse.add_argument('-a','--auto',action="store_true",dest="automation",help="Realizar discoberta de subdominios")
parse.add_argument('-d','--dest',type=str,dest="destino",help="Insira o endereço de destino")
parse.add_argument('-p',help="Insira a porta para ser escaneada")
parse.add_argument('-s','--subs',action="store_true",dest="subdomain",help="Realizar discoberta de subdominios")
parse.add_argument('-ps','--scan',action="store_true",dest="portscan",help="Realizar escaneamento de portas")
parse.add_argument('-f','--fuzz',dest="fuzzing",help="Realizar um fuzzing ao encontrar portas web abertas")
parse.add_argument('-hc',help="Para especificar os códigos HTTP que deseja esconder")
parse.add_argument('-sc',help="Para especificar os códigos HTTP que deseja mostrar") 
parse.add_argument('-w',type=str,help="Adicionar uma wordlist para a realização do fuzzing (OPCIONAL)")
args = parse.parse_args()

def main():

    banners()

    try:
        if args.destino != None:
            domain = args.destino
            ports = args.p
        else:
            domain = None
        
        if args.automation: auto(domain,ports,args.w,args.sc,args.hc)

        if args.subdomain: subdomain(domain)

        if args.portscan == True or args.p != None: port_scan(domain,ports)

        if args.fuzzing: fuzzing(domain,args.sc,args.hc,args.automation,args.fuzzing,args.w)

    except KeyboardInterrupt:
        print("\n[!] Execução cancelada!")
    except Exception as e:
        print('\n[!] Error: {}'.format(e))
    else:
        print('\n[+] Execução finalizada com sucesso!')

if __name__ == "__main__":
    main()
