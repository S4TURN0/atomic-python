#!/usr/bin/python3
try:
    from lib.scriptslib import *
    from utils.banner import banners
    import argparse,re
except KeyboardInterrupt:
    print("\n[!] Execução cancelada!")
    exit()

parse = argparse.ArgumentParser(prog='./atomic-python.py',allow_abbrev=True,description=banners())
parse.add_argument('-a','--auto',action="store_true",dest="automation",help="Automatiza todo o processo de discovery, scanning e web fuzzing")
parse.add_argument('-d',type=str,dest="destino",help="Insira o endereço de destino (Domínio ou IPV4)")
#parse.add_argument('-t',default=200,dest="threads",help="Modifica a quantidade de threads utilizas (padrão 200)")

subs = parse.add_argument_group("Subdomain arguments")
subs.add_argument('-s','--subs',action="store_true",dest="subdomain",help="Realizar descoberta de subdominios")
#subs.add_argument('-sA','--subs-active',action="store_true",dest="subs_active",help="Realizar descoberta de subdominios e filtra por ativos")

scan = parse.add_argument_group("Portscan arguments")
scan.add_argument('-pS','--scan',action="store_true",dest="portscan",help="Realizar escaneamento de portas")
scan.add_argument('-p',dest="porta",help="Insira a porta para ser escaneada")

fuzz = parse.add_argument_group("Web Fuzzing arguments")
fuzz.add_argument('-f',nargs="?",default=False,dest="fuzzing",help="Realizar descoberta de diretórios acessiveis")
fuzz.add_argument('-hc',help="Para especificar os códigos HTTP que deseja esconder")
fuzz.add_argument('-sc',help="Para especificar os códigos HTTP que deseja mostrar") 
fuzz.add_argument('-w',default="utils/wordlists/common.txt",help="Adicionar uma wordlist para a realização do fuzzing (Padrão: common.txt)")

args = parse.parse_args()

def main():
    try:
        if args.destino != None:
            if re.search('^[\w\.\-]+\.[a-z]+$',args.destino.lower()) or re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',args.destino):
                domain = args.destino
                ports = args.porta
                
                if args.automation: auto(domain,ports,args.w,args.sc,args.hc)
                
                elif args.subdomain and args.portscan:
                    for domains in subdomain(domain):
                        port_scan(domains,ports)

                elif args.subdomain and args.fuzzing == None:
                    for domains in subdomain(domain):
                        fuzzing(domains,args.sc,args.hc,True,None,args.w)

                elif args.subdomain: subdomain(domain)
                
                elif args.portscan: port_scan(domain,ports)
                
                else:
                    parse.print_help()
                    exit()
            else:
                print('[!] Destino inválido: {}\n'.format(args.destino))
                parse.print_help()
                exit()

        elif args.fuzzing: 
            domain = None
            fuzzing(domain,args.sc,args.hc,args.automation,args.fuzzing,args.w)
        else:
            parse.print_help()
            exit()

    except KeyboardInterrupt:
        print("\n[!] Execução cancelada!")
        exit()
    else:
        print('\n[*] Execução finalizada!')

if __name__ == "__main__":
    main()