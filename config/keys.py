import random,json

def random_api(api):    
    keys = get_api(api)
    key = random.randrange(len(keys))
    return keys[key]

def get_api(api):
    with open('config/api_keys.json','r') as key:
        return json.load(key)[api]

def sec_api():
    return random_api('sectrails')

def cert_api():
    return random_api('certspotter')

def dnsdb_api():
    return random_api('dnsdb')

def virustotal_api():
    return random_api('virustotal')

def passive_api():
    user,passwd = random_api('passivetotal')
    return user,passwd

def shodan_api():
    return random_api('shodan')

def zoomeye_api():
    return random_api('zoomeye')