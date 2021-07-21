import random,json

def random_api(api):    
    try:
        keys = get_api(api)
        key = random.randrange(len(keys))
        return keys[key]
    except:
        keys = get_api(api)['api']
        cookies = get_api(api)['cookie']
        key = random.randrange(len(keys))
        cookie = random.randrange(len(keys))
        return keys[key],cookies[cookie]

def get_api(api):
    with open('.config/api_keys.json','r') as key:
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
    
def chaos_api():
    return random_api('chaos')

def fofa_api():
    return random_api('fofa')