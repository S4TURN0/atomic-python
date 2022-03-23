import random,json,os

def random_api(api):
    try:
        keys = get_key(api)
        key = random.randrange(len(keys))
        if api != 'passivetotal': 
            return keys[key]
        else:
            user,passwd = keys[key]
            return user,passwd
    except:
        keys = get_key(api)['api']
        cookies = get_key(api)['cookie']
        key = random.randrange(len(keys))
        cookie = random.randrange(len(keys))
        return keys[key],cookies[cookie]

def get_key(api):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path+'/api_keys.json','r') as key:
        return json.load(key)[api]