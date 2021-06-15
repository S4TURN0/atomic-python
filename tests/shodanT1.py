import shodan

SPI = 'Nq0mOunMlDkNjgGBUr6ir0QPdwIAiWjN'

api = shodan.Shodan(SPI)

host = api.host('172.67.182.214')

print('IP: {}'.format(host['ip_str']))


for item in host['data']:
    print('Porta: {}'.format(item['port']))


#print('''
#        IP: {}
#        Organization:{}
#        Operating System: {}
#'''.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))


#for item in host['data']:
#print('''
#        Port: {}
#        Banner: {}
#'''.format(item['port'], item['data']))