# -*- encoding: utf-8 -*-
import os
import sys
import re
import json
import ovh
import configparser
from pprint import pprint

config = configparser.ConfigParser()

if len(sys.argv) > 1:
    my_ovh_config_file = sys.argv[1]
else:
    my_ovh_config_file = 'ovh.conf'

config.read(my_ovh_config_file)

def replace_in_file(filename, regex, replace):
    with open (filename, 'r' ) as f:
        content = f.read()
    content_new = re.sub(regex, replace, content, flags = re.M)

    with open("ovh.conf",'w') as w:
        w.write(content_new)

if not 'application_key' in config[config['default']['endpoint']]:
    print("Please visit https://eu.api.ovh.com/createApp/ to create an API key")
    application_key = raw_input('Please enter your Application Key: ')
    replace_in_file(my_ovh_config_file, r"(;application_key=.*)", r"application_key=" + application_key)
    application_secret = raw_input('Please enter your Application Secret: ')
    replace_in_file(my_ovh_config_file, r"(;application_secret=.*)", r"application_secret=" + application_secret)


# create a client using configuration
client = ovh.Client(config_file=my_ovh_config_file)

# Request RO, /me API access
ck = client.new_consumer_key_request()
ck.add_rules(ovh.API_READ_WRITE, "/*")

if not 'consumer_key' in config[config['default']['endpoint']]:
    # Request token
    validation = ck.request()
    print("Please visit %s to authenticate" % validation['validationUrl'])
    raw_input("and press Enter to continue...")
    print "Welcome", client.get('/me')['firstname']
    print("Btw, your 'consumerKey' is '%s'" % validation['consumerKey'])
    replace_in_file('ovh.conf', r"(;consumer_key=.*)", r"consumer_key=" + validation['consumerKey'])

result = client.get('/hosting/privateDatabase')

print(json.dumps(result, indent=4))

print("please tell on me which DB you want to update ip tables ?")
db_to_update = raw_input('Please the database server name (format like should be like ab12345-001): ')

def get_db_restrictions(db):

    #current restrictions
    result = client.get('/hosting/privateDatabase/' + db_to_update + '/whitelist', 
        service=True,
        sftp=False, 
    )
    return result


print(" -------- ")
print("getting current ip restrictions")

print(json.dumps(get_db_restrictions(db_to_update)))
print(" -------- ")

print("setting new ip restrictions")

with open('ip-ranges.json') as f:
    data = json.load(f)
    prefixes = data['prefixes']
    for ips in prefixes:
        try:
            result = client.post('/hosting/privateDatabase/' + db_to_update + '/whitelist', 
                ip=ips['ip_prefix'],
                name=ips['service'] + "-" + ips['region'],
                service=True,
                sftp=False,
            )
        except:
            print(ips['service'] + "-" + ips['region'] + " already whitelisted")

print(" -------- ")
print("getting new ip restrictions")

print(json.dumps(get_db_restrictions(db_to_update)))
print(" -------- ")

