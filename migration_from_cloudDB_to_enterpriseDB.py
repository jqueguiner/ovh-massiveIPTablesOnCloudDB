# -*- encoding: utf-8 -*-
import os
import sys
import re
import json
import ovh
import time
import configparser
from pprint import pprint
import argparse
import random_name

from sh import gunzip

import requests
import wget
import random
import string
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from random import randint

import operator
import gzip



def main():
    global my_ip
    global db_name
    db_name = ""
    password = randomStringDigits(12) + str(random_with_N_digits(2))


    response = requests.get('http://ifconfig.co/ip')
    my_ip = response.content.rstrip()

    parser = argparse.ArgumentParser(description='Migration from OVH CloudDB to Enterprise Cloud DB')
    parser.add_argument('config_file', 
        type=str, 
        help='path to OVH config file | default ovh.conf ', 
        default='ovh.conf')

    args = parser.parse_args()

    api_setup(args.config_file)

    cloudDB = get_available_db('cloudDB')
    cloudDB_to_migrate_from = raw_input('Please the CloudDB database name to migrate from : ')

    enterpriseDB = get_available_db('enterpriseDB')
    enterpriseDB_to_migrate_to = raw_input('Please the enterpriseDB database name to migrate to : ')

    ip_restriction_cloudDB = get_ip_restrictions('cloudDB', cloudDB_to_migrate_from)
    # add current IP to manage migration
    ip_restriction_cloudDB.append(my_ip)

    ip_restriction_enterpriseDB = get_ip_restrictions('enterpriseDB', enterpriseDB_to_migrate_to)
    

    set_ip_restrictions("enterpriseDB", enterpriseDB_to_migrate_to, ip_to_whitelist = ip_restriction_cloudDB, existing_ips = ip_restriction_enterpriseDB)

    move_to_readonly = raw_input('Do you want to move the original DB user to readonly before dump. [Y]/n ? ')

    dump_file = dump_db("cloudDB", cloudDB_to_migrate_from, move_to_readonly)


    print("setting users admin passwords to " + password)

    user = get_or_create_user_db("enterpriseDB", enterpriseDB_to_migrate_to, password)
    

    restore_db(dump_file, enterpriseDB_to_migrate_to, user['name'], password, db_name)



def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


def randomStringDigits(stringLength=6):
    """Generate a random string of letters and digits """
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))


def replace_in_file(filename, regex, replace):
    with open (filename, 'r' ) as f:
        content = f.read()
    content_new = re.sub(regex, replace, content, flags = re.M)

    with open("ovh.conf",'w') as w:
        w.write(content_new)


def api_setup(ovh_config_file):
    global config, client

    config = configparser.ConfigParser()

    config.read(ovh_config_file)


    if not 'application_key' in config[config['default']['endpoint']]:
        print("Please visit https://eu.api.ovh.com/createApp/ to create an API key")
        application_key = raw_input('Please enter your Application Key: ')
        replace_in_file(ovh_config_file, r"(;application_key=.*)", r"application_key=" + application_key)
        application_secret = raw_input('Please enter your Application Secret: ')
        replace_in_file(ovh_config_file, r"(;application_secret=.*)", r"application_secret=" + application_secret)


    # create a client using configuration
    client = ovh.Client(config_file=ovh_config_file)

    # Request RO, /me API access
    ck = client.new_consumer_key_request()
    ck.add_rules(ovh.API_READ_WRITE, "/*")

    if not 'consumer_key' in config[config['default']['endpoint']]:
        # Request token
        validation = ck.request()
        print("Please visit %s to authenticate" % validation['validationUrl'])
        raw_input("and press Enter to continue...")
        print("Welcome %s" % client.get('/me')['firstname'])
        print("Btw, your 'consumerKey' is '%s'" % validation['consumerKey'])
        replace_in_file('ovh.conf', r"(;consumer_key=.*)", r"consumer_key=" + validation['consumerKey'])


def get_available_db(db_type):
    
    if db_type == "cloudDB":
        result = client.get('/hosting/privateDatabase')
        print(json.dumps(result, indent=4))

    else:
        result = client.get('/cloudDB/enterprise/cluster')
        print(json.dumps(result, indent=4))

    return result


def get_ip_restrictions(db_type, db, get_ip_restrictions = ""):
    global security_group_to_update

    if db_type == "cloudDB":
        
        existing_ip_tables = client.get('/hosting/privateDatabase/' + db + '/whitelist', 
                service=True,
                sftp=True,
            )

        print(" -------- ")
        print("getting current ip restrictions on cloudDB")

        print(json.dumps(existing_ip_tables, indent=4))

        print(" -------- ")

        return existing_ip_tables

    else:
        clusterId = db

        security_groups = client.get('/cloudDB/enterprise/cluster/' + clusterId + '/securityGroup')

        if not security_groups:
            print("setting up a new security group")
            security_group_to_create = raw_input('Please input the Security Group name to create : ')

            if security_group_to_create != '':
                security_group_to_create = random_name.generate_name()
                print('empty security group name set we decided to create a random one : ' + security_group_to_create)

            result = client.post('/cloudDB/enterprise/cluster/' + clusterId + '/securityGroup', 
                clusterId=clusterId,
                name=security_group_to_create
                )


        
        security_groups = client.get('/cloudDB/enterprise/cluster/' + clusterId + '/securityGroup')
 
        print(" -------- ")
        print("getting current security Groups on Enterprise cloudDB")

        security_group_by_name = dict()

        for security_group in security_groups:
            security_group_details = client.get('/cloudDB/enterprise/cluster/' + clusterId + '/securityGroup/' + security_group)
            security_group_by_name[security_group_details['name']] = security_group_details['id']
        
        print(json.dumps(security_group_by_name, indent=4))
            

        print(" -------- ")


        print("please tell me which Security Group Name you want to get ip tables from ?")
        security_group_to_update = raw_input('Please input the Security Group name : ')

        security_group_to_update = security_group_by_name[security_group_to_update]
        security_group = security_group_to_update


        existing_rules = client.get('/cloudDB/enterprise/cluster/' + clusterId + '/securityGroup/' + security_group_to_update + '/rule')

        existing_ip_tables = list()

        for rule in existing_rules:
            existing_rules = client.get('/cloudDB/enterprise/cluster/' + clusterId + '/securityGroup/' + security_group_to_update + '/rule/' + rule)
            existing_ip_tables.append(existing_rules["source"])


        return existing_ip_tables


def set_ip_restrictions(db_type, db, ip_to_whitelist = [], existing_ips = []):
    print("")
    if db_type == "cloudDB" :

        # with open('ip-ranges.json') as f:
        #     data = json.load(f)
        #     prefixes = data['prefixes']
        #     for ips in prefixes:
        #     if not ips['ip_prefix'] in existing_ip_tables:
        #             try:
        #                 result = client.post('/hosting/privateDatabase/' + db_to_update + '/whitelist', 
        #                     ip=ips['ip_prefix'],
        #                     name=ips['service'] + "-" + ips['region'],
        #                     service=True,
        #                     sftp=False,
        #                 )
        #             except:
        #                 print(ips['service'] + "-" + ips['region'] + " already whitelisted")

        # print(" -------- ")
        # print("getting new ip restrictions")

        # print(json.dumps(get_db_restrictions(db_to_update)))
        print(" -------- ")
    else:

        for ip in ip_to_whitelist:
            if not ip in existing_ips:
                print('/cloudDB/enterprise/cluster/' + db + '/securityGroup/' + security_group_to_update + '/rule')
                print(ip)
                try:

                    result = client.post('/cloudDB/enterprise/cluster/' + db + '/securityGroup/' + security_group_to_update + '/rule',
                        source=ip,
                        )
                except Exception as e:
                    print(e)
                    print("Failed to set " + ip)
            else:
                print(ip + " already whitelisted")

        print(" -------- ")
        print("getting new ip restrictions")

        print(json.dumps(get_ip_restrictions(db_type, db, security_group_to_update)))  


def make_users_ro(db_type, db):

    if db_type == "cloudDB" :
        users = client.get('/hosting/privateDatabase/' + db + '/user')

        for user in users:
            client.post('/hosting/privateDatabase/' + db + '/user/mi/grant/stats/update', 
                grant='ro'
                )
    else:
        print('not implemented yet')


def dump_db(db_type, db, move_to_readonly):
    global db_name
    if db_type == "cloudDB" :

        db_list = client.get('/hosting/privateDatabase/' + db + '/database/')

        print(json.dumps(db_list, indent=4))

        db_name = raw_input('Please input the DB to dump : ')

        existing_dumps = client.get('/hosting/privateDatabase/' + db + '/database/' + db_name + '/dump', 
            )

        if move_to_readonly.lower() == 'y':
            make_users_ro(db_type, db)

        try:
            client.post('/hosting/privateDatabase/' + db + '/database/' + db_name + '/dump', 
                sendEmail=False
                )
        except:
            print('dump already in progress')

        ready = False

        

        while ready == False:
            print("waiting for dump for " + db + " db : " + db_name)

            dumps = client.get('/hosting/privateDatabase/' + db + '/database/' + db_name + '/dump', 
                )

            if existing_dumps[0] != dumps[0]:
                dump_id = dumps[0]
                ready = True

            if ready == False:
                time.sleep(5)

        print("dump ready : dump_id = " + str(dump_id))

        print("downloading dump : " + str(dump_id))
        dl_dump = client.get('/hosting/privateDatabase/' + db + '/database/stats/dump/' + str(dump_id))
        
        print(dl_dump["url"])

        dump_file =  "dump_" + db + "_" + str(dump_id) + '.gz'

        wget.download(dl_dump["url"], dump_file)

        return dump_file

    else:
        print("Not implemented yet")


def get_or_create_user_db(db_type, db, password):

    if db_type == "enterpriseDB":

        user = client.post('/cloudDB/enterprise/cluster/' + db + '/user', 
            password=password
        )
        # time to wait for the new password to be taken into account
        time.sleep(10)
        
    return user

def get_rw_endpoint(db):
    endpoints = client.get('/cloudDB/enterprise/cluster/' + db + '/endpoint')
    fqdn = ""
    port = 0

    for endpoint in endpoints:
        ep = client.get('/cloudDB/enterprise/cluster/' + db + '/endpoint/' + endpoint)
        if ep['name'] == "read-write":
            fqdn = ep['fqdn']
            port = ep['port']
            print("Found RW endpoint : " + fqdn + ":" + str(port))
        else:
            print("Found R endpoint : " + ep['fqdn'] + ":" + str(ep['port']))

    return fqdn, port


def restore_db(dump_file, db, username, password, db_name):

    fqdn, port = get_rw_endpoint(db)

    print("password : " + password)

    
    
    con = psycopg2.connect(
        dbname='postgres',
        user=username, 
        host=fqdn,
        port=str(port),
        password=password,
        sslmode='require'
        )


    con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

    cursor = con.cursor()

    # get existing databases
    cursor.execute(sql.SQL("SELECT datname FROM pg_database"))

    all_dbs = reduce(operator.concat, cursor.fetchall())

    if db_name not in all_dbs:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(
            sql.Identifier(db_name))
        )
    else:
        print("database %s already exists please clean it using DROP DATABASE IF EXISTS %s " % (db_name, db_name))
        print("""
            -----   DANGER ZONE   -----
            --- DO YOU WANT TO DROP ---
            --- THE TARGET DATABASE ---
            ---    TO IMPORT THE    ---
            ---    ORIGNAL DUMP ?   ---
            ---------------------------
            """)

        drop_question = raw_input('[N]/y ?')

        if lower(drop_question) == 'y':
            cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
                sql.Identifier(db_name))
                )

            cursor.execute(sql.SQL("CREATE DATABASE {}").format(
                sql.Identifier(db_name))
            )

            cursor.execute("select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';")

            print(cursor.fetchall())
        else:
            print("Exiting : As Database exists we can't import the existing database.")
            sys.exit(0)


    cmd = "PGPASSWORD=%s ; gzip -d --stdout %s |  psql --host %s --username %s --port %d %s" % (password, dump_file, fqdn, username, port,db_name)

    print("-------------------------------")
    print("-- RUNNING COMMAND TO IMPORT --")
    print("-------------------------------")

    print(cmd)

    os.system(cmd)



    cursor.execute("SELECT datname FROM pg_database;")

    
    all_dbs = cursor.fetchall()

    print("--------------------------------")
    print("------------ ALL DBS -----------")
    print(all_dbs)
    print("--------------------------------")

    con.close()
    
    for db in all_dbs:
        db = db[0]
        try:
            con = psycopg2.connect(
                dbname=db,
                user=username, 
                host=fqdn,
                port=str(port),
                password=password,
                sslmode='require'
            )

            cursor = con.cursor()

            cursor.execute("SELECT * FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';")

            print("--------------------------------")
            print(" ALL TABLE IN %s ") % (db)
            print(cursor.fetchall())
            print("--------------------------------")
            cursor.execute("SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;")
            print("--------------------------------")
            lines = cursor.fetchall()
            print(lines)
            
            print("We found %s Lines in %s" % (lines[2], lines[1]))
            print("--------------------------------")
            con.close()
            
        except:
            print("error while retrieving tables for DB: " + db)
        




    


main() 


