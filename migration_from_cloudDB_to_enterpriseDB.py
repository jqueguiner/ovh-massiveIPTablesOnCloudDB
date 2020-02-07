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

import argparse




def main():

    parser = argparse.ArgumentParser(description='Migration from OVH CloudDB to Enterprise Cloud DB')
    
    parser.add_argument('--config_file',
        default='ovh.conf',
        type=str,
        help='path to OVH config file | default ovh.conf'
        )

    parser.add_argument('--silent_migration',
        default=False,
        type=str2bool, 
        help='Force silent migration : not interactive meaning we might make some default choices for you | Default False'
        )

    parser.add_argument('--original_service',
        default='',
        type=str, 
        help='Cloud Database Service to migrate from (privateSQL) should look like ab12345-001'
        )


    parser.add_argument('--original_database',
        default='',
        type=str, 
        help='Database inside the Original Cloud Database Service to migrate (db_name)'
        )

    parser.add_argument('--original_database_lock', 
        default=True,
        type=str2bool,
        help='Lock the Original Cloud Database to migrate from | Default True'
        )

    parser.add_argument('--destination_service',
        default='',
        type=str, 
        help='Enterprise Cloud Database Service to migrate to (CloudDB) should look like 1234567a-a12a-1234-1abc-a12a1234ab12'
        )

    parser.add_argument('--destination_security_group',
        default='',
        type=str, 
        help='Enterprise Cloud Database Security Group to set IP restriction to | empty security group will lead to creation of a new group'
        )

    parser.add_argument('--destination_user_password',
        default='',
        type=str, 
        help='''
        Enterprise Cloud Database Security Group password | Inline cli password is not recommanded, 
        leaving empty will lead the script to choose his own password'''
        )

    parser.add_argument('--destination_database',
        default='',
        type=str, 
        help='Database to migrate to within the Enterprise Cloud Database Service | if empty will be the same as the original database name'
        )

    parser.add_argument('--destination_database_force_overwrite',
        default=True,
        type=str2bool, 
        help='Force overwrite on destination database | Default True'
        )


    args = handle_options(parser)

    enterprise_create_security_group(args.destination_service, args.destination_security_group)

    transfer_ip_whitelisting(args.original_service, args.destination_service, args.destination_security_group, True)

    destination_user = enterprise_create_user_password(args.destination_service, args.destination_user_password)

    dump_file = dump_db("cloudDB", args.original_service, args.original_database, args.original_database_lock)

    restore_db(dump_file, 
        args.destination_service, 
        destination_user, 
        args.destination_user_password, 
        args.destination_database,
        args.destination_database_force_overwrite
        )


def transfer_ip_whitelisting(original_service, destination_service, destination_security_group, include_local_ip = True):

    ip_restriction_cloudDB = get_ip_restrictions('cloudDB', original_service)

    if include_local_ip:
        response = requests.get('http://ifconfig.co/ip')
        my_ip = response.content.rstrip()
        ip_restriction_cloudDB.append(my_ip)
    else:
        print("[WARNING] Not adding local IP will potentially make the rest of the migration failed !")

    ip_restriction_enterpriseDB = get_ip_restrictions('enterpriseDB', destination_service, destination_security_group)

    set_ip_restrictions(
        db_type="enterpriseDB", 
        service_name=destination_service,
        security_group_to_update=destination_security_group, 
        ip_to_whitelist=ip_restriction_cloudDB, 
        existing_ips=ip_restriction_enterpriseDB
        )

    return ip_restriction_enterpriseDB


def handle_options(parser):

    args = parser.parse_args()

    api_setup(args.config_file)

    if args.original_service == "":
        cloudDB = get_available_db_services('cloudDB')
        print(json.dumps(cloudDB, indent=4))
        args.original_service = raw_input('Please the CloudDB service name to migrate from : ')


    if args.original_database == "":
        cloudb_databases = get_available_database('cloudDB', args.original_service)
        print(json.dumps(cloudb_databases, indent=4))
        args.original_database = raw_input('Please tell me which database to migration from service %s : ' % (args.original_service))


    if args.destination_service == "":
        enterpriseDB = get_available_db_services('enterpriseDB')
        print(json.dumps(enterpriseDB, indent=4))
        args.destination_service = raw_input('Please the Enterprise Database Service to migrate to : ')


    if args.destination_database == "":
        args.destination_database = args.original_database


    if args.destination_security_group == "":
        if args.silent_migration:
            args.destination_security_group = random_name.generate_name()
            print('[INFO] Defining a random security group name as you are in silent_migration mode : %s' % (args.destination_security_group))
        else:
            enterprisedb_groups = enterprise_get_security_groups(args.destination_service)
            print(json.dumps(enterprisedb_groups, indent=4))
            args.destination_security_group = raw_input('Please the Enterprise Database Service Security Group to set IP restrictions to : ')
            if args.destination_security_group == "":
                args.destination_security_group = random_name.generate_name()
                print('[INFO] Defining a random security group name as you defined an empty security group name : %s' % (args.destination_security_group))


    if args.destination_user_password == "":
        args.destination_user_password = randomStringDigits(12) + str(random_with_N_digits(2))


    print("[INFO] Starting Migration with parameters: ")
    print("")
    print(args)
    print("")
    print("")
    print("-------")

    return args


def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


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


def enterprise_get_security_groups(service_name):
    security_groups = client.get('/cloudDB/enterprise/cluster/' + service_name + '/securityGroup')


    security_groups_by_name = dict()

    for security_group in security_groups:
        security_group_details = client.get('/cloudDB/enterprise/cluster/' + service_name + '/securityGroup/' + security_group)
        security_groups_by_name[security_group_details['name']] = security_group_details['id']
       

    return security_groups_by_name


def enterprise_get_security_group_by_name(service_name, security_group_name):
    return enterprise_get_security_groups(service_name)[security_group_name]    


def enterpise_security_group_exists(service_name, security_group_name):
    security_groups = enterprise_get_security_groups(service_name)
    return security_group_name in security_groups


def enterprise_create_security_group(service_name, security_group_name = ""):
        if enterpise_security_group_exists(service_name, security_group_name):
            print("[INFO] %s security group already exists for service %s - Skipping" % (security_group_name, service_name))
        else:
            if security_group_name == "":
                if not silent_migration:
                    security_group_name = raw_input('Please input the Security Group name to create : ')

                if security_group_name == "":
                    security_group_name = random_name.generate_name()
                    print('[INFO] Empty security group name set for service %s so we decided to create a random one : %s' % (service_name, security_group_name))

            print("[INFO] Setting up a new security group (%s) for service %s" % (security_group_name, service_name))    

            result = client.post('/cloudDB/enterprise/cluster/' + service_name + '/securityGroup', 
                clusterId=service_name,
                name=security_group_name
                )

        return security_group_name


def enterprise_create_user_password(service_name, password):

    print('[INFO] Setting destination user password')

    client.post('/cloudDB/enterprise/cluster/' + service_name + '/user', 
        password=password
    )
    
    # time to wait for the new password to be taken into account
    user_updated = False
    while user_updated == False:
        user = client.get('/cloudDB/enterprise/cluster/' + service_name + '/user')
        if user['status'] != 'updated':
            time.sleep(5)
            print('[INFO] Waiting for destination user password changes to apply')
        else:
            print('[INFO] Destination user password changes applied')
            user_updated = True


    return user['name']


def get_available_db_services(db_type):
    
    if db_type == "cloudDB":
        result = client.get('/hosting/privateDatabase')

    else:
        result = client.get('/cloudDB/enterprise/cluster')

    return result


def get_ip_restrictions(db_type, service_name, security_group_name = ''):

    if db_type == "cloudDB":

        existing_ip_tables = client.get('/hosting/privateDatabase/' + service_name + '/whitelist', 
                service=True,
                sftp=True,
            )

        print(" -------- ")
        print("[INFO] Getting current ip restrictions on service %s" % (service_name))

        print(json.dumps(existing_ip_tables, indent=4))

        print(" -------- ")

        return existing_ip_tables

    else:
        if security_group_name == "":
            print(json.dumps(enterprise_get_security_groups, indent=4))
            security_group_name = raw_input('Please tell me which Security Group Name you want to get ip tables from : ')

        
        security_group_id = enterprise_get_security_group_by_name(service_name, security_group_name)
        existing_rules = client.get('/cloudDB/enterprise/cluster/' + service_name + '/securityGroup/' + security_group_id + '/rule')

        existing_ip_tables = list()

        for rule in existing_rules:
            existing_rules = client.get('/cloudDB/enterprise/cluster/' + service_name + '/securityGroup/' + security_group_id + '/rule/' + rule)
            existing_ip_tables.append(existing_rules["source"])


        return existing_ip_tables


def set_ip_restrictions(db_type, service_name, security_group_to_update = "", ip_to_whitelist = [], existing_ips = []):
    print("")
    if db_type == "cloudDB" :
        print("not implemented yet")
    else:
        security_group_id = enterprise_get_security_group_by_name(service_name, security_group_to_update)
        for ip in ip_to_whitelist:
            if not ip in existing_ips:
                try:

                    result = client.post('/cloudDB/enterprise/cluster/' + service_name + '/securityGroup/' + security_group_id + '/rule',
                        source=ip,
                        )
                except Exception as e:
                    print(e)
                    print("[INFO] Failed to set " + ip)
            else:
                print("[INFO] %s already whitelisted" % ip)

        print(" -------- ")


def make_users_ro(db_type, service_name, db_name):
    
    if db_type == "cloudDB" :
        users = client.get('/hosting/privateDatabase/' + service_name + '/user')

        for user in users:            
            client.post('/hosting/privateDatabase/' + service_name + '/user/' + user + '/grant/' + db_name + '/update', 
                grant='ro'
                )
    else:
        print('not implemented yet')


def get_available_database(db_type, service_name):
    if db_type == "cloudDB" :
        db_list = client.get('/hosting/privateDatabase/' + service_name + '/database/')

        return db_list
    else:
        print("not implemented yet")
        return ""


def dump_db(db_type, service_name, db_name, move_to_readonly):
    
    if db_type == "cloudDB" :

        existing_dumps = client.get('/hosting/privateDatabase/' + service_name + '/database/' + db_name + '/dump', 
            )

        if move_to_readonly:
            make_users_ro(db_type, service_name, db_name)

        try:
            client.post('/hosting/privateDatabase/' + service_name + '/database/' + db_name + '/dump', 
                sendEmail=False
                )
        except:
            print('[INFO] Dump already in progress for database %s in service %s' % (db_name, service_name))

        ready = False

        while ready == False:
            print('[INFO] Waiting for dump for database %s in service %s' % (db_name, service_name))

            dumps = client.get('/hosting/privateDatabase/' + service_name + '/database/' + db_name + '/dump', 
                )

            if existing_dumps[0] != dumps[0]:
                dump_id = dumps[0]
                ready = True

            if ready == False:
                time.sleep(5)

        print("[INFO] Dump ready for database %s in service %s with dump_id = %s" % (db_name, service_name, str(dump_id)))

        print("[INFO] Downloading dump for database %s in service %s with id %s " % (db_name, service_name, str(dump_id)))

        dl_dump = client.get('/hosting/privateDatabase/' + service_name + '/database/stats/dump/' + str(dump_id))
        
        print("[INFO] Dump url for dump_id %s is %s" % (str(dump_id), dl_dump["url"]))

        dump_file =  "dump_%s_%s.gz" % (service_name, str(dump_id))

        wget.download(dl_dump["url"], dump_file)

        return dump_file

    else:
        print("Not implemented yet")




def get_rw_endpoint(service_name):
    endpoints = client.get('/cloudDB/enterprise/cluster/' + service_name + '/endpoint')
    fqdn = ""
    port = 0

    for endpoint in endpoints:
        ep = client.get('/cloudDB/enterprise/cluster/' + service_name + '/endpoint/' + endpoint)

        if ep['name'] == "read-write":
            fqdn = ep['fqdn']
            port = ep['port']
            print("[INFO] Found RW endpoint : " + fqdn + ":" + str(port))
        else:
            print("[INFO] Found R endpoint : " + ep['fqdn'] + ":" + str(ep['port']))

    return fqdn, port


def restore_db(dump_file, service_name, username, password, db_name, force_overwrite):

    fqdn, port = get_rw_endpoint(service_name)

    print("[INFO] password : " + password)

    
    
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



        if force_overwrite:
            cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
                sql.Identifier(db_name))
                )

            cursor.execute(sql.SQL("CREATE DATABASE {}").format(
                sql.Identifier(db_name))
            )

            cursor.execute("select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';")

            print(cursor.fetchall())
        else:
            print("[FATAL ERROR] Exiting : As Database exists we can't import the existing database.")
            sys.exit(0)


    cmd = "gzip -d --stdout %s |  PGPASSWORD=%s psql --host %s --username %s --port %d %s" % (dump_file, password, fqdn, username, port,db_name)

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
            print(" ALL TABLES IN %s ") % (db)
            print(cursor.fetchall())
            print("--------------------------------")
            cursor.execute("SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;")
            print("--------------------------------")
            lines = cursor.fetchall()
            print(lines)
            for line in lines:
                print("We found %s Lines in %s.%s" % (line[2], db, line[1]))
                print("--------------------------------")
            con.close()
            
        except:
            print("error while retrieving tables for DB: " + db)


main() 


