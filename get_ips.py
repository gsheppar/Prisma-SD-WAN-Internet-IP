#!/usr/bin/env python3

import prisma_sase
import argparse
from prisma_sase import jd, jd_detailed, jdout
import prismasase_settings
import sys
import logging
import os
import datetime
import collections
import csv
import ipaddress
from csv import DictReader
import time
from datetime import datetime, timedelta
import math
import re

# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SCRIPT_NAME = 'CloudGenix: Get Public IP'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())

try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID

except ImportError:
    PRISMASASE_CLIENT_ID=None
    PRISMASASE_CLIENT_SECRET=None
    PRISMASASE_TSG_ID=None

def get(cgx):
    
    
    ion_list = []
    
    for site in cgx.get.sites().cgx_content['items']:
        site_name = site["name"]
        site_id = site["id"]
        for element in cgx.get.elements().cgx_content['items']:
            if element["site_id"] == site_id:
                element_id = element["id"]
                element_name = element["name"]
                if element_name == None:
                    element_name = "no-name-element"
                print("Checking " + element_name)
                try:
                    for interface in cgx.get.interfaces(site_id=site_id, element_id=element_id).cgx_content['items']:
                        if interface["used_for"] == "public" and interface["site_wan_interface_ids"]:                      
                            try:
                                ion_data = {}
                                ion_data["Site_Name"] = site_name
                                ion_data["ION_Name"] = element_name
                                ion_data["Interface"] = interface["name"]
                                ion_data["DHCP/Static"] = interface["ipv4_config"]["type"]
                                ion_data["IP"] = None
                                ion_data["Gateway"] = None
                                
                                
                                if ion_data["DHCP/Static"] == "static":
                                    if interface["ipv4_config"]["static_config"]:
                                        ion_data["IP"] = interface["ipv4_config"]["static_config"]["address"]
                                    if interface["ipv4_config"]["routes"]:
                                        ion_data["Gateway"] = interface["ipv4_config"]["routes"][0]["via"]
                                else:
                                    resp = cgx.get.interfaces_status(site_id=site_id, element_id=element_id, interface_id=interface["id"]).cgx_content
                                    if resp["ipv4_addresses"]:
                                        ion_data["IP"] = resp["ipv4_addresses"][0]
                                    if resp["routes"]:
                                        ion_data["Gateway"] = resp["routes"][0]["via"]

                                ion_list.append(ion_data)
                            except:
                                print("Failed to collect interface data on " + element_name + " interface " + interface["name"])
                except:
                    print("No interfaces on " + element_name + " to check")
        
    csv_columns = []        
    for key in (ion_list)[0]:
        csv_columns.append(key) 
    csv_file = "interface_ip.csv"
    try:
        with open(csv_file, 'w', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in ion_list:
                try:
                    writer.writerow(data)
                except:
                    print("Failed to write data for row")
                    print(data)
            print("\nSaved interface_ip.csv file")
    except IOError:
        print("CSV Write Failed")
    
    return

                                          
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    sase_session = prisma_sase.API()
    #sase_session.set_debug(2)
    
    sase_session.interactive.login_secret(client_id=PRISMASASE_CLIENT_ID,
                                          client_secret=PRISMASASE_CLIENT_SECRET,
                                          tsg_id=PRISMASASE_TSG_ID)

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    cgx = sase_session

    get(cgx)
    
    # end of script, run logout to clear session.

if __name__ == "__main__":
    go()