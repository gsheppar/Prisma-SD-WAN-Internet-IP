#!/usr/bin/env python3

# 20201020 - Add a function to add a single prefix to a local prefixlist - Dan
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed
import cloudgenix_settings
import sys
import logging
import os
import datetime
import collections
import csv 



# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Get IPs'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

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

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    args = vars(parser.parse_args())
                             
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session

    get(cgx)
    
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()