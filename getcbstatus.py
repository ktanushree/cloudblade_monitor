#!/usr/bin/env python
"""
Prisma SDWAN script to get CloudBlade Status from the Monitor tab
tkamath@paloaltonetworks.com
"""
import sys
import os
import argparse
import cloudgenix
import pandas as pd
import sys
import os
import datetime

SCRIPT_NAME = "Get CloudBlade Monitor Status"
SCRIPT_VERSION = "v1.0"


# Import CloudGenix Python SDK
try:
    import cloudgenix
except ImportError as e:
    cloudgenix = None
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {0}\n".format(e))
    sys.exit(1)

# Check for cloudgenix_settings.py config file in cwd.
sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # if cloudgenix_settings.py file does not exist,
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    # Also, separately try and import USERNAME/PASSWORD from the config file.
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


# Handle differences between python 2 and 3. Code can use text_type and binary_type instead of str/bytes/unicode etc.
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes



APP_STATUS_BASE_URL = "https://sdwanappsapi.hood.cloudgenix.com/v2.0/api/tenants/{}/sdwanapps/{}/appstatus/{}"
cb_input_name = {
    "aws": "AWS Transit Gateway Integration",
    #"azure": "Azure Virtual WAN Integration",
    "azure_ion": "Azure Virtual WAN with vION",
    "gcp": "GCP NCC Integration CloudBlade",
    "zs": "Zscaler Enforcement Nodes (ZEN) Integration"
}
cb_id_name = {}
cb_id_status = {}

def create_dicts(cgx_session, cname):
    resp = cgx_session.get.sdwanapps()
    if resp.cgx_status:
        apps = resp.cgx_content.get("items", None)
        for cb in apps:
            cb_id_name[cb["id"]] = cb["name"]
            if cb["name"] == cname:
                resp = cgx_session.get.sdwanapps_configs(sdwanapp_id=cb["id"])
                if resp.cgx_status:
                    config = resp.cgx_content.get("items")[0]
                    if config.get("state") == "enabled":
                        print("INFO: CloudBlade {} is enabled. Getting Status data..".format(cname))
                        return cb["id"]
                    else:
                        print("ERR: CloudBlade is not enabled. Can't get status details")
                        cloudgenix.jd_detailed(resp)
                        cleanexit(cgx_session)
                else:
                    print("ERR: Could not retrieve CloudBlade Status")
                    cloudgenix.jd_detailed(resp)
                    cleanexit(cgx_session)

    else:
        print("ERR: Could not retrieve CloudBlades")
        cloudgenix.jd_detailed(resp)
        cleanexit(cgx_session)


def cleanexit(cgx_session):
    print("INFO: Logging Out")
    cgx_session.get.logout()
    sys.exit()


def go():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run do_site()
    :return: No return
    """

    #############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Debug Settings
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--sdkdebug", "-D", help="Enable SDK Debug output, levels 0-2", type=int,
                             default=0)

    # Config Settings
    config_group = parser.add_argument_group('Config', 'Provide CloudBlade Detail')
    config_group.add_argument("--cloudblade", "-CN", help="Enter CloudBlade Name. Allowed values: aws, azure_ion, gcp, zs", default=None)

    ############################################################################
    # Parse arguments provided via CLI
    ############################################################################
    args = vars(parser.parse_args())
    sdk_debuglevel = args["sdkdebug"]
    cloudblade = args["cloudblade"]

    if cloudblade not in ["aws", "azure_ion", "gcp", "zs"]:
        print("ERR: Invalid cloudblade. Please provide a valid cloudblade name. Allowed values: aws, azure_ion, gcp, zs")
        sys.exit()

    ############################################################################
    # Instantiate API & Login
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    cgx_session.set_debug(sdk_debuglevel)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, cgx_session.version, cgx_session.controller))

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
    # Update User Role
    ############################################################################
    cname = cb_input_name[cloudblade]
    cid = create_dicts(cgx_session, cname)

    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
    tenantname = cgx_session.tenant_name
    tenantname = tenantname.replace(" ", "")
    tenantname = tenantname.replace("/", "")

    if cloudblade == "aws":
        print("INFO: Retrieving data from AWS Status tab")
        status = "status?limit=10&offset=0"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid,status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_status_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from AWS Status saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

        print("INFO: Retrieving data from AWS Site Connectivity tab")
        status = "site_connectivity?limit=10&offset=0"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_siteconn_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from AWS Site Connectivity saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

    elif cloudblade == "azure_ion":
        print("INFO: Retrieving data from Azure Deployment Status tab")
        status = "status?limit=10&offset=0&order=des&sort=timestamp"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_status_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from Azure Deployment Status saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

        print("INFO: Retrieving data from Azure Site Connectivity tab")
        status = "site_connectivity?limit=10&offset=0"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_siteconn_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from Azure Site Connectivity saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)


    elif cloudblade == "gcp":
        print("INFO: Retrieving data from GCP Deployment Status tab")
        status = "status?limit=10&offset=0"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_status_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from GCP Deployment Status saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

        print("INFO: Retrieving data from GCP Site Connectivity tab")
        status = "site_connectivity?limit=10&offset=0"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_siteconn_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from GCP Site Connectivity saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

    elif cloudblade == "zs":
        print("INFO: Retrieving data from Stats tab")
        status = "stats?limit=10&offset=0"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_stats_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from ZScaler Stats saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)


        print("INFO: Retrieving data from Summary tab")
        status = "summary?limit=10&offset=0&order=asc&sort=siteName"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_summary_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from ZScaler Summary saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

        print("INFO: Retrieving data from Detail tab")
        status = "details?limit=10&offset=0&order=asc&sort=siteName"
        status_url = APP_STATUS_BASE_URL.format(cgx_session.tenant_id, cid, status)
        resp = cgx_session.rest_call(url=status_url, method="GET")
        if resp.cgx_status:
            data = resp.cgx_content.get("data", None)
            links = resp.cgx_content.get("links", None)
            df = pd.DataFrame(data)

            filename = "{}/{}_{}_detail_{}.csv".format(os.getcwd(), tenantname, cloudblade, curtime_str)
            df.to_csv(filename, index=False)
            print("INFO: Data from ZScaler Detail saved to {}".format(filename))

        else:
            print("ERR: Could not retrieve CloudBlade status")
            cloudgenix.jd_detailed(resp)
            cleanexit(cgx_session)

    ############################################################################
    # Logout to clear session.
    ############################################################################
    cleanexit(cgx_session)


if __name__ == "__main__":
    go()
