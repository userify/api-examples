#! /usr/bin/env python

# Userify Cloud Signup
# Copyright (c) 2017 Userify Corporation

try:
    import json
except:
    import simplejson as json
import subprocess
import os, os.path, sys
import httplib
import base64
import string
import getpass
import socket
from pprint import pprint, pformat
import ssl
import tempfile
import time
import argparse # python 2.7 & later
import configparser
import random

# recapture sdtin, since it's closed since we're
# coming in from a piped process..
sys.stdin = open('/dev/tty')

ssl_security_context = None
try:
    # fails on python < 2.6:
    import ssl
    # not avail in python < 2.7:
    ssl_security_context = (hasattr(ssl, '_create_unverified_context')
        and ssl._create_unverified_context() or None)
except:
    pass

# socket.setdefaulttimeout(60)


def die(code, text):
    print("")
    print ("Sorry! Something went wrong with this script!")
    print ("Please email support@userify.com "
          +"and we'll fix it asap!\n")
    print("%s %s" % (code, text))
    sys.exit(1)


class API:

    auth = ""
    https_proxy = ""
    https_proxy_port = 443
    debug = False

    def __init__(self, host="api.userify.com", port=443, prefix="/api/userify", debug=False):
        self.final_host = host
        self.final_port = port
        self._retrieve_https_proxy()
        self.prefix = prefix
        self.debug_log = []

    def log(self, msg):
        self.debug_log.append(str(msg))
        if self.debug: print msg

    def login(self, username, password):
        self.auth = "Basic " + base64.b64encode(
            ":".join((username, password)))

    def _retrieve_https_proxy(self):
        # thx Purinda Gunasekara @ News Corp:
        if 'https_proxy' in os.environ:
            self.https_proxy = os.environ['https_proxy'].strip()
            if self.https_proxy.startswith("http"):
                self.https_proxy = https_proxy.replace("https://","",1)
                self.https_proxy = https_proxy.replace("http://","",1)
                if ":" in self.https_proxy:
                    self.https_proxy, self.https_proxy_port = self.https_proxy.split(":")
                    self.https_proxy_port = int(''.join(c for c in self.https_proxy_port if c.isdigit()))

    def https(self, method, path, data=""):
        if ssl_security_context:
            reqobj = httplib.HTTPSConnection(
                self.https_proxy if self.https_proxy else self.final_host,
                self.https_proxy_port if self.https_proxy_port else self.final_port,
                timeout=20,
                context=ssl_security_context)
        else:
            reqobj = httplib.HTTPSConnection(
                self.https_proxy if self.https_proxy else self.final_host,
                self.https_proxy_port if self.https_proxy_port else self.final_port,
                timeout=20)
        self.log("NEW https connection %s" % reqobj)
        if self.https_proxy:
            self.log("Proxy %s:%s" % (self.final_host, self.final_port))
            reqobj.set_tunnel(self.final_host, self.final_port)
        self.log("Host: %s:%s" % (self.final_host, self.final_port))
        data = data or {}
        data['signup_version'] = "1.0"
        data = json.dumps(data)
        headers = {"Accept": "text/plain, */json"}
        if self.auth:
            headers["Authorization"] = self.auth
        self.log("%s %s" % (method, path))
        self.log(pformat(data))
        self.log(pformat(headers))
        try:
            reqobj.request(method, path, data, headers)
        except Exception, e:
            self.log("Error: %s" % e)
        return reqobj

    def _handle_error(self, text, handle_error=True):
        if handle_error and self.response.status != 200:
            self.log(self.response.status)
            if text and text.startswith('{"error": '):
                self.log(json.loads(text)["error"])
            else:
                self.log("%s %s" % (self.response.reason, text))
            self.log("Please try again at https://dashboard.userify.com")
            self.log("or email support@userify.com.")
            print("\n".join(self.debug_log))
            die(self.response.status, self.response.reason)

    def request(self, method, path, data=""):
        path = self.prefix.rstrip("/") + "/" + path.lstrip("/")
        self.log(path)
        reqobj = self.https(method, path, data)
        # reqobj.sock.settimeout(15)
        self.response = reqobj.getresponse()
        self.log(self.response.status)
        self.log(self.response.msg)
        self.log(self.response.reason)
        return self.response.read()

    def _handle_request(self, method, path, data, handle_error=True):
        self.log(method)
        self.log(path)
        self.log(data)
        response_data = self.request(method, path, data)
        self.log(response_data)
        if handle_error:
            self._handle_error(response_data, handle_error)
        data = json.loads(response_data) if response_data else {}
        return self.response, data

    def head(self, path, data="", handle_error=True):
        return self._handle_request("HEAD", path, data, handle_error=handle_error)

    def get(self, path, data="", handle_error=True):
        return self._handle_request("GET", path, data, handle_error=handle_error)

    def put(self, path, data, handle_error=True):
        return self._handle_request("PUT", path, data, handle_error=handle_error)

    def post(self, path, data, handle_error=True):
        return self._handle_request("POST", path, data, handle_error=handle_error)

    def delete(self, path, data="", handle_error=True):
        return self._handle_request("DELETE", path, data, handle_error=handle_error)


def string_test(s, is_email=False):
    safe = (string.ascii_letters + string.digits + "_")
    if is_email:
        safe += "@.,+-"
    if not s:
        return ""
    s = s.strip().lower()
    if not s:
        return ""
    if not is_email and s[0] not in string.ascii_letters:
        print "Linux usernames must start with a Latin alphabet letter."
        return ""
    if is_email and (not "@" in s or len(s.split("@")) < 2):
        return ""
    for k in list(s):
        if k not in safe:
            print "Sorry, unsupported character: %s" % k
            return ""
    return s


def main():

    creds_help = "\n".join(("This requires a .userify_creds.ini file in your home directory,\nwith the following format:\n\n",
        "[default]",
        "hostname=api.userify.com",
        "username=USERNAME",
        "password=PASSWORD",
    ))

    parser = argparse.ArgumentParser(
        description="Create/sign up users via the Userify API (all editions).",
        epilog=creds_help)
    parser.add_argument("--email", help="Email of the user to create (required)", action="store")
    parser.add_argument("--username", help="Username of the user to create (required)", action="store")
    parser.add_argument("--password", help="User password (optional, otherwise user must request reset)", action="store")
    parser.add_argument("--company_id", help="Optionally add company ID to add the user to (optional)", action="store")
    parser.add_argument("--list-companies", help="List my company IDs and exit.", action="store_true")
    parser.add_argument("--profile", help="Name of the profile in the .userify_creds.ini file to use (optional)", action="store")
    parser.add_argument("--auth_file", help="Filename to load your user ID and password from (default $HOME/.userify_creds.ini)(optional)", action="store")
    parser.add_argument("--invite-only", help="Only invite the requested user to join your company (do not attempt to create)(optional)", action="store_true")
    args = parser.parse_args()

    # try to read credentials
    USER = os.environ.get("USER", "")
    HOME = os.environ.get("HOME", "")
    CREDS = {}

    # hopefully HOME isn't /root/ ...!
    for HOMEDIR in [HOME, "/home/%s" % USER]:
        INIFILE = HOMEDIR + "/.userify_creds.ini" if HOMEDIR else ""
        if os.path.isfile(INIFILE):
            CREDS = configparser.ConfigParser()
            try:
                CREDS.read(INIFILE)
            except:
                raise
            break

    if not CREDS:
        print creds_help
        sys.exit(1)

    if args.profile:
        args.profile = args.profile.lower()
    else:
        args.profile = "default"

    if args.profile in CREDS:
        CREDS = CREDS[args.profile]
    else:
        print "Profile %s was not found in ~/.userify_creds.ini" % args.profile
        sys.exit(1)

    if not CREDS or not CREDS["username"] or not CREDS["password"]:
        print creds_help
        sys.exit(1)

    if "hostname" not in CREDS:
        CREDS["hostname"] = "dashboard.userify.com"

    # create API object
    api = API(host=CREDS["hostname"])

    # check args.username and args.email
    args.username = string_test(args.username)
    args.email = string_test(args.email, is_email=True)
    if not args.username or not args.email:
        parser.print_help()
        sys.exit(1)

    # generate long random password if not provided:
    if not args.password or len(args.password) < 8:
        args.password = ''.join(random.choice(string.letters) for i in range(64))

    # login and verify that getting profile works for the user in ~/.userify_creds.ini
    api.login(CREDS["username"], CREDS["password"])
    response, this_user_account = api.get("/profile", handle_error=False)
    if response.status == 412:
        print ("Unable to log %s in: %s"%(CREDS["username"], "This account requires an MFA code."))
        print ("Please set a non-MFA username and password in ~/.userify_creds.ini")
        sys.exit(1)
    elif response.status != 200:
        if this_user_account and "error" in this_user_account:
            error = this_user_account["error"]
            print ("Unable to log %s in: %s"%(CREDS["username"], error))
            print ("Please confirm your username and password in ~/.userify_creds.ini")
            sys.exit(1)
        else:
            print ("Unable to log %s in: %s"%(CREDS["username"], this_user_account))
            print ("Please confirm your username and password in ~/.userify_creds.ini")
            sys.exit(1)

    if args.list_companies:
        if this_user_account["companies"]:
            print ("Available company IDs:\n%s" % "\n".join(
                this_user_account["companies"]))
        else:
            print "User %s has no companies." % args.username
        sys.exit(1)

    if not args.invite_only:
        # create user account.
        data = {"username": args.username, "password": args.password, "email": args.email}
        response, response_data = api.post("/profile", data, handle_error=False)
        if response.status != 200:
            if response_data and "error" in response_data:
                error = response_data["error"]
                if response.status == 400:
                    print (str(args.username).ljust(40)+error)
                    sys.exit(1)
            else:
                api._handle_error(response_data, handle_error=True)

    # now invite the user to the company
    if args.company_id:

        print "/invitation/company_id/" + args.company_id + "/email/" + args.email

        response, response_data = api.put(
            "/invitation/company_id/" + args.company_id
            + "/email/" + args.email, {}, handle_error=False)
        if response.status != 200:
            if response_data and "error" in response_data:
                error = response_data["error"]
                if response.status == 400:
                    print (str(args.username).ljust(40)+error)
                    if error.endswith("is not available."):
                        if this_user_account["companies"]:
                            print ("Available company IDs:\n%s" % "\n".join(
                                this_user_account["companies"]))
                        else:
                            print "User %s has no companies." % args.username
                    sys.exit(1)
            else:
                api._handle_error(response_data, handle_error=True)
                sys.exit(1)
    
    print args.username.ljust(40), "success"



if __name__ == "__main__":
    main()
