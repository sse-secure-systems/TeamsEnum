#!/usr/bin/python3

import argparse
import requests
import json
import os
import teamsenum.auth
import time
from teamsenum.auth import p_success, p_err, p_warn, p_normal, p_info
from teamsenum.enum import TeamsUserEnumerator

def banner(__version__):
   print("""
 _______                       ______                       
|__   __|                     |  ____|                      
   | | ___  __ _ _ __ ___  ___| |__   _ __  _   _ _ __ ___  
   | |/ _ \/ _` | '_ ` _ \/ __|  __| | '_ \| | | | '_ ` _ \ 
   | |  __/ (_| | | | | | \__ \ |____| | | | |_| | | | | | |
   |_|\___|\__,_|_| |_| |_|___/______|_| |_|\__,_|_| |_| |_|

   v%s developed by %s
   %s
   """ % (__version__, "@_bka_", "SSE | Secure Systems Engineering GmbH"))

if __name__ == "__main__":
   """
   Main entrypoint. Parses command line arguments and invokes login and enumeration sequence.

   Args:
      argv (str []): Command line arguments passed to this script

   Returns:
      None
   """
   __version__ = "1.0.0"

   banner(__version__)
   parser = argparse.ArgumentParser()

   parser.add_argument('-a', '--authentication', dest='authentication', choices=['devicecode','password','token'], required=True, help='')
   parser.add_argument('-u', '--username', dest='username', type=str, required=False,  help='Username for authentication')
   parser.add_argument('-p', '--password', dest='password', type=str, required=False, help='Password for authentication')
   parser.add_argument('-o', '--outfile', dest='outfile', type=str, required=False, help='File to write the results to')

   parser.add_argument('-d', '--devicecode', dest='devicecode', type=str, required=False, help='Use Device code authentication flow')

   parser.add_argument('-s', '--skypetoken',  dest='skypetoken',  type=str, required=False, help='Skype specific token from X-Skypetoken header. Only required for personal accounts')
   parser.add_argument('-t', '--accesstoken', dest='bearertoken', type=str, required=False,  help='Bearer token from Authorization: Bearer header. Required by teams and live.com accounts')

   parser.add_argument('--delay', dest='delay', type=int, required=False, default=0, help='Delay in [s] between each attempt. Default: 0')

   parser_inputdata_group = parser.add_mutually_exclusive_group(required=True)
   parser_inputdata_group.add_argument('-e', '--targetemail', dest='email', type=str, required=False, help='Single target email address')
   parser_inputdata_group.add_argument('-f', '--file', dest='file', type=str, required=False, help='Input file containing a list of target email addresses')
   args = parser.parse_args()

   if args.outfile:
      fd = teamsenum.utils.open_file(args.outfile)
   else:
      fd = None

   accounttype, bearertoken, skypetoken, teams_enrolled = teamsenum.auth.do_logon(args)

   enum = TeamsUserEnumerator(skypetoken, bearertoken, teams_enrolled)

   if (args.email):
      emails = [args.email]

   if (args.file):
      with open(args.file) as f:
         emails = f.readlines()

   p_info("Starting user enumeration\n")
   for email in emails:
      time.sleep(args.delay)
      enum.check_user(email.strip(), accounttype, presence=True, outfile=fd)

   if fd:
      fd.close()
