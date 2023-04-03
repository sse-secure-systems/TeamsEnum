#!/usr/bin/python3

import requests
import json
from getpass import getpass
from msal import PublicClientApplication
from teamsenum.utils import p_success, p_warn, p_err, p_normal, p_info, p_file

def check_account_type(username):
   """
   Checks whether the user account is a personal or corporate account.
   This information is important since different endpoints and token types are used between those two categories.

   Args:
       username (str): The username that is used for authentication.

   Returns:
       A JSON structure containing information about the accounts existence, and its type (dict)
   """
   if "@" not in username:
      p_warn("Invalid username format", exit=True)

   domain = username.split("@")[-1]

   is_microsoft_account = False

   # Accounts with an outlook.de, outlook.com and hotmail.com domain are MSA accounts and are classified as personal accounts.
   is_microsoft_account = domain.lower() in ["outlook.de", "outlook.com", "hotmail.com"]

   headers = {
      "Content-Type": "application/json"
   }

   payload = {
      "username":username,
      "isOtherIdpSupported":"true",
   }

   # Fetch some information about the provided user account
   content = requests.post("https://login.microsoftonline.com/common/GetCredentialType", headers=headers, json=payload)

   json_content = json.loads(content.text)
   if "IfExistsResult" not in json_content:
      p_warn("Error retrieving account status", exit=True)

   # IfExistsResult is used to determine whether or not an account exists, and if the account type is personal or corporate

   account_types = {
       1: {"exists": False}, # User does not exist
       0: {"exists": True, "type": "corporate", "msa": is_microsoft_account},
       4: {"exists": False}, # User invalid
       5: {"exists": True, "type": "personal", "msa": is_microsoft_account},
       6: {"exists": True, "type": "personal_and_corporate", "msa": is_microsoft_account},
   }

   if_exists_result = json_content.get("IfExistsResult")

   if if_exists_result not in account_types:
      p_warn("Unknown account type - There might have been a change in the Microsoft API - Please reach out", exit=True)

   return account_types.get(if_exists_result)

def get_tenant_id(username):
   """
   Based on an email address, try to fetch the tenant id if a corporate account is used.

   Args:
       username (str): The username that is used to check what tenant it belongs to.

   Returns:
       Tenant-ID (str): ID of the queried tenant
   """
   domain = username.split("@")[-1]
   response = requests.get("https://login.microsoftonline.com/%s/.well-known/openid-configuration" % (domain))
   if response.status_code != 200:
      p_warn("Could not retrieve tenant id for domain %s" % (domain), exit=True)
   json_content = json.loads(response.text)
   tenant_id = json_content.get('authorization_endpoint').split("/")[3]
   return tenant_id

def account_is_teams_enrolled(accesstoken, account_type):
   """
   Find out whether the own user account is enrolled in Teams

   Args:
       accesstoken (str): The access token that is used for authentication

   Returns:
       Statement if account is enrolled (boolean): Returns True or False, depending on the Teams subscription
   """

   if account_type == "personal":
      return True

   headers = {
      "Authorization": "Bearer %s" % (accesstoken)
   }

   # Fetch information about the own user
   response = requests.get("https://teams.microsoft.com/api/mt/emea/beta/users/tenants", headers=headers)

   if response.status_code != 200:
      p_warn("Could not retrieve Teams enrollment status for account")

   json_content = json.loads(response.text)

   if len(json_content) == 0:
      p_warn("Could not retrieve Teams enrollment status for account")
      return False

   if "userId" not in json_content[0]:
      p_warn("Could not retrieve Teams enrollment status for account")
      return False

   if "hasNoAccess" in json_content[0] and json_content[0].get('hasNoAccess') == True:
      p_warn("Your account does not have a valid Teams subscription. You can still enumerate valid users but won't get all user details.")
      return False

   p_success("Found a valid Teams subscription for your account")
   return True

def get_skype_token(access_token):
   """
   Personal accounts that use the live.com endpoints require an additional X-Skypetoken header.
   In order to acquire this, a valid bearer token has to be provided.

   Args:
       access_token (str): The bearer token used to make an authenticated request.

   Returns:
       A valid Skypetoken (str)
   """
   headers = {
       "Authorization": "Bearer " + access_token
   }

   # Requests a Skypetoken
   content = requests.post("https://teams.live.com/api/auth/v1.0/authz/consumer", headers=headers)

   if content.status_code != 200:
      p_err("Error: %d" % (content.status_code), exit=True)
      return

   json_content = json.loads(content.text)
   if "skypeToken" not in json_content:
      p_warn("Could not retrieve Skype token", exit=True)
   return json_content.get("skypeToken").get("skypetoken")

def logon_with_credentials(auth_metadata, username, password, account_type):
   """
   Attempts to log in to the specified app using the provided credentials and scope.
   This method can't be used with personal accounts.

   Args:
       auth_metadata (dict): Dict containing scope, client_id and tenant for oauth flow.
       username (str): The username to use for authentication.
       password (str): The password to use for authentication.
       account_type (dict): Dict containing information about the user account

   Returns:
       Access token (dict): An object containing access tokens
   """

   if account_type.get('type') == "personal" or account_type.get('msa') is True:
      p_warn("Username/Password authentication cannot be used with personal Microsoft accounts. Either use the device code authentication flow or try again with a user managed by an organization.", exit=True)

   p_info("Attempting to login with provided credentials")

   # Ask for the password if not specified on the command line. Otherwise use the provided value
   if password is None:
      p_info("Please enter the password to authenticate:")
      password = getpass("")

   # Initialize MSAL logon sequence only if device code or password-based authentication is used.
   app = PublicClientApplication( auth_metadata.get('client_id'), authority="https://login.microsoftonline.com/%s" % (auth_metadata.get('tenant')) )

   result = None

   try:
      # Initiates authentication based on credentials.
      result = app.acquire_token_by_username_password(username, password, scopes=[auth_metadata.get('scope')])
   except ValueError as err:
      if "This typically happens when attempting MSA accounts" in err.args[0]:
         p_warn("Username/Password authentication cannot be used with Microsoft accounts. Either use the device code authentication flow or try again with a user managed by an organization.", exit=True)
      p_warn("Error while acquring token", exit=True)
   return result, app

def logon_with_devicecode(auth_metadata):
   """
   Attempts to log in based on a device code authentication flow. This routine is recommended when using this script on a machine without internet access or when MFA is required.

   Args:
       auth_metadata (dict): Dict containing scope, client_id and tenant for oauth flow.

   Returns:
       Access token (dict): An object containing access tokens
   """
   # Initialize MSAL logon sequence only if device code or password-based authentication is used.
   app = PublicClientApplication( auth_metadata.get('client_id'), authority="https://login.microsoftonline.com/%s" % (auth_metadata.get('tenant')) )

   try:
      # Initiate the device code authentication flow and print instruction message
      flow = app.initiate_device_flow(scopes=[auth_metadata.get('scope')])
      if "user_code" not in flow:
         p_warn("Could not retrieve user code in authentication flow", exit=True)
      p_info(flow.get("message"))
   except:
      p_warn("Could not initiate device code authentication flow", exit=True)

   # Initiates authentication based on the previously created flow. Polls the MS endpoint for entered device codes.
   try:
      result = app.acquire_token_by_device_flow(flow)
   except Exception as err:
      p_warn("Error while authenticating: %s" % (err.args[0]), exit=True)

   return result, app

def logon_with_accesstoken(auth_metadata, app):
   """
   Attempts to log in based on an access token. This step is required to acquire a X-Skypetoken using the previously acquired Bearer token

   Args:
       app (msal.application.PublicClientApplication): The application context used to log in.

   Returns:
       Access token (dict): An object containing access tokens
   """

   try:
      # Fetches cached logins
      accounts = app.get_accounts()
      result = app.acquire_token_silent(scopes=["service::api.fl.spaces.skype.com::MBI_SSL openid profile"], account=accounts[0])
   except Exception as err:
      p_warn("Error while authenticating: %s" % (err.args[0]), exit=True)

   return result

def check_token_format(accesstoken, skypetoken):
   """
   Performs some very basic checks to distinguish between corporate and personal tokens, based on the first token bytes

   Args:
       accesstoken (str): The access token that is mandatory for authentication
       skypetoken (str): The skypetoken that is only relevant for personal accounts

   Returns:
       Account type (str): String that indicates whether the account is 'personal' or 'corporate'
       Access token (str): Returns the access token if the check was successful
       Skypetoken (str): Return the skypetoken if the check was successful
   """
   if not accesstoken:
      p_warn("Token authentication type selected, but accesstoken missing", exit=True)

   if "ey" == accesstoken[0:2]:
      return "corporate", accesstoken, None

   elif "Ew" == accesstoken[0:2]:
      if not skypetoken:
         p_warn("Personal account used, but mandatory Skypetoken is missing", exit=True)
      return "personal", accesstoken, skypetoken

   else:
      p_warn("Unknown access token format - If this error was raised by mistake, please reach out", exit=True)


def get_authentication_metadata(account_type, username):
   """
   Based on the account type, returns a set of distinct oauth scope, client_id and tenant id

   Args:
       account_type (str): Type of the account that is used for authentication

   Returns:
       Authentication information (dict): Information that is used during the oauth authentication flow
   """
   if account_type == "personal":
      return {
                'scope': 'service::api.fl.teams.microsoft.com::MBI_SSL openid profile',
                'client_id':'5e3ce6c0-2b1f-4285-8d4b-75ee78787346',
                'tenant':'9188040d-6c67-4c5b-b112-36a304b66dad'
             }

   if account_type == "corporate" or account_type == "personal_and_corporate":
      return {
                'scope':'https://api.spaces.skype.com/.default',
                'client_id':'1fec8e78-bce4-4aaf-ab1b-5451cc387264',
                'tenant':get_tenant_id(username)
             }

   return {}

def do_logon(args):
   """
   Logon wrapper that performs actions depnding on the chosen logon type.

   Args:
       args (dict): Command line arguments, passed to the application.

   Returns:
       Account type (str): Account type, either 'personal' or 'corporate'
       Access Token (str): Access token for primary authentication
       Skypetoken (str): Skypetoken, used by personal accounts
       teams_enrolled (boolean): Flag whether the own account is enrolled in Teams
   """
   if args.authentication == "token":
      account_type, accesstoken, skypetoken = check_token_format(args.bearertoken, args.skypetoken)
      teams_enrolled = account_is_teams_enrolled(accesstoken, account_type)
      return account_type, accesstoken, skypetoken, teams_enrolled

   # If device code or password-based authentication is used, the username needs to be provided to check if the account is a personal or corporate account
   if not args.username:
      p_warn("Password or device code authentication type selected, but username missing", exit=True)

   # For all auth methods except token the username needs to be analysed to find the correct API endpoints
   p_info("Checking account type")
   account_type = check_account_type(args.username)
   p_info("Account type is: %s" % (account_type.get('type')))

   # Retrieves scope, client_id and tenant id, based on the account type
   auth_metadata = get_authentication_metadata(account_type.get('type'), args.username)

   # Check if user account exists. If not exit program
   if account_type.get('exists') == False:
      p_warn("Username does not exist", exit=True)

   result = None

   # Go to device code login sequence
   if args.authentication == "devicecode":
      result, app = logon_with_devicecode( auth_metadata )
   # Go to password-based login sequence
   elif args.authentication == "password":
      result, app = logon_with_credentials( auth_metadata, args.username, args.password, account_type )

   # Login not successful
   if "access_token" not in result:
      if "Error validating credentials due to invalid username or password" in result.get("error_description"):
         p_warn("Invalid credentials entered", exit=True)
      elif "This device code has expired" in result.get("error_description"):
         p_warn("The device code has expired. Please try again", exit=True)
      else:
         p_warn(result.get("error_description"), exit=True)

   # Login successful, Token is retrieved
   p_success("Successfully retrieved access token")
   teams_enrolled = account_is_teams_enrolled(result["access_token"], account_type.get('type'))

   skypetoken = None
   if account_type.get('type') == "personal":
      result_tokenlogin = logon_with_accesstoken(auth_metadata, app)
      skypetoken = get_skype_token(result_tokenlogin["access_token"])
      p_success("Successfully retrieved skype token")

   return account_type.get('type'), result["access_token"], skypetoken, teams_enrolled
