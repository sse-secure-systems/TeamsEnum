#!/usr/bin/python3

import requests
import json
from teamsenum.utils import p_success, p_err, p_warn, p_normal, p_file
from teamsenum.auth import logon_with_accesstoken

class TeamsUserEnumerator:
   """ Class that handles enumeration of users that use Microsoft Teams either from a personal, or corporate account  """

   def __init__(self, skypetoken, bearertoken, teams_enrolled, refresh_token, auth_app, auth_metadata):
      """
      Constructor that accepts authentication tokens for use during enumeration

      Args:
         skypetoken (str): Skype access token
         bearertoken (str): Bearer token for Teams
         teams_enrolled (boolean): Flag to indicate whether the own account has a valid Teams subscription

      Returns:
         None
      """
      self.skypetoken = skypetoken
      self.bearertoken = bearertoken
      self.teams_enrolled = teams_enrolled
      self.refresh_token = refresh_token
      self.auth_app = auth_app
      self.auth_metadata = auth_metadata

   def check_user(self, email, type, presence=False, outfile=None):
      """
      Wrapper that either calls check_live_user or check_teams_user depending on the account type

      Args:
         email (str): Email address of the user that should be checked
         type (str): Type of the account (either 'personal' or 'corporate')
         presence (boolean): Flag that indicates whether the presence should also be checked
         outfile (str): File descriptor for writing the results into an outfile

      Returns:
         None
      """
      if type == "personal":
         self.check_live_user(email, presence, outfile)
      elif type == "corporate":
         self.check_teams_user(email, presence, outfile)

   def check_teams_user(self, email, presence=False, outfile=None, recursive_call=False):
      """
      Checks the existence and properties of a user, using the teams.microsoft.com endpoint

      Args:
         email (str): Email address of the user that should be checked
         presence (boolean): Flag that indicates whether the presence should also be checked
         outfile (str): File descriptor for writing the results into an outfile

      Returns:
         None
      """
      headers = {
         "Authorization": "Bearer " + self.bearertoken,
         "X-Ms-Client-Version": "1415/1.0.0.2023031528",
         "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
      }

      user = {'email':email}
      user['exists'] = False

      content = requests.get("https://teams.microsoft.com/api/mt/emea/beta/users/%s/externalsearchv3?includeTFLUsers=true" % (email), headers=headers)

      if content.status_code == 403:
         user['exists'] = True
         if self.teams_enrolled:
            user['info'] = "User exists but full user details can't be fetched. Either the target tenant or your tenant disallow communication to external domains."
         else:
            user['info'] = "User exists but full user details can't be fetched. You don't have a valid Teams subscription."
         p_success("%s - %s" % (email, user.get('info')))
         p_file(json.dumps(user), outfile)
         return

      if content.status_code == 401:
         if( not recursive_call and self.refresh_token ):
            p_warn("Unable to enumerate user. Trying to get a new access token...")
            result = logon_with_accesstoken(self.auth_metadata, self.auth_app)
            if( 'access_token' in result ):
               p_warn("Got new access token. Rechecking the user...")
               self.bearertoken = result['access_token']
               return self.check_teams_user(email, presence=presence, outfile=outfile, recursive_call=True)
         else:
            p_warn("Unable to enumerate user. Is the access token valid?", exit=True)

      if content.status_code != 200:
         p_warn("Unable to enumerate user %s. Invalid target email address?" % (email))
         return

      user_profile = json.loads(content.text)
      user['info'] = user_profile

      if len(user_profile) > 0 and isinstance(user_profile, list):
         user['exists'] = True
         if presence and "mri" in user_profile[0]:
            mri = user_profile[0].get('mri')
            presence = self.check_teams_presence(mri)
            user['presence'] = presence
         result_stdout = "%s - %s" % (email, user.get('info')[0].get('displayName'))
         result_stdout += "" if not presence else " (%s, %s)" % (user.get('presence')[0].get('presence').get('availability'), user.get('presence')[0].get('presence').get('deviceType'))
         p_success(result_stdout)
      else:

         user['info'] = "Target user not found. Either the user does not exist, is not Teams-enrolled or is configured to not appear in search results (personal accounts only)"
         p_warn("%s - %s" % (email, user.get('info')))

      p_file(json.dumps(user), outfile)

   def check_live_user(self, email, presence=False, outfile=None):
      """
      Checks the existence and properties of a user, using the teams.live.com endpoint

      Args:
         email (str): Email address of the user that should be checked
         presence (boolean): Flag that indicates whether the presence should also be checked
         outfile (str): File descriptor for writing the results into an outfile

      Returns:
         None
      """
      headers = {
         "Content-Type": "application/json",
         "Authorization": "Bearer " + self.bearertoken,
         "X-Skypetoken": self.skypetoken
      }

      payload = {
         "emails": [email],
      }

      content = requests.post("https://teams.live.com/api/mt/beta/users/searchUsers", headers=headers, json=payload)

      if content.status_code == 400:
         p_warn("Unable to enumerate user. Is the Skypetoken valid?", exit=True)

      if content.status_code == 401:
         p_warn("Unable to enumerate user. Is the access token valid?", exit=True)

      if content.status_code != 200:
         p_warn("Error: %d" % (content.status_code))
         return

      json_content = json.loads(content.text)

      if len(json_content) == 0:
         p_warn("Cannot retrieve information about the user %s" % (email))
         return

      for item in json_content:
         user_profile = json_content.get(item).get('userProfiles')
         user = {'email': item}
         user['exists'] = False
         user['info'] = user_profile
         if json_content.get(item).get("status") == "Success":
            user['exists'] = True
            if presence and len(user_profile) > 0 and isinstance(user_profile, list) and "mri" in user_profile[0]:
               mri = user_profile[0].get('mri')
               presence = self.check_live_presence(mri)
               user['presence'] = presence
            result_stdout = "%s - %s" % (email, user.get('info')[0].get('displayName'))
            result_stdout += "" if not presence else " (%s, %s)" % (user.get('presence')[0].get('presence').get('availability'), user.get('presence')[0].get('presence').get('deviceType'))
            p_success(result_stdout)
         else:
            user['info'] = "Target user not found. Either the user does not exist, is not enrolled for Teams or disallows communication with your account"
            p_warn("%s - %s" % (item, user.get('info')))

         p_file(json.dumps(user), outfile)

   def check_teams_presence(self, mri):
      """
      Checks the presence of a user, using the teams.microsoft.com endpoint

      Args:
         mri (str): MRI of the user that should be checked

      Returns:
         Presence data structure (dict): Structure containing presence information about the targeted user
      """
      headers = {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + self.bearertoken,
      }

      payload = [{"mri":mri}]

      content = requests.post("https://presence.teams.microsoft.com/v1/presence/getpresence/", headers=headers, json=payload)

      if content.status_code != 200:
         p_warn("Error: %d" % (content.status_code))
         return

      json_content = json.loads(content.text)
      return json_content

   def check_live_presence(self, mri):
      """
      Checks the presence of a user, using the live.com endpoint

      Args:
         mri (str): MRI of the user that should be checked

      Returns:
         Presence data structure (dict): Structure containing presence information about the targeted user
      """
      headers = {
         "Content-Type": "application/json",
         "X-Ms-Client-Consumer-Type": "teams4life",
         "X-Skypetoken": self.skypetoken
      }

      payload = [{"mri":mri}]

      content = requests.post("https://presence.teams.live.com/v1/presence/getpresence/", headers=headers, json=payload)

      if content.status_code != 200:
         p_warn("Error: %d" % (content.status_code))
         return

      json_content = json.loads(content.text)
      return json_content
