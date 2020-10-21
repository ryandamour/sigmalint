#!/usr/bin/python3
from bs4 import BeautifulSoup
import requests
import re

def mitre_pull(technique_id):
  tactics = []

  # Redirect
  try:
      url = "https://attack.mitre.org/techniques/{}/".format(str(technique_id))
      redirect = requests.get(url,allow_redirects=True)
      redirect_url = re.search('url=/(.*)"',redirect.text) 

      # Technique URL
      mitre_url = "https://attack.mitre.org/{}/".format(str(redirect_url.group(1)))
      mitre_request = requests.get(mitre_url,allow_redirects=False)
      mitre_soup = BeautifulSoup(mitre_request.text,"html.parser")

      # Tactic ID's
      tactic_id = mitre_soup.find('div', class_='card-data', id='card-tactics').get_text()
      tactic_id = tactic_id.replace('Tactics:','').replace(' ','').replace('Tactic:\n','').strip("\n") 
      tactic_id = tactic_id.split(',') 
      tactics = tactic_id
  
      # Sub Techniques
      sub_techniques_regex = re.search('Sub-technique of(.*?)</a>',mitre_request.text,re.M | re.DOTALL)
      sub_techniques = sub_techniques_regex.group(1).replace(':&nbsp;','').replace(' ','').strip("\n")
      sub_techniques = re.sub('<[^>]+>','',sub_techniques)
      sub_techniques = sub_techniques.replace('\n','')

      return tactics, sub_techniques
  except:
      return None, None 
