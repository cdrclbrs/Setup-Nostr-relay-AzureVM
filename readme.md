```shell
 _   _           _          ____       _               
| \ | | ___  ___| |_ _ __  / ___|  ___| |_ _   _ _ __  
|  \| |/ _ \/ __| __| '__| \___ \ / _ \ __| | | | '_ \ 
| |\  | (_) \__ \ |_| |     ___) |  __/ |_| |_| | |_) |
|_| \_|\___/|___/\__|_|    |____/ \___|\__|\__,_| .__/ 
                                                |_|    
````


### What is Nostr?
Nostr is a protocol, designed for simplicity, that aims to create a censorship-resistant global social network. Let's unpack that a little:

### Simple
The protocol is based on very simple & flexible event objects (which are passed around as plain JSON) and uses standard elliptic-curve cryptography for keys and signing. The only supported transport is websockets connections from clients to relays. This makes it easy to write clients and relays and promotes software diversity.

#### Resilient
Because Nostr doesn't rely on a small number of trusted servers for moving or storing data, it's very resilient. The protocol assumes that relays will disappear and allows users to connect and publish to an arbitrary number of relays that they can change over time.

#### Verifiable
Because Nostr accounts are based on public-key cryptography it's easy to verify messages were really sent by the user in question.

Like HTTP or TCP-IP, Nostr is a protocol; an open standard upon which anyone can build. Nostr is not an app or service that you sign up for.

#### Why we need Nostr
Social media has developed into a key way information flows around the world. Unfortunately, our current social media systems are broken:

Uses your attention to sell ads
Uses bizarre techniques to keep you addicted (refer to point 1)
Decides what content to show you based on a secret algorithm that you can't inspect or change
Has complete control over who can participate and who is censored
Is overrun with spam and bots

# Nostr relay Setup on Azure

## Intro

This is a step-by-step, complete guide on how to set up a Nostr relay with Nginx reverse proxy, SSL/TSL 


The steps are based mostly on Azure 
Some content of this setup where adapted based on errors i could encounter, and this setup step-by-step is comming fron BlockChainCaffe reporsitory for AWS deployment.


## Requirements

  - Azure subscription 
  - root privileges (unless otherwise specified all commands are executed as root)
  - a domain you own and can set DNS records
      - in this guide i'll use the nostr.lbrs.io domain

## VM template

```yaml
{
    "resources": [
        {
            "type": "Microsoft.Compute/virtualMachines",
            "apiVersion": "2022-11-01",
            "name": "[parameters('virtualMachines_NOSTRrelay_name')]",
            "location": "westeurope",
            "properties": {
                "hardwareProfile": {
                    "vmSize": "Standard_D2s_v3"
                },
                "storageProfile": {
                    "imageReference": {
                        "publisher": "canonical",
                        "offer": "0001-com-ubuntu-server-jammy",
                        "sku": "22_04-lts-gen2",
                        "version": "latest"
                    },
                    "osDisk": {
                        "osType": "Linux",
                        "name": "[concat(parameters('virtualMachines_NOSTRrelay_name'), '_OsDisk_1_9ba52768022147a1b2c62c58e729574a')]",
                        "createOption": "FromImage",
                        "caching": "ReadWrite",
                        "managedDisk": {
                            "storageAccountType": "StandardSSD_LRS",
                            "id": "[parameters('disks_NOSTRrelay_OsDisk_1_9ba52768022147a1b2c62c58e729574a_externalid')]"
                        },
                        "deleteOption": "Delete",
                        "diskSizeGB": 30
                    },
                    "dataDisks": []
                },
                "osProfile": {
                    "computerName": "[parameters('virtualMachines_NOSTRrelay_name')]",
                    "adminUsername": "XXX",
                    "linuxConfiguration": {
                        "disablePasswordAuthentication": true,
                        "ssh": {
                            "publicKeys": [
                                {
                                    "path": "/home/XXX/.ssh/authorized_keys",
                                }
                            ]
                        },
                        "provisionVMAgent": true,
                        "patchSettings": {
                            "patchMode": "ImageDefault",
                            "assessmentMode": "ImageDefault"
                        },
                        "enableVMAgentPlatformUpdates": false
                    },
                    "secrets": [],
                    "allowExtensionOperations": true,
                    "requireGuestProvisionSignal": true

            }
        }
    ]
}
```


## Domain DNS configuration

Go to your Domain/DNS provider and create a **A record** entry that points to the public IP of your VM

## Installation Steps

### Perform the updates

``` bash

apt-get update
apt-get upgrade -y
```

### Install rust tools (press 1 when asked)

``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source /root/.cargo/env
```

### Update i had

 Check that rust is installed and in your path

``` bash
rustc --version
cargo --version
```

### Ensure that your rust version is above 1.64
```shell
root@NOSTRrelay:/etc/nginx/sites-available# rustc --version
cargo --version
rustc 1.67.1 (d5a82bbd2 2023-02-07)
cargo 1.67.1 (8ecd4f20a 2023-01-10)
````


### Install dependencies

``` bash
apt-get install certbot build-essential sqlite3 libsqlite3-dev libssl-dev pkg-config nginx git -y
apt-get install net-tools whois -y
```

### Compile nostr-rs

``` bash
cd /opt
mkdir nostr-data
git clone https://github.com/scsibug/nostr-rs-relay.git
cd nostr-rs-relay
cargo build --release
```

Compilation can take about 10 minutes or so and produces a binary of about 19mb

### Install nostr-rs

``` bash
install target/release/nostr-rs-relay /usr/local/bin
```

## Nostr Configuration

### Create a nostr user to run the service and turn into that user

``` bash
adduser --disabled-login nostr  # keep pressing enter until it ends 
su - nostr
```

### Download the sample configuration file

``` bash
wget https://raw.githubusercontent.com/scsibug/nostr-rs-relay/master/config.toml
```

 Update / change the configuration file with your favourite editor     (ex **vim** o **nano**)
 Parameters you might want to change:
  - **relay\_url** : put ***nostr.domainname.com*** ( ⚠️ replace with the URL of the domain name you own and that points to the server)
  - **name** : don't be shy ... 
  - **description** : ... introduce yourself
  - **pubkey** : your public key
  - **contact** : your email
  - **tracing** : ⚠️ leave commented otherwise it trows errors and won't start
  - **data\_directory** : set it to **/opt/nostr-data/**
  - **address** : set it to **127.0.0.1** as we will later use nginx as a proxy
  - **remote_ip_header** : set it to **"x-forwarded-for"** for logging real client IP addresses


Go back to user root

``` bash
exit
```

### First Test / Dry-run 

Start nostr-relay as a stand alone foreground process and check the logs

``` bash
RUST_LOG=warn,nostr_rs_relay=info /usr/local/bin/nostr-rs-relay
```

Check the INFO messages, then check that the DB and other files are there

``` bash
ls -al /opt/nostr-data
total 112
drwxr-xr-x 2 root root  4096 Jan  9 07:54 ./
drwxr-xr-x 4 root root  4096 Jan  8 19:53 ../
-rw-r--r-- 1 root root 73728 Jan  9 07:55 nostr.db
-rw-r--r-- 1 root root 32768 Jan  9 07:55 nostr.db-shm
-rw-r--r-- 1 root root     0 Jan  9 07:55 nostr.db-wal
```

### Give the permissions to the user nostr

``` bash
chown -R nostr:nostr /opt/nostr-data
```

## Service Setup

### Systemd run script

Create a file **/etc/systemd/system/nostr-relay.service** with the following content

``` bash
[Unit]
Description=Nostr Relay
After=network.target

[Service]
Type=simple
User=nostr
WorkingDirectory=/home/nostr
Environment=RUST_LOG=info,nostr_rs_relay=info
ExecStart=/usr/local/bin/nostr-rs-relay
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then enable and start the nostr relay service

``` bash
systemctl daemon-reload
systemctl enable nostr-relay.service
systemctl start nostr-relay.service
```

### Check that the service is running

``` bash
systemctl status nostr-relay.service
```

``` bash
netstat -tnap | grep nostr
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      37860/nostr-rs-rela 
```

## Setup NginX proxy

### Site configuration
Create a nginx configuration file for the proxy and folders for HTTPS/TLS certificate creation

``` bash
mkdir -p /var/www/nostr/.well-known/acme-challenge/
chown -R 33:33 /var/www/nostr
cd /etc/nginx/sites-available
vim nostr-relay.conf
```

Paste this as the content of the configuration file. ⚠️ Remember to use the domain you picked

``` nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

upstream websocket {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name nostr.domainname.com;  ## <<=== CHANGE THIS

    location /.well-known/acme-challenge/ {
    root /var/www/nostr;
    allow all;
    }

    location / {
        proxy_pass http://websocket;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Enable and start the site

<!-- end list -->

``` bash
ln -s /etc/nginx/sites-available/nostr-relay.conf /etc/nginx/sites-enabled/.
rm -f /etc/nginx/sites-enabled/default
nginx -t # must say "ok... test successful"
nginx -s reload
```

### Run an external check

From another pc/server/vps (your laptop) check that you can connect to
nostr through nginx

``` bash
wget nostr01.lbrs.io
```

this should download an index.html file. Check the content

``` bash
cat index.html 
Please use a Nostr client to connect
```

## Add HTTPS/TLS

### Prepare dhparams
Create dhparams 4096 bit prime number(this will require a minute or so)

``` bash
mkdir /etc/nginx/ssl
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```

Let the screen fill up with "....+..." etc

### Certificate request 

Try certificate request in dry-run mode

``` bash
cd /var/www/nostr
certbot certonly --webroot -w . -d nostr.domainname.com --dry-run --agree-tos ## <<== Change with your domain
```

If all goes well do the **real** certificate request

``` bash
cd /var/www/nostr
certbot certonly --webroot -w . -d nostr.domainname.com ## <<== Change with your domain
```
![image](https://github.com/cdrclbrs/Setup-Nostr-relay-AzureVM/blob/main/screenshots/dryrun%20succcess.png)


The issued certificates will be found in letsencrypt folder

``` bash
ll /etc/letsencrypt/live/nostr.domainname.com/
total 12
drwxr-xr-x 2 root root 4096 Jan  9 09:04 ./
drwx------ 3 root root 4096 Jan  9 09:04 ../
-rw-r--r-- 1 root root  692 Jan  9 09:04 README
lrwxrwxrwx 1 root root   48 Jan  9 09:04 cert.pem -> ../../archive/nostr.domainname.com/cert1.pem
lrwxrwxrwx 1 root root   49 Jan  9 09:04 chain.pem -> ../../archive/nostr.domainname.com/chain1.pem
lrwxrwxrwx 1 root root   53 Jan  9 09:04 fullchain.pem -> ../../archive/nostr.domainname.com/fullchain1.pem
lrwxrwxrwx 1 root root   51 Jan  9 09:04 privkey.pem -> ../../archive/nostr.domainname.com/privkey1.pem

```
![image](https://raw.githubusercontent.com/cdrclbrs/Setup-Nostr-relay-AzureVM/main/screenshots/letsencrypt.png)

Now that you have a valid certificate set, replace the nginx configuration file to use it

``` bash
cd /etc/nginx/sites-available
vim nostr-relay.conf
```

### Update Nginx site file
Update the content as follows:

``` bash
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

upstream websocket {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name nostr.domainname.com;

   location /.well-known/acme-challenge/ {
        root /var/www/nostr;
        allow all;
    }

    location / {
        return 301 https://nostr.domainname.com;
    }
}

server  {
    listen          443 ssl;
    server_name nostr.domainname.com;

    location / {
        proxy_pass http://websocket;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    #### SSL ####

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS";
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_dhparam ssl/dhparam.pem;
    ssl_ecdh_curve secp384r1;

    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy same-origin;
    add_header Feature-Policy "geolocation none;midi none;notifications none;push none;sync-xhr none;microphone none;camera none;magnetometer none;gyroscope none;speaker self;vibrate none;fullscreen self;payment none;";


    ssl_certificate /etc/letsencrypt/live/nostr.domainname.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nostr.domainname.com/privkey.pem; 
}
```

**NOTE** : remember to change all the occurrences of ***nostr.domainname.com*** with your domain

Check the new configuration and reload it into nginx

``` bash
nginx -t
nginx -s reload
```

Now check that nginx + http + nostr are all working

``` bash
netstat -tnap | grep 'nginx\|nostr'
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      37860/nostr-rs-rela 
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      8545/nginx: master  
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      8545/nginx: master 
```

Now check that they are reachable from the outside. Like before go to another pc/server and 

``` bash
wget nostr.domainname.com
--2023-01-09 10:22:05--  http://nostr.domainname.com/
Resolving nostr.domainname.com (nostr.domainname.com)... 3.123.142.158
Connecting to nostr.domainname.com (nostr.domainname.com)|3.123.142.158|:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://nostr.domainname.com [following]
--2023-01-09 10:22:05--  https://nostr.domainname.com/
Connecting to nostr.domainname.com (nostr.domainname.com)|3.123.142.158|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 37 [text/plain]
Saving to: ‘index.html.1’

index.html.1                     100%[=============================>]      37  --.-KB/s    in 0s      
```

**NOTE** : the test is like the previous one, just this time it tries to connect to http first and get redirected (301) to https, then in https the file is download and its content are the same as before

``` bash
cat index.html 
Please use a Nostr client to connect
```

### you can test your server at url

```bash
https://websocketking.com/
```
![image](https://raw.githubusercontent.com/cdrclbrs/Setup-Nostr-relay-AzureVM/main/screenshots/WebsocketKing.png)


## Add your relay in your Nostr client (Damus)

![image](https://raw.githubusercontent.com/cdrclbrs/Setup-Nostr-relay-AzureVM/main/screenshots/damus.png)


## See it at work

This section is mostly sysadmin related but can be very useful when
trying to get "why it's not working"

### Logs

#### Nostr relay logs

To keep an eye on what's goin on simply ask the logs

``` bash
journalctl -f | grep --line-buffered nostr_rs_relay | cut -d' ' -f 10,12-100 
```

... you might want to set an alias for this. This will show the logs of nostr relay in real time. Press CTRL+C to stop it

#### Nginx logs

``` bash
tail -f /var/log/nginx/*.log
```

You can fire up a **tmux** session if you don't want to start multiple consoles

### Inspect Database

**NOTE** : ⚠️ carefull with this one as you might damage the db

Try some sqlite commands like:

    cd /opt/nostr-data
    sqlite3 nostr.db
    ...
    sqlite> .databases
    sqlite> .tables
    sqlite> select * from event;
    sqlite> select count(*) from event;
    ...

## Connect your client

If you made it so far, congrats \!\!

Now is time to connect your client and see it at work \!\!

Just connect your client to **<wss://nostr.domainname.com>**.
Send some messages, see the log get them in (almost) real time and find them in the database.

## Pitfalls

  - Do not install rust, cargo etc using apt. Just use rustup

## Links

  - <https://github.com/scsibug/nostr-rs-relay>

<!-- end list -->

  - <https://andreneves.xyz/p/set-up-a-nostr-relay-server-in-under> (5 minutes my ass)
  - <https://www.w3irdrobot.codes/posts/deploying-a-nostr-relay/>