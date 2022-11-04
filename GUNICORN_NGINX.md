# Configuration for Production Internet-Facing Web Service #

Install and configure [Gunicorn](https://docs.gunicorn.org/en/stable/) (Python WSGI HTTP Server for UNIX) to cater for multiple concurrent web-processes and worker processes running against the base Flask python web-app.
  
The Gunicorn HTTP service is fronted by NGINX.  
  
Supervisor can be used to monitor and control Gunicorn processes.  

<img style="float: left;" src="./doc/gunicorn_nginx.png">


These notes are tested on 
+ Ubuntu 18.04  
+ Python version 3.9.11
+ gunicorn-20.1.0  

## Gunicorn ##

Python WSGI HTTP Server for UNIX.  Allows multiple worker-threads and a standard web-framework interface for integration with NGINX
 
As the Flask application user (not root), install Gunicorn: 

+ set the Python environment.  
 
```
pip install gunicorn --upgrade
```

**Optional**: Run Gunicorn on port 8000 for testing 
 + use the `--preload` option to get log information for any errors
 + Set the necessary environment variables in advance - EG `export FLASK_LOG_DIR=./logs`


```
gunicorn -b localhost:8000 -w 4 app:app --preload
```

### Configure SYSTEMD Service for Gunicorn ###

Configure Gunicorn so that it is started and managed by the Linux Systemd service.

As `root` user create the following file:

```
/etc/systemd/system/flaskapp.service
```

and add the following contents:

```
[Unit]
Description=Gunicorn instance to serve Flask Application
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/flask-oauth-dance
Environment="PATH=/home/ubuntu/flask_app_env/bin"
Environment="FLASK_APP=flask-oauth.py"

#Environment="POSTGRES_HOST=localhost"
#Environment="POSTGRES_PORT=5432"
#Environment="POSTGRES_DB=dbname"
#Environment="POSTGRES_USER=dbname_user"

Environment="FLASK_LOG_DIR=/home/ubuntu/flask-oauth-dance/logs"
Environment="GOOGLE_OAUTH_CLIENT_ID=<client-id>.apps.googleusercontent.com"
Environment="GOOGLE_OAUTH_CLIENT_SECRET=<Google API secret token>"

#Environment="MAIL_SERVER=smtp.googlemail.com"
#Environment="MAIL_PORT=587"
#Environment="MAIL_USE_TLS=1"

ExecStart=/home/ubuntu/flask_app_env/bin/gunicorn --workers 4 --bind unix:flask-oauth.sock -m 007 flask-oauth:app

[Install]
WantedBy=multi-user.target

```

Change the paths, port etc as appropriate.  
The "flask-oauth" term in `flask-oauth:app` and `unix:flask-oauth.sock` relates to the
name of the Base flask-app name - i.e. `flask-oauth.py` in the root of the application tree heirarchy.


### Set SystemD Startup Options ###

Stop NGINX if it is running
```
sudo systemctl stop nginx
```

Start  Gunicorn:
```
sudo systemctl start flaskapp
```

Set Gunicorn to start automatically at server boot:
```
sudo systemctl enable flaskapp
```

## NGINX ##

Configure Nginx to pass web requests to the Gunicorn socket file `flask-oauth.sock` by making some additions to the Nginx configuration file.
  
As `root` user, create a configuration file `flaskapp` in the Nginx sites config directory
```
/etc/nginx/sites-available/flaskapp
```
with contents

```
server {
    listen 80;
    server_name <hostname>.com www.<hostname>.com;
    location / {
        include proxy_params;
        proxy_pass http://unix:/home/ubuntu/flask-oauth-dance/flask-oauth.sock;
    }
}

```
Link the `flaskapp` Nginx configuration to the `sites-enabled` directory

```
ln -s /etc/nginx/sites-available/flaskapp /etc/nginx/sites-enabled
```


#### Test Nginx Configuration ####

```
nginx -t
```
Expected output:
```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Restart Nginx to add configuration ###


```commandline
systemctl restart flaskapp
```

```
systemctl restart nginx
```

The flask application should be available on Port 80, if the firewall rules allow it.
  
Check status:
```
systemctl status nginx
```



## SSL Encryption ##

ref: https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-in-ubuntu-16-04

```
cd /etc/ssl
```

Generate a Self-Signed Certificate and Key

```
openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
```
Sample output:
```
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [UK]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:My Org
Organizational Unit Name (eg, section) []:My Org Unit
Common Name (e.g. server FQDN or YOUR name) []:<my DNS or my public IP>
Email Address []:
```

Check the Key and Certificate:

```
openssl x509 -noout -modulus -in /etc/ssl/certs/nginx-selfsigned.crt | openssl md5
openssl rsa -noout -modulus -in /etc/ssl/private/nginx-selfsigned.key | openssl md5
```
These should have the same output (https://stackoverflow.com/questions/26191463/ssl-error0b080074x509-certificate-routinesx509-check-private-keykey-values)



Generate a Diffie-Hellman parameters for secure key exchange:

```
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048 
```

Add the new config to the Nginx `snippets` folder in file `/etc/nginx/snippets/self-signed.conf` 
   
Contents:  

```
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;

```

Add an Nginx Params Snippet to file `/etc/nginx/snippets/ssl-params.conf`
  
Contents:

```
# from https://cipherli.st/
# and https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html

ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
ssl_ecdh_curve secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;

ssl_dhparam /etc/ssl/certs/dhparam.pem;

```

## Update the Nginx Sites file to use SSL Encrypt Cert on Port 443 ##

```
/etc/nginx/sites-enabled/flaskapp
```


Before
```

server {
    listen 80;
    server_name mydomain.com www.mydomain.com;
    location / {
        include proxy_params;
        proxy_pass http://unix:/home/ubuntu/flask-oauth-dance/flask-oauth.sock;
    }
}


```

After

```
server {
    listen 443 ssl;
    server_name mydomain.com www.mydomain.com;
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    location / {
        include proxy_params;
        proxy_pass http://unix:/home/ubuntu/flask-oauth-dance/flask-oauth.sock;
    }
}

```

and use 

```
nginx -t
```
to test the configuration.

### Ensure Port 80 Redirect is in place ###

Edit the default NGINX web configuration to redirect all port 80 traffic to port 443.

Edit `/etc/nginx/sites-enabled/default` and change as follows:

```
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        return 302 https://$host$request_uri;
```
where `mydomain.com` is an example domain to redirect target traffic for (replace as appropriate)

Use `nginx -t` to check the config.  

### Start with New Configuration ###


Restart the services:

```
systemctl restart flaskapp
systemctl restart nginx

```

*This still results in Site Not Secure message in browser due to self-certified certificate*

# SSL Encryption with a Signed Certificate #

ref: https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-18-04

1. Install CertBot for NGINX

```
add-apt-repository ppa:certbot/certbot

apt install python-certbot-nginx
```

2. Add the domain to be configured to the CertBot configuration

```

certbot --nginx -d <mydomain>.com -d www.<mydomain>.com
```


Sample session:

```
# certbot --nginx -d <mydomain>.com -d www.<mydomain>.com
...
...
Enter email address (used for urgent renewal and security notices) (Enter 'c' to
cancel): 
...
...
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Please read the Terms of Service at
https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf. You must
agree in order to register with the ACME server at
https://acme-v02.api.letsencrypt.org/directory
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(A)gree/(C)ancel: A

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Would you be willing to share your email address with the Electronic Frontier
Foundation, a founding partner of the Let's Encrypt project and the non-profit
organization that develops Certbot? We'd like to send you email about our work
encrypting the web, EFF news, campaigns, and ways to support digital freedom.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(Y)es/(N)o: N
Obtaining a new certificate
Performing the following challenges:
http-01 challenge for <mydomain>.com
http-01 challenge for www.<mydomain>.com
Waiting for verification...
Cleaning up challenges
Deploying Certificate to VirtualHost /etc/nginx/sites-enabled/flaskapp
Deploying Certificate to VirtualHost /etc/nginx/sites-enabled/flaskapp

Please choose whether or not to redirect HTTP traffic to HTTPS, removing HTTP access.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
1: No redirect - Make no further changes to the webserver configuration.
2: Redirect - Make all requests redirect to secure HTTPS access. Choose this for
new sites, or if you're confident your site works on HTTPS. You can undo this
change by editing your web server's configuration.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Select the appropriate number [1-2] then [enter] (press 'c' to cancel): 2
No matching insecure server blocks listening on port 80 found.
No matching insecure server blocks listening on port 80 found.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Congratulations! You have successfully enabled https://<mydomain>.com and
https://www.<mydomain>.com

IMPORTANT NOTES:
 - Congratulations! Your certificate and chain have been saved at:
   /etc/letsencrypt/live/<mydomain>.com/fullchain.pem
   Your key file has been saved at:
   /etc/letsencrypt/live/<mydomain>.com/privkey.pem
   Your cert will expire on <YYYY-MM-DD>. To obtain a new or tweaked
   version of this certificate in the future, simply run certbot again
   with the "certonly" option. To non-interactively renew *all* of
   your certificates, run "certbot renew"
 - Your account credentials have been saved in your Certbot
   configuration directory at /etc/letsencrypt. You should make a
   secure backup of this folder now. This configuration directory will
   also contain certificates and private keys obtained by Certbot so
   making regular backups of this folder is ideal.
 - If you like Certbot, please consider supporting our work by:

   Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
   Donating to EFF:                    https://eff.org/donate-le
```


This updates the `/etc/nginx/sites-available/flaskapp` configuration and installs the CertBot signed certificates.

**Remove the default NGINX site configuration** - this has probably been mangled by the certbot installation 

```commandline
rm /etc/nginx/sites-enabled/default

mv /etc/nginx/sites-available/default /root/nginx.default.bak
```
  
Restart FlaskApp and Nginx and test.  

SSL access should be possible without any insecure site messages.  


### Sample NGINX Site Configuration

```
server {
    listen 443 ssl;
    server_name  <mydomain>.net www.<mydomain>.net;
    ssl_certificate /etc/letsencrypt/live/<mydomain>.net/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/<mydomain>.net/privkey.pem; # managed by Certbot

    location / {
        include proxy_params;
        proxy_pass http://unix:/home/ubuntu/flask-oauth-dance/flask-oauth.sock;
    }

}

```