---
title: "Measuring web traffic with Matomo"
subtitle: "You get what you measure"
date: 2021-04-22T20:40:57+03:00
tags: ["matomo", "haproxy", "letsencrypt", "website","opensuse"]
type: post
---
  

Matomo is an open source PHP/MySQL  based web analytics application to track online visits to websites and displays reports on these visits. It does what Google Analytics does, but it is open source. Matomo has commercial cloud based offering for those who do not want to host their own instance but the code is there on GitHub ([https://github.com/matomo-org/matomo](https://github.com/matomo-org/matomo)) for anyone who is interested.

I decided to first test drive the cloud based solution and then install my own instance. 

### Test drive on the cloud

This was a boringly simple and straight forward job. Just visited the [https://matomo.org/start-free-analytics-trial/](https://matomo.org/start-free-analytics-trial/) and signed up my [https://bzoltan1.github.io/](https://bzoltan1.github.io/) for the 21 day free trial period.

The only hurdle to jump over was to inject the tracker script to the Hugo base. 

```bash
cd blog-source  
mkdir -p layouts/partials  
cp themes/beautifulhugo/layouts/partials/head.html ./layouts/partials/head.html
```
  

And then copy and paste the script what the Matomo page shows to the end of the head.html template. To me it was like this

```html
<!-- Matomo -->
<script type="text/javascript">
    var _paq = window._paq = window._paq || [];
    /* tracker methods like "setCustomDimension" should be called before "trackPageView" */
    _paq.push(['trackPageView']);
    _paq.push(['enableLinkTracking']);
    (function() {
        var u="https://bzoltan1.matomo.cloud/";
        _paq.push(['setTrackerUrl', u+'matomo.php']);
        _paq.push(['setSiteId', '1']);
        var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
        g.type='text/javascript'; g.async=true; g.src='//cdn.matomo.cloud/bzoltan1.matomo.cloud/matomo.js'; s.parentNode.insertBefore(g,s);
    })();
</script>
<!-- End Matomo Code -->
```
  

After deploying this change the [https://bzoltan1.matomo.cloud](https://bzoltan1.matomo.cloud) started to show numbers.

That was easy. But my motivation to go away from Google Analytics was that I do not necessarily want to share with anybody the data I collect from my visitors.

### Installing Matomo

My server is running on beta Leap 15.3 and it has matomo available in the repository.

```bash
sudo zypper in matomo
```

This installs Matomo under `/srv/www/matomo` what I am not entirely happy as on my system the default webroot is `/srv/www/htdocs`. That actually will cause a tiny cosmetic issue later on.

I needed to set up the database and the database user in MariaDB

```sql
CREATE DATABASE matomo_db;  
CREATE USER matomouser@localhost IDENTIFIED BY '[password]';  
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, DROP, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES ON matomo_db.* TO matomouser@localhost;  
GRANT FILE ON *.* TO matomouser@localhost;
```

Naturally the `matomo_db` and `matomouser` may be different than the default in the manuals. But I prefer using vanilla names.


At that point I needed to stop a bit. My system is based on Apache2 webserver with HAProxy load balancer and with Let's Encrypt certifications. So I needed to teach my Apache where to find the webroot for Matomo.

I created `/etc/apache2/vhosts.d/matomo.conf` file with the following content


```xml
<VirtualHost matomo.nokedli.local:8080>  
   DocumentRoot "/srv/www/matomo/"  
   ServerName matomo.nokedli.org  
   <Directory /srv/www/matomo/>  
      Require all granted  
      AllowOverride All  
      Options FollowSymLinks MultiViews  
      DirectoryIndex index.php  
      <IfModule mod\_dav.c>  
         Dav off  
      </IfModule>  
    </Directory>  
</VirtualHost>
```

I have extended my HAProxy  configuration `/etc/haproxy/haproxy.cfg` to contain  the routing information

```
frontend all_443
  mode http
  # that following line comes after the certificate was successfully created
  bind *:443 ssl crt /etc/ssl/matomo.nokedli.org/matomo.nokedli.org.pem 
  http-request set-header X-Forwarded-Proto https if { ssl_fc }
  acl lets_encrypt path_beg /.well-known/acme-challenge/
  use_backend lets_encrypt if lets_encrypt
  use_backend matomo-server if { ssl_fc_sni_end matomo.nokedli.org }
  use_backend matomo-server if { ssl_fc_sni_end matomo.nokedli.local }

frontend fe-nokedli
  bind *:80
  mode http
  option httplog
  redirect scheme https code 301 if !{ ssl_fc }
  acl lets_encrypt path_beg /.well-known/acme-challenge/
  use_backend lets_encrypt if lets_encrypt
  acl is_matomo hdr_beg(host) -i matomo.nokedli.local
  acl is_matomo hdr_beg(host) -i matomo.nokedli.org
  use_backend matomo-server if is_matomo
  default_backend be-nokedli

backend lets_encrypt
  mode http
  server local localhost:54321

# default Backend
backend be-nokedli
  # Config omitted here

# Matomo Backend
backend matomo-server
  server matomo-server matomo.nokedli.local:8080
```
  

Then I created the Let's Encrypt certificate

```bash
bash -c "mkdir -p /etc/ssl/matomo.nokedli.org/ && cd /etc/letsencrypt/live/matomo.nokedli.org/ && cat fullchain.pem privkey.pem > /etc/ssl/matomo.nokedli.org/matomo.nokedli.org.pem"
```

and added the `/etc/ssl/matomo.nokedli.org/matomo.nokedli.org.pem` to the `/etc/haproxy/haproxy.cfg`

And at the end I needed to fix apparmor to let the haproxy access the PEM file, so the `/etc/apparmor.d/local/usr.sbin.haproxy` need to contain `/etc/ssl/matomo.nokedli.org/* r,`


After that visiting the [https://matomo.nokedli.org/index.php](https://matomo.nokedli.org/index.php) I could do the actual installation of the Matomo. There is not much to record about that process. I simple entered the username, password and database what I have created and used with the SQL commands above.

And then replace the script in the head.html to this

```html
<!-- Matomo -->  
<script type="text/javascript">
    var _paq = window._paq || [];
    /* tracker methods like "setCustomDimension" should be called before "trackPageView" */
    _paq.push(['trackPageView']);
    _paq.push(['enableLinkTracking']);
    (function() {
        var u="//matomo.nokedli.org/";
        _paq.push(['setTrackerUrl', u+'matomo.php']);
        _paq.push(['setSiteId', '1']);var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
        g.type='text/javascript'; g.async=true; g.defer=true; g.src=u+'matomo.js'; s.parentNode.insertBefore(g,s);
    })();
</script>
<!-- End Matomo Code -->  
```
 
What I am not happy with is that I need to use the [https://matomo.nokedli.org/index.php](https://matomo.nokedli.org/index.php) address with the `index.php` even if the `.htaccess` and the vhost configuration is configured to default to the index.php. My assumption is that there is access permission problem when the application's root is outside of the apache's webroot. I wonder why matomo is installed to the `/srv/www/` instead of the more appropriate `/srv/www/htdocs/`. I could be very wrong here, if somebody knows the solution please get in touch with me.

**UPDATE on 23.04**

Thanks for the help of [Jan Bayer](https://github.com/baierjan) we managed to figure out what caused the problem of accessing the root of the matomo. The `.htaccess` was  unnecessary and actually the root of the application was not the root :) cause of the problem.

The solution was to add to the VirtualHost section in the  `/etc/apache2/vhosts.d/matomo.conf` file the following section

```xml
 <Location "/">
    Require all granted
 </Location>
```

Most likely there was a conflict with an other webapp provided by the same web server what includes configuration snippets which affects global settings. Apache has a very complex configuration system. No wonder that it is safer and easier to deploy and maintain containerized webapps.

