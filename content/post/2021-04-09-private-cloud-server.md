---
title: "Private cloud based on openSUSE Leap 15.3 beta and Nextcloud"
subtitle: "Be yourself. Unless you can be a unicorn, In that case, you should always be a unicorn."
date: 2021-04-05T19:36:57+03:00
tags: ["opensuse", "nextcloud", "mdadm", "haproxy","letsencrypt","monit","telegram"]
type: post
---


### Motivation

I used to have a Synology DS414 server what worked  well for about 8 years. Naturally, occasionally I had to change disks in the RAID5 system in it, but other than that it did its job. But regardless of the really smooth user experience and the low maintenance needs I never really liked that system as the Synology Disk Station Manager OS is not like many "real" Linux distributions and the community behind that OS is basically non existent. And to be honest I do not really feel that Synology is very eager to build and maintain a community around their OS. It looks more like that they just barely comply with the GPL. All in all, I had just enough motivation to migrate my private cloud and NAS to a proper OS.

I guess it is hardly a surprise that my choice is openSUSE. I was hesitating to use Tumbleweed, the rolling development release of openSUSE, but then I thought that will do a conservative decision and  go with the Leap 15.3 release. Leap is stable, thou I had no problem running my daily driver computer on Tumbleweed.

### The hardware

*   A fairly mature ASUS P8H77-M Pro motherboard with
*   core i5-3550 CPU @ 3.30GHz and
*   16GB of RAM.
*   The disk system would be the same as in Synology, a 4 * Western Digital NAS grade Red 3T  SATA RAID5 where one disk is a dedicated hot spare.

### The plan 

*   Install the openSUSE Leap 15.3
*   Software RAID5 with mdadm
*   NFS server for LAN clients
*   Apache web server with HAProxy load balancer and proxy server 
*   Let's Encrypt SSL certification
*   NextCloud with all the cool applications
*   Monit for system monitoring

  

### Installing the base OS

I have downloaded the installation media from the official place [http://download.opensuse.org/distribution/leap/15.3/iso/](http://download.opensuse.org/distribution/leap/15.3/iso/)

I very seldom use any other tool than the good old `dd` command  to create a USB boot stick, but this time I wanted to try out something fancy. So I installed the imagewriter app, what is a graphical utility for writing raw disk images & hybrid ISOs to USB keys. I just opened the app and dragged the `openSUSE-Leap-15.3-NET-x86_64-Build91.1-Media.iso` from the file manager to the app and plugged in an USB stick. I have quickly configured the server's BIOS to enable it booting from USB and that was it. Installing the Leap 15.3 was a pretty boring, straight forward, next-next-finish job.

### Softrawe RAID

First of all, the best instruction I have found on how to work with software raid on Linux is from Xiao Guoan - [https://www.linuxbabe.com/linux-server/linux-software-raid-1-setup](https://www.linuxbabe.com/linux-server/linux-software-raid-1-setup). I really recommend it for reading, it explains the whole workflow and the testing steps very well.

In my case to build the RAID5 from three disks was fairly simple.

I made new MBR partition table on the hard drives,created a new partition on each drive with linux raid type and assembled the RAID drive from these three disk partitions

```
parted /dev/sdb mklabel gpt
parted /dev/sdc mklabel gpt
parted /dev/sdd mklabel gpt
echo -e "n\np\n1\n\n\nt\n29\nw\nq\n" > autopart.txt
fdisk /dev/sdb < ./autopart.txt
fdisk /dev/sdc < ./autopart.txt
fdisk /dev/sdd < ./autopart.txt
mdadm --create /dev/md0 --level=5 --raid-devices=3 /dev/sdb1 /dev/sdc1 /dev/sdd1
```

After creating the drive I checked if all looks fine

```  
cat /proc/mdstat
mdadm --detail /dev/md0
mdadm --examine /dev/sdb1 /dev/sdc1 /dev/sdd1
```
  
I chose teh ext4 file system, formatted the drive and mounted it.  

```
mkfs.ext4 /dev/md0
mkdir /mnt/volume1
mount /dev/md0 /mnt/volume1
setfacl -R -m u:username:rwx /mnt/volume1
df -h
```

I want my new drive to be mounted automatically so I add an extra line to the fstab.

```
echo "UUID=`blkid|grep md0| sed -r 's/^.*UUID=\"(.*)\" BLOCK.*$/\1/'`/mnt/volume1 ext4 defaults 0 0 "
```

### NFS server

Most probably there are many other solutions to provide storage service from a private NAS. I do not know if I am totally outdated or just old school but to me NFS has worked for decades. I have been happy NFS user on HP-UX, Solaris, FreeBSD and on various Linux distros.  It is easy to set up, performs well for my needs and one can find tons of instructions, troubleshooting guides for it easily. To me the most important question when I choose a technology is usually if there is an active and big enough community behind the technology or not. Technical superiority may be worthless if I am all alone with any possible problems.

The way to set up NFS server is really easy

At this point just to have a nice system got the hosts and hostname set. I was a little bit wondering why the Leap installation did not take care of it. Maybe I accidentally looked over  something

```
echo "nas" > /etc/hostname
echo -e "127.0.0.1 nas\n::1 nas\n" > /etc/hosts
```

For the sake of the consistency of my story here I pretend if I have Music, Pictures and Movies directories to export

```
zypper install nfs-kernel-server
echo "/mnt/volume1/Music 192.168.1.0/24(rw,async,no_wdelay,no_root_squash,no_subtree_check,insecure_locks)" >> /etc/exports
echo "/mnt/volume1/Pictures 192.168.1.0/24(rw,async,no_wdelay,no_root_squash,no_subtree_check,insecure_locks)" >> /etc/exports
echo "/mnt/volume1/Movies 192.168.1.0/24(rw,async,no_wdelay,no_root_squash,no_subtree_check,insecure_locks)" >> /etc/exports
exportfs -r
systemctl enable nfsserver
systemctl restart nfsserver
showmount -e localhost
```

### Let's Encrypt with HAProxy

Naturally I want to use my NextCloud server's web UI with secure http and for that I need proper TLS certificate. Nowadays the most convenient certificate provider authority is [Let's Encrypt](https://letsencrypt.org/). 

Also I would like to use haproxy  what provides a high availability load balancer and proxy server for apache. It means that I can deploy multiple http services on my server easily. I know it is possible to work it out with apache configuration but I prefer to keep the load balancing as a separate layer.

First install both services

```
sudo zypper install haproxy apache2
```

The haproxy's default configuration is just fine but we need to add the frontend and backend configurations

```  
frontend all_443  
    mode http  
    bind *:443 ssl crt /etc/ssl/nas.nokedli.org/nas.nokedli.org.pem  
    http-request set-header X-Forwarded-Proto https if { ssl_fc }  
    use_backend nas-server if { ssl_fc_sni_end nas.nokedli.org }  
    use_backend nas-server if { ssl_fc_sni_end nas.nokedli.local }

frontend fe-nokedli  
    bind *:80  
    redirect scheme https code 301 if !{ ssl_fc }  
    acl letsencrypt-acl path_beg /.well-known/acme-challenge/  
    acl is_nas hdr_beg(host) -i nas.nokedli.local  
    use_backend letsencrypt-backend if letsencrypt-acl  
    use_backend nas-server if is_nas  
    default_backend nas-server

backend letsencrypt-backend  
    server letsencrypt 127.0.0.1:8888

backend be-nokedli  
    # Config omitted here

backend nas-server  
     server nas-server nas.nokedli.local:8080
```

With Let's Encrypt there are few tricks here. First of all, since haproxy is standing in front of the apache I need to request certificate for the webroot of the nextcloud and not for the web server. The key is the `--webroot` option.


```  
certbot certonly --standalone --non-interactive --webroot --agree-tos --email [ email address ] -d [ domain ] -w /srv/www/htdocs/nextcloud/
```

Yet again the [article about the Let's Encrypt with webroot on LinuxBabe](https://www.linuxbabe.com/security/letsencrypt-webroot-tls-certificate) is super useful and easy to understand.

Important to note that Let's Encrypt certificates are only valid for 90 days. So using Crontab to run renew regularly is a good idea.

HAProxy needs an ssl-certificate to be one file, in a certain format. To do that, I simple dump the certificates from Let's Encrypt to a single file

```
bash -c "mkdir -p /etc/ssl/nas.nokedli.org/ && cd /etc/letsencrypt/live/nas.nokedli.org/ && cat fullchain.pem privkey.pem > /etc/ssl/nas.nokedli.org/nas.nokedli.org.pem"
```

After that I needed one more thing. This is something what wasted several hours of my life as haproxy was complaining about not being able to load SSL private key from PEM file.
After some debugging I came to realize that I need to convince the apparmor to  let the haproxy access the PEM file, so the `/etc/apparmor.d/local/usr.sbin.haproxy` need to contain this

```  
/etc/ssl/nas.nokedli.org/* r,
```

### NextCloud

Installing NextCloud is not a short process, but still fairly simple and straight forward as the openSUSE documentation is complete. I just followed the instructions step by step.

[https://en.opensuse.org/SDB:LAMP_setup](https://en.opensuse.org/SDB:LAMP_setup)

[https://en.opensuse.org/SDB:Nextcloud](https://en.opensuse.org/SDB:Nextcloud)

There is one thing what is not mentioned in the documentation. In my case after the after `zypper install nextcloud` the server must be rebooted.

Also since I am using secure http the `/srv/www/htdocs/nextcloud/config/config.php` add `'overwriteprotocol' => 'https',`

And the  array of the trusted domains should be fixed too

```  
'trusted_domains' =>  
    array (  
        0 => 'nas.nokedli.org',  
        1 => 'nas.nokedli.local',  
    ),  
```

### Monit

The fundamentum of the idea is Monit. 

[https://mmonit.com/wiki/Monit/Installation](https://mmonit.com/wiki/Monit/Installation)

  

`/etc/monit.d/mdadm_monitor`

```
# Using simple regular expression matching
check file raid with path /proc/mdstat
   if match "\[.*_.*\]" then exec "/usr/local/etc/monit/scripts/message.sh"
# Using mdadm for improved granularity
check program raid-md0 with path "/sbin/mdadm --misc --detail --test /dev/md0"
  if status != 0 then exec "/usr/local/etc/monit/scripts/message.sh"

```

where the /usr/local/etc/monit/scripts/message.sh is

```
#!/bin/sh  
/usr/bin/curl --request POST --data '{"sender":"'"`uname -n` - ${MONIT_SERVICE}"'","content":"'"${MONIT_EVENT}"'"}' http://localhost:10000/send
```

I have posted a dedicated article about how I like my system being monitored

[https://bzoltan1.github.io/telegram-bridge/](https://bzoltan1.github.io/telegram-bridge/)

```  
zypper ar -f https://download.opensuse.org/repositories/home:/bzoltan1/openSUSE_Leap_15.0 bzoltan1
zypper ref
zypper in tgb
systemctl enable tgb
systemctl start tgb
```

Naturally I needed to add my token and chatid to the `/etc/tgb.yaml`


### Summary

All in all it was a fun excercise and finally I can have a fully open source and real community backed NAS with all (and more) the features what I used to have.
